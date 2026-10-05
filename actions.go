package main

// Scheduled actions: things the Orbic does by itself at a chosen time on chosen days, from a short fixed list (never an arbitrary command): save a settings snapshot, update the
// DNS block lists, run the diagnostics (anything not fine becomes an event), and reboot. Times are in the schedule time zone (see -tz). A run that is missed because
// the box was off is skipped, not made up later. A reboot needs the typed word `reboot` to create, edit or run, and is refused within 10 minutes of the box starting (so a bad schedule
// cannot become a reboot loop). Each run's result is kept with the action and logged as an event.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type schedAction struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Action     string `json:"action"` // snapshot | update_lists | diagnostics | reboot
	Time       string `json:"time"`   // HH:MM
	Days       []int  `json:"days"`   // 0 = Sunday .. 6
	Enabled    bool   `json:"enabled"`
	LastRun    int64  `json:"last_run,omitempty"`
	LastResult string `json:"last_result,omitempty"`
}

var actionKinds = map[string]string{
	"snapshot":     "Save a settings snapshot",
	"update_lists": "Update the DNS block lists",
	"diagnostics":  "Run the diagnostics",
	"reboot":       "Reboot the Orbic",
}

type actionManager struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	uptime  func() time.Duration
	runners map[string]func() (string, error)
	note    func(kind, sev, text, public string) // records an event
	running map[int]bool
}

func defaultActionManager() *actionManager {
	m := &actionManager{path: *actionsFile, now: func() time.Time { return time.Now().In(schedLoc()) }, running: map[int]bool{},
		uptime: func() time.Duration { return time.Duration(procFloat("/proc/uptime", 0)) * time.Second },
		note: func(kind, sev, text, public string) {
			if events != nil {
				events.Add([]evt{{T: time.Now().Unix(), Kind: kind, Sev: sev, Text: text, Public: public}})
			}
		}}
	m.runners = map[string]func() (string, error){
		"snapshot": func() (string, error) {
			if snaps == nil {
				return "", errors.New("snapshots are not available")
			}
			n, err := snaps.Create("scheduled")
			return "saved as " + n, err
		},
		"update_lists": func() (string, error) {
			if dnsUpdater == nil {
				return "", errors.New("the DNS filter is not running")
			}
			errs := dnsUpdater.UpdateAll(false)
			if len(errs) > 0 {
				var parts []string
				for n, e := range errs {
					parts = append(parts, n+": "+e.Error())
				}
				sort.Strings(parts)
				return "", errors.New(strings.Join(parts, "; "))
			}
			return "lists are current", nil
		},
		"diagnostics": func() (string, error) {
			r := runDiag()
			bad := r.Counts["warn"] + r.Counts["fail"]
			if bad > 0 {
				var names []string
				for _, c := range r.Checks {
					if c.Status == "warn" || c.Status == "fail" {
						names = append(names, c.Name)
					}
				}
				m.note("diagnostics", sevAttention, fmt.Sprintf("Scheduled diagnostics found %d thing(s) to look at: %s", bad, strings.Join(names, ", ")), "The Orbic's scheduled diagnostics found something to look at")
			}
			return fmt.Sprintf("%d fine, %d to look at, %d broken", r.Counts["ok"], r.Counts["warn"], r.Counts["fail"]), nil
		},
		"reboot": func() (string, error) { return "rebooting", doReboot("reboot") },
	}
	return m
}

func (m *actionManager) load() []schedAction {
	var l []schedAction
	if b, err := os.ReadFile(m.path); err == nil {
		json.Unmarshal(b, &l)
	}
	return l
}

func (m *actionManager) save(l []schedAction) error {
	b, _ := json.MarshalIndent(l, "", " ")
	return writeFileAtomic(m.path, b, 0o600)
}

func validateAction(a schedAction) error {
	if _, ok := actionKinds[a.Action]; !ok {
		return errors.New("pick one of: save a snapshot, update the block lists, run the diagnostics, reboot")
	}
	if !hhmmRe.MatchString(a.Time) {
		return errors.New("the time must look like 03:30")
	}
	if len(a.Days) == 0 {
		return errors.New("pick at least one day")
	}
	for _, d := range a.Days {
		if d < 0 || d > 6 {
			return errors.New("bad day")
		}
	}
	if len([]rune(a.Name)) > 40 {
		return errors.New("the name is too long (40 characters)")
	}
	for _, r := range a.Name {
		if r < 0x20 || r == 0x7f {
			return errors.New("the name contains a control character")
		}
	}
	return nil
}

// Set creates (ID 0) or changes an action. A reboot action needs confirm == "reboot".
func (m *actionManager) Set(a schedAction, confirm string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a.Name = strings.TrimSpace(a.Name)
	sort.Ints(a.Days)
	if a.Name == "" {
		a.Name = actionKinds[a.Action]
	}
	if err := validateAction(a); err != nil {
		return 0, err
	}
	if a.Action == "reboot" && confirm != "reboot" {
		return 0, errors.New(`a reboot schedule needs the word "reboot" typed to confirm`)
	}
	l := m.load()
	if a.ID == 0 {
		if len(l) >= 16 {
			return 0, errors.New("too many scheduled actions (16 is the limit)")
		}
		max := 0
		for _, x := range l {
			if x.ID > max {
				max = x.ID
			}
		}
		a.ID = max + 1
		l = append(l, a)
	} else {
		found := false
		for i := range l {
			if l[i].ID == a.ID {
				a.LastRun, a.LastResult = l[i].LastRun, l[i].LastResult
				l[i], found = a, true
			}
		}
		if !found {
			return 0, errors.New("no such action")
		}
	}
	return a.ID, m.save(l)
}

func (m *actionManager) Delete(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.load()
	var keep []schedAction
	for _, x := range l {
		if x.ID != id {
			keep = append(keep, x)
		}
	}
	if len(keep) == len(l) {
		return errors.New("no such action")
	}
	return m.save(keep)
}

func (a schedAction) dueAt(t time.Time) bool {
	if !a.Enabled || t.Format("15:04") != a.Time {
		return false
	}
	return hasDay(a.Days, int(t.Weekday()))
}

// nextRun is the next time the action is due after `from` (zero if it never is).
func (a schedAction) nextRun(from time.Time) time.Time {
	if !a.Enabled {
		return time.Time{}
	}
	var h, mi int
	fmt.Sscanf(a.Time, "%d:%d", &h, &mi)
	for d := 0; d < 8; d++ {
		c := time.Date(from.Year(), from.Month(), from.Day()+d, h, mi, 0, 0, from.Location())
		if c.After(from) && hasDay(a.Days, int(c.Weekday())) {
			return c
		}
	}
	return time.Time{}
}

// run executes one action and records the result; reboots are refused right after the box started.
func (m *actionManager) run(id int, viaRun bool) (string, error) {
	m.mu.Lock()
	l := m.load()
	var a *schedAction
	for i := range l {
		if l[i].ID == id {
			a = &l[i]
		}
	}
	if a == nil {
		m.mu.Unlock()
		return "", errors.New("no such action")
	}
	if m.running[id] {
		m.mu.Unlock()
		return "", errors.New("it is already running")
	}
	act, name := a.Action, a.Name
	if act == "reboot" && m.uptime() < 10*time.Minute {
		a.LastRun, a.LastResult = m.now().Unix(), "skipped: the box started less than 10 minutes ago"
		m.save(l)
		m.mu.Unlock()
		return "", errors.New(a.LastResult)
	}
	m.running[id] = true
	m.mu.Unlock()
	if act == "reboot" {
		m.note("scheduled_reboot", sevInfo, "Rebooting now: scheduled action \""+name+"\"", "The Orbic is rebooting (scheduled)")
	}
	res, err := m.runners[act]()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.running, id)
	l = m.load()
	for i := range l {
		if l[i].ID == id {
			l[i].LastRun = m.now().Unix()
			if err != nil {
				l[i].LastResult = "failed: " + err.Error()
			} else {
				l[i].LastResult = res
			}
			m.save(l)
		}
	}
	if err != nil {
		m.note("scheduled_failed", sevAttention, fmt.Sprintf("Scheduled action \"%s\" failed: %v", name, err), "A scheduled action on the Orbic failed")
		return "", err
	}
	if act != "reboot" {
		m.note("scheduled", sevInfo, fmt.Sprintf("Scheduled action \"%s\" ran: %s", name, res), "A scheduled action ran")
	}
	return res, nil
}

// Tick starts every action that is due this minute (once).
func (m *actionManager) Tick() {
	t := m.now()
	m.mu.Lock()
	l := m.load()
	var due []int
	for _, a := range l {
		if a.dueAt(t) && t.Unix()-a.LastRun > 90 && !m.running[a.ID] {
			due = append(due, a.ID)
		}
	}
	m.mu.Unlock()
	for _, id := range due {
		go m.run(id, false)
	}
}

func (m *actionManager) Loop() {
	for {
		m.Tick()
		time.Sleep(20 * time.Second)
	}
}

type actionView struct {
	schedAction
	Label   string `json:"label"`
	NextRun string `json:"next_run,omitempty"`
}

func (m *actionManager) View() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var out []actionView
	for _, a := range m.load() {
		v := actionView{schedAction: a, Label: actionKinds[a.Action]}
		if n := a.nextRun(now); !n.IsZero() {
			v.NextRun = n.Format("Mon 15:04 MST")
		}
		out = append(out, v)
	}
	if out == nil {
		out = []actionView{}
	}
	return map[string]any{"actions": out, "kinds": actionKinds, "now": now.Format("Mon 15:04 MST")}
}

var actions *actionManager
