package main

// Our own firewall rules, replacing the stock admin's firewall pages (whose rules live in /usrdata/data/usr/firewall/*.xml and are not used here). Two kinds:
//   - blocked destinations: an IP or CIDR no device on the network (and not the Orbic itself, so the proxied traffic is covered too) may reach;
//   - internet schedules and pauses: a device's internet is cut during a weekly window or until a time, while its LAN access, DHCP and this web page stay.
// The list of record is /data/proxy/fw.json (0600). Everything is rendered into chains we own (HS_FW forward, HS_FWIN input, HS_FWOUT output, HS_FW6 for
// IPv6) and loaded atomically with iptables-restore --noflush; a loop every 15 s re-evaluates the clock, expires pauses and re-asserts the hooks, which the stock
// firmware can rebuild. Rules are matched by MAC, as the block list is.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the zone database is compiled in: the Orbic has no usable one for the configured zone and its stock zone is fixed Eastern
)

type fwDest struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
}

type fwSched struct {
	ID      int    `json:"id"`
	MAC     string `json:"mac"`
	Days    []int  `json:"days"` // 0 = Sunday .. 6 = Saturday; the day the window starts
	From    string `json:"from"` // HH:MM, the Orbic's local time
	To      string `json:"to"`   // a window with To before From runs past midnight
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
}

type fwState struct {
	Next  int              `json:"next"`
	Dest  []fwDest         `json:"dest"`
	Sched []fwSched        `json:"sched"`
	Pause map[string]int64 `json:"pause"` // MAC -> unix time the pause ends
}

var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

func hhmm(s string) int {
	var h, m int
	fmt.Sscanf(s, "%d:%d", &h, &m)
	return h*60 + m
}

// normDest turns "1.2.3.4" or "10.0.0.0/8" into canonical CIDR form and refuses what would cut the house off from itself or the world.
func normDest(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return "", errors.New("not an address: use 203.0.113.7 or 203.0.113.0/24")
		}
		if ip.To4() != nil {
			s += "/32"
		} else {
			s += "/128"
		}
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", errors.New("not an address: use 203.0.113.7 or 203.0.113.0/24")
	}
	ones, _ := n.Mask.Size()
	if ip.To4() != nil {
		if ones < 8 {
			return "", errors.New("too wide: IPv4 ranges must be /8 or narrower")
		}
	} else if ones < 16 {
		return "", errors.New("too wide: IPv6 ranges must be /16 or narrower")
	}
	for _, c := range []string{"192.168.1.0/24", "127.0.0.0/8", "0.0.0.0/8", "::1/128", "fe80::/10"} {
		_, k, _ := net.ParseCIDR(c)
		if k.Contains(n.IP) || n.Contains(k.IP) {
			return "", errors.New("that range overlaps the local network or the Orbic itself")
		}
	}
	return n.String(), nil
}

func validateSched(s fwSched) error {
	if !macRe.MatchString(s.MAC) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	if len(s.Days) == 0 {
		return errors.New("pick at least one day")
	}
	for _, d := range s.Days {
		if d < 0 || d > 6 {
			return errors.New("bad day")
		}
	}
	if !hhmmRe.MatchString(s.From) || !hhmmRe.MatchString(s.To) {
		return errors.New("times must look like 22:30")
	}
	if s.From == s.To {
		return errors.New("the window must not start and end at the same time")
	}
	if len(s.Note) > 60 {
		return errors.New("the note is too long")
	}
	return nil
}

func hasDay(days []int, d int) bool {
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}

// schedActive says whether a window is in force at `now`.
func schedActive(s fwSched, now time.Time) bool {
	if !s.Enabled {
		return false
	}
	t, d := now.Hour()*60+now.Minute(), int(now.Weekday())
	from, to := hhmm(s.From), hhmm(s.To)
	if from < to {
		return hasDay(s.Days, d) && t >= from && t < to
	}
	return (hasDay(s.Days, d) && t >= from) || (hasDay(s.Days, (d+6)%7) && t < to)
}

// cutMACs lists the devices whose internet is cut at `now` (schedules and pauses).
func cutMACs(st fwState, now time.Time) []string {
	set := map[string]bool{}
	for _, s := range st.Sched {
		if schedActive(s, now) {
			set[s.MAC] = true
		}
	}
	for m, until := range st.Pause {
		if until > now.Unix() {
			set[m] = true
		}
	}
	var out []string
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// planFW renders the IPv4 and IPv6 rule blocks. Pure function: unit-tested.
func planFW(st fwState, cut []string) (v4, v6 string) {
	var a, b strings.Builder
	a.WriteString("*filter\n:HS_FW - [0:0]\n:HS_FWIN - [0:0]\n:HS_FWOUT - [0:0]\n")
	b.WriteString("*filter\n:HS_FW6 - [0:0]\n")
	for _, m := range cut {
		fmt.Fprintf(&a, "-A HS_FW -i bridge0 -m mac --mac-source %s ! -d 192.168.1.0/24 -j REJECT --reject-with icmp-port-unreachable\n", m)
		fmt.Fprintf(&a, "-A HS_FWIN -m mac --mac-source %s -p udp --dport 53 -j DROP\n", m)
		fmt.Fprintf(&a, "-A HS_FWIN -m mac --mac-source %s -p tcp --dport 53 -j DROP\n", m)
		fmt.Fprintf(&a, "-A HS_FWIN -m mac --mac-source %s -p tcp --dport 3128 -j DROP\n", m)
		fmt.Fprintf(&b, "-A HS_FW6 -i bridge0 -m mac --mac-source %s ! -d fe80::/10 -j REJECT --reject-with icmp6-port-unreachable\n", m)
	}
	for _, d := range st.Dest {
		if strings.Contains(d.CIDR, ":") {
			fmt.Fprintf(&b, "-A HS_FW6 -i bridge0 -d %s -j REJECT --reject-with icmp6-port-unreachable\n", d.CIDR)
		} else {
			fmt.Fprintf(&a, "-A HS_FW -i bridge0 -d %s -j REJECT --reject-with icmp-port-unreachable\n", d.CIDR)
			fmt.Fprintf(&a, "-A HS_FWOUT -d %s -j REJECT --reject-with icmp-port-unreachable\n", d.CIDR)
		}
	}
	a.WriteString("COMMIT\n")
	b.WriteString("COMMIT\n")
	return a.String(), b.String()
}

type fwManager struct {
	mu    sync.Mutex
	path  string
	now   func() time.Time
	apply func(v4, v6 string) error
}

// schedLoc is the zone schedules and the page's clock use (the -tz flag; the stock firmware's own clock is fixed Eastern).
func schedLoc() *time.Location {
	loc, err := time.LoadLocation(*schedTZ)
	if err != nil {
		log.Printf("time zone %q: %v; using the system zone", *schedTZ, err)
		return time.Local
	}
	return loc
}

func defaultFWManager() *fwManager {
	loc := schedLoc()
	return &fwManager{path: *fwFile, now: func() time.Time { return time.Now().In(loc) }, apply: func(v4, v6 string) error {
		if err := restore("iptables-restore", v4); err != nil {
			return err
		}
		if err := restore("ip6tables-restore", v6); err != nil {
			return err
		}
		for _, h := range [][2]string{
			{"iptables", "FORWARD 2 -j HS_FW"}, {"iptables", "INPUT 2 -j HS_FWIN"}, {"iptables", "OUTPUT 1 -j HS_FWOUT"}, {"ip6tables", "FORWARD 1 -j HS_FW6"},
		} {
			parts := strings.SplitN(h[1], " ", 2) // "FORWARD", "2 -j HS_FW"
			chain, rest := parts[0], parts[1]
			spec := rest[strings.Index(rest, "-j"):]
			if out, err := run("sh", "-c", fmt.Sprintf("%s -C %s %s 2>/dev/null || %s -I %s %s", h[0], chain, spec, h[0], chain, rest)); err != nil {
				return fmt.Errorf("hook %s %s: %v %s", h[0], chain, err, out)
			}
		}
		return nil
	}}
}

func (m *fwManager) load() fwState {
	var st fwState
	if b, err := os.ReadFile(m.path); err == nil {
		json.Unmarshal(b, &st)
	}
	if st.Pause == nil {
		st.Pause = map[string]int64{}
	}
	return st
}

func (m *fwManager) save(st fwState) error {
	b, _ := json.MarshalIndent(st, "", " ")
	return writeFileAtomic(m.path, b, 0o600)
}

// commit saves and applies; a failure to apply is reported but the state stays saved (the loop retries).
func (m *fwManager) commit(st fwState) error {
	if err := m.save(st); err != nil {
		return err
	}
	if err := m.reapply(st); err != nil {
		return fmt.Errorf("saved, but %v (it is re-applied within 15 seconds)", err)
	}
	return nil
}

func (m *fwManager) reapply(st fwState) error {
	v4, v6 := planFW(st, cutMACs(st, m.now()))
	return m.apply(v4, v6)
}

func (m *fwManager) Reconcile() {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.load()
	changed := false
	for mac, until := range st.Pause { // expired pauses go
		if until <= m.now().Unix() {
			delete(st.Pause, mac)
			changed = true
		}
	}
	if changed {
		m.save(st)
	}
	if err := m.reapply(st); err != nil {
		fmt.Fprintf(os.Stderr, "firewall: %v\n", err)
	}
}

func (m *fwManager) Run() {
	for {
		m.Reconcile()
		time.Sleep(15 * time.Second)
	}
}

func (m *fwManager) AddDest(cidr, note string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := normDest(cidr)
	if err != nil {
		return err
	}
	if len(note) > 60 {
		return errors.New("the note is too long")
	}
	st := m.load()
	for _, d := range st.Dest {
		if d.CIDR == c {
			return errors.New("already blocked")
		}
	}
	if len(st.Dest) >= 128 {
		return errors.New("too many blocked destinations (128 is the limit)")
	}
	st.Dest = append(st.Dest, fwDest{CIDR: c, Note: strings.TrimSpace(note)})
	return m.commit(st)
}

func (m *fwManager) DeleteDest(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := normDest(cidr)
	if err != nil {
		return err
	}
	st := m.load()
	var keep []fwDest
	for _, d := range st.Dest {
		if d.CIDR != c {
			keep = append(keep, d)
		}
	}
	if len(keep) == len(st.Dest) {
		return errors.New("that destination is not blocked")
	}
	st.Dest = keep
	return m.commit(st)
}

func (m *fwManager) SetSched(s fwSched) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.MAC = strings.ToLower(strings.TrimSpace(s.MAC))
	s.Note = strings.TrimSpace(s.Note)
	sort.Ints(s.Days)
	if err := validateSched(s); err != nil {
		return err
	}
	st := m.load()
	found := false
	for i := range st.Sched {
		if s.ID != 0 && st.Sched[i].ID == s.ID {
			st.Sched[i], found = s, true
		}
	}
	if s.ID != 0 && !found {
		return errors.New("no such schedule")
	}
	if !found {
		if len(st.Sched) >= 32 {
			return errors.New("too many schedules (32 is the limit)")
		}
		st.Next++
		s.ID = st.Next
		st.Sched = append(st.Sched, s)
	}
	return m.commit(st)
}

func (m *fwManager) DeleteSched(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.load()
	var keep []fwSched
	for _, s := range st.Sched {
		if s.ID != id {
			keep = append(keep, s)
		}
	}
	if len(keep) == len(st.Sched) {
		return errors.New("no such schedule")
	}
	st.Sched = keep
	return m.commit(st)
}

func (m *fwManager) Pause(mac string, minutes int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	if minutes < 1 || minutes > 1440 {
		return errors.New("pause for 1 to 1440 minutes")
	}
	st := m.load()
	st.Pause[mac] = m.now().Add(time.Duration(minutes) * time.Minute).Unix()
	return m.commit(st)
}

func (m *fwManager) Resume(mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	st := m.load()
	if _, ok := st.Pause[mac]; !ok {
		return errors.New("that device is not paused")
	}
	delete(st.Pause, mac)
	return m.commit(st)
}

type fwView struct {
	Now    string        `json:"now"`
	Dest   []fwDest      `json:"dest"`
	Sched  []fwSchedView `json:"sched"`
	Paused []fwPauseView `json:"paused"`
	CutNow []string      `json:"cut_now"`
}
type fwSchedView struct {
	fwSched
	Name   string `json:"name,omitempty"`
	Active bool   `json:"active"`
}
type fwPauseView struct {
	MAC   string `json:"mac"`
	Name  string `json:"name,omitempty"`
	Until string `json:"until"`
}

func (m *fwManager) View(names map[string]string) fwView {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.load()
	now := m.now()
	v := fwView{Now: now.Format("Mon 15:04 MST"), Dest: append([]fwDest{}, st.Dest...), Sched: []fwSchedView{}, Paused: []fwPauseView{}, CutNow: cutMACs(st, now)}
	for _, s := range st.Sched {
		v.Sched = append(v.Sched, fwSchedView{fwSched: s, Name: names[s.MAC], Active: schedActive(s, now)})
	}
	for mac, until := range st.Pause {
		if until > now.Unix() {
			v.Paused = append(v.Paused, fwPauseView{MAC: mac, Name: names[mac], Until: time.Unix(until, 0).In(now.Location()).Format("Mon 15:04")})
		}
	}
	sort.Slice(v.Paused, func(i, j int) bool { return v.Paused[i].MAC < v.Paused[j].MAC })
	return v
}

// Replace swaps the rules and schedules (a restore); live pauses are kept as they are. The state must already be cleaned.
func (m *fwManager) Replace(in fwState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.load()
	in.Pause = cur.Pause
	return m.commit(in)
}
