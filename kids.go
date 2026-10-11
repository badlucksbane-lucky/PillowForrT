package main

// Kids mode: ONE house-wide switch. While it is on, the Browse page hides titles rated R, NC-17, TV-MA or adult, and unrated ones (the page asks kidsMgrG.On(); the server side of that filter is the
// next phase), and the devices marked as kids' devices get the kids network filter. The state lives in <kids-file> (0600): the switch, the parent PIN as a bcrypt hash (never the PIN), the kids' devices
// and the PIN lockout. It is deliberately NOT one of the backup sections (snapSections), so a restore can never switch Kids mode off or replace the PIN.
//
// Who may do what, all behind the web login (the script API token may read the state and nothing else):
//   turn it ON            any signed-in session, once a PIN exists (a mode nobody could lift would be a trap)
//   turn it OFF           only a session that has entered the PIN in the last 10 minutes
//   set the first PIN     any signed-in session (while Kids mode is off there is nothing to protect)
//   change the PIN        a session that is unlocked, or that sends the current PIN; every other unlock is dropped
//   add a kids' device    any signed-in session; REMOVE one: unlocked
// While Kids mode is on the server also enforces it, so the page cannot be bypassed: the torrent bridge (/api/bt/peers, /conn, /mux) answers only a session that has had a title CLEARED (POST /api/kids/clear:
// the box looks up the title's rating and only an allowed one clears; the clearance names the torrent's info-hash and lasts 6 hours, in memory), and the free-text Web and Nyaa searches are refused. What
// this does not do: the box cannot tell which title an info-hash really belongs to, so a determined person could clear a harmless title and play another hash; and a magnet link opened outside the page
// is outside all of this.
// The control for all of it lives on the /ui page (the "kiosk"). Browse, Play, Retro and the phone pages have none, and the PIN is what stops anything else that holds a session from using this API.
// Wrong PINs are counted for the whole house, not per session or address: five in a row lock the PIN for 5 minutes, then 10, 20, 40, at most 60, and a right PIN starts the count again.
// The unlock windows are per session and only in memory: a restart of the program locks everything again.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	kidsUnlockFor = 10 * time.Minute
	kidsMaxTries  = 5
	kidsLockBase  = 5 * time.Minute
	kidsLockMax   = 60 * time.Minute
	kidsMaxDevs   = 32
	kidsClearFor  = 6 * time.Hour
	kidsMaxClear  = 64 // titles cleared per session at once
)

var kidsPinRe = regexp.MustCompile(`^[0-9]{4,8}$`)

var (
	errKidsNoPin    = errors.New("set a parent PIN first")
	errKidsNeedsPin = errors.New("enter the parent PIN first")
	errKidsBadPin   = errors.New("wrong PIN")
	errKidsPinForm  = errors.New("the PIN is 4 to 8 digits")
	errKidsDevice   = errors.New("not a MAC address")
	errKidsTooMany  = errors.New("too many kids' devices")
)

// kidsLockedErr is returned while the PIN is locked out.
type kidsLockedErr struct{ Left time.Duration }

func (e kidsLockedErr) Error() string {
	return fmt.Sprintf("too many wrong PINs: try again in %d minutes", int((e.Left+time.Minute-1)/time.Minute))
}

// kidsWrongErr is a wrong PIN with how many tries are left before the lockout.
type kidsWrongErr struct{ Left int }

func (e kidsWrongErr) Error() string { return errKidsBadPin.Error() }

type kidsState struct {
	On        bool     `json:"on"`
	PinHash   string   `json:"pin_hash,omitempty"`
	Devices   []string `json:"devices"`
	Fails     int      `json:"fails"`
	LockUntil int64    `json:"lock_until,omitempty"`
	Rounds    int      `json:"lock_rounds,omitempty"`
}

type kidsMgr struct {
	mu       sync.Mutex
	path     string
	st       kidsState
	now      func() time.Time
	emit     func(evt)
	unlocked map[string]time.Time            // session id -> until (memory only)
	cleared  map[string]map[string]time.Time // session id -> info-hash -> until (memory only)
	cost     int
}

var kidsMgrG *kidsMgr

func newKidsMgr(path string) *kidsMgr {
	m := &kidsMgr{path: path, now: time.Now, unlocked: map[string]time.Time{}, cleared: map[string]map[string]time.Time{}, cost: bcryptCost,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &m.st)
	}
	if m.st.Devices == nil {
		m.st.Devices = []string{}
	}
	return m
}

// On says whether Kids mode is on. A nil manager (tests, a build without it) is off.
func (m *kidsMgr) On() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.On
}

// Devices returns the MACs marked as kids' devices.
func (m *kidsMgr) Devices() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.st.Devices...)
}

func (m *kidsMgr) saveLocked() {
	b, _ := json.Marshal(m.st)
	writeFileAtomic(m.path, b, 0o600)
}

func (m *kidsMgr) note(kind, sev, text, public string) {
	if m.emit != nil {
		m.emit(evt{T: m.now().Unix(), Kind: kind, Sev: sev, Text: text, Public: public})
	}
}

// ---- the PIN and the unlock windows ----

func (m *kidsMgr) lockedLeftLocked() time.Duration {
	if m.st.LockUntil == 0 {
		return 0
	}
	left := time.Unix(m.st.LockUntil, 0).Sub(m.now())
	if left <= 0 {
		return 0
	}
	return left
}

func (m *kidsMgr) unlockedLocked(sid string) bool {
	u, ok := m.unlocked[sid]
	if !ok {
		return false
	}
	if !m.now().Before(u) {
		delete(m.unlocked, sid)
		return false
	}
	return true
}

// checkPinLocked tests a PIN against the stored hash and keeps the house-wide count. The caller holds m.mu, which also means two guesses can never run at once.
func (m *kidsMgr) checkPinLocked(pin string) error {
	if m.st.PinHash == "" {
		return errKidsNoPin
	}
	if left := m.lockedLeftLocked(); left > 0 {
		return kidsLockedErr{left}
	}
	if bcrypt.CompareHashAndPassword([]byte(m.st.PinHash), []byte(pin)) == nil {
		m.st.Fails, m.st.Rounds, m.st.LockUntil = 0, 0, 0
		m.saveLocked()
		return nil
	}
	m.st.Fails++
	if m.st.Fails >= kidsMaxTries {
		m.st.Rounds++
		d := kidsLockBase << (m.st.Rounds - 1)
		if d > kidsLockMax || d <= 0 {
			d = kidsLockMax
		}
		m.st.Fails = 0
		m.st.LockUntil = m.now().Add(d).Unix()
		m.saveLocked()
		m.note("kids_pin_locked", sevAttention, fmt.Sprintf("The Kids mode PIN was entered wrongly %d times and is locked for %d minutes.", kidsMaxTries, int(d/time.Minute)), "The router locked a parental setting after wrong PIN tries")
		return kidsLockedErr{d}
	}
	m.saveLocked()
	return kidsWrongErr{kidsMaxTries - m.st.Fails}
}

// Unlock checks the PIN for this session and opens its 10-minute window.
func (m *kidsMgr) Unlock(sid, pin string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkPinLocked(pin); err != nil {
		return 0, err
	}
	m.unlocked[sid] = m.now().Add(kidsUnlockFor)
	m.note("kids_unlocked", sevInfo, "The Kids mode PIN was entered; its settings are open for 10 minutes.", "A parental setting was opened")
	return kidsUnlockFor, nil
}

// Lock closes this session's window now.
func (m *kidsMgr) Lock(sid string) {
	m.mu.Lock()
	delete(m.unlocked, sid)
	m.mu.Unlock()
}

// ---- the settings ----

// SetOn turns Kids mode on (any session, once a PIN exists) or off (an unlocked session only).
func (m *kidsMgr) SetOn(sid string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on == m.st.On {
		return nil
	}
	if m.st.PinHash == "" {
		return errKidsNoPin
	}
	if !on && !m.unlockedLocked(sid) {
		return errKidsNeedsPin
	}
	m.st.On = on
	m.saveLocked()
	if on {
		m.note("kids_mode_on", sevInfo, "Kids mode was turned on.", "A parental setting was changed")
	} else {
		m.note("kids_mode_off", sevAttention, "Kids mode was turned off.", "A parental setting was changed")
	}
	return nil
}

// SetPin sets the first PIN (any session), or changes it (an unlocked session, or the current PIN). Every unlock window is closed afterwards, and a changed PIN starts the count again.
func (m *kidsMgr) SetPin(sid, pin, current string) error {
	if !kidsPinRe.MatchString(pin) {
		return errKidsPinForm
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	had := m.st.PinHash != ""
	if had && !m.unlockedLocked(sid) {
		if current == "" {
			return errKidsNeedsPin // asking for the PIN is not a wrong try
		}
		if err := m.checkPinLocked(current); err != nil {
			if errors.Is(err, errKidsNoPin) {
				return errKidsNeedsPin
			}
			return err
		}
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pin), m.cost)
	if err != nil {
		return err
	}
	m.st.PinHash = string(h)
	m.st.Fails, m.st.Rounds, m.st.LockUntil = 0, 0, 0
	m.unlocked = map[string]time.Time{}
	m.saveLocked()
	if had {
		m.note("kids_pin_changed", sevAttention, "The Kids mode PIN was changed.", "A parental setting was changed")
	} else {
		m.note("kids_pin_set", sevInfo, "A Kids mode PIN was set.", "A parental setting was changed")
	}
	return nil
}

// SetDevices replaces the list of kids' devices: adding is open to any session, removing one needs an unlocked session.
func (m *kidsMgr) SetDevices(sid string, macs []string) error {
	want := make([]string, 0, len(macs))
	seen := map[string]bool{}
	for _, x := range macs {
		x = strings.ToLower(strings.TrimSpace(x))
		if !macRe.MatchString(x) {
			return errKidsDevice
		}
		if !seen[x] {
			seen[x] = true
			want = append(want, x)
		}
	}
	if len(want) > kidsMaxDevs {
		return errKidsTooMany
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removing := false
	for _, old := range m.st.Devices {
		if !seen[old] {
			removing = true
		}
	}
	if removing && m.st.PinHash != "" && !m.unlockedLocked(sid) {
		return errKidsNeedsPin
	}
	m.st.Devices = want
	m.saveLocked()
	m.note("kids_devices", sevInfo, fmt.Sprintf("The list of kids' devices changed (%d).", len(want)), "A parental setting was changed")
	return nil
}

// ---- clearing titles for the torrent bridge ----

// Clear records that this session may play this torrent (the caller has checked the title's rating).
func (m *kidsMgr) Clear(sid, hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cleared[sid]
	if c == nil {
		c = map[string]time.Time{}
		m.cleared[sid] = c
	}
	now := m.now()
	for h, u := range c {
		if !now.Before(u) {
			delete(c, h)
		}
	}
	if len(c) >= kidsMaxClear { // the oldest goes
		var oh string
		var ou time.Time
		for h, u := range c {
			if oh == "" || u.Before(ou) {
				oh, ou = h, u
			}
		}
		delete(c, oh)
	}
	c[hash] = now.Add(kidsClearFor)
}

// IsCleared says whether this session may play this torrent. With Kids mode off everything is.
func (m *kidsMgr) IsCleared(sid, hash string) bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.st.On {
		return true
	}
	u, ok := m.cleared[sid][hash]
	return ok && m.now().Before(u)
}

// AnyCleared says whether this session has any title cleared now (the bridge's connections carry no info-hash). With Kids mode off it is always true.
func (m *kidsMgr) AnyCleared(sid string) bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.st.On {
		return true
	}
	for _, u := range m.cleared[sid] {
		if m.now().Before(u) {
			return true
		}
	}
	return false
}

var kidsRefusal = map[string]any{"error": "Kids mode is on: this title is not cleared", "kids": true}

// kidsBridgeOK is the gate in front of the torrent bridge: peers needs this torrent cleared, the connections need any clearance. A script token has no session and is refused while Kids mode is on.
func kidsBridgeOK(w http.ResponseWriter, r *http.Request, path string) bool {
	m := kidsMgrG
	if m == nil || !m.On() {
		return true
	}
	sid := kidsSID(r)
	ok := false
	switch path {
	case "bt/peers":
		ok = sid != "" && m.IsCleared(sid, strings.ToLower(r.URL.Query().Get("h")))
	case "bt/conn", "bt/mux":
		ok = sid != "" && m.AnyCleared(sid)
	default:
		return true
	}
	if !ok {
		writeJSON(w, 403, kidsRefusal)
	}
	return ok
}

// kidsNoSearch refuses the free-text searches (the Web tab and Nyaa) while Kids mode is on.
func kidsNoSearch(w http.ResponseWriter) bool {
	if kidsMgrG != nil && kidsMgrG.On() {
		writeJSON(w, 403, map[string]any{"error": "Search is off while Kids mode is on", "kids": true})
		return true
	}
	return false
}

// ---- what the page sees ----

type kidsView struct {
	On         bool     `json:"on"`
	HasPin     bool     `json:"has_pin"`
	Unlocked   bool     `json:"unlocked"`
	UnlockLeft int      `json:"unlock_left"` // seconds
	LockedFor  int      `json:"locked_for"`  // seconds the PIN is locked out, 0 when it is not
	TriesLeft  int      `json:"tries_left"`
	RatingsKey bool     `json:"ratings_key"` // a TMDB key is set, so movies and series can be rated; without it Kids mode hides them all
	Devices    []string `json:"devices"`
}

// viewOf is what the API returns: the manager's view plus whether ratings are set up (rating.go).
func (m *kidsMgr) viewOf(sid string) kidsView {
	v := m.View(sid)
	v.RatingsKey = ratingMgrG.Configured()
	return v
}

func (m *kidsMgr) View(sid string) kidsView {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := kidsView{On: m.st.On, HasPin: m.st.PinHash != "", Devices: append([]string{}, m.st.Devices...), TriesLeft: kidsMaxTries - m.st.Fails}
	if m.unlockedLocked(sid) {
		v.Unlocked, v.UnlockLeft = true, int(m.unlocked[sid].Sub(m.now()).Seconds())
	}
	v.LockedFor = int(m.lockedLeftLocked().Seconds())
	return v
}

// ---- the API: /api/kids ----

func kidsSID(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// kidsFail turns an error from the manager into the right status and body.
func kidsFail(w http.ResponseWriter, err error) {
	var lk kidsLockedErr
	var wr kidsWrongErr
	switch {
	case errors.As(err, &lk):
		w.Header().Set("Retry-After", fmt.Sprint(int(lk.Left.Seconds())+1))
		writeJSON(w, 429, map[string]any{"error": lk.Error(), "locked_for": int(lk.Left.Seconds())})
	case errors.As(err, &wr):
		writeJSON(w, 403, map[string]any{"error": "wrong PIN", "tries_left": wr.Left})
	case errors.Is(err, errKidsNeedsPin):
		writeJSON(w, 403, map[string]any{"error": err.Error(), "needs_pin": true})
	case errors.Is(err, errKidsNoPin):
		writeJSON(w, 409, map[string]any{"error": err.Error(), "needs_setup": true})
	default:
		writeJSON(w, 400, map[string]string{"error": err.Error()})
	}
}

func handleKidsAPI(w http.ResponseWriter, r *http.Request, path string) {
	m := kidsMgrG
	if m == nil {
		writeJSON(w, 404, map[string]string{"error": "not available"})
		return
	}
	sid := kidsSID(r)
	if path == "kids" && r.Method == http.MethodGet { // the state: also for the script token, which sees a locked view
		writeJSON(w, 200, m.viewOf(sid))
		return
	}
	// everything else changes something: a signed-in web session only. The script API token never changes Kids mode.
	if s, _ := r.Context().Value(sessionKey).(*session); s == nil || sid == "" {
		writeJSON(w, 403, map[string]string{"error": "Kids mode is changed from the web page, signed in; the script token cannot"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var b struct {
		PIN     string    `json:"pin"`
		Current string    `json:"current"`
		On      *bool     `json:"on"`
		Devices *[]string `json:"devices"`
		Kind    string    `json:"kind"`
		ID      string    `json:"id"`
		Hash    string    `json:"hash"`
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	switch path {
	case "kids/unlock":
		left, err := m.Unlock(sid, b.PIN)
		if err != nil {
			kidsFail(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"unlocked_for": int(left.Seconds()), "view": m.viewOf(sid)})
	case "kids/lock":
		m.Lock(sid)
		writeJSON(w, 200, m.viewOf(sid))
	case "kids/set":
		if b.On == nil && b.Devices == nil {
			writeJSON(w, 400, map[string]string{"error": "nothing to change"})
			return
		}
		if b.Devices != nil { // the more restrictive change first; each is checked on its own
			if err := m.SetDevices(sid, *b.Devices); err != nil {
				kidsFail(w, err)
				return
			}
		}
		if b.On != nil {
			if err := m.SetOn(sid, *b.On); err != nil {
				kidsFail(w, err)
				return
			}
		}
		writeJSON(w, 200, m.viewOf(sid))
	case "kids/clear": // the page is about to play a torrent: is its title allowed?
		h := strings.ToLower(b.Hash)
		if !validHash(h) || (b.Kind != "movie" && b.Kind != "series" && b.Kind != "anime") {
			writeJSON(w, 400, map[string]string{"error": "kind and a 40-character hash are needed"})
			return
		}
		if !m.On() {
			writeJSON(w, 200, map[string]any{"cleared": true, "kids": false})
			return
		}
		ok, why := ratingMgrG.Allowed(r.Context(), b.Kind, b.ID)
		if !ok {
			writeJSON(w, 403, map[string]any{"error": "hidden by Kids mode", "why": why, "kids": true})
			return
		}
		m.Clear(sid, h)
		writeJSON(w, 200, map[string]any{"cleared": true, "kids": true})
	case "kids/pin":
		if err := m.SetPin(sid, b.PIN, b.Current); err != nil {
			kidsFail(w, err)
			return
		}
		writeJSON(w, 200, m.viewOf(sid))
	default:
		http.Error(w, "not found", 404)
	}
}
