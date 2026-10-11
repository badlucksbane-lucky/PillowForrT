package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func testKids(t *testing.T) (*kidsMgr, *time.Time, *[]evt) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	var got []evt
	m := newKidsMgr(filepath.Join(t.TempDir(), "kids.json"))
	m.now = func() time.Time { return now }
	m.emit = func(e evt) { got = append(got, e) }
	m.cost = bcrypt.MinCost
	return m, &now, &got
}

func wantErr(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: got %v, want %v", what, err, want)
	}
}

func TestKidsStartsOffAndNeedsAPinToTurnOn(t *testing.T) {
	m, _, _ := testKids(t)
	v := m.View("a")
	if v.On || v.HasPin || v.Unlocked || v.LockedFor != 0 || v.TriesLeft != 5 || len(v.Devices) != 0 {
		t.Errorf("a fresh box: %+v", v)
	}
	wantErr(t, m.SetOn("a", true), errKidsNoPin, "on with no PIN (a mode nobody could lift is a trap)")
	for _, bad := range []string{"", "123", "12345678 ", "123456789", "abcd", "12 34", "１２３４"} {
		if err := m.SetPin("a", bad, ""); !errors.Is(err, errKidsPinForm) {
			t.Errorf("PIN %q must be refused: %v", bad, err)
		}
	}
	if err := m.SetPin("a", "1234", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.SetOn("b", true); err != nil || !m.On() {
		t.Errorf("any session may turn it ON once a PIN exists: %v", err)
	}
	raw, _ := os.ReadFile(m.path)
	if strings.Contains(string(raw), "1234") || !strings.Contains(string(raw), "$2a$") {
		t.Errorf("the file must hold a bcrypt hash and never the PIN: %s", raw)
	}
	if fi, _ := os.Stat(m.path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
}

func TestKidsTurningOffNeedsTheUnlock(t *testing.T) {
	m, now, got := testKids(t)
	m.SetPin("a", "1234", "")
	m.SetOn("a", true)
	wantErr(t, m.SetOn("a", false), errKidsNeedsPin, "off without the PIN")
	if !m.On() {
		t.Fatal("still on")
	}
	_, err := m.Unlock("a", "9999")
	var wr kidsWrongErr
	if !errors.As(err, &wr) || wr.Left != 4 {
		t.Errorf("a wrong PIN says how many tries are left: %v", err)
	}
	wantErr(t, m.SetOn("a", false), errKidsNeedsPin, "a wrong PIN opens nothing")
	if _, err := m.Unlock("a", "1234"); err != nil {
		t.Fatal(err)
	}
	if v := m.View("a"); !v.Unlocked || v.UnlockLeft != 600 || v.TriesLeft != 5 {
		t.Errorf("unlocked for 10 minutes, count reset: %+v", v)
	}
	if v := m.View("b"); v.Unlocked {
		t.Error("another session is not unlocked by it")
	}
	wantErr(t, m.SetOn("b", false), errKidsNeedsPin, "another session still cannot")
	*now = now.Add(9*time.Minute + 59*time.Second)
	if !m.View("a").Unlocked {
		t.Error("still open just before 10 minutes")
	}
	*now = now.Add(2 * time.Second)
	wantErr(t, m.SetOn("a", false), errKidsNeedsPin, "after 10 minutes the window is closed")
	m.Unlock("a", "1234")
	if err := m.SetOn("a", false); err != nil || m.On() {
		t.Errorf("an unlocked session turns it off: %v", err)
	}
	m.SetOn("a", true)
	m.Lock("a")
	wantErr(t, m.SetOn("a", false), errKidsNeedsPin, "Lock now closes the window")
	kinds := []string{}
	for _, e := range *got {
		kinds = append(kinds, e.Kind)
		if strings.Contains(e.Public, "1234") || strings.Contains(e.Text, "1234") || strings.Contains(e.Public, "Kids") {
			t.Errorf("events must never carry the PIN, and the public text is generic: %+v", e)
		}
	}
	if strings.Join(kinds, ",") != "kids_pin_set,kids_mode_on,kids_unlocked,kids_unlocked,kids_mode_off,kids_mode_on" {
		t.Errorf("events: %v", kinds)
	}
	for _, e := range *got {
		if e.Kind == "kids_mode_off" && e.Sev != sevAttention {
			t.Errorf("turning it off is worth a look: %+v", e)
		}
	}
}

func TestKidsPinLockoutEscalates(t *testing.T) {
	m, now, got := testKids(t)
	m.SetPin("a", "4321", "")
	try := func(pin string) error { _, err := m.Unlock("a", pin); return err }
	for i := 0; i < 4; i++ {
		try("0000")
	}
	var lk kidsLockedErr
	if err := try("0000"); !errors.As(err, &lk) || lk.Left != 5*time.Minute {
		t.Fatalf("the fifth wrong PIN locks for 5 minutes: %v", err)
	}
	if err := try("4321"); !errors.As(err, &lk) {
		t.Errorf("even the right PIN is refused while locked: %v", err)
	}
	if v := m.View("a"); v.LockedFor != 300 {
		t.Errorf("the page is told how long: %+v", v)
	}
	*now = now.Add(5*time.Minute + time.Second)
	for i := 0; i < 5; i++ {
		try("0000")
	}
	if err := try("4321"); !errors.As(err, &lk) || lk.Left < 9*time.Minute || lk.Left > 10*time.Minute {
		t.Errorf("the second lockout is 10 minutes: %v", err)
	}
	*now = now.Add(10*time.Minute + time.Second)
	for i := 0; i < 5; i++ {
		try("0000")
	}
	*now = now.Add(20*time.Minute + time.Second)
	for i := 0; i < 5; i++ {
		try("0000")
	}
	*now = now.Add(40*time.Minute + time.Second)
	for i := 0; i < 5; i++ {
		try("0000")
	}
	if err := try("4321"); !errors.As(err, &lk) || lk.Left > 60*time.Minute || lk.Left < 59*time.Minute {
		t.Errorf("never longer than 60 minutes: %v", err)
	}
	*now = now.Add(60*time.Minute + time.Second)
	if err := try("4321"); err != nil {
		t.Errorf("the right PIN works when the lockout is over: %v", err)
	}
	for i := 0; i < 5; i++ {
		try("0000")
	}
	if err := try("4321"); !errors.As(err, &lk) || lk.Left != 5*time.Minute {
		t.Errorf("a right PIN starts the escalation again: %v", err)
	}
	n := 0
	for _, e := range *got {
		if e.Kind == "kids_pin_locked" {
			n++
			if e.Sev != sevAttention {
				t.Errorf("a lockout is an attention event: %+v", e)
			}
		}
	}
	if n < 5 {
		t.Errorf("every lockout is an event, got %d", n)
	}
}

func TestKidsLockoutIsHouseWideAndSurvivesARestart(t *testing.T) {
	m, now, _ := testKids(t)
	m.SetPin("a", "4321", "")
	for i := 0; i < 5; i++ {
		m.Unlock([]string{"a", "b", "c", "d", "e"}[i], "0000") // five different sessions share one count
	}
	if v := m.View("z"); v.LockedFor == 0 {
		t.Errorf("the count is for the house, not per session: %+v", v)
	}
	m2 := newKidsMgr(m.path)
	m2.now = func() time.Time { return *now }
	if v := m2.View("a"); v.LockedFor == 0 || !v.HasPin {
		t.Errorf("a restart (a deploy) must not clear the lockout: %+v", v)
	}
	if _, err := m2.Unlock("a", "4321"); err == nil {
		t.Error("and the right PIN is still refused")
	}
}

func TestKidsChangingThePin(t *testing.T) {
	m, _, _ := testKids(t)
	m.SetPin("a", "1111", "")
	m.SetOn("a", true)
	wantErr(t, m.SetPin("a", "2222", ""), errKidsNeedsPin, "a new PIN with no proof")
	var wr kidsWrongErr
	if err := m.SetPin("a", "2222", "9999"); !errors.As(err, &wr) {
		t.Errorf("a wrong current PIN counts as a wrong try: %v", err)
	}
	m.Unlock("b", "1111")
	if err := m.SetPin("a", "2222", "1111"); err != nil {
		t.Fatalf("the current PIN is proof enough: %v", err)
	}
	if m.View("b").Unlocked {
		t.Error("changing the PIN closes every unlock window, other sessions included")
	}
	if _, err := m.Unlock("a", "1111"); err == nil {
		t.Error("the old PIN no longer works")
	}
	if _, err := m.Unlock("a", "2222"); err != nil {
		t.Error("the new one does")
	}
	if err := m.SetPin("a", "3333", ""); err != nil {
		t.Errorf("an unlocked session may change the PIN without typing the old one: %v", err)
	}
	if v := m.View("a"); v.TriesLeft != 5 {
		t.Errorf("a changed PIN starts the count again: %+v", v)
	}
}

func TestKidsDevices(t *testing.T) {
	m, _, _ := testKids(t)
	m.SetPin("a", "1234", "")
	if err := m.SetDevices("a", []string{"AA:BB:CC:DD:EE:01", " aa:bb:cc:dd:ee:02 ", "aa:bb:cc:dd:ee:01"}); err != nil {
		t.Fatal(err)
	}
	if d := m.Devices(); len(d) != 2 || d[0] != "aa:bb:cc:dd:ee:01" || d[1] != "aa:bb:cc:dd:ee:02" {
		t.Errorf("lower case, trimmed, no duplicates: %v", d)
	}
	if err := m.SetDevices("a", []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}); err != nil {
		t.Errorf("adding a kids' device is open to any session: %v", err)
	}
	wantErr(t, m.SetDevices("a", []string{"aa:bb:cc:dd:ee:01"}), errKidsNeedsPin, "removing one needs the PIN")
	if len(m.Devices()) != 3 {
		t.Error("nothing changed")
	}
	m.Unlock("a", "1234")
	if err := m.SetDevices("a", []string{"aa:bb:cc:dd:ee:01"}); err != nil || len(m.Devices()) != 1 {
		t.Errorf("an unlocked session may remove: %v", err)
	}
	for _, bad := range []string{"nonsense", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:0g", ""} {
		if err := m.SetDevices("a", []string{bad}); !errors.Is(err, errKidsDevice) {
			t.Errorf("%q must be refused: %v", bad, err)
		}
	}
	many := []string{}
	for i := 0; i < 33; i++ {
		many = append(many, "aa:bb:cc:dd:"+string(rune('0'+i/10))+string(rune('0'+i%10))+":01")
	}
	if err := m.SetDevices("a", many); err == nil {
		t.Error("at most 32 devices")
	}
}

func TestKidsStateSurvivesARestartButUnlocksDoNot(t *testing.T) {
	m, now, _ := testKids(t)
	m.SetPin("a", "1234", "")
	m.SetOn("a", true)
	m.SetDevices("a", []string{"aa:bb:cc:dd:ee:01"})
	m.Unlock("a", "1234")
	m2 := newKidsMgr(m.path)
	m2.now = func() time.Time { return *now }
	if !m2.On() || len(m2.Devices()) != 1 || !m2.View("a").HasPin {
		t.Errorf("the switch, the list and the PIN survive: %+v", m2.View("a"))
	}
	if m2.View("a").Unlocked {
		t.Error("but an unlock window does not: a restart locks everything again")
	}
	if _, err := m2.Unlock("a", "1234"); err != nil {
		t.Error("the old PIN still opens it")
	}
	var nilMgr *kidsMgr
	if nilMgr.On() || nilMgr.Devices() != nil {
		t.Error("a nil manager is off")
	}
}

func TestKidsIsNotInTheBackups(t *testing.T) {
	for _, s := range snapSections {
		if strings.Contains(strings.ToLower(s), "kid") || strings.Contains(strings.ToLower(s), "pin") {
			t.Errorf("backup section %q: Kids mode and its PIN must not be restorable from a backup", s)
		}
	}
	src, _ := os.ReadFile("snapshot.go")
	if strings.Contains(string(src), "kidsMgrG") || strings.Contains(string(src), "kids.json") {
		t.Error("snapshot.go must not touch Kids mode state")
	}
}

// ---- the API, through the real login and CSRF layer ----

type kidsHTTP struct {
	t    *testing.T
	h    http.HandlerFunc
	sid  string
	csrf string
}

func newKidsHTTP(t *testing.T) (*kidsHTTP, *kidsMgr, *time.Time) {
	t.Helper()
	m, now, _ := testKids(t)
	old := kidsMgrG
	kidsMgrG = m
	t.Cleanup(func() { kidsMgrG = old })
	u := &webUI{auth: testAuth(t)}
	sid, csrf := u.auth.NewSession("ben")
	return &kidsHTTP{t: t, h: u.apiAuthed(handleAPI), sid: sid, csrf: csrf}, m, now
}

func (k *kidsHTTP) do(method, path, body string, mod func(*http.Request)) (int, map[string]any) {
	k.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: k.sid})
	if method == "POST" {
		req.Header.Set("X-CSRF-Token", k.csrf)
	}
	if mod != nil {
		mod(req)
	}
	rec := httptest.NewRecorder()
	k.h(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestKidsAPIFlow(t *testing.T) {
	k, m, _ := newKidsHTTP(t)
	code, v := k.do("GET", "/api/kids", "", nil)
	if code != 200 || v["on"] != false || v["has_pin"] != false {
		t.Fatalf("state: %d %v", code, v)
	}
	if code, v = k.do("POST", "/api/kids/set", `{"on":true}`, nil); code != 409 || v["needs_setup"] != true {
		t.Errorf("on before a PIN: %d %v", code, v)
	}
	if code, _ = k.do("POST", "/api/kids/pin", `{"pin":"12"}`, nil); code != 400 {
		t.Errorf("a bad PIN form: %d", code)
	}
	if code, v = k.do("POST", "/api/kids/pin", `{"pin":"2468"}`, nil); code != 200 || v["has_pin"] != true {
		t.Errorf("first PIN: %d %v", code, v)
	}
	if code, v = k.do("POST", "/api/kids/set", `{"on":true}`, nil); code != 200 || v["on"] != true {
		t.Errorf("on: %d %v", code, v)
	}
	if code, v = k.do("POST", "/api/kids/set", `{"on":false}`, nil); code != 403 || v["needs_pin"] != true || !m.On() {
		t.Errorf("off without the PIN must be refused: %d %v", code, v)
	}
	if code, v = k.do("POST", "/api/kids/unlock", `{"pin":"0000"}`, nil); code != 403 || v["tries_left"] != float64(4) {
		t.Errorf("wrong PIN: %d %v", code, v)
	}
	if code, v = k.do("POST", "/api/kids/unlock", `{"pin":"2468"}`, nil); code != 200 || v["unlocked_for"] != float64(600) {
		t.Errorf("right PIN: %d %v", code, v)
	}
	if code, v = k.do("GET", "/api/kids", "", nil); v["unlocked"] != true {
		t.Errorf("the state shows the unlock: %v", v)
	}
	if code, v = k.do("POST", "/api/kids/set", `{"on":false}`, nil); code != 200 || v["on"] != false {
		t.Errorf("off when unlocked: %d %v", code, v)
	}
	if code, v = k.do("POST", "/api/kids/lock", `{}`, nil); code != 200 || v["unlocked"] != false {
		t.Errorf("lock: %d %v", code, v)
	}
	for i := 0; i < 5; i++ {
		code, v = k.do("POST", "/api/kids/unlock", `{"pin":"0000"}`, nil)
	}
	if code != 429 || v["locked_for"] == nil {
		t.Errorf("the lockout is a 429 with the time: %d %v", code, v)
	}
	if code, _ = k.do("POST", "/api/kids/unlock", `{"pin":"2468"}`, nil); code != 429 {
		t.Errorf("the right PIN is refused during the lockout: %d", code)
	}
}

func TestKidsAPIGuards(t *testing.T) {
	k, m, _ := newKidsHTTP(t)
	m.SetPin(k.sid, "2468", "")
	m.SetOn(k.sid, true)
	// no CSRF token on a POST: the login layer refuses before Kids mode is reached
	if code, _ := k.do("POST", "/api/kids/unlock", `{"pin":"2468"}`, func(r *http.Request) { r.Header.Del("X-CSRF-Token") }); code != 403 || m.View(k.sid).Unlocked {
		t.Errorf("a POST without the CSRF token: %d", code)
	}
	// no session at all
	if code, _ := k.do("GET", "/api/kids", "", func(r *http.Request) { r.Header.Del("Cookie") }); code != 401 {
		t.Errorf("signed out: %d", code)
	}
	// the script token reads the state and can change nothing, not even with the right PIN
	tok := filepath.Join(t.TempDir(), "ui.token")
	os.WriteFile(tok, []byte("script-secret"), 0o600)
	old := uiTokenFile
	uiTokenFile = tok
	defer func() { uiTokenFile = old }()
	viaToken := func(r *http.Request) {
		r.Header.Del("Cookie")
		r.Header.Del("X-CSRF-Token")
		r.Header.Set("X-UI-Token", "script-secret")
	}
	if code, v := k.do("GET", "/api/kids", "", viaToken); code != 200 || v["on"] != true || v["unlocked"] != false {
		t.Errorf("the token may read: %d %v", code, v)
	}
	for _, p := range []string{"/api/kids/unlock", "/api/kids/set", "/api/kids/pin", "/api/kids/lock"} {
		if code, _ := k.do("POST", p, `{"pin":"2468","on":false,"current":"2468"}`, viaToken); code != 403 {
			t.Errorf("%s with the script token must be refused: %d", p, code)
		}
	}
	if !m.On() || m.View(k.sid).Unlocked {
		t.Error("the token changed something")
	}
	// bad bodies and methods
	if code, _ := k.do("POST", "/api/kids/unlock", `not json`, nil); code != 400 {
		t.Errorf("junk body: %d", code)
	}
	if code, _ := k.do("POST", "/api/kids/set", `{}`, nil); code != 400 {
		t.Errorf("nothing to change: %d", code)
	}
	if code, _ := k.do("POST", "/api/kids/nope", `{}`, nil); code != 404 {
		t.Errorf("unknown path: %d", code)
	}
	if code, _ := k.do("POST", "/api/kids", `{}`, nil); code == 200 {
		t.Error("POST on the state path")
	}
	if code, _ := k.do("POST", "/api/kids/unlock", strings.Repeat("x", 5000), nil); code != 400 {
		t.Errorf("an oversized body: %d", code)
	}
	// the state never carries the PIN or its hash
	raw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/kids", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: k.sid})
	k.h(raw, req)
	if strings.Contains(raw.Body.String(), "$2a$") || strings.Contains(raw.Body.String(), "2468") || strings.Contains(raw.Body.String(), "pin_hash") {
		t.Errorf("the state must not leak the PIN or the hash: %s", raw.Body.String())
	}
}

// ---- clearing titles, and the server-side gates ----

func TestKidsClearances(t *testing.T) {
	m, now, _ := testKids(t)
	h1, h2 := strings.Repeat("a", 40), strings.Repeat("b", 40)
	if !m.IsCleared("s", h1) || !m.AnyCleared("s") {
		t.Error("with Kids mode off everything is cleared")
	}
	m.SetPin("s", "1234", "")
	m.SetOn("s", true)
	if m.IsCleared("s", h1) || m.AnyCleared("s") {
		t.Fatal("with Kids mode on nothing is cleared until it is")
	}
	m.Clear("s", h1)
	if !m.IsCleared("s", h1) || m.IsCleared("s", h2) || !m.AnyCleared("s") {
		t.Error("exactly the cleared hash")
	}
	if m.IsCleared("other", h1) || m.AnyCleared("other") {
		t.Error("another session is not cleared by it")
	}
	*now = now.Add(kidsClearFor - time.Second)
	if !m.IsCleared("s", h1) {
		t.Error("still good just before 6 hours")
	}
	*now = now.Add(2 * time.Second)
	if m.IsCleared("s", h1) || m.AnyCleared("s") {
		t.Error("a clearance ends after 6 hours")
	}
	for i := 0; i < kidsMaxClear+5; i++ {
		*now = now.Add(time.Second)
		m.Clear("s", fmt.Sprintf("%040d", i))
	}
	if n := len(m.cleared["s"]); n != kidsMaxClear {
		t.Errorf("at most %d titles cleared per session, got %d", kidsMaxClear, n)
	}
	if m.IsCleared("s", fmt.Sprintf("%040d", 0)) || !m.IsCleared("s", fmt.Sprintf("%040d", kidsMaxClear+4)) {
		t.Error("the oldest clearance goes first")
	}
	m.SetPin("s", "4321", "1234")
	_ = m
	var nilMgr *kidsMgr
	if !nilMgr.IsCleared("s", h1) || !nilMgr.AnyCleared("s") {
		t.Error("a nil manager gates nothing")
	}
}

func TestKidsBridgeGate(t *testing.T) {
	k, m, _ := newKidsHTTP(t)
	h1, h2 := strings.Repeat("a", 40), strings.Repeat("b", 40)
	call := func(path, q string, withSession bool) (bool, int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/"+path+q, nil)
		if withSession {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: k.sid})
		}
		ok := kidsBridgeOK(rec, req, path)
		return ok, rec.Code, rec.Body.String()
	}
	for _, p := range []string{"bt/peers", "bt/conn", "bt/mux", "bt", "bt/set"} {
		if ok, _, _ := call(p, "?h="+h1, true); !ok {
			t.Errorf("%s is open while Kids mode is off", p)
		}
	}
	m.SetPin(k.sid, "1234", "")
	m.SetOn(k.sid, true)
	for _, p := range []string{"bt/peers", "bt/conn", "bt/mux"} {
		if ok, code, body := call(p, "?h="+h1, true); ok || code != 403 || !strings.Contains(body, `"kids":true`) {
			t.Errorf("%s with nothing cleared must be refused: %v %d %s", p, ok, code, body)
		}
	}
	for _, p := range []string{"bt", "bt/set"} {
		if ok, _, _ := call(p, "", true); !ok {
			t.Errorf("%s (status, settings) is not part of the gate", p)
		}
	}
	m.Clear(k.sid, h1)
	if ok, _, _ := call("bt/peers", "?h="+strings.ToUpper(h1), true); !ok {
		t.Error("peers for the cleared hash (any letter case) are allowed")
	}
	if ok, code, _ := call("bt/peers", "?h="+h2, true); ok || code != 403 {
		t.Error("but not for another hash")
	}
	if ok, _, _ := call("bt/peers", "", true); ok {
		t.Error("and not with no hash")
	}
	if ok, _, _ := call("bt/conn", "", true); !ok {
		t.Error("a connection needs only that the session has something cleared")
	}
	if ok, _, _ := call("bt/mux", "", true); !ok {
		t.Error("so does the multiplexed connection")
	}
	if ok, _, _ := call("bt/peers", "?h="+h1, false); ok {
		t.Error("no session (the script token) is refused while Kids mode is on")
	}
	if ok, _, _ := call("bt/conn", "", false); ok {
		t.Error("also for connections")
	}
}

func TestKidsNoSearch(t *testing.T) {
	k, m, _ := newKidsHTTP(t)
	old := searchMgrG
	searchMgrG = nil
	defer func() { searchMgrG = old }()
	get := func(p string) (int, string) {
		rec := httptest.NewRecorder()
		handleSearchAPI(rec, httptest.NewRequest("GET", "/api/"+p+"?q=cats", nil), p)
		return rec.Code, rec.Body.String()
	}
	for _, p := range []string{"search/web", "search/nyaa"} {
		if code, body := get(p); code == 403 || strings.Contains(body, "Kids") {
			t.Errorf("%s is open while Kids mode is off: %d %s", p, code, body)
		}
	}
	m.SetPin(k.sid, "1234", "")
	m.SetOn(k.sid, true)
	for _, p := range []string{"search/web", "search/nyaa"} {
		if code, body := get(p); code != 403 || !strings.Contains(body, `"kids":true`) {
			t.Errorf("%s must be refused in Kids mode: %d %s", p, code, body)
		}
	}
	if code, body := get("search"); code == 403 || strings.Contains(body, "Kids") {
		t.Errorf("the search status is not blocked: %d %s", code, body)
	}
}

func TestKidsClearAPI(t *testing.T) {
	k, m, _ := newKidsHTTP(t)
	rm, f, _ := testRatings(t)
	oldR := ratingMgrG
	ratingMgrG = rm
	defer func() { ratingMgrG = oldR }()
	bm := newBTMgr(filepath.Join(t.TempDir(), "bt.json"))
	oldB := btMgrG
	btMgrG = bm
	defer func() { btMgrG = oldB }()
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"PG"}}
	f.titles["tt0000002"] = fakeTitle{id: 12, certs: []string{"R"}}
	f.titles["tt0000003"] = fakeTitle{id: 13, certs: nil}
	hOK, hR, hNone := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	body := func(kind, id, hash string) string {
		return fmt.Sprintf(`{"kind":%q,"id":%q,"hash":%q}`, kind, id, hash)
	}
	if code, v := k.do("POST", "/api/kids/clear", body("movie", "tt0000002", hR), nil); code != 200 || v["kids"] != false {
		t.Errorf("with Kids mode off, clearing is a no-op that says so (and asks TMDB nothing): %d %v", code, v)
	}
	if f.hits.Load() != 0 {
		t.Error("nothing is looked up when Kids mode is off")
	}
	m.SetPin(k.sid, "1234", "")
	m.SetOn(k.sid, true)
	if code, v := k.do("POST", "/api/kids/clear", body("movie", "tt0000001", hOK), nil); code != 200 || v["cleared"] != true {
		t.Fatalf("a PG title clears: %d %v", code, v)
	}
	if code, v := k.do("POST", "/api/kids/clear", body("movie", "tt0000002", hR), nil); code != 403 || v["why"] != "R" {
		t.Errorf("an R title does not, and says why: %d %v", code, v)
	}
	if code, v := k.do("POST", "/api/kids/clear", body("movie", "tt0000003", hNone), nil); code != 403 || v["why"] != "no rating" {
		t.Errorf("an unrated title does not: %d %v", code, v)
	}
	for _, bad := range []string{body("movie", "tt0000001", "xyz"), body("bogus", "tt0000001", hOK), body("movie", "tt0000001", ""), `{}`} {
		if code, _ := k.do("POST", "/api/kids/clear", bad, nil); code != 400 {
			t.Errorf("%s must be a 400: %d", bad, code)
		}
	}
	peers := func(hash string) (int, string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/bt/peers?h="+hash, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: k.sid})
		k.h(rec, req)
		return rec.Code, rec.Body.String()
	}
	if _, b := peers(hOK); strings.Contains(b, `"kids":true`) {
		t.Errorf("the cleared title gets past the gate (whatever the bridge then says): %s", b)
	}
	for _, h := range []string{hR, hNone} {
		if code, b := peers(h); code != 403 || !strings.Contains(b, `"kids":true`) {
			t.Errorf("a title that did not clear is refused at the bridge: %d %s", code, b)
		}
	}
	tok := filepath.Join(t.TempDir(), "ui.token")
	os.WriteFile(tok, []byte("script-secret"), 0o600)
	old := uiTokenFile
	uiTokenFile = tok
	defer func() { uiTokenFile = old }()
	viaToken := func(r *http.Request) {
		r.Header.Del("Cookie")
		r.Header.Del("X-CSRF-Token")
		r.Header.Set("X-UI-Token", "script-secret")
	}
	if code, _ := k.do("POST", "/api/kids/clear", body("movie", "tt0000001", hOK), viaToken); code != 403 {
		t.Errorf("the script token cannot clear a title: %d", code)
	}
	// no ratings manager at all: nothing clears
	ratingMgrG = nil
	if code, v := k.do("POST", "/api/kids/clear", body("movie", "tt0000001", strings.Repeat("4", 40)), nil); code != 403 {
		t.Errorf("without a ratings service nothing is allowed: %d %v", code, v)
	}
}

func TestKidsStateSaysWhetherRatingsAreSetUp(t *testing.T) {
	k, _, _ := newKidsHTTP(t)
	oldR := ratingMgrG
	defer func() { ratingMgrG = oldR }()
	ratingMgrG = nil
	if _, v := k.do("GET", "/api/kids", "", nil); v["ratings_key"] != false {
		t.Errorf("no ratings service: %v", v)
	}
	rm, _, _ := testRatings(t)
	ratingMgrG = rm
	if _, v := k.do("GET", "/api/kids", "", nil); v["ratings_key"] != true {
		t.Errorf("a key in place: %v", v)
	}
	os.Remove(rm.keyFile)
	if _, v := k.do("GET", "/api/kids", "", nil); v["ratings_key"] != false {
		t.Errorf("the key file removed: %v", v)
	}
	if _, v := k.do("POST", "/api/kids/lock", `{}`, nil); v["ratings_key"] != false {
		t.Errorf("every answer carries it: %v", v)
	}
}
