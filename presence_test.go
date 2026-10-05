package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newPres(t *testing.T) (*presenceStore, *[]evt, *time.Time) {
	var got []evt
	clock := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p := &presenceStore{path: filepath.Join(t.TempDir(), "p.json"), devs: map[string]*presDev{}, now: func() time.Time { return clock },
		nameOf: func(mac string) string {
			if mac == "aa:bb:cc:dd:ee:01" {
				return "tablet"
			}
			return ""
		},
		emit: func(e evt) { got = append(got, e) }}
	return p, &got, &clock
}

func set(macs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range macs {
		m[x] = true
	}
	return m
}

const mA, mB = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"

func TestPresenceSeedsSilentlyThenWatchedArriveAndLeave(t *testing.T) {
	p, _, clock := newPres(t)
	if es := p.Observe(set(mA, mB)); len(es) != 0 {
		t.Fatalf("those already here are not arrivals: %+v", es)
	}
	p.SetWatch(mA, true)
	*clock = clock.Add(20 * time.Second)
	if es := p.Observe(set(mA, mB)); len(es) != 0 {
		t.Error("nothing changed")
	}
	// tablet disappears: gone only after two checks in a row
	if es := p.Observe(set(mB)); len(es) != 0 {
		t.Errorf("one missed check is a doze, not a departure: %+v", es)
	}
	if es := p.Observe(set(mA, mB)); len(es) != 0 {
		t.Error("back after one miss: nothing to report")
	}
	p.Observe(set(mB))
	*clock = clock.Add(20 * time.Minute)
	es := p.Observe(set(mB))
	if len(es) != 1 || es[0].Kind != "device_left" || es[0].Sev != sevAttention || !strings.Contains(es[0].Text, "tablet left") || !strings.Contains(es[0].Text, "minutes") {
		t.Fatalf("two checks in a row: %+v", es)
	}
	if strings.Contains(es[0].Public, "tablet") || strings.Contains(es[0].Public, "aa:bb") {
		t.Errorf("the pushed text must be generic: %q", es[0].Public)
	}
	*clock = clock.Add(time.Hour)
	es = p.Observe(set(mA, mB))
	if len(es) != 1 || es[0].Kind != "device_arrived" || !strings.Contains(es[0].Text, "tablet arrived") {
		t.Fatalf("arrival: %+v", es)
	}
	// an unwatched device comes and goes without a single event
	p.Observe(set(mA))
	p.Observe(set(mA))
	p.Observe(set(mA, mB))
	if info := p.Info(); info[mB].LastSeen == 0 || !info[mB].Online || info[mA].Watched != true {
		t.Errorf("info: %+v", info)
	}
}

func TestPresenceDHCPHook(t *testing.T) {
	p, _, clock := newPres(t)
	p.Observe(set()) // seeded, nobody here
	p.SetWatch(mA, true)
	es, err := p.Hook("add", "AA:BB:CC:DD:EE:01", "192.168.1.77", "Galaxy-Tab", "android-dhcp-14")
	if err != nil || len(es) != 1 || es[0].Kind != "device_arrived" || !strings.Contains(es[0].Text, "just got an address") {
		t.Fatalf("a new lease is an arrival: %v %+v", err, es)
	}
	if es, _ := p.Hook("old", mA, "192.168.1.77", "Galaxy-Tab", "android-dhcp-14"); len(es) != 0 {
		t.Error("a renewal is not an arrival")
	}
	if es, _ := p.Hook("del", mA, "192.168.1.77", "", ""); len(es) != 0 {
		t.Error("a lease ending is not a departure")
	}
	if i := p.Info()[mA]; i.Vendor != "android-dhcp-14" || !i.Online {
		t.Errorf("the hook teaches the vendor class: %+v", i)
	}
	if es := p.Observe(set(mA)); len(es) != 0 {
		t.Error("the radio then sees it: no second arrival")
	}
	for name, c := range map[string][5]string{
		"bad op":     {"nuke", mA, "1.2.3.4", "h", "v"},
		"bad mac":    {"add", "zz", "1.2.3.4", "h", "v"},
		"bad host":   {"add", mA, "1.2.3.4", "h;rm -rf /", "v"},
		"bad vendor": {"add", mA, "1.2.3.4", "h", "v\nx"},
		"long host":  {"add", mA, "1.2.3.4", strings.Repeat("h", 64), "v"},
	} {
		if _, err := p.Hook(c[0], c[1], c[2], c[3], c[4]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	_ = clock
}

func TestHookLearningIsSavedAtOnce(t *testing.T) {
	p, _, clock := newPres(t)
	p.Observe(set())
	p.Hook("old", mA, "192.168.1.5", "pixel", "android-dhcp-14")
	b, _ := os.ReadFile(p.path)
	if !strings.Contains(string(b), "android-dhcp-14") {
		t.Errorf("a newly learned vendor class must be on disk at once: %q", b)
	}
	*clock = clock.Add(20 * time.Second)
	fi1, _ := os.Stat(p.path)
	p.Hook("old", mA, "192.168.1.5", "pixel", "android-dhcp-14") // nothing new: no write
	fi2, _ := os.Stat(p.path)
	if !fi2.ModTime().Equal(fi1.ModTime()) {
		t.Error("an unchanged identity must not rewrite the file")
	}
}

func TestPresenceSaveIsThrottledAndLoads(t *testing.T) {
	p, _, clock := newPres(t)
	p.Observe(set(mA))
	if _, err := os.Stat(p.path); err != nil {
		t.Fatal("the first save is immediate")
	}
	fi1, _ := os.Stat(p.path)
	*clock = clock.Add(20 * time.Second)
	p.Observe(set(mA, mB)) // an arrival marks it dirty, but the file is touched at most every 5 minutes
	fi2, _ := os.Stat(p.path)
	if !fi2.ModTime().Equal(fi1.ModTime()) {
		t.Error("written again within 5 minutes")
	}
	*clock = clock.Add(6 * time.Minute)
	p.Observe(set(mA, mB))
	b, _ := os.ReadFile(p.path)
	if !strings.Contains(string(b), mB) {
		t.Error("the later save should hold the new device")
	}
	if fi, _ := os.Stat(p.path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	p2 := &presenceStore{path: p.path, devs: map[string]*presDev{}}
	if x, _ := os.ReadFile(p.path); len(x) > 0 {
		if err := json.Unmarshal(x, &p2.devs); err != nil || p2.devs[mA].LastSeen == 0 {
			t.Errorf("reload: %v %+v", err, p2.devs[mA])
		}
	}
	if err := p.SetWatch("nope", true); err == nil {
		t.Error("bad MAC")
	}
}

func TestDHCPHookEndpoint(t *testing.T) {
	p, _, _ := newPres(t)
	p.Observe(set())
	old, oldTok := presence, *beatTokenFile
	presence = p
	dir := t.TempDir()
	tf := filepath.Join(dir, "tok")
	os.WriteFile(tf, []byte("s3cret\n"), 0o600)
	*beatTokenFile = tf
	defer func() { presence, *beatTokenFile = old, oldTok }()
	post := func(remote, token, body string) int {
		r := httptest.NewRequest("POST", "/dhcp-hook", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = remote
		if token != "" {
			r.Header.Set("X-Beat-Token", token)
		}
		rec := httptest.NewRecorder()
		handleDHCPHook(rec, r)
		return rec.Code
	}
	good := "op=add&mac=aa:bb:cc:dd:ee:09&ip=192.168.1.5&host=pixel&vendor=android-dhcp-14%20x"
	if c := post("127.0.0.1:5555", "s3cret", good); c != 204 {
		t.Errorf("good: %d", c)
	}
	if v := p.Info()["aa:bb:cc:dd:ee:09"].Vendor; v != "android-dhcp-14 x" {
		t.Errorf("a percent-encoded vendor class: %q", v)
	}
	if c := post("192.168.1.77:5555", "s3cret", good); c != 403 {
		t.Errorf("a LAN device must not post here even with the token: %d", c)
	}
	if c := post("127.0.0.1:5555", "wrong", good); c != 403 {
		t.Errorf("wrong token: %d", c)
	}
	if c := post("127.0.0.1:5555", "", good); c != 403 {
		t.Errorf("no token: %d", c)
	}
	if c := post("127.0.0.1:5555", "s3cret", "op=add&mac=bad"); c != 400 {
		t.Errorf("bad fields: %d", c)
	}
	r := httptest.NewRequest("GET", "/dhcp-hook", nil)
	r.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	handleDHCPHook(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET: %d", rec.Code)
	}
}

func TestDevicesCarryPresence(t *testing.T) {
	in := devInputs{ARP: devARP, Presence: map[string]presInfo{"00:00:5e:00:53:02": {Online: true, Since: 100, LastSeen: 200, Vendor: "android-dhcp-14", Watched: true}, "00:00:5e:00:53:03": {Online: false, Since: 50, LastSeen: 60}}}
	by := map[string]devView{}
	for _, d := range buildDevices(in) {
		by[d.MAC] = d
	}
	if m := by["00:00:5e:00:53:02"]; m.Since != 100 || m.LastSeen != 200 || m.Vendor != "android-dhcp-14" || !m.Watched {
		t.Errorf("%+v", m)
	}
	if p := by["00:00:5e:00:53:03"]; p.Since != 0 || p.LastSeen != 60 {
		t.Errorf("an offline device has no 'since': %+v", p)
	}
}

func TestPresenceSinceSurvivesARestart(t *testing.T) {
	p, _, clock := newPres(t)
	p.Observe(set(mA)) // first run
	since := p.Info()[mA].Since
	*clock = clock.Add(2 * time.Hour)
	p.Observe(set(mA))
	p.maybeSave(true)
	// a new process, the device never left
	q := &presenceStore{path: p.path, devs: map[string]*presDev{}, now: func() time.Time { return clock.Add(30 * time.Second) }, nameOf: p.nameOf, emit: p.emit}
	b, _ := os.ReadFile(p.path)
	json.Unmarshal(b, &q.devs)
	q.Observe(set(mA))
	if q.Info()[mA].Since != since {
		t.Errorf("a restart must not reset 'here since': %d vs %d", q.Info()[mA].Since, since)
	}
	// a long gap: it left while nothing was watching
	r := &presenceStore{path: p.path, devs: q.devs, now: func() time.Time { return clock.Add(3 * time.Hour) }, nameOf: p.nameOf, emit: p.emit}
	r.Observe(set(mA))
	if r.Info()[mA].Since == since {
		t.Error("after a long silence the device is a fresh arrival")
	}
	// saved as here, but not present at the next start: no longer "here"
	s2 := &presenceStore{path: p.path, devs: map[string]*presDev{mA: {Since: 5, LastSeen: 5}}, now: func() time.Time { return clock.Add(time.Hour) }, nameOf: p.nameOf, emit: p.emit}
	s2.Observe(set())
	if s2.devs[mA].Since != 0 {
		t.Error("a device saved as here that is gone must have its since cleared")
	}
}
