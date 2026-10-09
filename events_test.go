package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func base(now time.Time) evIn {
	return evIn{Now: now, UplinkOK: true, TempMax: 48, SysUptime: 5000, CertFP: "AA", Online: []devObs{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.2", Band: "2.4 GHz", Host: "pi"}}}
}

func kinds(es []evt) string {
	var k []string
	for _, e := range es {
		k = append(k, e.Kind)
	}
	return strings.Join(k, ",")
}

func TestDetectorSeedsThenSeesNewDevices(t *testing.T) {
	d := newDetector(nil)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	in := base(now)
	if k := kinds(d.step(in)); k != "restart" {
		t.Fatalf("the first step only reports the start, devices already here are not new: %q", k)
	}
	if k := kinds(d.step(in)); k != "" {
		t.Errorf("nothing changed: %q", k)
	}
	in.Online = append(in.Online, devObs{MAC: "02:11:22:33:44:55", IP: "192.168.1.77", Band: "5 GHz", Host: ""})
	es := d.step(in)
	if kinds(es) != "new_device" || es[0].Sev != sevAttention || !strings.Contains(es[0].Text, "02:11:22:33:44:55") {
		t.Fatalf("%+v", es)
	}
	if strings.Contains(es[0].Public, "02:11") || strings.Contains(es[0].Public, "192.168") {
		t.Errorf("the public text must be generic: %q", es[0].Public)
	}
	if k := kinds(d.step(in)); k != "" {
		t.Errorf("a device is new only once: %q", k)
	}
}

func TestDetectorRestartMessage(t *testing.T) {
	d := newDetector(nil)
	in := base(time.Now())
	in.SysUptime = 60
	es := d.step(in)
	if es[0].Text != "The box restarted" {
		t.Errorf("%q", es[0].Text)
	}
	d2 := newDetector(nil)
	if e := d2.step(base(time.Now())); e[0].Text != "The web page and proxy started" {
		t.Errorf("%q", e[0].Text)
	}
}

func TestDetectorUplinkAndDoH(t *testing.T) {
	d := newDetector(nil)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	d.step(base(now))
	in := base(now)
	in.UplinkOK, in.UplinkFails = false, 2
	if k := kinds(d.step(in)); k != "" {
		t.Errorf("two failed probes are not an outage yet: %q", k)
	}
	in.UplinkFails = 3
	es := d.step(in)
	if kinds(es) != "uplink_down" || es[0].Sev != sevAlert {
		t.Fatalf("%+v", es)
	}
	if k := kinds(d.step(in)); k != "" {
		t.Errorf("reported once: %q", k)
	}
	in.Now = now.Add(7 * time.Minute)
	in.UplinkOK, in.UplinkFails = true, 0
	es = d.step(in)
	if kinds(es) != "uplink_up" || !strings.Contains(es[0].Text, "7 minute") {
		t.Errorf("%+v", es)
	}
	in.DoHDown = true
	if kinds(d.step(in)) != "doh_down" || kinds(d.step(in)) != "" {
		t.Error("doh fallback must be reported once")
	}
	in.DoHDown = false
	if kinds(d.step(in)) != "doh_ok" {
		t.Error("doh recovery")
	}
}

func TestDetectorServicesHeatSSHRadioCertPlan(t *testing.T) {
	d := newDetector(nil)
	now := time.Now()
	d.step(base(now))
	in := base(now)
	in.ServicesDown = []string{"dropbear"}
	if kinds(d.step(in)) != "" {
		t.Error("one missed check is not a dead service")
	}
	if es := d.step(in); kinds(es) != "service_down" || es[0].Sev != sevAlert {
		t.Errorf("%+v", es)
	}
	in.ServicesDown = nil
	if kinds(d.step(in)) != "service_up" {
		t.Error("service recovery")
	}
	in.TempMax = 72
	if kinds(d.step(in)) != "" || kinds(d.step(in)) != "hot" || kinds(d.step(in)) != "" {
		t.Error("heat: two readings, once")
	}
	in.TempMax = 67
	if kinds(d.step(in)) != "" {
		t.Error("between 65 and 70 is neither hot nor cool: no flapping")
	}
	in.TempMax = 60
	if kinds(d.step(in)) != "cool" {
		t.Error("cool")
	}
	in.SSHFailed = 4
	if kinds(d.step(in)) != "" {
		t.Error("4 failures are noise")
	}
	in.SSHFailed = 9
	if kinds(d.step(in)) != "ssh_failed" || kinds(d.step(in)) != "" {
		t.Error("a burst of 5 or more is reported once")
	}
	in.SSHFailed = 0 // the log restarted
	in.SSHFailed = 2
	if kinds(d.step(in)) != "" {
		t.Error("after a reboot the base resets")
	}
	in.Wifi5Down = true
	if kinds(d.step(in)) != "" || kinds(d.step(in)) != "radio_down" {
		t.Error("radio down after two checks")
	}
	in.Wifi5Down = false
	if kinds(d.step(in)) != "radio_up" {
		t.Error("radio up")
	}
	in.CertFP = "BB"
	if kinds(d.step(in)) != "cert_renewed" || kinds(d.step(in)) != "" {
		t.Error("certificate renewal")
	}
	in.BudgetPct = 85
	if es := d.step(in); kinds(es) != "plan" || es[0].Sev != sevAttention {
		t.Errorf("%+v", es)
	}
	if kinds(d.step(in)) != "" {
		t.Error("80% only once")
	}
	in.BudgetPct = 101
	if es := d.step(in); kinds(es) != "plan" || es[0].Sev != sevAlert {
		t.Errorf("%+v", es)
	}
	in.BudgetPct = 10 // a new billing cycle
	d.step(in)
	in.BudgetPct = 82
	if kinds(d.step(in)) != "plan" {
		t.Error("the threshold must re-arm after the usage drops")
	}
}

func newES(t *testing.T) (*eventStore, *[]string, *time.Time) {
	var posts []string
	var mu sync.Mutex
	clock := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s := &eventStore{path: filepath.Join(t.TempDir(), "e.json"), cfgPath: filepath.Join(t.TempDir(), "n.json"), lastOf: map[string]time.Time{}, now: func() time.Time { return clock },
		cfg: notifyCfg{Min: sevAttention}, post: func(u, title, body string, prio int) error {
			mu.Lock()
			posts = append(posts, body)
			mu.Unlock()
			return nil
		}}
	t.Cleanup(s.Flush) // the file is written in the background: let it finish before the temporary directory goes
	return s, &posts, &clock
}

func TestEventStoreNotifiesOnlyWhenAskedAndGenerically(t *testing.T) {
	s, posts, clock := newES(t)
	s.Add([]evt{{Kind: "new_device", Sev: sevAttention, Text: "A new device joined: x (aa:bb)", Public: "A new device joined the network"}})
	if len(*posts) != 0 {
		t.Fatal("nothing may leave the house until an address is set")
	}
	if err := s.SetNotify(notifyCfg{URL: "https://ntfy.sh/secret-topic", Min: sevAttention, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.Add([]evt{{Kind: "uplink_down", Sev: sevAlert, Text: "private", Public: "The box's internet connection is down"}, {Kind: "restart", Sev: sevInfo, Public: "restarted"}})
	if len(*posts) != 1 || (*posts)[0] != "The box's internet connection is down" {
		t.Fatalf("only events at or above the chosen level, with the generic text: %v", *posts)
	}
	s.Add([]evt{{Kind: "uplink_down", Sev: sevAlert, Public: "again"}})
	if len(*posts) != 1 {
		t.Error("the same kind within 10 minutes must not push again")
	}
	*clock = clock.Add(11 * time.Minute)
	s.Add([]evt{{Kind: "uplink_down", Sev: sevAlert, Public: "later"}})
	if len(*posts) != 2 {
		t.Error("after the cool-down it may")
	}
	before := len(*posts)
	for i := 0; i < 40; i++ { // 40 different kinds within a minute: the hourly cap of 20 pushes applies
		*clock = clock.Add(time.Second)
		s.Add([]evt{{Kind: "k" + strings.Repeat("x", i), Sev: sevAlert, Public: "p"}})
	}
	if n := len(*posts); n > 20 {
		t.Errorf("more than 20 pushes in an hour: %d (before the burst: %d)", n, before)
	}
	if v := s.View(); v.Notify.Where != "ntfy.sh" || strings.Contains(strings.ToLower(v.Notify.Where), "secret") {
		t.Errorf("the topic must never be shown back: %+v", v.Notify)
	}
}

func TestEventStoreSeenCountsClearCap(t *testing.T) {
	s, _, _ := newES(t)
	for i := 0; i < 130; i++ {
		s.Add([]evt{{Kind: "k", Sev: sevAttention, Text: "t"}})
	}
	v := s.View()
	if len(v.Events) != 100 || v.Unseen != 100 || v.Events[0].ID <= v.Events[99].ID {
		t.Fatalf("cap and newest-first: %d %d", len(v.Events), v.Unseen)
	}
	if n, last := s.Counts(); n != 100 || last == 0 {
		t.Errorf("%d %d", n, last)
	}
	s.MarkSeen()
	if n, _ := s.Counts(); n != 0 {
		t.Error("seen")
	}
	s.Add([]evt{{Kind: "info", Sev: sevInfo}})
	if n, _ := s.Counts(); n != 0 {
		t.Error("an info event must not raise the attention count")
	}
	s.Clear()
	if v := s.View(); len(v.Events) != 1 || v.Events[0].Kind != "events_cleared" || !v.Chain.OK || v.Chain.Length != 1 {
		t.Errorf("clear must leave one marker event starting a fresh chain: %+v", v.Chain)
	}
}

func TestEventChainLinksAndDetectsTampering(t *testing.T) {
	s, _, _ := newES(t)
	for i := 0; i < 130; i++ {
		s.Add([]evt{{Kind: "k", Sev: sevAttention, Text: fmt.Sprint("t", i)}})
	}
	v := s.View()
	if !v.Chain.OK || v.Chain.Length != 100 || v.Chain.Head == "" || v.Chain.Since == 0 {
		t.Fatalf("%+v", v.Chain)
	}
	if v.Events[0].Hash != v.Chain.Head || v.Events[0].Prev != v.Events[1].Hash {
		t.Error("newest event must carry the head and link to the one before")
	}
	if s.base == "" || v.Events[99].Prev != s.base {
		t.Error("the oldest kept event must link to the hash of the last one dropped")
	}
	s.MarkSeen()
	if c := s.Chain(); !c.OK {
		t.Error("marking seen must not break the chain")
	}

	// reload from the file: still intact
	s.Flush() // the file is written in the background; Flush waits for it
	r := &eventStore{path: s.path, cfgPath: s.cfgPath, lastOf: map[string]time.Time{}, now: s.now, post: s.post}
	b, _ := os.ReadFile(s.path)
	var f eventsFileV2
	if json.Unmarshal(b, &f) != nil || f.Format != "orbic-events-2" {
		t.Fatal("new file format not written")
	}
	r.events, r.base, r.since = f.Events, f.Base, f.Since
	if c := r.Chain(); !c.OK || c.Length != 100 {
		t.Fatalf("reloaded: %+v", c)
	}

	// edit one event's text in the middle: the chain breaks there and nowhere earlier
	r.events = append([]evt(nil), f.Events...)
	r.events[40].Text = "something else"
	if c := r.Chain(); c.OK || c.BrokenAt != r.events[40].ID {
		t.Errorf("edit: %+v", c)
	}
	// delete one from the middle
	r.events, r.base, r.since = append([]evt(nil), f.Events...), f.Base, f.Since
	r.events = append(r.events[:50], r.events[51:]...)
	if c := r.Chain(); c.OK || c.BrokenAt != f.Events[51].ID {
		t.Errorf("delete: %+v", c)
	}
	// truncate the front without carrying the base
	r.events, r.base = append([]evt(nil), f.Events[10:]...), f.Base
	if c := r.Chain(); c.OK || c.BrokenAt != f.Events[10].ID {
		t.Errorf("truncate: %+v", c)
	}
	// the old file format (a bare array, no hashes) loads, and the chain begins with the next event
	legacy := []evt{{ID: 1, T: 1, Kind: "old", Sev: sevInfo}, {ID: 2, T: 2, Kind: "old", Sev: sevInfo}}
	lb, _ := json.Marshal(legacy)
	os.WriteFile(s.path, lb, 0o600)
	l := &eventStore{path: s.path, cfgPath: s.cfgPath, lastOf: map[string]time.Time{}, now: s.now, post: s.post}
	t.Cleanup(l.Flush)
	var arr []evt
	json.Unmarshal(lb, &arr)
	l.events = arr
	l.next = 3
	if c := l.Chain(); !c.OK || c.Length != 0 {
		t.Errorf("legacy before any hashed event: %+v", c)
	}
	l.Add([]evt{{Kind: "new", Sev: sevInfo}})
	if c := l.Chain(); !c.OK || c.Length != 1 || c.Since == 0 {
		t.Errorf("legacy then one hashed: %+v", c)
	}
	if l.events[2].Prev != "" {
		t.Error("the first hashed event after a legacy log links to nothing")
	}
}

func TestNtfyURLValidation(t *testing.T) {
	for _, ok := range []string{"https://ntfy.sh/my-topic", "http://192.168.1.5:8080/alerts", "http://127.0.0.1:8081/t"} {
		if err := validNtfyURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ntfy.sh/topic", "https://ntfy.sh", "https://ntfy.sh/", "http://ntfy.sh/topic", "http://8.8.8.8/t", "ftp://x/y", "https://user:pw@ntfy.sh/t", "https://" + strings.Repeat("a", 200) + "/t"} {
		if validNtfyURL(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	s, _, _ := newES(t)
	if err := s.SetNotify(notifyCfg{Min: "loud"}); err == nil {
		t.Error("bad level")
	}
	if err := s.SetNotify(notifyCfg{Min: sevAlert, Enabled: true}); err == nil {
		t.Error("enabling without an address")
	}
	s.SetNotify(notifyCfg{URL: "https://ntfy.sh/t1", Min: sevAlert, Enabled: true})
	if err := s.SetNotify(notifyCfg{Min: sevAttention, Enabled: true}); err != nil || s.cfg.URL != "https://ntfy.sh/t1" {
		t.Errorf("a blank address must keep the stored one: %v %q", err, s.cfg.URL)
	}
	s.ClearNotifyURL()
	if s.cfg.URL != "" || s.cfg.Enabled {
		t.Error("clear")
	}
}

func TestPostNtfyReallySends(t *testing.T) {
	var gotBody, gotTitle, gotPrio string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 200)
		n, _ := r.Body.Read(b)
		gotBody, gotTitle, gotPrio = string(b[:n]), r.Header.Get("Title"), r.Header.Get("Priority")
	}))
	defer srv.Close()
	if err := postNtfy(srv.URL+"/topic", "PillowForrT", "hello", 4); err != nil || gotBody != "hello" || gotTitle != "PillowForrT" || gotPrio != "4" {
		t.Errorf("%v %q %q %q", err, gotBody, gotTitle, gotPrio)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if err := postNtfy(bad.URL+"/t", "O", "x", 3); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("a failing server must be reported: %v", err)
	}
	if err := postNtfy("http://127.0.0.1:1/t", "O", "x", 3); err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("an unreachable server is an error that does not repeat the address: %v", err)
	}
}

func TestMarkSeenKindsOnlyTouchesTheNamedKinds(t *testing.T) {
	s, _, _ := newES(t)
	s.Add([]evt{
		{Kind: "tor_down", Sev: sevAttention, Text: "t1"}, {Kind: "tor_down", Sev: sevAttention, Text: "t2"},
		{Kind: "doh_down", Sev: sevAttention, Text: "d1"}, {Kind: "rogue_dhcp", Sev: sevAlert, Text: "r1"},
	})
	if n := s.MarkSeenKinds([]string{"tor_down", "rogue_dhcp"}); n != 3 {
		t.Fatalf("changed %d, want 3", n)
	}
	un, _ := s.Counts()
	if un != 1 {
		t.Fatalf("unseen %d, want 1 (the doh_down)", un)
	}
	if n := s.MarkSeenKinds([]string{"tor_down"}); n != 0 {
		t.Fatalf("marking an already-seen kind changed %d", n)
	}
	s.MarkSeenKinds(nil) // no kinds = everything, as before
	if un, _ := s.Counts(); un != 0 {
		t.Fatalf("unseen %d after marking all", un)
	}
}
