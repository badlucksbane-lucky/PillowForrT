package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(day time.Weekday, hm string) time.Time { // a Sunday 2026-10-04 is weekday 0
	base := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(day))
	t, _ := time.Parse("15:04", hm)
	return time.Date(base.Year(), base.Month(), base.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
}

func TestNormDest(t *testing.T) {
	for in, want := range map[string]string{"203.0.113.7": "203.0.113.7/32", "203.0.113.9/24": "203.0.113.0/24", "2001:db8::1": "2001:db8::1/128"} {
		if got, err := normDest(in); err != nil || got != want {
			t.Errorf("%s -> %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "0.0.0.0/0", "8.0.0.0/4", "192.168.1.5", "192.168.0.0/16", "127.0.0.1", "10.0.0.0/7", "::/0", "fe80::1"} {
		if _, err := normDest(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := normDest("192.168.20.5"); err != nil { // another private network is fine: it does not overlap the LAN
		t.Error(err)
	}
}

func TestSchedWindows(t *testing.T) {
	day := fwSched{MAC: "aa:bb:cc:dd:ee:01", Days: []int{1, 2}, From: "09:00", To: "17:00", Enabled: true}
	if !schedActive(day, at(1, "09:00")) || !schedActive(day, at(2, "16:59")) || schedActive(day, at(2, "17:00")) || schedActive(day, at(3, "10:00")) || schedActive(day, at(1, "08:59")) {
		t.Error("daytime window wrong")
	}
	night := fwSched{MAC: "aa:bb:cc:dd:ee:01", Days: []int{5}, From: "22:00", To: "06:00", Enabled: true} // Friday night
	if !schedActive(night, at(5, "22:00")) || !schedActive(night, at(5, "23:59")) || !schedActive(night, at(6, "05:59")) || schedActive(night, at(6, "06:00")) || schedActive(night, at(5, "21:59")) || schedActive(night, at(0, "05:00")) {
		t.Error("overnight window wrong")
	}
	if !schedActive(night, at(6, "00:30")) { // Saturday 00:30 belongs to Friday's window
		t.Error("after midnight not covered")
	}
	night.Enabled = false
	if schedActive(night, at(5, "23:00")) {
		t.Error("disabled window active")
	}
}

func TestPlanFW(t *testing.T) {
	st := fwState{Dest: []fwDest{{CIDR: "203.0.113.0/24"}, {CIDR: "2001:db8::/32"}}}
	v4, v6 := planFW(st, []string{"aa:bb:cc:dd:ee:01"})
	for _, w := range []string{
		"-A HS_FW -i bridge0 -m mac --mac-source aa:bb:cc:dd:ee:01 ! -d 192.168.1.0/24 -j REJECT",
		"-A HS_FWIN -m mac --mac-source aa:bb:cc:dd:ee:01 -p udp --dport 53 -j DROP",
		"-A HS_FWIN -m mac --mac-source aa:bb:cc:dd:ee:01 -p tcp --dport 3128 -j DROP",
		"-A HS_FW -i bridge0 -d 203.0.113.0/24 -j REJECT", "-A HS_FWOUT -d 203.0.113.0/24 -j REJECT"} {
		if !strings.Contains(v4, w) {
			t.Errorf("v4 missing %q\n%s", w, v4)
		}
	}
	if !strings.Contains(v6, "-d 2001:db8::/32") || !strings.Contains(v6, "--mac-source aa:bb:cc:dd:ee:01 ! -d fe80::/10") || strings.Contains(v4, "2001:db8") {
		t.Errorf("v6 wrong\n%s", v6)
	}
	if !strings.HasSuffix(v4, "COMMIT\n") || !strings.HasSuffix(v6, "COMMIT\n") {
		t.Error("no COMMIT")
	}
	e4, e6 := planFW(fwState{}, nil) // an empty plan still declares the chains, so a removed rule really goes
	if !strings.Contains(e4, ":HS_FW - ") || !strings.Contains(e6, ":HS_FW6 - ") || strings.Contains(e4, "-A ") {
		t.Errorf("empty plan\n%s", e4)
	}
}

func newFW(t *testing.T) (*fwManager, *[]string, *time.Time) {
	now := at(5, "21:00")
	var applied []string
	return &fwManager{path: filepath.Join(t.TempDir(), "fw.json"), now: func() time.Time { return now },
		apply: func(v4, v6 string) error { applied = append(applied, v4); return nil }}, &applied, &now
}

func TestFWManager(t *testing.T) {
	m, applied, now := newFW(t)
	if err := m.AddDest("203.0.113.5", "spam"); err != nil || m.AddDest("203.0.113.5", "") == nil {
		t.Fatal("dest add/dup")
	}
	if err := m.SetSched(fwSched{MAC: "AA:BB:CC:DD:EE:01", Days: []int{5, 1}, From: "22:00", To: "06:00", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if m.SetSched(fwSched{MAC: "aa:bb:cc:dd:ee:01", Days: nil, From: "22:00", To: "06:00"}) == nil || m.SetSched(fwSched{MAC: "aa:bb:cc:dd:ee:01", Days: []int{1}, From: "22:00", To: "22:00"}) == nil {
		t.Error("bad schedule accepted")
	}
	v := m.View(map[string]string{"aa:bb:cc:dd:ee:01": "kid"})
	if len(v.Sched) != 1 || v.Sched[0].Active || v.Sched[0].Name != "kid" || v.Sched[0].ID != 1 {
		t.Fatalf("%+v", v.Sched)
	}
	*now = at(5, "22:30")
	m.Reconcile()
	if !strings.Contains((*applied)[len(*applied)-1], "--mac-source aa:bb:cc:dd:ee:01 ! -d") {
		t.Error("schedule did not start")
	}
	if err := m.Pause("aa:bb:cc:dd:ee:02", 30); err != nil || len(m.View(nil).Paused) != 1 || m.Pause("aa:bb:cc:dd:ee:02", 0) == nil {
		t.Error("pause")
	}
	*now = now.Add(31 * time.Minute)
	m.Reconcile()
	if len(m.View(nil).Paused) != 0 || strings.Contains((*applied)[len(*applied)-1], "ee:02") {
		t.Error("pause did not expire")
	}
	if m.Resume("aa:bb:cc:dd:ee:02") == nil {
		t.Error("resume of an expired pause should say it is not paused")
	}
	if err := m.DeleteSched(1); err != nil || m.DeleteSched(1) == nil {
		t.Error("delete sched")
	}
	if err := m.DeleteDest("203.0.113.5/32"); err != nil || m.DeleteDest("203.0.113.5") == nil {
		t.Error("delete dest")
	}
}

func TestScheduleZone(t *testing.T) { // the same instant is 22:30 Friday in Chicago and 23:30 in New York: the window must follow the configured zone
	chi, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatal(err)
	}
	ny, _ := time.LoadLocation("America/New_York")
	s := fwSched{MAC: "aa:bb:cc:dd:ee:01", Days: []int{5}, From: "23:00", To: "06:00", Enabled: true}
	inst := time.Date(2026, 10, 3, 3, 30, 0, 0, time.UTC) // Fri 22:30 Chicago (CDT)
	if schedActive(s, inst.In(chi)) || !schedActive(s, inst.In(ny)) {
		t.Error("zone not honoured")
	}
}
