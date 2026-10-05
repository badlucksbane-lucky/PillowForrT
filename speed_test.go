package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSpeed(t *testing.T) (*speedTester, *[]evt, *time.Time) {
	now := time.Unix(1_800_000_000, 0)
	var got []evt
	s := newSpeedTester(filepath.Join(t.TempDir(), "speed.json"))
	s.now = func() time.Time { return now }
	s.emit = func(e evt) { got = append(got, e) }
	s.busy = func() bool { return false }
	s.linkUp = func() bool { return true }
	s.planFull = func() bool { return false }
	s.measure = func() speedRec { return speedRec{T: now.Unix(), Down: 1_000_000, Up: 200_000, LatMs: 80} }
	return s, &got, &now
}

func TestSlowVerdict(t *testing.T) {
	var h []speedRec
	for i := 0; i < 3; i++ {
		h = append(h, speedRec{Down: 1_000_000})
	}
	if slow, _ := slowVerdict(h, 10); slow {
		t.Error("with only 3 tests there is nothing to compare against")
	}
	h = append(h, speedRec{Down: 1_000_000}, speedRec{Err: "timed out"}) // a failed test is not data
	if slow, m := slowVerdict(h, 200_000); !slow || m != 1_000_000 {
		t.Errorf("200k against a 1M median is slow: %v %v", slow, m)
	}
	if slow, _ := slowVerdict(h, 400_000); slow {
		t.Error("40% of the median is not yet slow")
	}
	if slow, _ := slowVerdict(h, 0); slow {
		t.Error("no number is not slow")
	}
}

func TestSpeedRunRecordsAndPersists(t *testing.T) {
	s, got, now := testSpeed(t)
	if err := s.run(false); err != nil {
		t.Fatal(err)
	}
	if v := s.View(); v.Hist != 1 || v.Last == nil || v.Last.Down != 1_000_000 || len(v.T) != 1 || *v.Down[0] != 1_000_000 || v.MedianDn != 1_000_000 {
		t.Fatalf("view: %+v", v)
	}
	if len(*got) != 0 {
		t.Errorf("a normal test raises nothing: %v", *got)
	}
	*now = now.Add(7 * time.Hour)
	s.Set(true, 3)
	s2 := newSpeedTester(s.path) // a restart
	if len(s2.hist) != 1 || s2.set.IntervalH != 3 || !s2.set.Enabled {
		t.Errorf("history and settings must survive a restart: %+v %+v", s2.hist, s2.set)
	}
}

func TestSpeedGates(t *testing.T) {
	s, _, now := testSpeed(t)
	ran := 0
	s.measure = func() speedRec { ran++; return speedRec{T: now.Unix(), Down: 1} }
	s.busy = func() bool { return true }
	if err := s.run(false); err == nil || !strings.Contains(err.Error(), "using the link") || ran != 0 {
		t.Errorf("a scheduled test waits while the house uses the link: %v", err)
	}
	if err := s.run(true); err != nil || ran != 1 || !s.hist[0].Busy {
		t.Errorf("a manual test runs anyway, marked busy: %v %d %+v", err, ran, s.hist)
	}
	if err := s.run(true); err == nil {
		t.Error("two manual tests inside two minutes are refused")
	}
	*now = now.Add(3 * time.Minute)
	s.busy = func() bool { return false }
	s.linkUp = func() bool { return false }
	if err := s.run(true); err == nil {
		t.Error("no test while the link is down")
	}
	s.linkUp = func() bool { return true }
	s.planFull = func() bool { return true }
	if err := s.run(true); err == nil || ran != 1 {
		t.Error("no test when the plan is nearly used up")
	}
	s.planFull = func() bool { return false }
	s.running = true
	if err := s.run(true); err == nil {
		t.Error("no second test while one runs")
	}
}

func TestSpeedDue(t *testing.T) {
	s, _, now := testSpeed(t)
	if !s.due() {
		t.Error("with no history a test is due")
	}
	s.run(false)
	if s.due() {
		t.Error("not due right after a test")
	}
	*now = now.Add(5*time.Hour + 59*time.Minute)
	if s.due() {
		t.Error("not due before the interval")
	}
	*now = now.Add(2 * time.Minute)
	if !s.due() {
		t.Error("due after the interval")
	}
	s.nextTry = now.Add(10 * time.Minute)
	if s.due() {
		t.Error("a deferred retry waits")
	}
	s.nextTry = time.Time{}
	s.Set(false, 6)
	if s.due() {
		t.Error("switched off means never due")
	}
}

func TestSpeedSlowEventOnlyForRealTests(t *testing.T) {
	s, got, now := testSpeed(t)
	for i := 0; i < 5; i++ {
		*now = now.Add(7 * time.Hour)
		s.run(false)
	}
	s.measure = func() speedRec { return speedRec{T: now.Unix(), Down: 100_000, Up: 1} }
	*now = now.Add(7 * time.Hour)
	s.run(false)
	if len(*got) != 1 || (*got)[0].Kind != "uplink_slow" || strings.Contains((*got)[0].Public, "Mbit") {
		t.Fatalf("a slow test is an event with a generic public text: %v", *got)
	}
	s.busy = func() bool { return true }
	*now = now.Add(7 * time.Hour)
	s.run(true) // slow but the house was using the link
	if len(*got) != 1 {
		t.Error("a test taken while busy never raises a slow event")
	}
	s.measure = func() speedRec { return speedRec{T: now.Unix(), Err: "download: timed out"} }
	s.busy = func() bool { return false }
	*now = now.Add(7 * time.Hour)
	s.run(false)
	v := s.View()
	if len(*got) != 1 || len(v.Errors) != 1 || v.Down[len(v.Down)-1] != nil {
		t.Errorf("a failed test is a gap in the chart and a listed failure, not an event: %v %+v", *got, v.Errors)
	}
}

func TestSpeedViewByHourSkipsBusyAndFailures(t *testing.T) {
	s, _, _ := testSpeed(t)
	base := time.Date(2026, 10, 2, 20, 0, 0, 0, schedLoc()).Unix()
	s.hist = []speedRec{{T: base, Down: 500}, {T: base + 60, Down: 700}, {T: base + 120, Down: 9999, Busy: true}, {T: base + 180, Err: "x"}}
	v := s.View()
	if v.ByHour[20] != 700 || v.MedianDn != 700 || v.BestDn != 700 {
		t.Errorf("busy and failed tests must not count: %+v median %v best %v", v.ByHour[20], v.MedianDn, v.BestDn)
	}
	if v.PerDayMB < 4 || v.PerDayMB > 6 {
		t.Errorf("data cost: %v MB a day", v.PerDayMB)
	}
}

func TestSpeedSetValidates(t *testing.T) {
	s, _, _ := testSpeed(t)
	if s.Set(true, 5) == nil || s.Set(true, 0) == nil {
		t.Error("only 1, 3, 6, 12 and 24 hours are allowed")
	}
	if err := s.Set(false, 12); err != nil || s.set.Enabled || s.set.IntervalH != 12 {
		t.Errorf("%v %+v", err, s.set)
	}
}

func TestSpeedHistoryIsBounded(t *testing.T) {
	s, _, now := testSpeed(t)
	for i := 0; i < speedKeep+25; i++ {
		*now = now.Add(time.Hour)
		s.run(true)
		s.lastRun = time.Time{}
	}
	if len(s.hist) != speedKeep || len(s.View().T) != 200 {
		t.Errorf("kept %d, charted %d", len(s.hist), len(s.View().T))
	}
}
