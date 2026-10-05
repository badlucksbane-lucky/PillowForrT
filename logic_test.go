package main

import (
	"testing"
	"time"
)

func TestDelta(t *testing.T) {
	if delta(150, 100) != 50 {
		t.Fatal("growth")
	}
	if delta(30, 100) != 30 { // counter reset by a reboot: count what it has now
		t.Fatal("reset")
	}
	if delta(100, 100) != 0 {
		t.Fatal("flat")
	}
}

func TestCycleStart(t *testing.T) {
	loc := time.UTC
	cases := []struct {
		now  time.Time
		day  int
		want string
	}{
		{time.Date(2026, 10, 1, 12, 0, 0, 0, loc), 1, "2026-10-01"},
		{time.Date(2026, 10, 14, 12, 0, 0, 0, loc), 15, "2026-09-15"},
		{time.Date(2026, 10, 15, 0, 0, 0, 0, loc), 15, "2026-10-15"},
		{time.Date(2027, 1, 3, 0, 0, 0, 0, loc), 20, "2026-12-20"},   // crosses the year
		{time.Date(2026, 10, 30, 0, 0, 0, 0, loc), 31, "2026-10-28"}, // clamped to 28
	}
	for _, c := range cases {
		if got := cycleStart(c.now, c.day).Format("2006-01-02"); got != c.want {
			t.Errorf("cycleStart(%v,%d)=%s want %s", c.now, c.day, got, c.want)
		}
	}
}

func TestSampleUsage(t *testing.T) {
	loc := time.UTC
	var st usageState
	d1 := time.Date(2026, 10, 2, 0, 0, 0, 0, loc)
	sampleUsage(&st, 1000, 500, d1, 1) // first sample only sets the baseline
	if st.Down != 0 || st.Up != 0 || !st.Armed {
		t.Fatalf("baseline: %+v", st)
	}
	sampleUsage(&st, 1600, 700, d1.Add(time.Hour), 1)
	if st.Down != 600 || st.Up != 200 {
		t.Fatalf("growth: %+v", st)
	}
	sampleUsage(&st, 50, 10, d1.Add(2*time.Hour), 1) // reboot: counters restart low
	if st.Down != 650 || st.Up != 210 {
		t.Fatalf("reboot: %+v", st)
	}
	sampleUsage(&st, 100, 20, time.Date(2026, 11, 1, 0, 5, 0, 0, loc), 1) // new cycle
	if st.Cycle != "2026-11-01" || st.Down != 50 || st.Up != 10 {
		t.Fatalf("rollover keeps only growth since the last sample: %+v", st)
	}
}

func TestBeatStep(t *testing.T) {
	var b beatState
	t0 := time.Unix(1_000_000, 0)
	to := 10 * time.Minute
	if ev := beatStep(&b, t0.Add(time.Hour), to, false, ""); ev != "" {
		t.Fatal("unarmed watchdog must never fire")
	}
	if ev := beatStep(&b, t0, to, true, "pi"); ev != "" || !b.Armed {
		t.Fatal("first beat arms quietly")
	}
	if ev := beatStep(&b, t0.Add(9*time.Minute), to, false, ""); ev != "" {
		t.Fatal("not yet silent")
	}
	if ev := beatStep(&b, t0.Add(11*time.Minute), to, false, ""); ev != "silent" || !b.Silent || b.Events != 1 {
		t.Fatal("goes silent once")
	}
	if ev := beatStep(&b, t0.Add(12*time.Minute), to, false, ""); ev != "" {
		t.Fatal("silent event fires once per episode")
	}
	if ev := beatStep(&b, t0.Add(13*time.Minute), to, true, "pi"); ev != "recover" || b.Silent {
		t.Fatal("recovery")
	}
}

func TestPruneHosts(t *testing.T) {
	m := map[string]*hostStat{"big": {Down: 100}, "mid": {Down: 10}, "small": {Down: 1}}
	pruneHosts(m, 2)
	if len(m) != 2 || m["small"] != nil || m["big"] == nil {
		t.Fatalf("%v", m)
	}
}
