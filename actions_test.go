package main

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type actEnv struct {
	m     *actionManager
	now   *time.Time
	ran   *[]string
	notes *[]string
	up    *time.Duration
}

func newAM(t *testing.T) actEnv {
	loc, _ := time.LoadLocation("America/Chicago")
	clock := time.Date(2026, 10, 2, 3, 29, 30, 0, loc) // a Friday
	var ran, notes []string
	var mu sync.Mutex
	up := 5 * time.Hour
	m := &actionManager{path: filepath.Join(t.TempDir(), "a.json"), now: func() time.Time { return clock }, uptime: func() time.Duration { return up }, running: map[int]bool{},
		note: func(kind, sev, text, public string) { mu.Lock(); notes = append(notes, kind+": "+text); mu.Unlock() }}
	ok := func(name string) func() (string, error) {
		return func() (string, error) { mu.Lock(); ran = append(ran, name); mu.Unlock(); return name + " done", nil }
	}
	m.runners = map[string]func() (string, error){"snapshot": ok("snapshot"), "update_lists": ok("lists"), "diagnostics": ok("diag"), "reboot": ok("reboot")}
	return actEnv{m, &clock, &ran, &notes, &up}
}

func (e actEnv) wait(t *testing.T, n int) {
	for i := 0; i < 200 && len(*e.ran) < n; i++ {
		time.Sleep(5 * time.Millisecond)
	}
}

func TestActionValidation(t *testing.T) {
	e := newAM(t)
	good := schedAction{Action: "snapshot", Time: "03:30", Days: []int{1, 3, 5}, Enabled: true}
	id, err := e.m.Set(good, "")
	if err != nil || id != 1 {
		t.Fatalf("%v %d", err, id)
	}
	if l := e.m.load(); l[0].Name != "Save a settings snapshot" {
		t.Errorf("a blank name gets the kind's name: %q", l[0].Name)
	}
	for name, a := range map[string]schedAction{
		"unknown action": {Action: "rm -rf", Time: "03:30", Days: []int{1}},
		"bad time":       {Action: "snapshot", Time: "25:00", Days: []int{1}},
		"no days":        {Action: "snapshot", Time: "03:30"},
		"bad day":        {Action: "snapshot", Time: "03:30", Days: []int{7}},
		"long name":      {Action: "snapshot", Time: "03:30", Days: []int{1}, Name: strings.Repeat("n", 41)},
		"control name":   {Action: "snapshot", Time: "03:30", Days: []int{1}, Name: "a\nb"},
	} {
		if _, err := e.m.Set(a, ""); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := e.m.Set(schedAction{Action: "reboot", Time: "04:00", Days: []int{0}, Enabled: true}, "yes"); err == nil {
		t.Error("a reboot schedule without the typed word was accepted")
	}
	if _, err := e.m.Set(schedAction{Action: "reboot", Time: "04:00", Days: []int{0}, Enabled: true}, "reboot"); err != nil {
		t.Error(err)
	}
	if _, err := e.m.Set(schedAction{ID: 99, Action: "snapshot", Time: "03:30", Days: []int{1}}, ""); err == nil {
		t.Error("editing a missing action")
	}
	for i := 0; i < 20; i++ {
		e.m.Set(good, "")
	}
	if _, err := e.m.Set(good, ""); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("the 17th action: %v", err)
	}
}

func TestActionDueAndNext(t *testing.T) {
	loc, _ := time.LoadLocation("America/Chicago")
	a := schedAction{Action: "snapshot", Time: "03:30", Days: []int{5}, Enabled: true} // Fridays
	fri := time.Date(2026, 10, 2, 3, 30, 10, 0, loc)
	if !a.dueAt(fri) || a.dueAt(fri.Add(time.Minute)) || a.dueAt(fri.AddDate(0, 0, 1)) {
		t.Error("due only on Friday at 03:30")
	}
	a.Enabled = false
	if a.dueAt(fri) || !a.nextRun(fri).IsZero() {
		t.Error("a disabled action is never due")
	}
	a.Enabled = true
	if n := a.nextRun(fri); n.Format("2006-01-02 15:04") != "2026-10-09 03:30" {
		t.Errorf("the next Friday: %v", n)
	}
	if n := a.nextRun(fri.Add(-time.Hour)); n.Format("15:04 Mon") != "03:30 Fri" {
		t.Errorf("earlier the same day: %v", n)
	}
}

func TestActionTickRunsOnceAndRecords(t *testing.T) {
	e := newAM(t)
	e.m.Set(schedAction{Name: "Nightly", Action: "snapshot", Time: "03:30", Days: []int{5}, Enabled: true}, "")
	e.m.Tick()
	if len(*e.ran) != 0 {
		t.Fatal("not due yet at 03:29")
	}
	*e.now = e.now.Add(40 * time.Second) // 03:30:10
	e.m.Tick()
	e.wait(t, 1)
	if len(*e.ran) != 1 || (*e.ran)[0] != "snapshot" {
		t.Fatalf("%v", *e.ran)
	}
	time.Sleep(30 * time.Millisecond)
	e.m.Tick() // the loop ticks every 20 s: the same minute must not run twice
	e.m.Tick()
	time.Sleep(30 * time.Millisecond)
	if len(*e.ran) != 1 {
		t.Errorf("ran %d times in one minute", len(*e.ran))
	}
	l := e.m.load()
	if l[0].LastResult != "snapshot done" || l[0].LastRun == 0 {
		t.Errorf("%+v", l[0])
	}
	if len(*e.notes) != 1 || !strings.Contains((*e.notes)[0], "Nightly") {
		t.Errorf("an event for the run: %v", *e.notes)
	}
	v := e.m.View()["actions"].([]actionView)
	if v[0].NextRun != "Fri 03:30 CDT" {
		t.Errorf("next run %q", v[0].NextRun)
	}
}

func TestActionFailureAndRebootGuards(t *testing.T) {
	e := newAM(t)
	e.m.runners["snapshot"] = func() (string, error) { return "", errors.New("disk full") }
	id, _ := e.m.Set(schedAction{Action: "snapshot", Time: "03:30", Days: []int{5}, Enabled: true}, "")
	if _, err := e.m.run(id, true); err == nil {
		t.Fatal("a failing action must say so")
	}
	if l := e.m.load(); !strings.HasPrefix(l[0].LastResult, "failed: disk full") {
		t.Errorf("%q", l[0].LastResult)
	}
	if n := *e.notes; len(n) != 1 || !strings.HasPrefix(n[0], "scheduled_failed") {
		t.Errorf("a failure is an event to look at: %v", n)
	}
	rid, _ := e.m.Set(schedAction{Action: "reboot", Time: "04:00", Days: []int{5}, Enabled: true}, "reboot")
	*e.up = 3 * time.Minute
	if _, err := e.m.run(rid, true); err == nil || !strings.Contains(err.Error(), "10 minutes") {
		t.Errorf("a reboot right after boot must be refused: %v", err)
	}
	if len(*e.ran) != 0 {
		t.Error("the reboot must not have run")
	}
	*e.up = time.Hour
	if res, err := e.m.run(rid, true); err != nil || res != "reboot done" {
		t.Errorf("%v %q", err, res)
	}
	if err := e.m.Delete(rid); err != nil || e.m.Delete(rid) == nil {
		t.Error("delete")
	}
}
