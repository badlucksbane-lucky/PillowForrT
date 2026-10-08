package main

import (
	"testing"
	"time"
)

func testGuardWatch() (*guardWatch, *time.Time, *string, *bool, *[]string) {
	now := time.Unix(1_800_000_000, 0)
	sig := "up|10.1.2.3"
	canary := true
	var events []string
	w := &guardWatch{
		now:      func() time.Time { return now },
		sig:      func() string { return sig },
		canaryOK: func() bool { return canary },
		runGuard: func() {},
		emit:     func(kind, text string) { events = append(events, kind) },
	}
	return w, &now, &sig, &canary, &events
}

// A link change runs the guard at once and twice more (5 s and 20 s later); a quiet link with the rules in place runs it never.
func TestGuardWatchRunsOnLinkChange(t *testing.T) {
	w, now, sig, _, events := testGuardWatch()
	runs := 0
	w.runGuard = func() { runs++ }
	w.step() // first look: the baseline, not a change
	*now = now.Add(30 * time.Second)
	w.step()
	if runs != 0 {
		t.Fatalf("a quiet link must not run the guard: %d", runs)
	}
	*sig = "up|10.9.9.9" // the carrier gave a new address
	w.step()
	if runs != 1 {
		t.Fatalf("a link change must run the guard at once: %d", runs)
	}
	for _, d := range []time.Duration{2, 4} { // nothing yet
		*now = now.Add(d * time.Second)
		w.step()
	}
	if runs != 2 { // +6 s: the +5 s follow-up
		t.Fatalf("the follow-up at 5 s: %d", runs)
	}
	*now = now.Add(20 * time.Second)
	w.step()
	if runs != 3 {
		t.Fatalf("the follow-up at 20 s: %d", runs)
	}
	*now = now.Add(time.Minute)
	w.step()
	if runs != 3 || len(*events) != 0 {
		t.Errorf("no further runs and no event for a plain link change: runs=%d events=%v", runs, *events)
	}
}

// Missing rules (a firewall rebuilt by the firmware with no link change) are noticed within the canary interval, restored, and reported once.
func TestGuardWatchRestoresMissingRules(t *testing.T) {
	w, now, _, canary, events := testGuardWatch()
	runs := 0
	w.runGuard = func() { runs++; *canary = true } // the guard puts them back
	w.step()
	*canary = false
	*now = now.Add(11 * time.Second)
	w.step()
	if runs != 1 || len(*events) != 1 || (*events)[0] != "guard_rules_missing" {
		t.Fatalf("missing rules: runs=%d events=%v", runs, *events)
	}
	*canary = false
	*now = now.Add(11 * time.Second)
	w.step()
	if runs != 2 || len(*events) != 1 {
		t.Errorf("run again, but tell the owner once per ten minutes: runs=%d events=%v", runs, *events)
	}
}

// Runs are never closer than the minimum gap, and a change inside the gap is not lost.
func TestGuardWatchMinGap(t *testing.T) {
	w, now, sig, _, _ := testGuardWatch()
	runs := 0
	w.runGuard = func() { runs++ }
	w.step()
	*sig = "a"
	w.step() // run 1
	*sig = "b"
	*now = now.Add(time.Second)
	w.step() // inside the gap: deferred, not dropped
	if runs != 1 {
		t.Fatalf("inside the minimum gap: %d", runs)
	}
	*now = now.Add(3 * time.Second)
	w.step()
	if runs < 2 {
		t.Errorf("the deferred run must happen: %d", runs)
	}
}

func TestLinkSignatureMissingInterface(t *testing.T) {
	if s := linkSignature("no-such-iface0", ""); s != "absent" {
		t.Errorf("%q", s)
	}
}

// A rule the guard cannot bring back must not turn into a loop that runs the guard every few seconds.
func TestGuardWatchBacksOffWhenRulesWillNotStay(t *testing.T) {
	w, now, _, canary, _ := testGuardWatch()
	runs := 0
	w.runGuard = func() { runs++ } // the rules stay missing
	w.step()
	*canary = false
	for i := 0; i < 60; i++ { // 10 minutes of looks, 10 s apart
		*now = now.Add(10 * time.Second)
		w.step()
	}
	if runs > 8 {
		t.Errorf("too many guard runs for rules that will not stay: %d", runs)
	}
	if runs < 3 {
		t.Errorf("it must keep trying: %d", runs)
	}
}
