package main

import (
	"strings"
	"testing"
	"time"
)

func torGateForTest() *rungGate {
	g, _ := newRungGates()
	return g
}

// Stepping up waits (stable for a while, enough good probes, a quiet box) while a lower rung is serving.
func TestRungStepsUpOnlyWhenReady(t *testing.T) {
	g := torGateForTest()
	t0 := time.Unix(1_800_000_000, 0)
	if g.step(t0, true, false, true) {
		t.Fatal("just came up: not usable yet")
	}
	g.report(true)
	g.report(true)
	if g.step(t0.Add(torStepUpAfter-time.Second), true, false, true) {
		t.Error("two good probes are not enough before the rung has been up long enough")
	}
	if g.step(t0.Add(torStepUpAfter), true, false, false) {
		t.Error("a busy box does not step up")
	}
	if !g.step(t0.Add(torStepUpAfter+time.Second), true, false, true) {
		t.Error("up long enough, probed twice, box quiet: step up")
	}
	// one good probe is not two
	h := torGateForTest()
	h.step(t0, true, false, true)
	h.report(true)
	if h.step(t0.Add(time.Hour), true, false, true) {
		t.Error("one good probe is not enough when a lower rung is serving")
	}
	h.report(false)
	h.report(true)
	if h.step(t0.Add(time.Hour), true, false, true) {
		t.Error("a failure resets the run of good probes")
	}
}

// Stepping down is immediate when the rung goes, and after two failures when it is up on paper only; then it is held down before another try.
func TestRungStepsDownAtOnceAndHoldsDown(t *testing.T) {
	g := torGateForTest()
	t0 := time.Unix(1_800_000_000, 0)
	g.step(t0, true, false, true)
	g.report(true)
	g.report(true)
	now := t0.Add(time.Minute)
	if !g.step(now, true, false, true) {
		t.Fatal("up")
	}
	if g.step(now, false, false, true) || g.step(now.Add(time.Second), true, false, true) {
		t.Error("when the rung goes it is gone at once, and coming back starts the wait again")
	}
	// up, then it fails twice in a row
	g = torGateForTest()
	g.step(t0, true, false, true)
	g.report(true)
	g.report(true)
	g.step(t0.Add(time.Minute), true, false, true)
	g.report(false)
	if !g.step(t0.Add(time.Minute), true, false, true) {
		t.Error("one failure is not enough to give up")
	}
	g.report(false)
	if g.step(t0.Add(time.Minute), true, false, true) {
		t.Error("two failures in a row: given up")
	}
	// hold-down: good probes right away do not bring it back
	g.report(true)
	g.report(true)
	if g.step(t0.Add(time.Minute+torHoldDown-time.Second), true, false, true) {
		t.Error("held down after a failure")
	}
	if !g.step(t0.Add(time.Minute+torHoldDown+time.Second), true, false, true) {
		t.Error("after the hold-down, with good probes, it steps up again")
	}
}

// When nothing lower is serving, the wait is dropped: one good probe is enough, and a hold-down or a busy box does not keep the house blocked.
func TestRungDoesNotWaitWhenNothingElseServes(t *testing.T) {
	g := torGateForTest()
	t0 := time.Unix(1_800_000_000, 0)
	g.step(t0, true, true, true)
	if g.step(t0, true, true, true) {
		t.Error("still needs one good probe")
	}
	g.report(true)
	if !g.step(t0, true, true, false) {
		t.Error("needed: one good probe, no stability wait, load ignored")
	}
	g = torGateForTest()
	g.holdUntil = t0.Add(time.Hour)
	g.step(t0, true, true, true)
	g.report(true)
	if !g.step(t0, true, true, true) {
		t.Error("needed: the hold-down is ignored too")
	}
}

// Through the router: the lookups stay on the tunnel while Tor boots, move to Tor when it has proved itself, and fall back the moment it goes.
func TestRouterFollowsViabilityOfTor(t *testing.T) {
	s := ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true}
	r, _, now := testRouter(&s)
	r.torG.stableFor, r.torG.probesNeeded = torStepUpAfter, 2 // the real waiting for Tor
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Fatalf("tunnel only: %v", rt)
	}
	s.TorEnabled, s.TorReady, s.TorOverVPN = true, true, true // Tor says it is ready
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Errorf("Tor just reported ready: the tunnel keeps serving, got %v", rt)
	}
	*now = now.Add(torStepUpAfter + time.Second)
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Errorf("up long enough but not probed: still the tunnel, got %v", rt)
	}
	r.reportTor(true)
	r.reportTor(true)
	if rt, _ := r.Now(); rt != routeTor {
		t.Errorf("proved itself: step up to Tor, got %v", rt)
	}
	r.reportTor(false) // real dials through Tor fail
	r.reportTor(false)
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Errorf("failing in practice: back to the tunnel at once, got %v", rt)
	}
	r.reportTor(true)
	r.reportTor(true)
	*now = now.Add(time.Minute)
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Errorf("held down: the tunnel keeps serving, got %v", rt)
	}
	*now = now.Add(torHoldDown)
	if rt, _ := r.Now(); rt != routeTor {
		t.Errorf("after the hold-down: Tor again, got %v", rt)
	}
	s.TorReady = false // Tor goes away
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Errorf("Tor gone: tunnel, got %v", rt)
	}
	s.TunnelUp = false // and then the tunnel, in the middle tier: blocked
	if rt, _ := r.Now(); rt != routeBlock {
		t.Errorf("nothing up in the middle tier: blocked, got %v", rt)
	}
	// the tunnel returns while Tor is still booting: no waiting, nothing else is serving
	s.TunnelUp = true
	if rt, _ := r.Now(); rt != routeTunnel {
		t.Errorf("tunnel back with nothing serving: at once, got %v", rt)
	}
}

// The page's view: which rung serves, and why Tor through Mullvad is not serving when it is not.
func TestOwnViewRungAndWhy(t *testing.T) {
	s := ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true}
	r, _, now := testRouter(&s)
	r.torG.stableFor, r.torG.probesNeeded = torStepUpAfter, 2 // the real waiting for Tor
	want := func(label string, rung int, route string, top bool, whyHas string) ownView {
		t.Helper()
		v := r.View()
		if v.Rung != rung || v.Route != route || v.TopReady != top || (whyHas == "" && v.TopWhy != "") || (whyHas != "" && !strings.Contains(v.TopWhy, whyHas)) {
			t.Errorf("%s: %+v", label, v)
		}
		return v
	}
	want("Tor off", 2, "tunnel", false, "Tor is switched off")
	s.TorEnabled = true
	want("Tor on, not over Mullvad", 2, "tunnel", false, "not ticked")
	s.TorOverVPN = true
	want("Tor not ready", 2, "tunnel", false, "still starting")
	s.TorReady = true
	v := want("Tor ready, not proved", 2, "tunnel", false, "not yet proved itself")
	if !strings.Contains(v.TopWhy, "0 of 2 test connections") || !strings.Contains(v.TopWhy, "of settling") {
		t.Errorf("it should say what it is waiting for: %q", v.TopWhy)
	}
	*now = now.Add(torStepUpAfter + time.Second)
	r.reportTor(true)
	r.reportTor(true)
	want("proved", 1, "tor", true, "")
	s.TunnelUp, s.TorReady = false, false // Tor over Mullvad stops with the tunnel
	want("tunnel down, Tor gone with it", 0, "blocked", false, "tunnel is down")
	s.Tier = tierDirect
	v = want("direct tier, nothing up", 3, "direct", false, "tunnel is down")
	if v.Reason == "" {
		t.Error("a raw route with a private path configured says why")
	}
	r.load = func() float64 { return 3.2 }
	s.TunnelUp, s.TorReady = true, true
	*now = now.Add(time.Hour)
	r.torG.up = false
	if v := r.View(); !strings.Contains(v.TopWhy, "less busy") {
		t.Errorf("a busy box is named as the wait: %q", v.TopWhy)
	}
}
