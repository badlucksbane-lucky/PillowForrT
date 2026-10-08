package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDecideOwnRoute(t *testing.T) {
	for _, c := range []struct {
		name   string
		s      ownState
		want   ownRoute
		whyHas string // "" = no reason expected
	}{
		// direct tier: nothing is ever blocked; the best private path that is up, else the cellular link
		{"direct: tunnel up", ownState{Tier: tierDirect, MullvadWanted: true, TunnelUp: true}, routeTunnel, ""},
		{"direct: Tor through Mullvad up: rung 1 goes first", ownState{Tier: tierDirect, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true, TorOverVPN: true}, routeTor, ""},
		{"direct: tunnel down, Tor ready", ownState{Tier: tierDirect, MullvadWanted: true, TorEnabled: true, TorReady: true}, routeTor, ""},
		{"direct: tunnel down, nothing else: raw with a reason", ownState{Tier: tierDirect, MullvadWanted: true}, routeDirect, "set to direct"},
		{"direct: Tor on but not ready: raw with a reason, never blocked", ownState{Tier: tierDirect, TorEnabled: true}, routeDirect, "Tor is not ready"},
		{"direct: nothing configured: raw, no warning", ownState{Tier: tierDirect}, routeDirect, ""},
		// middle tier: the tunnel or Tor, blocked when neither is up
		{"middle: tunnel up", ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true}, routeTunnel, ""},
		{"middle: tunnel up beats Tor that is not over Mullvad", ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true}, routeTunnel, ""},
		{"middle: Tor through Mullvad up: rung 1 goes first", ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true, TorOverVPN: true}, routeTor, ""},
		{"middle: Tor over Mullvad configured but not ready: the tunnel alone carries it", ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorOverVPN: true}, routeTunnel, ""},
		{"middle: tunnel down, Tor ready: Tor", ownState{Tier: tierPrivate, MullvadWanted: true, TorEnabled: true, TorReady: true}, routeTor, ""},
		{"middle: Tor only, ready", ownState{Tier: tierPrivate, TorEnabled: true, TorReady: true}, routeTor, ""},
		{"middle: tunnel down, Tor not ready: blocked", ownState{Tier: tierPrivate, MullvadWanted: true, TorEnabled: true}, routeBlock, "middle kill-switch tier"},
		{"middle: Tor only, not ready: blocked", ownState{Tier: tierPrivate, TorEnabled: true}, routeBlock, "middle kill-switch tier"},
		{"middle: nothing switched on: raw with a reason, not a house-wide block", ownState{Tier: tierPrivate}, routeDirect, "neither is"},
		// top tier: Tor running over the tunnel, or nothing
		{"top: Tor through Mullvad up", ownState{Tier: tierTorMullvad, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true, TorOverVPN: true}, routeTor, ""},
		{"top: tunnel up but Tor not ready: blocked (not the tunnel alone)", ownState{Tier: tierTorMullvad, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorOverVPN: true}, routeBlock, "top kill-switch tier"},
		{"top: tunnel down: blocked", ownState{Tier: tierTorMullvad, MullvadWanted: true, TorEnabled: true, TorReady: true, TorOverVPN: true}, routeBlock, "top kill-switch tier"},
		{"top: Tor ready but not over Mullvad: raw with a reason (mis-set tier cannot black out the house)", ownState{Tier: tierTorMullvad, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true}, routeDirect, "top kill-switch tier needs"},
		{"top: Mullvad off: raw with a reason", ownState{Tier: tierTorMullvad, TorEnabled: true, TorReady: true, TorOverVPN: true}, routeDirect, "top kill-switch tier needs"},
		{"no tier set behaves as direct", ownState{MullvadWanted: true}, routeDirect, "set to direct"},
	} {
		got, why := decideOwnRoute(c.s)
		if got != c.want || (c.whyHas == "" && why != "") || (c.whyHas != "" && !strings.Contains(why, c.whyHas)) {
			t.Errorf("%s: got %v %q", c.name, got, why)
		}
	}
}

func TestKillTierPrereq(t *testing.T) {
	for _, c := range []struct {
		tier                  string
		mullvad, torOn, torVP bool
		ok                    bool
	}{
		{tierDirect, false, false, false, true},
		{tierPrivate, true, false, false, true},
		{tierPrivate, false, true, false, true},
		{tierPrivate, false, false, false, false},
		{tierTorMullvad, true, true, true, true},
		{tierTorMullvad, true, true, false, false},
		{tierTorMullvad, true, false, true, false},
		{tierTorMullvad, false, true, true, false},
	} {
		if err := killTierPrereq(c.tier, c.mullvad, c.torOn, c.torVP); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func testRouter(s *ownState) (*ownRouter, *[]string, *time.Time) {
	now := time.Unix(1_800_000_000, 0)
	var got []string
	return &ownRouter{state: func() ownState { return *s }, now: func() time.Time { return now }, warnedAt: map[string]time.Time{},
		emit: func(kind, sev, text, public string) { got = append(got, kind) }}, &got, &now
}

// A change of route bumps the generation (so pooled connections are closed), and the owner is told about a blocked or raw route, once per ten minutes.
func TestOwnRouterGenerationAndWarnings(t *testing.T) {
	s := ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true}
	r, ev, now := testRouter(&s)
	g0 := r.Gen()
	if r.Gen() != g0 || len(*ev) != 0 {
		t.Fatalf("a steady route changes nothing: %d %v", r.Gen(), *ev)
	}
	s.TunnelUp = false // the tunnel drops with the kill switch on
	if g := r.Gen(); g == g0 || len(*ev) != 1 || (*ev)[0] != "own_traffic_blocked" {
		t.Fatalf("a change bumps the generation and reports the block: gen %d events %v", g, *ev)
	}
	g1 := r.Gen()
	s.TunnelUp = true
	*now = now.Add(time.Minute)
	if r.Gen() == g1 {
		t.Error("coming back is a change too")
	}
	s.TunnelUp = false // flaps inside ten minutes: one event, not a flood
	*now = now.Add(time.Minute)
	r.Gen()
	if len(*ev) != 1 {
		t.Errorf("rate limited: %v", *ev)
	}
	*now = now.Add(11 * time.Minute)
	s.TunnelUp = true
	r.Gen()
	s.TunnelUp = false
	r.Gen()
	if len(*ev) != 2 {
		t.Errorf("after the window it is reported again: %v", *ev)
	}
	// raw with a private path configured but down is reported; raw with nothing configured is not
	s2 := ownState{Tier: tierDirect, TorEnabled: true}
	r2, ev2, _ := testRouter(&s2)
	r2.Gen()
	if len(*ev2) != 1 || (*ev2)[0] != "own_traffic_raw" {
		t.Errorf("Tor on but not ready: %v", *ev2)
	}
	s3 := ownState{}
	r3, ev3, _ := testRouter(&s3)
	r3.Gen()
	if len(*ev3) != 0 {
		t.Errorf("nothing configured is the owner's choice, not a warning: %v", *ev3)
	}
}

func TestOwnDialBlockedNeverDials(t *testing.T) {
	old := ownR
	defer func() { ownR = old }()
	s := ownState{Tier: tierPrivate, MullvadWanted: true}
	ownR, _, _ = testRouter(&s)
	c, err := ownDial(nil, "tcp", "9.9.9.9:443")
	if c != nil || !errors.Is(err, errOwnBlocked) {
		t.Fatalf("blocked must not dial: %v %v", c, err)
	}
	if !ownBlocked() || ownTimeout() != 2*time.Second {
		t.Error("blocked helpers")
	}
	s.TunnelUp = true
	if ownBlocked() || ownTimeout() != 4*time.Second {
		t.Error("tunnel route: not blocked, a little more time")
	}
	s.MullvadWanted, s.TorEnabled, s.TorReady = false, true, true
	if ownTimeout() != 12*time.Second {
		t.Error("Tor needs the longest")
	}
}

// A pooled DoH connection opened under one route is not reused under the next.
func TestUpstreamClosesPooledConnectionsWhenTheRouteChanges(t *testing.T) {
	doh, pool := newFakeDoH(t)
	var gen uint64
	up := newUpstream(upstreamConfig{DoHURLs: []string{doh.URL}, Roots: pool, DoHTimeout: time.Second, ProbeEvery: time.Hour,
		Dial: (&net.Dialer{Timeout: time.Second}).DialContext, RouteGen: func() uint64 { return gen }})
	count := func() int {
		n := 0
		doh.conns.Range(func(_, _ any) bool { n++; return true })
		return n
	}
	q := mkQuery("a.example.net", qtA, 1, true)
	if _, _, _, err := up.ResolveFrom(q); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := up.ResolveFrom(q); err != nil || count() != 1 {
		t.Fatalf("same route: one connection is reused (%d)", count())
	}
	gen++
	if _, _, _, err := up.ResolveFrom(q); err != nil || count() != 2 {
		t.Fatalf("route changed: a new connection must be opened (%d)", count())
	}
}

// While the route is blocked, only api.mullvad.net is looked up (over the cellular link); every other name is refused.
func TestBootstrapLookupWhileBlocked(t *testing.T) {
	old := ownR
	defer func() { ownR = old }()
	s := ownState{Tier: tierPrivate, MullvadWanted: true}
	ownR, _, _ = testRouter(&s)
	doh, pool := newFakeDoH(t)
	p := testProxyURLs(t, []string{doh.URL}, pool)
	boot := p.Up.cfg
	boot.Dial = func(ctx context.Context, n, a string) (net.Conn, error) { return nil, errOwnBlocked }
	boot.BootDial = (&net.Dialer{Timeout: time.Second}).DialContext
	p.Up = newUpstream(boot)
	if addrOf(ask(p, "api.mullvad.net", 1)) != "93.184.216.34" {
		t.Error("the Mullvad API name must resolve while the route is blocked, or the tunnel can never come back")
	}
	if rcodeOf(ask(p, "example.org", 2)) != 2 {
		t.Error("every other name is refused while the route is blocked")
	}
}
