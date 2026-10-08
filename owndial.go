package main

// tinyfwd's own traffic: how it leaves the box. The devices' traffic follows each device's mode (direct, Mullvad, Tor); this is the traffic tinyfwd makes for itself (the encrypted-DNS
// lookups for every device, list downloads, notification pushes), which used to go out of the cellular link raw whatever the state of the private paths.
//
// It follows a ladder, always trying the top rung first:
//   1  Tor through Mullvad   (Tor running over the tunnel, torvpn.go)
//   2  Mullvad or Tor        (the tunnel if it is up, else Tor)
//   3  direct                (the cellular link)
// The kill-switch tier (vpn.go) is the lowest rung that is allowed: top = rung 1 only, middle = rungs 1 and 2, direct = all three. When no allowed rung is up the traffic is BLOCKED
// (top, middle) or goes out the cellular link with a warning event when a private path was configured but is down (direct).
// A tier whose rungs are not switched on at all (nothing to wait for) is treated as direct, with a warning, so a mis-set tier cannot take the house's name lookups down by itself.
//
// Declared exceptions, which stay on the cellular link by design: the WireGuard handshake itself, the Mullvad API (registration and the relay list), the uplink probe, speed tests and
// diagnostics (they measure the cellular link), and the lookup of api.mullvad.net while the route is blocked (without it a restarted tinyfwd could never fetch the relay list, and the
// tunnel could never come back). Everything else tinyfwd dials for itself goes through ownDial.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ownRoute int

const (
	routeDirect ownRoute = iota
	routeTunnel
	routeTor
	routeBlock
)

func (r ownRoute) String() string {
	return [...]string{"direct", "tunnel", "tor", "blocked"}[r]
}

type ownState struct {
	MullvadWanted bool // registered and switched on
	TunnelUp      bool
	Tier          string // the kill-switch tier
	TorEnabled    bool
	TorReady      bool
	TorOverVPN    bool // Tor is set to run over Mullvad
}

// decideOwnRoute is the whole policy, as a pure function. reason says why when the route is blocked, or is not a private one although a private path was asked for.
func decideOwnRoute(s ownState) (ownRoute, string) {
	tunnel := s.MullvadWanted && s.TunnelUp
	tor := s.TorEnabled && s.TorReady
	if tunnel && tor && s.TorOverVPN { // rung 1: Tor through Mullvad (the Tor gate keeps Tor from running over the tunnel while the tunnel is down)
		return routeTor, ""
	}
	if s.Tier == tierTorMullvad {
		if !s.MullvadWanted || !s.TorEnabled || !s.TorOverVPN {
			return routeDirect, "the top kill-switch tier needs Mullvad, Tor and Tor over Mullvad all switched on, and they are not"
		}
		return routeBlock, "Tor through Mullvad is not up (the top kill-switch tier)"
	}
	switch { // rung 2: Mullvad or Tor
	case tunnel:
		return routeTunnel, ""
	case tor:
		return routeTor, ""
	}
	if s.Tier == tierPrivate {
		if !s.MullvadWanted && !s.TorEnabled {
			return routeDirect, "the middle kill-switch tier needs Mullvad or Tor switched on, and neither is"
		}
		return routeBlock, "neither the Mullvad tunnel nor Tor is up (the middle kill-switch tier)"
	}
	switch { // rung 3: direct, which is never a block
	case s.MullvadWanted:
		return routeDirect, "the Mullvad tunnel is down and the kill switch is set to direct"
	case s.TorEnabled:
		return routeDirect, "Tor is not ready yet"
	}
	return routeDirect, ""
}

// killTierPrereq says whether a tier can be set now: a tier that nothing can satisfy would block everything the moment it is chosen.
func killTierPrereq(tier string, mullvadWanted, torOn, torOverVPN bool) error {
	switch tier {
	case tierTorMullvad:
		if !mullvadWanted || !torOn || !torOverVPN {
			return errors.New("the top tier needs Mullvad switched on, Tor switched on and Tor over Mullvad ticked first")
		}
	case tierPrivate:
		if !mullvadWanted && !torOn {
			return errors.New("the middle tier needs Mullvad or Tor switched on first")
		}
	}
	return nil
}

// torSeen is the last Tor state read: the Tor manager holds its lock for seconds while it starts or stops a process, and a name lookup must not wait behind that.
var torSeen struct{ enabled, ready, overVPN atomic.Bool }

func liveOwnState() ownState {
	var s ownState
	if vpn != nil {
		s.MullvadWanted, s.TunnelUp, s.Tier = vpn.OwnState()
	}
	if m := torMgrG; m != nil {
		if m.mu.TryLock() {
			torSeen.enabled.Store(m.cfg.Enabled)
			torSeen.overVPN.Store(m.cfg.OverVPN)
			torSeen.ready.Store(m.running() && m.boot >= 100)
			m.mu.Unlock()
		}
		s.TorEnabled, s.TorReady, s.TorOverVPN = torSeen.enabled.Load(), torSeen.ready.Load(), torSeen.overVPN.Load()
	}
	return s
}

var errOwnBlocked = errors.New("tinyfwd's own traffic is blocked")

// ownRouter remembers the last route so a change can close pooled connections (a connection opened under the old route would carry on under it) and be reported.
type ownRouter struct {
	mu       sync.Mutex
	state    func() ownState
	emit     func(kind, sev, text, public string)
	now      func() time.Time
	last     ownRoute
	lastWhy  string
	started  bool
	gen      uint64
	warnedAt map[string]time.Time
	torG     *rungGate // viability of Tor as a rung (rungs.go)
	tunG     *rungGate // and of the tunnel
	load     func() float64
}

// newOwnRouter builds a router with its rung gates; state, now and emit are replaceable for tests.
func newOwnRouter(state func() ownState, now func() time.Time, emit func(kind, sev, text, public string)) *ownRouter {
	tor, tun := newRungGates()
	return &ownRouter{state: state, now: now, emit: emit, warnedAt: map[string]time.Time{}, torG: tor, tunG: tun, load: loadAvg1}
}

var ownR = newOwnRouter(liveOwnState, time.Now, func(kind, sev, text, public string) {
	if events != nil {
		events.Add([]evt{{T: time.Now().Unix(), Kind: kind, Sev: sev, Text: text, Public: public}})
	}
})

const ownWarnEvery = 10 * time.Minute

// Now returns the route for this moment and notes a change.
func (o *ownRouter) Now() (ownRoute, string) {
	raw := o.state()
	o.mu.Lock()
	defer o.mu.Unlock()
	r, why := decideOwnRoute(o.gated(raw))
	if !o.started {
		o.started, o.last, o.lastWhy = true, r, why
		o.noteLocked(r, why)
		return r, why
	}
	if r != o.last {
		o.gen++
		log.Printf("own traffic: %v -> %v %s", o.last, r, why)
		o.last = r
		o.noteLocked(r, why)
	}
	o.lastWhy = why
	return r, why
}

// gated turns the raw state into the usable one: a rung counts as up only when its gate says so (rungs.go). The tunnel is judged first, then Tor, which steps up without delay only when
// no tunnel is serving. The caller holds o.mu.
func (o *ownRouter) gated(s ownState) ownState {
	now := o.now()
	loadOK := o.load == nil || o.load() < stepUpLoadLimit
	tunRaw := s.MullvadWanted && s.TunnelUp
	torRaw := s.TorEnabled && s.TorReady
	tun := o.tunG.step(now, tunRaw, !torRaw || !o.torG.up, loadOK) // a tunnel with no Tor serving needs no waiting; with Tor serving it waits like any step up
	tor := o.torG.step(now, torRaw, !tun, loadOK)
	s.TunnelUp = tun
	s.TorReady = tor
	return s
}

// reportTor records a probe, or a real dial, through Tor.
func (o *ownRouter) reportTor(ok bool) {
	o.mu.Lock()
	o.torG.report(ok)
	o.mu.Unlock()
}

func (o *ownRouter) torUp() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.torG.up
}

// noteLocked reports the routes that are worth the owner's attention: blocked, and raw with a private path configured but unavailable. At most one event per kind every ten minutes.
func (o *ownRouter) noteLocked(r ownRoute, why string) {
	kind, sev, text, public := "", "", "", ""
	switch {
	case r == routeBlock:
		kind, sev = "own_traffic_blocked", sevAttention
		text = "tinyfwd's own traffic (encrypted DNS lookups, list downloads, notifications) is blocked: " + why + ". Name lookups are refused until the tunnel is back."
		public = "The Orbic's own traffic is blocked while the VPN is down"
	case r == routeDirect && why != "":
		kind, sev = "own_traffic_raw", sevAttention
		text = "tinyfwd's own traffic (encrypted DNS lookups, list downloads, notifications) is leaving over the cellular link because " + why + "."
		public = "The Orbic's own traffic is leaving over the cellular link because a private path is unavailable"
	default:
		return
	}
	if t, ok := o.warnedAt[kind]; ok && o.now().Sub(t) < ownWarnEvery {
		return
	}
	o.warnedAt[kind] = o.now()
	o.emit(kind, sev, text, public)
}

// Gen changes whenever the route does.
func (o *ownRouter) Gen() uint64 {
	o.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.gen
}

// ownView is what the page shows: which rung is serving the router's own traffic right now, and, when the top rung (Tor through Mullvad) is not serving, why not.
type ownView struct {
	Route    string `json:"route"`  // tunnel | tor | direct | blocked
	Reason   string `json:"reason"` // why it is blocked, or raw although a private path was asked for
	Rung     int    `json:"rung"`   // 1 Tor through Mullvad, 2 Mullvad or Tor, 3 direct, 0 blocked
	TopReady bool   `json:"top_ready"`
	TopWhy   string `json:"top_why,omitempty"` // why Tor through Mullvad is not serving
}

func (o *ownRouter) View() ownView {
	r, why := o.Now()
	raw := o.state()
	o.mu.Lock()
	defer o.mu.Unlock()
	v := ownView{Route: r.String(), Reason: why}
	top := r == routeTor && raw.TorOverVPN && raw.MullvadWanted && raw.TunnelUp
	switch {
	case top:
		v.Rung = 1
	case r == routeTunnel || r == routeTor:
		v.Rung = 2
	case r == routeDirect:
		v.Rung = 3
	}
	v.TopReady = top
	if !top {
		v.TopWhy = o.topWhyLocked(raw)
	}
	return v
}

// topWhyLocked says in a sentence why Tor through Mullvad is not serving: the first thing that is missing, or, when Tor itself is ready, what the step-up is still waiting for.
func (o *ownRouter) topWhyLocked(raw ownState) string {
	switch {
	case !raw.MullvadWanted:
		return "Mullvad is not switched on"
	case !raw.TorEnabled:
		return "Tor is switched off"
	case !raw.TorOverVPN:
		return "Tor over Mullvad is not ticked"
	case !raw.TunnelUp:
		return "the Mullvad tunnel is down"
	case !raw.TorReady:
		return "Tor is still starting"
	}
	g, now := o.torG, o.now()
	var wait []string
	if now.Before(g.holdUntil) {
		wait = append(wait, fmt.Sprintf("held down after a failure for %d more s", int(g.holdUntil.Sub(now).Seconds())+1))
	}
	if !g.since.IsZero() && now.Sub(g.since) < g.stableFor {
		wait = append(wait, fmt.Sprintf("%d s of settling", int((g.stableFor-now.Sub(g.since)).Seconds())+1))
	}
	if g.okRun < g.probesNeeded {
		wait = append(wait, fmt.Sprintf("%d of %d test connections through Tor", g.okRun, g.probesNeeded))
	}
	if o.load != nil {
		if l := o.load(); l >= stepUpLoadLimit {
			wait = append(wait, fmt.Sprintf("the router to be less busy (load %.1f, needs under %.1f)", l, stepUpLoadLimit))
		}
	}
	if len(wait) == 0 {
		return "Tor is ready and is about to take over"
	}
	return "Tor is ready but has not yet proved itself: waiting for " + strings.Join(wait, "; ")
}

func ownRouteNow() (ownRoute, string) { return ownR.Now() }
func ownRouteGen() uint64             { return ownR.Gen() }

// ownTimeout is how long an encrypted lookup may take on the current route (Tor needs a new circuit now and then).
func ownTimeout() time.Duration {
	switch r, _ := ownRouteNow(); r {
	case routeTor:
		return 12 * time.Second
	case routeTunnel:
		return 4 * time.Second
	}
	return 2 * time.Second
}

// ownDial is the dialler for everything tinyfwd connects to for itself.
func ownDial(ctx context.Context, network, addr string) (net.Conn, error) {
	r, why := ownRouteNow()
	switch r {
	case routeTunnel:
		return dialTunnelOnly(ctx, network, addr)
	case routeTor:
		host, ps, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(ps)
		if err != nil {
			return nil, err
		}
		c, err := socksConnect(onionSocksAddr, host, port, 15*time.Second)
		ownR.reportTor(err == nil) // a Tor that is "ready" but cannot carry this is given up (rungs.go)
		return c, err
	case routeBlock:
		return nil, fmt.Errorf("%w: %s", errOwnBlocked, why)
	}
	return dialUpstream(ctx, network, addr)
}

// ownBootstrapName: the one name looked up over the cellular link while the route is blocked (see the exceptions above).
func ownBootstrapName(name string) bool { return name == "api.mullvad.net" }
