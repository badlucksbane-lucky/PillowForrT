package main

// tinyfwd's own traffic: how it leaves the box. The devices' traffic follows each device's mode (direct, Mullvad, Tor); this is the traffic tinyfwd makes for itself, which used to go out
// of the cellular link raw whatever the state of the private paths: the encrypted-DNS lookups (DoH), list downloads, notification pushes. One function decides, from the state:
//
//   Mullvad configured and the tunnel up   -> through the tunnel only (marked and bound to mullvad0, as Tor's proxy connections are);
//   Mullvad configured, tunnel down        -> BLOCKED if the kill switch is on (one setting for devices and for this); otherwise as if Mullvad were not configured;
//   Tor on and ready                       -> through Tor (its SOCKS port);
//   Tor on but not ready, or neither       -> the cellular link, with a warning event when a private path is configured but not available. Tor alone never blocks: a memory pause
//                                             of Tor must not take the house's name lookups with it.
//
// Declared exceptions, which stay on the cellular link by design: the WireGuard handshake itself, the Mullvad API (registration and the relay list), the uplink probe, speed tests and
// diagnostics (they measure the cellular link), and the lookup of api.mullvad.net while the route is blocked (without it a restarted tinyfwd could never fetch the relay list, and the
// tunnel could never come back). Everything else tinyfwd dials for itself goes through ownDial.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
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
	KillSwitch    bool
	TorEnabled    bool
	TorReady      bool
}

// decideOwnRoute is the whole policy, as a pure function. reason says why when the route is not a private one.
func decideOwnRoute(s ownState) (ownRoute, string) {
	if s.MullvadWanted {
		if s.TunnelUp {
			return routeTunnel, ""
		}
		if s.KillSwitch {
			return routeBlock, "the Mullvad tunnel is down and the kill switch is on"
		}
	}
	if s.TorEnabled && s.TorReady {
		return routeTor, ""
	}
	switch {
	case s.MullvadWanted:
		return routeDirect, "the Mullvad tunnel is down and the kill switch is off"
	case s.TorEnabled:
		return routeDirect, "Tor is not ready yet"
	}
	return routeDirect, ""
}

// torSeen is the last Tor state read: the Tor manager holds its lock for seconds while it starts or stops a process, and a name lookup must not wait behind that.
var torSeen struct{ enabled, ready atomic.Bool }

func liveOwnState() ownState {
	var s ownState
	if vpn != nil {
		s.MullvadWanted, s.TunnelUp, s.KillSwitch = vpn.OwnState()
	}
	if m := torMgrG; m != nil {
		if m.mu.TryLock() {
			torSeen.enabled.Store(m.cfg.Enabled)
			torSeen.ready.Store(m.running() && m.boot >= 100)
			m.mu.Unlock()
		}
		s.TorEnabled, s.TorReady = torSeen.enabled.Load(), torSeen.ready.Load()
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
}

var ownR = &ownRouter{state: liveOwnState, now: time.Now, warnedAt: map[string]time.Time{}, emit: func(kind, sev, text, public string) {
	if events != nil {
		events.Add([]evt{{T: time.Now().Unix(), Kind: kind, Sev: sev, Text: text, Public: public}})
	}
}}

const ownWarnEvery = 10 * time.Minute

// Now returns the route for this moment and notes a change.
func (o *ownRouter) Now() (ownRoute, string) {
	r, why := decideOwnRoute(o.state())
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.started {
		o.started, o.last, o.lastWhy = true, r, why
		o.noteLocked(r, why)
		return r, why
	}
	if r != o.last {
		o.gen++
		o.last = r
		o.noteLocked(r, why)
	}
	o.lastWhy = why
	return r, why
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
		return socksConnect(onionSocksAddr, host, port, 15*time.Second)
	case routeBlock:
		return nil, fmt.Errorf("%w: %s", errOwnBlocked, why)
	}
	return dialUpstream(ctx, network, addr)
}

// ownBootstrapName: the one name looked up over the cellular link while the route is blocked (see the exceptions above).
func ownBootstrapName(name string) bool { return name == "api.mullvad.net" }
