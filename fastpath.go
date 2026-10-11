package main

// Fast-path handoff (dry run): shortcut_fe_cm (vpn_policy.go) is unloaded whenever any device needs the tunnel or Tor, because once it takes over a
// forwarded flow it picks the outgoing interface with a plain route lookup that ignores firewall marks (see the 2026-10-02 incident noted in vpn_policy.go).
// It can only be safe to reload when a plain lookup and the real policy agree completely: every device defaults to Mullvad with zero per-MAC direct
// exceptions (so there is one answer, not several), no device is on Tor (Tor redirects locally; a shortcut flow would skip the redirect, not just the
// mark), the tunnel is up, and DNS resolves through it. Reaching that state would still require repointing the main table's own default route at
// mullvad0 so the module's ignorant lookup happens to land correctly, and reverting that the instant any of the above stops holding — neither of which
// this does yet. For now this only watches and logs what it would decide, on the same cadence Reconcile already runs at, so the log can be read for a
// while before any of it is wired to insmod or ip route.

import (
	"log"
	"sync"
	"time"
)

const fastPathDNSProbeEvery = 20 * time.Second

// fastPathDNS caches the liveness probe (diag.go's lookupVia, same technique gatherDiag uses) so a Reconcile storm — egress/device/Tor changes all call
// it — doesn't turn into a storm of DNS lookups.
type fastPathDNS struct {
	mu      sync.Mutex
	healthy bool
	checked time.Time
}

var fastPathDNSG fastPathDNS

func (d *fastPathDNS) ok() bool {
	d.mu.Lock()
	stale := time.Since(d.checked) > fastPathDNSProbeEvery
	cur := d.healthy
	d.mu.Unlock()
	if !stale {
		return cur
	}
	_, _, err := lookupVia("example.com")
	d.mu.Lock()
	d.healthy, d.checked = err == nil, time.Now()
	result := d.healthy
	d.mu.Unlock()
	return result
}

// fastPathEligible is the strict-mode gate, pure and cheap: every device must default to Mullvad with no per-MAC direct exception, and no device on Tor.
// Mixed per-device policy (some direct, some tunneled) is never eligible: there is no single plain route that would be correct for all of them.
func fastPathEligible(p exitPlan, torActive bool) (bool, string) {
	switch {
	case torActive:
		return false, "a device is on Tor (shortcut flows would skip the SOCKS redirect)"
	case !p.DefaultVPN:
		return false, "default exit is not mullvad"
	case len(p.DirectMacs) > 0:
		return false, "per-device direct exception(s) exist: mixed policy has no single correct route"
	case !p.TunnelUp:
		return false, "tunnel is not up"
	default:
		return true, ""
	}
}

// logFastPathDecision reports what the handoff WOULD do, without doing it: no insmod, no ip route change. manageSFE's existing call right after this in
// Reconcile is untouched, so this cannot make anything less safe than today.
func logFastPathDecision(p exitPlan, torActive bool) {
	eligible, why := fastPathEligible(p, torActive)
	want := eligible && fastPathDNSG.ok()
	reason := why
	if eligible && !want {
		reason = "policy is eligible but the DNS probe through the tunnel failed"
	}
	loaded := moduleLoaded(sfeModule)
	log.Printf("fastpath: dry-run would-handoff=%v module-loaded=%v reason=%q", want, loaded, reason)
}
