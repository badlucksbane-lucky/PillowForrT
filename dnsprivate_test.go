package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// askAs sends a query the way dnsmasq does: with the asking device's address in an EDNS client-subnet option.
func askAs(p *DNSProxy, client, name string, id uint16) []byte {
	q := mkQuery(name, qtA, id, true)
	ip := net.ParseIP(client).To4()
	opt := []byte{0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 12, 0, 8, 0, 8, 0, 1, 32, 0}
	opt = append(opt, ip...)
	binary.BigEndian.PutUint16(q[10:12], 1)
	return p.Handle(append(q, opt...))
}

func mullvadClientVPN(t *testing.T, ip string, dnsViaVPN bool) *VPN {
	v := NewVPN(filepath.Join(t.TempDir(), "vpn"), http.DefaultClient)
	v.cfg.Registered = true
	v.cfg.DeviceExit[ip] = "mullvad"
	v.cfg.DNSViaVPN = dnsViaVPN
	return v
}

// A Mullvad device with Mullvad's resolver off still gets encrypted DNS or a refusal, never anything else; the refusal is counted and reported as a hard block.
func TestMullvadDeviceGetsEncryptedDNSOrNothing(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxyURLs(t, []string{doh.URL}, pool)
	p.VPN = mullvadClientVPN(t, "192.168.1.40", false)
	doh.fail.Store(true)

	r := askAs(p, "192.168.1.40", "m1.example.net", 1)
	if rcodeOf(r) != 2 {
		t.Fatalf("a Mullvad device must be refused when encrypted DNS is down: rcode=%d", rcodeOf(r))
	}
	if p.Stats.HardBlock.Load() == 0 {
		t.Error("the refusal must be counted as a hard block")
	}
	// an ordinary device is refused too (there is no plain fallback for anyone), but that is not a hard block of a private path
	hb := p.Stats.HardBlock.Load()
	if rcodeOf(askAs(p, "192.168.1.60", "m2.example.net", 2)) != 2 || p.Stats.HardBlock.Load() != hb {
		t.Error("an ordinary device is refused as well, without counting as a private-path block")
	}
	doh.fail.Store(false)
	if addrOf(askAs(p, "192.168.1.40", "m4.example.net", 4)) != "93.184.216.34" {
		t.Error("a Mullvad device resolves again once encrypted DNS is back")
	}
}

// Through the tunnel: Mullvad's encrypted resolver only. If it fails the lookup is refused: no plain DNS, no direct DoH from the cellular link.
func TestMullvadTunnelDNSFailsClosed(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxyURLs(t, []string{doh.URL}, pool)
	p.VPN = mullvadClientVPN(t, "192.168.1.40", true)
	p.VPN.upFn = func() bool { return true }
	oldR := ownR
	defer func() { ownR = oldR }()
	tun := ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true}
	ownR, _, _ = testRouter(&tun)
	var fail bool
	p.VPN.dohHook = func(q []byte) ([]byte, error) {
		if fail {
			return nil, errors.New("tunnel DoH down")
		}
		return answerFor(q, 60, false), nil
	}
	if addrOf(askAs(p, "192.168.1.40", "t1.example.net", 1)) != "93.184.216.34" || p.Stats.VPN.Load() != 1 {
		t.Fatal("the tunnel's resolver answers a Mullvad device")
	}
	fail = true
	r := askAs(p, "192.168.1.40", "t2.example.net", 2)
	if rcodeOf(r) != 2 || doh.hits.Load() != 0 {
		t.Fatalf("a failing tunnel resolver means a refused lookup, nothing else (no direct DoH either): rcode=%d doh=%d", rcodeOf(r), doh.hits.Load())
	}
	if p.Stats.HardBlock.Load() == 0 {
		t.Error("counted as a hard block")
	}
}

// The list rules reach Tor devices' answers too: a tracker behind a harmless name (CNAME cloaking) is refused over Tor as it is anywhere else.
func TestTorDeviceAnswersGetTheListRules(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxyURLs(t, []string{doh.URL}, pool)
	m, _, _, _ := testTor(t)
	m.cfg.Devices = []string{torMAC}
	m.cmd = exec.Command("sleep", "30")
	m.cmd.Start()
	defer m.cmd.Process.Kill()
	m.boot = 100
	cloaked := true
	m.resolve = func(q []byte) ([]byte, error) {
		dq, _ := parseQuery(q)
		r := append(respHeader(dq, 0, 1), q[12:dq.QEnd]...)
		if cloaked {
			target := []byte{7, 'b', 'l', 'o', 'c', 'k', 'e', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
			rec := []byte{0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, byte(len(target))}
			return append(append(r, rec...), target...), nil
		}
		return append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34), nil
	}
	p.Tor = m

	askAs(p, "192.168.1.50", "innocent.example.net", 1)
	if p.Stats.Blocked.Load() != 1 || p.Stats.Tor.Load() != 1 {
		t.Errorf("the cloaked answer must be blocked after Tor answered: blocked=%d tor=%d", p.Stats.Blocked.Load(), p.Stats.Tor.Load())
	}
	cloaked = false
	if addrOf(askAs(p, "192.168.1.50", "fine.example.net", 2)) != "93.184.216.34" {
		t.Error("an ordinary answer passes")
	}
	// Tor down: refused, counted, and nothing in the clear
	m.boot = -1
	if rcodeOf(askAs(p, "192.168.1.50", "down.example.net", 3)) != 2 || p.Stats.HardBlock.Load() == 0 || doh.hits.Load() != 0 {
		t.Error("Tor down is a hard block, with no other resolver asked")
	}
}

func TestHardBlockWarnsOncePerWindow(t *testing.T) {
	p := &DNSProxy{Stats: NewDNSStats()}
	for i := 0; i < 5; i++ {
		p.hardBlock("tor", "192.168.1.50", errors.New("x"))
	}
	p.hardBlock("mullvad", "192.168.1.40", errors.New("y"))
	if p.Stats.HardBlock.Load() != 6 {
		t.Errorf("every refusal is counted: %d", p.Stats.HardBlock.Load())
	}
	if len(p.warnAt) != 2 || time.Since(p.warnAt["tor"]) > time.Minute {
		t.Errorf("one warning window per path: %v", p.warnAt)
	}
}

// A Mullvad device's lookups climb the same ladder as the house's: Tor through Mullvad first, then Mullvad's own resolver through the tunnel (or Tor), then direct, and never below the tier.
func TestMullvadDeviceDNSFollowsTheLadder(t *testing.T) {
	old := ownR
	defer func() { ownR = old }()
	doh, pool := newFakeDoH(t)
	var st ownState
	ownR, _, _ = testRouter(&st)
	p := testProxyURLs(t, []string{doh.URL}, pool)
	p.Up.client.Transport.(*http.Transport).DialContext = ownDial // the real tier-aware dialler (a raw dial goes to the local test server)
	p.Up.cfg.RouteGen = ownRouteGen                               // as in main.go: a change of route closes pooled connections
	up := false
	p.VPN = mullvadClientVPN(t, "192.168.1.40", true)
	p.VPN.upFn = func() bool { return up }
	tunnelHits := 0
	p.VPN.dohHook = func(q []byte) ([]byte, error) { tunnelHits++; return answerFor(q, 60, false), nil }
	n := uint16(0)
	lookup := func() []byte { n++; return askAs(p, "192.168.1.40", fmt.Sprintf("tier%d.example.net", n), n) }
	set := func(s ownState) { st = s; up = s.TunnelUp }

	// rung 2: tunnel up, Tor not over Mullvad: Mullvad's resolver through the tunnel
	set(ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true})
	if addrOf(lookup()) != "93.184.216.34" || tunnelHits != 1 || doh.hits.Load() != 0 {
		t.Errorf("rung 2: tunnel hits %d, house DoH hits %d", tunnelHits, doh.hits.Load())
	}
	// rung 1 up as well: Tor through Mullvad goes first, so Mullvad's resolver is not asked (the lookup takes the house path, whose route is Tor; there is no Tor here, so it is refused
	// and nothing else answers it)
	set(ownState{Tier: tierPrivate, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true, TorOverVPN: true})
	th := tunnelHits
	lookup()
	if tunnelHits != th {
		t.Error("with Tor through Mullvad up the tunnel's own resolver must not be used")
	}
	// middle tier, nothing up: refused and counted, nothing goes out any other way
	set(ownState{Tier: tierPrivate, MullvadWanted: true, TorEnabled: true})
	hb, h0 := p.Stats.HardBlock.Load(), doh.hits.Load()
	if rcodeOf(lookup()) != 2 || doh.hits.Load() != h0 || tunnelHits != th || p.Stats.HardBlock.Load() != hb+1 {
		t.Errorf("middle, nothing up: must be refused and counted")
	}
	// direct tier, tunnel down: never blocked, the last rung (here the plain dial to the test server)
	set(ownState{Tier: tierDirect, MullvadWanted: true})
	if addrOf(lookup()) != "93.184.216.34" || doh.hits.Load() != h0+1 {
		t.Errorf("direct tier must still answer: doh hits %d", doh.hits.Load())
	}
	// top tier, tunnel up, Tor not ready: refused, and Mullvad's resolver is not a way round it
	set(ownState{Tier: tierTorMullvad, MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorOverVPN: true})
	h1, t1 := doh.hits.Load(), tunnelHits
	if rcodeOf(lookup()) != 2 || doh.hits.Load() != h1 || tunnelHits != t1 {
		t.Error("top tier without Tor through Mullvad must refuse, not use the tunnel's resolver")
	}
}
