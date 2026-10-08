package main

import (
	"encoding/binary"
	"errors"
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
