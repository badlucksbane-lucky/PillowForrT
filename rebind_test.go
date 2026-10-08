package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

// buildAAAAResponse is buildAResponse's IPv6 twin: one AAAA answer compressed to the question.
func buildAAAAResponse(name string, ip net.IP) []byte {
	var q []byte
	for _, l := range splitLabels(name) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 28, 0, 1)
	m := append([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, q...)
	m = append(m, 0xC0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	return append(m, ip.To16()...)
}

func TestPrivateAnswer(t *testing.T) {
	for _, p := range []string{"192.168.1.1", "10.0.0.5", "172.16.3.3", "127.0.0.1", "169.254.1.1", "0.0.0.0", "100.64.0.9", "100.127.255.1", "198.18.0.5", "198.19.1.1", "::1", "fd12::1", "fe80::1", "::", "::ffff:192.168.1.1"} {
		if !privateAnswer(net.ParseIP(p)) {
			t.Errorf("%s should be private", p)
		}
	}
	for _, p := range []string{"93.184.216.34", "1.1.1.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "2606:4700::1111", "8.8.8.8"} {
		if privateAnswer(net.ParseIP(p)) {
			t.Errorf("%s should be public", p)
		}
	}
	if privateAnswer(nil) {
		t.Error("nil")
	}
}

func TestAnswerIPsReadsAAndAAAA(t *testing.T) {
	if got := answerIPs(buildAResponse("x.example", net.ParseIP("10.1.2.3"))); len(got) != 1 || got[0].String() != "10.1.2.3" {
		t.Errorf("%v", got)
	}
	if got := answerIPs(buildAAAAResponse("x.example", net.ParseIP("fd00::1"))); len(got) != 1 || got[0].String() != "fd00::1" {
		t.Errorf("%v", got)
	}
	answerIPs(nil)
	answerIPs([]byte{1, 2, 3})
	answerIPs(buildAResponse("x.example", net.ParseIP("10.1.2.3"))[:25])
}

func TestMatchWild(t *testing.T) {
	for _, c := range []struct {
		p, n string
		want bool
	}{
		{"example.com", "example.com", true}, {"example.com", "a.example.com", true}, {"example.com", "notexample.com", false},
		{"*.example.com", "a.example.com", true}, {"*.example.com", "a.b.example.com", true}, {"*.example.com", "example.com", false},
		{"ads*.example.com", "ads1.example.com", true}, {"ads*.example.com", "bads.example.com", false},
		{"*track*", "a.tracker.net", true}, {"*track*", "a.trick.net", false},
		{"*.plex.direct", "1-2-3-4.abc123.plex.direct", true}, {"", "x", false},
	} {
		if got := matchWild(c.p, c.n); got != c.want {
			t.Errorf("%q vs %q: %v", c.p, c.n, got)
		}
	}
}

func TestRebindGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rebind.json")
	g := newRebindGuard(path)
	pub := buildAResponse("site.example", net.ParseIP("93.184.216.34"))
	priv := buildAResponse("evil.example", net.ParseIP("192.168.1.1"))
	plex := buildAResponse("1-2-3-4.abc.plex.direct", net.ParseIP("192.168.1.50"))

	if _, r := g.Refuse("site.example", pub); r {
		t.Error("a public answer refused")
	}
	if hit, r := g.Refuse("evil.example", priv); !r || hit.String() != "192.168.1.1" {
		t.Errorf("a private answer let through: %v %v", hit, r)
	}
	if _, r := g.Refuse("1-2-3-4.abc.plex.direct", plex); r {
		t.Error("the default Plex allowance missing")
	}
	if _, r := g.Refuse("evil.example", buildAAAAResponse("evil.example", net.ParseIP("fd00::1"))); !r {
		t.Error("a ULA answer let through")
	}
	if v := g.View(); !v.Enabled || v.Refused != 2 || len(v.Allow) != 1 {
		t.Errorf("%+v", v)
	}

	// the allow-list
	if err := g.Allow("*", true); err == nil {
		t.Error("a bare * accepted")
	}
	if err := g.Allow("bad name!", true); err == nil {
		t.Error("junk accepted")
	}
	if err := g.Allow("*.corp.example", true); err != nil {
		t.Fatal(err)
	}
	if _, r := g.Refuse("vpn.corp.example", buildAResponse("vpn.corp.example", net.ParseIP("10.9.9.9"))); r {
		t.Error("an allowed name refused")
	}
	g2 := newRebindGuard(path)
	if v := g2.View(); len(v.Allow) != 2 || v.Allow[1] != "*.corp.example" {
		t.Errorf("the allow-list did not persist: %+v", v)
	}
	g2.Allow("*.corp.example", false)
	if _, r := g2.Refuse("vpn.corp.example", buildAResponse("vpn.corp.example", net.ParseIP("10.9.9.9"))); !r {
		t.Error("a removed allowance still applied")
	}

	// switched off: nothing is refused
	g2.SetEnabled(false)
	if _, r := g2.Refuse("evil.example", priv); r {
		t.Error("refused while off")
	}
	if newRebindGuard(path).View().Enabled {
		t.Error("the switch did not persist")
	}
	// a nil guard (the stub without the filter) is a no-op
	var none *rebindGuard
	if _, r := none.Refuse("evil.example", priv); r {
		t.Error("nil guard refused")
	}
	if none.View().Allow == nil {
		t.Error("nil view must still carry an array")
	}
}

// The stub refuses a rebinding answer on the way out: a cached private answer for a public name comes back REFUSED, and the detector still saw it.
func TestStubRefusesRebindingAnswer(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)
	old, oldM := rebindMgr, dnsMITMMgr
	defer func() { rebindMgr, dnsMITMMgr = old, oldM }()
	rebindMgr = newRebindGuard("")
	var seen []evt
	dnsMITMMgr = newDNSMITMWatch()
	dnsMITMMgr.emit = func(e evt) { seen = append(seen, e) }
	dnsMITMMgr.macOf = func(string) string { return "" }
	dnsMITMMgr.recentARP = func(time.Time) bool { return false }

	q := queryWithOpt("evil.example", opt(8, 0, 1, 32, 0, 192, 168, 1, 40)) // from 192.168.1.40, as dnsmasq tags it
	dq, _ := parseQuery(q)
	p.Cache.put(cacheKey(dq), buildAResponse("evil.example", net.ParseIP("192.168.1.1")), time.Now())
	r := p.Handle(q)
	if rcodeOf(r) != 5 || len(answerIPs(r)) != 0 {
		t.Fatalf("rcode %d, answers %v", rcodeOf(r), answerIPs(r))
	}
	if r[0] != 0 || r[1] != 7 {
		t.Error("the query id was not kept")
	}
	if len(seen) != 1 || seen[0].Kind != "dns_mitm_suspect" {
		t.Errorf("the ARP / DNS correlation did not see it: %v", seen)
	}
	if rebindMgr.View().Refused != 1 {
		t.Error("not counted")
	}
	// an honest answer from upstream is untouched
	if r := ask(p, "example.org", 1); rcodeOf(r) != 0 || addrOf(r) != "93.184.216.34" {
		t.Errorf("public answer changed: %d %s", rcodeOf(r), addrOf(r))
	}
}
