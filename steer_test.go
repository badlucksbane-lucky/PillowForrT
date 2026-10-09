package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// ipv6Frame builds an Ethernet+IPv6 frame carrying one upper-layer payload.
func ipv6Frame(srcMAC []byte, next byte, src, dst string, payload []byte) []byte {
	f := make([]byte, 14+40)
	copy(f[0:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:14], 0x86dd)
	f[14] = 0x60
	binary.BigEndian.PutUint16(f[18:20], uint16(len(payload)))
	f[20], f[21] = next, 255
	copy(f[22:38], net.ParseIP(src).To16())
	copy(f[38:54], net.ParseIP(dst).To16())
	return append(f, payload...)
}

// ra builds an ICMPv6 router advertisement body with the given lifetime, flags and options.
func ra(lifetime uint16, flags byte, opts ...[]byte) []byte {
	b := make([]byte, 16)
	b[0], b[5] = 134, flags
	binary.BigEndian.PutUint16(b[6:8], lifetime)
	for _, o := range opts {
		b = append(b, o...)
	}
	return b
}

func raPrefix(prefix string, plen byte) []byte {
	o := make([]byte, 32)
	o[0], o[1], o[2] = 3, 4, plen
	copy(o[16:32], net.ParseIP(prefix).To16())
	return o
}

func raRDNSS(addrs ...string) []byte {
	o := make([]byte, 8+16*len(addrs))
	o[0], o[1] = 25, byte(len(o)/8)
	for i, a := range addrs {
		copy(o[8+16*i:], net.ParseIP(a).To16())
	}
	return o
}

func raDNSSL() []byte {
	return []byte{31, 2, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 0, 0, 0, 0, 0, 0}
}

func redirect6(target, dest string) []byte {
	b := make([]byte, 40)
	b[0] = 137
	copy(b[8:24], net.ParseIP(target).To16())
	copy(b[24:40], net.ParseIP(dest).To16())
	return b
}

func redirect4(gateway [4]byte, origDst [4]byte) []byte {
	b := make([]byte, 8+20)
	b[0] = 5
	copy(b[4:8], gateway[:])
	b[8] = 0x45
	copy(b[8+16:8+20], origDst[:])
	return b
}

var (
	steerMAC = []byte{0x02, 0, 0, 0, 0, 0x99}
	steerLL  = "fe80::1"
	allNodes = "ff02::1"
)

func TestSteerBPFAcceptsOnlySteeringMessages(t *testing.T) {
	prog := steerBPF()
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"router advertisement", ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(1800, 0)), true},
		{"icmpv6 redirect", ipv6Frame(steerMAC, 58, steerLL, "fe80::2", redirect6("fe80::1", "2001:db8::5")), true},
		{"icmpv4 redirect", ipv4Frame(steerMAC, 1, 64, [4]byte{192, 168, 1, 7}, lanDev, redirect4([4]byte{192, 168, 1, 7}, [4]byte{8, 8, 8, 8})), true},
		{"router solicitation", ipv6Frame(steerMAC, 58, steerLL, "ff02::2", []byte{133, 0, 0, 0, 0, 0, 0, 0}), false},
		{"neighbor advertisement", ipv6Frame(steerMAC, 58, steerLL, allNodes, append([]byte{136, 0, 0, 0}, make([]byte, 20)...)), false},
		{"icmpv6 echo", ipv6Frame(steerMAC, 58, steerLL, "fe80::2", []byte{128, 0, 0, 0, 0, 0, 0, 0}), false},
		{"ipv6 udp", ipv6Frame(steerMAC, 17, steerLL, "fe80::2", udpHdr(5353, 5353)), false},
		{"ra behind a hop-by-hop header is not inspected", ipv6Frame(steerMAC, 0, steerLL, allNodes, append([]byte{58, 0, 1, 4, 0, 0, 0, 0}, ra(1800, 0)...)), false},
		{"icmpv4 echo", ipv4Frame(steerMAC, 1, 64, lanDev, [4]byte{192, 168, 1, 1}, []byte{8, 0, 0, 0, 0, 0, 0, 0}), false},
		{"icmpv4 unreachable", ipv4Frame(steerMAC, 1, 64, lanDev, [4]byte{192, 168, 1, 1}, []byte{3, 1, 0, 0, 0, 0, 0, 0}), false},
		{"tcp", ipv4Frame(steerMAC, 6, 64, lanDev, [4]byte{192, 168, 1, 1}, tcpHdr(40000, 443, 0x02)), false},
		{"arp", arpFrame(1, otherMAC, "192.168.1.5", "192.168.1.1"), false},
	}
	for _, c := range cases {
		if got := runBPF(prog, c.frame) != 0; got != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, got, c.want)
		}
	}
}

func TestParseSteerRouterAdvertisement(t *testing.T) {
	m, ok := parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(1800, 0x80, raPrefix("2001:db8:1::", 64), raRDNSS("fd00::53", "fd00::54"), raDNSSL())))
	if !ok || m.Kind != "ra" || m.MAC != "02:00:00:00:00:99" || m.IP != "fe80::1" || m.Lifetime != 1800 || !m.Managed {
		t.Fatalf("%+v %v", m, ok)
	}
	if len(m.Prefixes) != 1 || m.Prefixes[0] != "2001:db8:1::/64" || len(m.DNS) != 2 || m.DNS[0] != "fd00::53" || m.DNS[1] != "fd00::54" || !m.Search {
		t.Errorf("options: %+v", m)
	}
	// a bare withdrawal: lifetime 0, no options
	m, ok = parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(0, 0)))
	if !ok || m.Kind != "ra" || m.Lifetime != 0 || m.Managed || len(m.Prefixes) != 0 || len(m.DNS) != 0 || m.Search {
		t.Errorf("%+v %v", m, ok)
	}
	// a broken option length ends the walk without a panic
	bad := raPrefix("2001:db8::", 64)
	bad[1] = 0
	if m, ok = parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(600, 0, bad, raRDNSS("fd00::1")))); !ok || len(m.Prefixes) != 0 || len(m.DNS) != 0 {
		t.Errorf("a zero-length option must end the walk: %+v", m)
	}
	if _, ok = parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(600, 0))[:60]); ok {
		t.Error("truncated")
	}
	if _, ok = parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, []byte{133, 0, 0, 0, 0, 0, 0, 0})); ok {
		t.Error("a solicitation is not a steering message")
	}
}

func TestParseSteerRedirects(t *testing.T) {
	m, ok := parseSteer(ipv6Frame(steerMAC, 58, steerLL, "fe80::2", redirect6("fe80::1", "2001:db8::5")))
	if !ok || m.Kind != "redirect6" || m.IP != "fe80::1" || m.Victim != "fe80::2" || m.Via != "fe80::1" || m.Dest != "2001:db8::5" {
		t.Errorf("%+v %v", m, ok)
	}
	m, ok = parseSteer(ipv4Frame(steerMAC, 1, 64, [4]byte{192, 168, 1, 7}, lanDev, redirect4([4]byte{192, 168, 1, 7}, [4]byte{8, 8, 8, 8})))
	if !ok || m.Kind != "redirect4" || m.IP != "192.168.1.7" || m.Victim != "192.168.1.20" || m.Via != "192.168.1.7" || m.Dest != "8.8.8.8" {
		t.Errorf("%+v %v", m, ok)
	}
	// a redirect with no original datagram attached still parses, without a destination
	m, ok = parseSteer(ipv4Frame(steerMAC, 1, 64, [4]byte{192, 168, 1, 7}, lanDev, redirect4([4]byte{192, 168, 1, 7}, [4]byte{8, 8, 8, 8})[:8]))
	if !ok || m.Kind != "redirect4" || m.Dest != "" {
		t.Errorf("%+v %v", m, ok)
	}
	if _, ok = parseSteer(ipv4Frame(steerMAC, 1, 64, [4]byte{192, 168, 1, 7}, lanDev, []byte{8, 0, 0, 0, 0, 0, 0, 0})); ok {
		t.Error("an echo is not a steering message")
	}
	if _, ok = parseSteer(make([]byte, 20)); ok {
		t.Error("short frame parsed")
	}
}

func testSteer() (*steerWatch, *[]evt, *time.Time) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	var got []evt
	w := newSteerWatch("")
	w.now = func() time.Time { return now }
	w.selfMAC = func() string { return bridgeMAC.String() }
	w.nameOf = func(mac string) string {
		if mac == "02:00:00:00:00:99" {
			return "travel-router"
		}
		return ""
	}
	w.emit = func(e evt) { got = append(got, e) }
	return w, &got, &now
}

func TestSteerRogueAdvertisement(t *testing.T) {
	w, got, now := testSteer()
	// the box's own advertisements (radish, the withdraw) are honest
	own, _ := parseSteer(ipv6Frame(bridgeMAC, 58, "fe80::aa", allNodes, ra(0, 0)))
	w.Observe(own, *now)
	w.Observe(own, *now)
	if len(*got) != 0 || w.View().Honest != 2 || w.View().Alerts != 0 {
		t.Fatalf("%v %+v", *got, w.View())
	}
	m, _ := parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(1800, 0, raPrefix("2001:db8:1::", 64), raRDNSS("fd00::53"))))
	w.Observe(m, *now)
	if len(*got) != 1 || (*got)[0].Kind != "ra_rogue" || (*got)[0].Sev != sevAlert {
		t.Fatalf("%v", *got)
	}
	txt := (*got)[0].Text
	for _, want := range []string{"travel-router (02:00:00:00:00:99)", "default router for 1800 s", "prefix 2001:db8:1::/64", "DNS servers fd00::53", "encrypted DNS stub", "whether or not LAN IPv6 is on"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q: %s", want, txt)
		}
	}
	if p := (*got)[0].Public; p != "A device on the network is announcing itself as a router" {
		t.Errorf("public text: %q", p)
	}
	w.Observe(m, now.Add(time.Minute))
	if len(*got) != 1 {
		t.Error("one event per source per kind per 10 minutes")
	}
	w.Observe(m, now.Add(11*time.Minute))
	if len(*got) != 2 {
		t.Error("it speaks again after the cool-down")
	}
	// a withdrawal from a stranger is still a stranger steering
	wd, _ := parseSteer(ipv6Frame([]byte{0x02, 0, 0, 0, 0, 0x77}, 58, "fe80::77", allNodes, ra(0, 0)))
	w.Observe(wd, now.Add(11*time.Minute))
	if len(*got) != 3 || !strings.Contains((*got)[2].Text, "router lifetime 0, a withdrawal") || strings.Contains((*got)[2].Text, "encrypted DNS stub") {
		t.Errorf("%v", (*got)[2:])
	}
	v := w.View()
	if v.Alerts != 4 || v.Sources != 2 || len(v.Messages) != 4 || v.Messages[0].MAC != "02:00:00:00:00:77" || v.Messages[1].Name != "travel-router" {
		t.Errorf("%+v", v)
	}
	*now = now.Add(25 * time.Hour)
	if v := w.View(); v.Alerts != 0 || v.Sources != 0 || len(v.Messages) != 4 {
		t.Errorf("old messages stay listed but leave the day's count: %+v", v)
	}
}

func TestSteerRogueRedirects(t *testing.T) {
	w, got, now := testSteer()
	m6, _ := parseSteer(ipv6Frame(steerMAC, 58, steerLL, "fe80::2", redirect6("fe80::1", "2001:db8::5")))
	m4, _ := parseSteer(ipv4Frame(steerMAC, 1, 64, [4]byte{192, 168, 1, 7}, lanDev, redirect4([4]byte{192, 168, 1, 7}, [4]byte{8, 8, 8, 8})))
	w.Observe(m6, *now)
	w.Observe(m4, *now)
	if len(*got) != 2 || (*got)[0].Kind != "redirect_rogue" || (*got)[1].Kind != "redirect_rogue" || (*got)[0].Sev != sevAlert {
		t.Fatalf("each family is its own finding: %v", *got)
	}
	if !strings.Contains((*got)[0].Text, "ICMPv6 redirect telling fe80::2 to use fe80::1 as its router for traffic to 2001:db8::5") {
		t.Errorf("text: %s", (*got)[0].Text)
	}
	if !strings.Contains((*got)[1].Text, "an ICMP redirect telling 192.168.1.20 to use 192.168.1.7 as its router for traffic to 8.8.8.8") {
		t.Errorf("text: %s", (*got)[1].Text)
	}
	if p := (*got)[1].Public; strings.Contains(p, "192.168") || strings.Contains(p, "02:00") {
		t.Errorf("public text must be generic: %q", p)
	}
	// the box's own redirects are honest
	own, _ := parseSteer(ipv4Frame(bridgeMAC, 1, 64, [4]byte{192, 168, 1, 1}, lanDev, redirect4([4]byte{192, 168, 1, 2}, [4]byte{192, 168, 1, 2})))
	w.Observe(own, *now)
	if len(*got) != 2 || w.View().Honest != 1 {
		t.Errorf("%v", *got)
	}
}

func TestSteerAllowedRouter(t *testing.T) {
	w, got, now := testSteer()
	m, _ := parseSteer(ipv6Frame(steerMAC, 58, steerLL, allNodes, ra(1800, 0)))
	w.Observe(m, *now)
	if len(*got) != 1 || len(w.View().Messages) != 1 {
		t.Fatalf("%v", *got)
	}
	if err := w.Allow("02:00:00:00:00:99", true); err != nil {
		t.Fatal(err)
	}
	if v := w.View(); len(v.Messages) != 0 || v.Alerts != 0 || len(v.Allowed) != 1 || v.Allowed[0].MAC != "02:00:00:00:00:99" || v.Allowed[0].Seen != 0 {
		t.Errorf("allowing forgets its messages: %+v", v)
	}
	w.Observe(m, now.Add(11*time.Minute))
	w.Observe(m, now.Add(12*time.Minute))
	if len(*got) != 1 {
		t.Error("an allowed router raises nothing")
	}
	if v := w.View(); v.Allowed[0].Seen != 2 || v.Allowed[0].Last != now.Add(12*time.Minute).Unix() {
		t.Errorf("but is counted: %+v", v.Allowed)
	}
	if err := w.Allow(bridgeMAC.String(), true); err == nil {
		t.Error("the box's own MAC cannot be on the list")
	}
	if err := w.Allow("not-a-mac", true); err == nil {
		t.Error("a malformed MAC is refused")
	}
	for i := 0; i < 7; i++ {
		if err := w.Allow(net.HardwareAddr{0x02, 0, 0, 0, 1, byte(i)}.String(), true); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Allow("02:00:00:00:02:00", true); err == nil {
		t.Error("eight is the limit")
	}
	if err := w.Allow("02:00:00:00:00:99", false); err != nil {
		t.Fatal(err)
	}
	w.Observe(m, now.Add(30*time.Minute))
	if len(*got) != 2 || len(w.View().Allowed) != 7 {
		t.Errorf("once no longer allowed it is a stranger again: %v %+v", *got, w.View().Allowed)
	}
}
