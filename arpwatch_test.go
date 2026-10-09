package main

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func arpFrame(op uint16, senderMAC net.HardwareAddr, senderIP string, targetIP string) []byte {
	b := make([]byte, 42)
	binary.BigEndian.PutUint16(b[12:], 0x0806)
	binary.BigEndian.PutUint16(b[14:], 1)
	binary.BigEndian.PutUint16(b[16:], 0x0800)
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:], op)
	copy(b[22:28], senderMAC)
	copy(b[28:32], net.ParseIP(senderIP).To4())
	copy(b[38:42], net.ParseIP(targetIP).To4())
	return b
}

func TestARPKernelFilter(t *testing.T) {
	p := arpBPF()
	// reuse the tiny interpreter: only ldh, jeq and ret are used
	if runRogueBPF(p, arpFrame(1, otherMAC, "192.168.1.5", "192.168.1.1")) == 0 {
		t.Error("ARP must pass")
	}
	if runRogueBPF(p, dhcpFrame("192.168.1.1", bridgeMAC, 2, "192.168.1.150", 20, 67)) != 0 {
		t.Error("IPv4 must not pass")
	}
}

func TestParseARPClaim(t *testing.T) {
	c, ok := parseARPClaim(arpFrame(2, otherMAC, "192.168.1.5", "192.168.1.1"))
	if !ok || c.IP != "192.168.1.5" || c.MAC != otherMAC.String() {
		t.Errorf("%+v %v", c, ok)
	}
	if _, ok := parseARPClaim(arpFrame(1, otherMAC, "0.0.0.0", "192.168.1.5")); ok {
		t.Error("an address probe (sender 0.0.0.0) claims nothing")
	}
	if _, ok := parseARPClaim(arpFrame(3, otherMAC, "192.168.1.5", "192.168.1.1")); ok {
		t.Error("only request and reply")
	}
	if _, ok := parseARPClaim(arpFrame(1, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "192.168.1.5", "192.168.1.1")); ok {
		t.Error("a broadcast sender MAC is malformed")
	}
	f := arpFrame(1, otherMAC, "192.168.1.5", "192.168.1.1")
	f[18] = 8
	if _, ok := parseARPClaim(f); ok {
		t.Error("not 6-byte hardware addresses")
	}
	if _, ok := parseARPClaim(f[:30]); ok {
		t.Error("truncated")
	}
}

func testARP() (*arpWatch, *[]evt, *time.Time) {
	now := time.Unix(1_800_000_000, 0)
	var got []evt
	w := newARPWatch()
	w.now = func() time.Time { return now }
	w.own = func() map[string]bool {
		return map[string]bool{"192.168.1.1": true, "192.168.1.254": true, "192.168.1.253": true}
	}
	w.selfMAC = func() string { return bridgeMAC.String() }
	w.reserved = func() map[string]reservation {
		return map[string]reservation{"192.168.1.2": {MAC: "00:00:5e:00:53:03", IP: "192.168.1.2", Name: "pi"}}
	}
	w.nameOf = func(m string) string {
		if m == "00:00:5e:00:53:03" {
			return "pi"
		}
		return ""
	}
	w.emit = func(e evt) { got = append(got, e) }
	return w, &got, &now
}

func TestARPHonestClaimsRaiseNothing(t *testing.T) {
	w, got, _ := testARP()
	w.observe(arpClaim{"192.168.1.1", bridgeMAC.String()})   // the router itself
	w.observe(arpClaim{"192.168.1.254", bridgeMAC.String()}) // its other address
	w.observe(arpClaim{"192.168.1.2", "00:00:5e:00:53:03"})  // the reserved owner
	w.observe(arpClaim{"192.168.1.150", otherMAC.String()})  // a pool device, first sight
	w.observe(arpClaim{"192.168.1.150", otherMAC.String()})  // again
	if len(*got) != 0 || len(w.View().Findings) != 0 || w.View().Claims != 5 {
		t.Fatalf("%v %+v", *got, w.View())
	}
}

func TestARPGatewayImpersonation(t *testing.T) {
	w, got, now := testARP()
	w.observe(arpClaim{"192.168.1.1", otherMAC.String()})
	if len(*got) != 1 || (*got)[0].Kind != "arp_gateway" || (*got)[0].Sev != sevAlert {
		t.Fatalf("%v", *got)
	}
	if p := (*got)[0].Public; strings.Contains(p, "192.168") || strings.Contains(p, "02:00") {
		t.Errorf("public text must be generic: %q", p)
	}
	w.observe(arpClaim{"192.168.1.1", otherMAC.String()})
	if len(*got) != 1 {
		t.Error("one event per address per 10 minutes")
	}
	*now = now.Add(11 * time.Minute)
	w.observe(arpClaim{"192.168.1.1", otherMAC.String()})
	if len(*got) != 2 {
		t.Error("it speaks again after the cool-down")
	}
	w.observe(arpClaim{"192.168.1.253", otherMAC.String()}) // the canary address is ours too
	if len(*got) != 3 {
		t.Error("the canary address is one of ours")
	}
	if v := w.View(); v.Alerts != 3 {
		t.Errorf("alerts %d", v.Alerts)
	}
}

func TestARPReservedAddressConflict(t *testing.T) {
	w, got, _ := testARP()
	w.observe(arpClaim{"192.168.1.2", otherMAC.String()})
	if len(*got) != 1 || (*got)[0].Kind != "arp_conflict" || !strings.Contains((*got)[0].Text, "pi") {
		t.Fatalf("%v", *got)
	}
}

func TestARPFlip(t *testing.T) {
	w, got, now := testARP()
	a, b := "aa:00:00:00:00:01", "bb:00:00:00:00:02"
	w.observe(arpClaim{"192.168.1.150", a})
	*now = now.Add(2 * time.Minute)
	w.observe(arpClaim{"192.168.1.150", b})
	if len(*got) != 1 || (*got)[0].Kind != "arp_flip" || (*got)[0].Sev != sevAttention {
		t.Fatalf("a quick change of owner is one to look at: %v", *got)
	}
	if v := w.View(); v.Alerts != 0 || len(v.Findings) != 1 {
		t.Errorf("a flip is not an alert: %+v", v)
	}
	// a slow change (DHCP reuse after a device left) is normal
	w2, got2, now2 := testARP()
	w2.observe(arpClaim{"192.168.1.151", a})
	*now2 = now2.Add(2 * time.Hour)
	w2.observe(arpClaim{"192.168.1.151", b})
	if len(*got2) != 0 {
		t.Errorf("an address that changed hands after hours is normal: %v", *got2)
	}
}

func TestARPFindingsAgeOutAndBindingsAreBounded(t *testing.T) {
	w, _, now := testARP()
	w.observe(arpClaim{"192.168.1.1", otherMAC.String()})
	*now = now.Add(25 * time.Hour)
	if v := w.View(); len(v.Findings) != 0 || v.Alerts != 0 {
		t.Errorf("findings older than a day leave the view: %+v", v)
	}
	for i := 0; i < 3000; i++ {
		*now = now.Add(2 * time.Second)
		w.observe(arpClaim{net.IPv4(10, 0, byte(i>>8), byte(i)).String(), "cc:00:00:00:00:03"})
	}
	if n := len(w.bind); n > 2100 {
		t.Errorf("bindings must stay bounded: %d", n)
	}
	for i := 0; i < 5000; i++ { // a flood inside one minute
		w.observe(arpClaim{net.IPv4(11, 0, byte(i>>8), byte(i)).String(), "dd:00:00:00:00:04"})
	}
	if n := len(w.bind); n > 2100 {
		t.Errorf("a fast flood must stay bounded too: %d", n)
	}
}

func TestParseARPRequest(t *testing.T) {
	mac, sender, target, ok := parseARPRequest(arpFrame(1, otherMAC, "192.168.1.5", "192.168.1.77"))
	if !ok || mac != otherMAC.String() || sender != "192.168.1.5" || target != "192.168.1.77" {
		t.Errorf("%s %s %s %v", mac, sender, target, ok)
	}
	if _, sender, target, ok := parseARPRequest(arpFrame(1, otherMAC, "0.0.0.0", "192.168.1.77")); !ok || sender != "" || target != "192.168.1.77" {
		t.Error("a probe from a device with no address yet still asks, and its sender is blank")
	}
	if _, _, _, ok := parseARPRequest(arpFrame(2, otherMAC, "192.168.1.5", "192.168.1.77")); ok {
		t.Error("a reply asks for nothing")
	}
	if _, _, _, ok := parseARPRequest(arpFrame(1, otherMAC, "192.168.1.5", "0.0.0.0")); ok {
		t.Error("a request for 0.0.0.0 is malformed")
	}
	if _, _, _, ok := parseARPRequest(arpFrame(1, otherMAC, "192.168.1.5", "192.168.1.77")[:40]); ok {
		t.Error("truncated")
	}
}

func TestARPSweep(t *testing.T) {
	w, got, now := testARP()
	ask := func(mac string, from, to int) {
		for i := from; i < to; i++ {
			w.observeRequest(mac, "192.168.1.5", net.IPv4(192, 168, 1, byte(i)).String())
		}
	}
	// an honest device resolves a handful of peers over the day
	ask(otherMAC.String(), 10, 15)
	if len(*got) != 0 {
		t.Fatalf("five asks are not a scan: %v", *got)
	}
	// the same address asked for again and again is one address, not twenty
	for i := 0; i < 40; i++ {
		w.observeRequest(otherMAC.String(), "192.168.1.5", "192.168.1.1")
	}
	if len(*got) != 0 {
		t.Fatalf("repeats of one address are not a scan: %v", *got)
	}
	// a sweep: 20 different addresses inside a minute
	ask(otherMAC.String(), 20, 40)
	if len(*got) != 1 || (*got)[0].Kind != "arp_sweep" || (*got)[0].Sev != sevAttention {
		t.Fatalf("%v", *got)
	}
	if p := (*got)[0].Public; strings.Contains(p, "192.168") || strings.Contains(p, "02:00") {
		t.Errorf("public text must be generic: %q", p)
	}
	if !strings.Contains((*got)[0].Text, "different addresses within a minute") || !strings.Contains((*got)[0].Text, otherMAC.String()) {
		t.Errorf("text: %s", (*got)[0].Text)
	}
	v := w.View()
	if v.Sweeps != 1 || v.Alerts != 0 || len(v.Findings) != 1 || v.Findings[0].MAC != otherMAC.String() || v.Findings[0].IP != "192.168.1.5" || v.Findings[0].Count < 20 {
		t.Errorf("a sweep is to look at, not an alert: %+v", v)
	}
	// the scan going on is not a new event every address
	ask(otherMAC.String(), 40, 200)
	if len(*got) != 1 {
		t.Error("one event per asker per 10 minutes")
	}
	*now = now.Add(11 * time.Minute)
	ask(otherMAC.String(), 40, 60)
	if len(*got) != 2 {
		t.Error("it speaks again after the cool-down, given a fresh run of asks")
	}
}

func TestARPSweepIgnoresSlowAsksOffLANAndTheRouterItself(t *testing.T) {
	w, got, now := testARP()
	// 30 addresses, but one every 5 seconds: never 20 inside any one minute
	for i := 0; i < 30; i++ {
		*now = now.Add(5 * time.Second)
		w.observeRequest(otherMAC.String(), "192.168.1.5", net.IPv4(192, 168, 1, byte(10+i)).String())
	}
	if len(*got) != 0 {
		t.Errorf("a slow walk of the LAN is not a sweep: %v", *got)
	}
	// a device with a wrong netmask asking for the internet
	for i := 0; i < 50; i++ {
		w.observeRequest("ee:00:00:00:00:05", "192.168.1.6", net.IPv4(8, 8, byte(i), 8).String())
	}
	// the box itself resolving everyone
	for i := 0; i < 50; i++ {
		w.observeRequest(bridgeMAC.String(), "192.168.1.1", net.IPv4(192, 168, 1, byte(10+i)).String())
	}
	if len(*got) != 0 || w.View().Sweeps != 0 {
		t.Errorf("off-LAN targets and the router's own requests never count: %v", *got)
	}
	// a flood of invented askers stays bounded
	for i := 0; i < 2000; i++ {
		w.observeRequest(net.HardwareAddr{0x02, 0, 0, byte(i >> 8), byte(i), 1}.String(), "", "192.168.1.9")
	}
	if n := len(w.sweep); n > 300 {
		t.Errorf("askers must stay bounded: %d", n)
	}
}
