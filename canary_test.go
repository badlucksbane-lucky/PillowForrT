package main

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var cip = net.ParseIP("192.168.1.253").To4()

// runBPF is a tiny interpreter for exactly the opcodes bpfProgram (and the other classic-BPF filters in this codebase) use, so a kernel filter is tested without privileges.
func runBPF(prog []unix.SockFilter, pkt []byte) uint32 {
	var a, x uint32
	pc := 0
	for steps := 0; steps < 64 && pc < len(prog); steps++ {
		i := prog[pc]
		switch i.Code {
		case 0x28: // ldh abs
			if int(i.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[i.K:]))
		case 0x20: // ld abs
			if int(i.K)+4 > len(pkt) {
				return 0
			}
			a = binary.BigEndian.Uint32(pkt[i.K:])
		case 0x30: // ldb abs
			if int(i.K)+1 > len(pkt) {
				return 0
			}
			a = uint32(pkt[i.K])
		case 0xb1: // ldx 4*([k]&0xf) (MSH)
			if int(i.K)+1 > len(pkt) {
				return 0
			}
			x = uint32(pkt[i.K]&0x0f) * 4
		case 0x48: // ldh [x+k] (indirect)
			off := int(x) + int(i.K)
			if off+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[off:]))
		case 0x15: // jeq k
			if a == i.K {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case 0x06:
			return i.K
		default:
			panic("opcode not in the interpreter")
		}
		pc++
	}
	return 0
}

func eth(src, dst string, typ uint16) []byte {
	d, _ := net.ParseMAC(dst)
	s, _ := net.ParseMAC(src)
	b := append(append([]byte{}, d...), s...)
	return binary.BigEndian.AppendUint16(b, typ)
}

func ipv4(proto byte, src, dst string, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8], h[9] = 64, proto
	copy(h[12:], net.ParseIP(src).To4())
	copy(h[16:], net.ParseIP(dst).To4())
	return append(h, payload...)
}

func tcpSeg(sport, dport int, flags byte) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:], uint16(sport))
	binary.BigEndian.PutUint16(t[2:], uint16(dport))
	t[12], t[13] = 0x50, flags
	return t
}

func frameTCP(src, dst string, dport int, flags byte) []byte {
	return append(eth("de:ad:be:ef:00:01", "00:00:5e:00:53:09", 0x0800), ipv4(6, src, dst, tcpSeg(40000, dport, flags))...)
}

func frameARP(senderIP, targetIP string, op uint16) []byte {
	a := make([]byte, 28)
	binary.BigEndian.PutUint16(a[0:], 1)
	binary.BigEndian.PutUint16(a[2:], 0x0800)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:], op)
	m, _ := net.ParseMAC("de:ad:be:ef:00:01")
	copy(a[8:], m)
	copy(a[14:], net.ParseIP(senderIP).To4())
	copy(a[24:], net.ParseIP(targetIP).To4())
	return append(eth("de:ad:be:ef:00:01", "ff:ff:ff:ff:ff:ff", 0x0806), a...)
}

func TestCanaryKernelFilter(t *testing.T) {
	prog := bpfProgram(cip)
	for name, c := range map[string]struct {
		pkt  []byte
		want bool
	}{
		"tcp to the canary":    {frameTCP("192.168.1.77", "192.168.1.253", 445, 0x02), true},
		"udp to the canary":    {append(eth("de:ad:be:ef:00:01", "00:00:5e:00:53:09", 0x0800), ipv4(17, "192.168.1.77", "192.168.1.253", make([]byte, 8))...), true},
		"tcp to another host":  {frameTCP("192.168.1.77", "192.168.1.20", 445, 0x02), false},
		"tcp to the gateway":   {frameTCP("192.168.1.77", "192.168.1.1", 80, 0x02), false},
		"arp who-has canary":   {frameARP("192.168.1.77", "192.168.1.253", 1), true},
		"arp who-has another":  {frameARP("192.168.1.77", "192.168.1.20", 1), false},
		"ipv6":                 {append(eth("de:ad:be:ef:00:01", "33:33:00:00:00:01", 0x86dd), make([]byte, 60)...), false},
		"a runt":               {make([]byte, 10), false},
		"canary as the source": {frameTCP("192.168.1.253", "192.168.1.77", 445, 0x12), false},
	} {
		if got := runBPF(prog, c.pkt) != 0; got != c.want {
			t.Errorf("%s: accepted=%v want %v", name, got, c.want)
		}
	}
}

func TestParseCanaryFrame(t *testing.T) {
	now := time.Unix(1790000000, 0)
	h, ok := parseCanaryFrame(frameTCP("192.168.1.77", "192.168.1.253", 445, 0x02), cip, now)
	if !ok || h.Proto != "tcp" || h.Port != 445 || h.Kind != "syn" || h.Src != "192.168.1.77" || h.MAC != "de:ad:be:ef:00:01" {
		t.Errorf("syn: %+v %v", h, ok)
	}
	for name, f := range map[string][]byte{
		"a syn-ack":           frameTCP("192.168.1.77", "192.168.1.253", 445, 0x12),
		"a plain ack":         frameTCP("192.168.1.77", "192.168.1.253", 445, 0x10),
		"another destination": frameTCP("192.168.1.77", "192.168.1.20", 445, 0x02),
		"an ARP reply":        frameARP("192.168.1.77", "192.168.1.253", 2),
		"an ARP for another":  frameARP("192.168.1.77", "192.168.1.20", 1),
		"a runt":              make([]byte, 20),
	} {
		if _, ok := parseCanaryFrame(f, cip, now); ok {
			t.Errorf("%s was recorded", name)
		}
	}
	if h, ok := parseCanaryFrame(frameARP("192.168.1.77", "192.168.1.253", 1), cip, now); !ok || h.Proto != "arp" || h.Src != "192.168.1.77" || h.MAC != "de:ad:be:ef:00:01" {
		t.Errorf("arp: %+v %v", h, ok)
	}
	if h, ok := parseCanaryFrame(frameARP("0.0.0.0", "192.168.1.253", 1), cip, now); !ok || h.Src != "0.0.0.0" {
		t.Errorf("an address-conflict probe is still a touch: %+v %v", h, ok)
	}
	echo := append(eth("de:ad:be:ef:00:01", "00:00:5e:00:53:09", 0x0800), ipv4(1, "192.168.1.77", "192.168.1.253", []byte{8, 0, 0, 0, 0, 0, 0, 0})...)
	if h, ok := parseCanaryFrame(echo, cip, now); !ok || h.Proto != "icmp" || h.Kind != "echo" {
		t.Errorf("ping: %+v %v", h, ok)
	}
	reply := append(eth("de:ad:be:ef:00:01", "00:00:5e:00:53:09", 0x0800), ipv4(1, "192.168.1.77", "192.168.1.253", []byte{0, 0, 0, 0, 0, 0, 0, 0})...)
	if _, ok := parseCanaryFrame(reply, cip, now); ok {
		t.Error("an echo reply is not a probe")
	}
	udp := append(eth("de:ad:be:ef:00:01", "00:00:5e:00:53:09", 0x0800), ipv4(17, "192.168.1.77", "192.168.1.253", []byte{0x9c, 0x40, 0x00, 0x35, 0, 8, 0, 0})...)
	if h, ok := parseCanaryFrame(udp, cip, now); !ok || h.Proto != "udp" || h.Port != 53 {
		t.Errorf("udp: %+v %v", h, ok)
	}
}

func newTestCanary(t *testing.T) (*canary, *[]evt, *time.Time) {
	var mu sync.Mutex
	var got []evt
	clock := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c := &canary{ip: cip, path: t.TempDir() + "/c.json", sources: map[string]*canarySource{}, now: func() time.Time { return clock }, perSrc: map[string]int{},
		own: map[string]bool{"192.168.1.1": true, "192.168.1.254": true, "192.168.1.253": true}, maxConns: 2, lifetime: 400 * time.Millisecond, capFD: -1,
		nameOf: func(mac string) string {
			if mac == "aa:bb:cc:dd:ee:01" {
				return "kitchen-bulb"
			}
			return ""
		},
		macOf:    func(ip string) string { return "aa:bb:cc:dd:ee:77" },
		emit:     func(e evt) { mu.Lock(); got = append(got, e); mu.Unlock() },
		listen:   func(a string) (net.Listener, error) { return net.Listen("tcp4", "127.0.0.1:0") },
		ensureIP: func(bool) bool { return true }}
	c.st.Enabled = true
	return c, &got, &clock
}

func TestCanaryEvents(t *testing.T) {
	c, got, clock := newTestCanary(t)
	c.record(canaryHit{T: 1, Src: "192.168.1.77", MAC: "aa:bb:cc:dd:ee:01", Proto: "tcp", Port: 22, Kind: "syn"})
	if len(*got) != 1 || (*got)[0].Kind != "canary" || (*got)[0].Sev != sevAttention || !strings.Contains((*got)[0].Text, "kitchen-bulb") || !strings.Contains((*got)[0].Text, "tcp port 22") {
		t.Fatalf("first touch: %+v", *got)
	}
	if p := (*got)[0].Public; strings.Contains(p, "192.168") || strings.Contains(p, "kitchen") {
		t.Errorf("the public text must be generic: %q", p)
	}
	for _, p := range []int{23, 80, 445} {
		c.record(canaryHit{Src: "192.168.1.77", MAC: "aa:bb:cc:dd:ee:01", Proto: "tcp", Port: p, Kind: "syn"})
	}
	if len(*got) != 1 {
		t.Errorf("four ports is not a scan yet and the same source must not repeat within 10 minutes: %d events", len(*got))
	}
	c.record(canaryHit{Src: "192.168.1.77", MAC: "aa:bb:cc:dd:ee:01", Proto: "tcp", Port: 3389, Kind: "syn"})
	if len(*got) != 2 || (*got)[1].Kind != "canary_scan" || !strings.Contains((*got)[1].Text, "5 ports") {
		t.Fatalf("the fifth port makes it a scan: %+v", *got)
	}
	c.record(canaryHit{Src: "192.168.1.77", Proto: "tcp", Port: 5900, Kind: "syn"})
	if len(*got) != 2 {
		t.Error("one scan event per 10 minutes")
	}
	*clock = clock.Add(11 * time.Minute)
	c.record(canaryHit{Src: "192.168.1.77", Proto: "tcp", Port: 9100, Kind: "syn"})
	if len(*got) != 4 {
		t.Errorf("after 10 minutes a persistent source is reported again (touch and scan): %d", len(*got))
	}
	c.record(canaryHit{Src: "192.168.1.88", Proto: "arp", Kind: "who-has"})
	if len(*got) != 5 || !strings.Contains((*got)[4].Text, "an ARP lookup") {
		t.Errorf("a different source is its own event: %+v", (*got)[len(*got)-1])
	}
	v := c.View()
	srcs := map[string]bool{}
	for _, x := range v.Sources {
		srcs[x.Src] = true
	}
	if len(v.Sources) != 2 || !srcs["192.168.1.77"] || !srcs["192.168.1.88"] || len(v.Hits) != 8 {
		t.Errorf("view: %d sources, %d hits", len(v.Sources), len(v.Hits))
	}
}

func TestCanaryCountsADuplicatedFrameOnce(t *testing.T) {
	c, got, clock := newTestCanary(t)
	h := canaryHit{T: clock.Unix(), Src: "192.168.1.77", Proto: "tcp", Port: 22, Kind: "syn"}
	c.record(h)
	c.record(h) // the same frame again, same instant
	if len(c.hits) != 1 || len(*got) != 1 {
		t.Errorf("a duplicated frame counted twice: %d hits", len(c.hits))
	}
	*clock = clock.Add(2 * time.Second)
	h.T = clock.Unix()
	c.record(h) // a real second attempt
	if len(c.hits) != 2 {
		t.Errorf("a real retry must count: %d", len(c.hits))
	}
}

func TestCanaryIgnoresOwnAddressesAndTheIgnoreList(t *testing.T) {
	c, got, _ := newTestCanary(t)
	for _, own := range []string{"192.168.1.1", "192.168.1.254", "192.168.1.253"} {
		c.record(canaryHit{Src: own, Proto: "icmp", Kind: "echo"})
	}
	if len(*got) != 0 || len(c.hits) != 0 {
		t.Error("the Orbic's own addresses are not visitors")
	}
	if err := c.IgnoreMAC("AA:BB:CC:DD:EE:99", true); err != nil {
		t.Fatal(err)
	}
	c.record(canaryHit{Src: "192.168.1.5", MAC: "aa:bb:cc:dd:ee:99", Proto: "tcp", Port: 22, Kind: "syn"})
	if len(*got) != 0 {
		t.Error("an ignored device raised an event")
	}
	c.IgnoreMAC("aa:bb:cc:dd:ee:99", false)
	c.record(canaryHit{Src: "192.168.1.5", MAC: "aa:bb:cc:dd:ee:99", Proto: "tcp", Port: 22, Kind: "syn"})
	if len(*got) != 1 {
		t.Error("an un-ignored device must be reported again")
	}
	if c.IgnoreMAC("nope", true) == nil {
		t.Error("bad MAC")
	}
	c.SetEnabled(false)
	c.record(canaryHit{Src: "192.168.1.6", Proto: "tcp", Port: 22, Kind: "syn"})
	if len(*got) != 1 {
		t.Error("a switched-off canary records nothing")
	}
}

func TestCanaryTarpitConnectionsCarryTheMACSoTheIgnoreListWorks(t *testing.T) {
	c, got, _ := newTestCanary(t)
	c.IgnoreMAC("aa:bb:cc:dd:ee:77", true) // what macOf returns for the loopback client
	c.openListeners()
	cn, err := net.DialTimeout("tcp", c.listeners[0].Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	time.Sleep(80 * time.Millisecond)
	if len(*got) != 0 || len(c.hits) != 0 {
		t.Errorf("an ignored device's connection was recorded: %d events, %d hits", len(*got), len(c.hits))
	}
	c.closeListeners()
}

func TestCanaryTarpitHoldsAndCaps(t *testing.T) {
	c, got, _ := newTestCanary(t)
	c.openListeners()
	if len(c.listeners) != len(canaryTCPPorts) {
		t.Fatalf("%d listeners", len(c.listeners))
	}
	addr := c.listeners[1].Addr().String() // a port other than 22
	dial := func() net.Conn {
		cn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return cn
	}
	a, b := dial(), dial()
	defer a.Close()
	defer b.Close()
	time.Sleep(60 * time.Millisecond)
	cc := dial() // a third connection from the same source: refused (3 per source is the cap, but maxConns is 2)
	cc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 8)
	if _, err := cc.Read(buf); err == nil {
		t.Error("the connection over the cap should have been closed at once")
	}
	cc.Close()
	if len(*got) != 1 || (*got)[0].Kind != "canary" {
		t.Errorf("a connection is a touch: %+v", *got)
	}
	c.mu.Lock()
	n := c.active
	c.mu.Unlock()
	if n != 2 {
		t.Errorf("two held connections, got %d", n)
	}
	a.SetReadDeadline(time.Now().Add(2 * time.Second))
	closed := false
	for i := 0; i < 20; i++ {
		if _, err := a.Read(buf); err != nil {
			closed = err.Error() != "" && !strings.Contains(err.Error(), "timeout")
			break
		}
	}
	if !closed {
		t.Error("the tarpit must let go after its lifetime")
	}
	c.closeListeners()
	if len(c.listeners) != 0 {
		t.Error("listeners not closed")
	}
}

func TestCanaryAddressIsNeverHandedOut(t *testing.T) {
	if err := validateReservation(reservation{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.253", Name: "x"}, nil); err == nil || !strings.Contains(err.Error(), "canary") {
		t.Errorf("a reservation on the canary address: %v", err)
	}
	if err := validateReservation(reservation{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.252", Name: "x"}, nil); err != nil {
		t.Errorf(".252 is a normal client address: %v", err)
	}
	if err := validatePool(dhcpPool{"192.168.1.100", "192.168.1.253", 3600}); err == nil {
		t.Error("a pool that reaches the canary address")
	}
	if err := validatePool(dhcpPool{"192.168.1.100", "192.168.1.252", 3600}); err != nil {
		t.Error(err)
	}
	if !canaryReserved("192.168.1.253") || canaryReserved("192.168.1.252") {
		t.Error("canaryReserved")
	}
}
