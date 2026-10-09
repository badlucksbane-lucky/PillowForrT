package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// runRogueBPF interprets exactly the opcodes rogueBPF uses.
func runRogueBPF(prog []unix.SockFilter, pkt []byte) uint32 {
	var a, x uint32
	pc := 0
	for steps := 0; steps < 64 && pc < len(prog); steps++ {
		i := prog[pc]
		switch i.Code {
		case 0x28:
			if int(i.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[i.K:]))
		case 0x30:
			if int(i.K)+1 > len(pkt) {
				return 0
			}
			a = uint32(pkt[i.K])
		case 0xb1:
			if int(i.K)+1 > len(pkt) {
				return 0
			}
			x = uint32(pkt[i.K]&0x0f) * 4
		case 0x48:
			if int(x+i.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[x+i.K:]))
		case 0x15:
			if a == i.K {
				pc += int(i.Jt)
			} else {
				pc += int(i.Jf)
			}
		case 0x06:
			return i.K
		}
		pc++
	}
	return 0
}

// dhcpFrame builds an Ethernet+IPv4+UDP+BOOTP/DHCP reply: type 2 offer, 5 ack, 6 nak.
func dhcpFrame(srcIP string, srcMAC net.HardwareAddr, typ byte, yi string, ihl int, srcPort uint16) []byte {
	d := make([]byte, 240)
	d[0] = 2
	copy(d[16:20], net.ParseIP(yi).To4())
	copy(d[28:34], []byte{0xde, 0xad, 0xbe, 0xef, 0, 1})
	binary.BigEndian.PutUint32(d[236:], 0x63825363)
	d = append(d, 53, 1, typ, 54, 4)
	d = append(d, net.ParseIP(srcIP).To4()...)
	d = append(d, 255)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], 68)
	f := make([]byte, 14+ihl)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	f[14] = 0x40 | byte(ihl/4)
	f[23] = 17
	copy(f[26:30], net.ParseIP(srcIP).To4())
	copy(f[30:34], []byte{255, 255, 255, 255})
	return append(append(f, udp...), d...)
}

var (
	bridgeMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	otherMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}
)

func TestRogueKernelFilter(t *testing.T) {
	p := rogueBPF()
	if runRogueBPF(p, dhcpFrame("192.168.1.1", bridgeMAC, 2, "192.168.1.150", 20, 67)) == 0 {
		t.Error("a DHCP reply must pass")
	}
	if runRogueBPF(p, dhcpFrame("192.168.1.1", bridgeMAC, 2, "192.168.1.150", 24, 67)) == 0 {
		t.Error("a reply with IP options (header 24 bytes) must pass")
	}
	if runRogueBPF(p, dhcpFrame("192.168.1.1", bridgeMAC, 2, "192.168.1.150", 20, 68)) != 0 {
		t.Error("a client-side frame (source port 68) must not pass")
	}
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if runRogueBPF(p, arp) != 0 {
		t.Error("ARP must not pass")
	}
	tcp := dhcpFrame("192.168.1.1", bridgeMAC, 2, "192.168.1.150", 20, 67)
	tcp[23] = 6
	if runRogueBPF(p, tcp) != 0 {
		t.Error("TCP must not pass")
	}
	if runRogueBPF(p, []byte{1, 2, 3}) != 0 {
		t.Error("a runt must not pass")
	}
}

func TestParseDHCPReply(t *testing.T) {
	for typ, want := range map[byte]string{2: "offer", 5: "ack", 6: "nak"} {
		r, ok := parseDHCPReply(dhcpFrame("10.9.9.9", otherMAC, typ, "10.9.9.50", 20, 67))
		if !ok || r.Type != want || r.SrcIP != "10.9.9.9" || r.SrcMAC != otherMAC.String() || r.ServerID != "10.9.9.9" || r.Yiaddr != "10.9.9.50" || r.ClientMAC != "de:ad:be:ef:00:01" {
			t.Errorf("type %d: %+v ok=%v", typ, r, ok)
		}
	}
	f := dhcpFrame("10.9.9.9", otherMAC, 2, "10.9.9.50", 20, 67)
	f[14+20+8] = 1 // a BOOTREQUEST is not a reply
	if _, ok := parseDHCPReply(f); ok {
		t.Error("a request must not parse as a reply")
	}
	f = dhcpFrame("10.9.9.9", otherMAC, 2, "10.9.9.50", 20, 67)
	binary.BigEndian.PutUint32(f[14+20+8+236:], 0)
	if _, ok := parseDHCPReply(f); ok {
		t.Error("no magic cookie, not DHCP")
	}
	if _, ok := parseDHCPReply(dhcpFrame("10.9.9.9", otherMAC, 3, "10.9.9.50", 20, 67)); ok {
		t.Error("a type we do not track (request) must not parse")
	}
	if _, ok := parseDHCPReply(f[:50]); ok {
		t.Error("a truncated frame must not parse")
	}
}

func TestRogueRecordsOnlyDishonestServers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var got []evt
	w := newRogueWatch()
	w.path = ""
	w.now = func() time.Time { return now }
	w.selfMAC = func() string { return bridgeMAC.String() }
	w.emit = func(e evt) { got = append(got, e) }
	rep := func(ip string, mac net.HardwareAddr, typ byte) dhcpReply {
		r, ok := parseDHCPReply(dhcpFrame(ip, mac, typ, "192.168.1.150", 20, 67))
		if !ok {
			t.Fatal("parse")
		}
		return r
	}
	w.record(rep("192.168.1.1", bridgeMAC, 2))
	w.record(rep("192.168.1.254", bridgeMAC, 5))
	if len(got) != 0 || len(w.View().Servers) != 0 || w.View().Honest != 2 {
		t.Fatalf("honest replies must raise nothing: %v %+v", got, w.View())
	}
	w.record(rep("192.168.1.77", otherMAC, 2)) // another server
	if len(got) != 1 || got[0].Kind != "rogue_dhcp" || got[0].Sev != sevAlert {
		t.Fatalf("a second server is an alert: %v", got)
	}
	if got[0].Public == "" || containsAny(got[0].Public, "192.168", "02:00") {
		t.Errorf("the public text must be generic: %q", got[0].Public)
	}
	w.record(rep("192.168.1.1", otherMAC, 5)) // our gateway address, forged by someone else
	if len(w.View().Servers) != 2 {
		t.Errorf("a forged gateway address is a rogue too: %+v", w.View().Servers)
	}
	n := len(got)
	w.record(rep("192.168.1.77", otherMAC, 5)) // same server again within 10 minutes
	if len(got) != n {
		t.Errorf("one event per server per 10 minutes, got %d more", len(got)-n)
	}
	now = now.Add(11 * time.Minute)
	w.record(rep("192.168.1.77", otherMAC, 5))
	if len(got) != n+1 {
		t.Errorf("after the cool-down it speaks again")
	}
	s := w.View().Servers
	var seen bool
	for _, x := range s {
		if x.IP == "192.168.1.77" && x.Replies == 3 && len(x.Types) == 2 && x.Gave == "192.168.1.150" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("view: %+v", s)
	}
	now = now.Add(25 * time.Hour)
	w.record(rep("192.168.1.88", otherMAC, 2))
	if len(w.View().Servers) != 1 {
		t.Errorf("servers quiet for a day are forgotten: %+v", w.View().Servers)
	}
}

func TestRogueWithoutBridgeMACJudgesByAddress(t *testing.T) {
	w := newRogueWatch()
	w.selfMAC = func() string { return "" }
	w.emit = func(evt) {}
	r, _ := parseDHCPReply(dhcpFrame("192.168.1.1", otherMAC, 2, "192.168.1.150", 20, 67))
	w.record(r)
	if len(w.View().Servers) != 0 {
		t.Error("with no known bridge MAC, our own address must not alarm")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

func TestRogueAllowList(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var got []evt
	w := newRogueWatch()
	w.path = filepath.Join(t.TempDir(), "rogue.json")
	w.now = func() time.Time { return now }
	w.selfMAC = func() string { return bridgeMAC.String() }
	w.emit = func(e evt) { got = append(got, e) }
	rep := func(ip string, mac net.HardwareAddr) dhcpReply {
		r, _ := parseDHCPReply(dhcpFrame(ip, mac, 2, "192.168.1.150", 20, 67))
		return r
	}
	w.record(rep("192.168.1.77", otherMAC))
	if len(got) != 1 || len(w.View().Servers) != 1 {
		t.Fatal("setup: the unknown server alerts")
	}
	if err := w.Allow(strings.ToUpper(otherMAC.String()), true); err != nil {
		t.Fatal(err)
	}
	if v := w.View(); len(v.Servers) != 0 || len(v.Allowed) != 1 || v.Allowed[0].MAC != otherMAC.String() {
		t.Errorf("allowing moves it out of the rogue list: %+v", v)
	}
	now = now.Add(time.Hour)
	w.record(rep("192.168.1.77", otherMAC))
	w.record(rep("192.168.1.88", otherMAC)) // it may answer from another address: trust is the MAC
	if len(got) != 1 {
		t.Errorf("an allowed server raises nothing: %v", got)
	}
	if a := w.View().Allowed[0]; a.Replies != 2 || a.IP != "192.168.1.88" {
		t.Errorf("its replies are still counted: %+v", a)
	}
	third := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x55}
	w.record(rep("192.168.1.77", third)) // another device forging the same address is NOT allowed
	if len(got) != 2 || len(w.View().Servers) != 1 {
		t.Errorf("trust is the MAC, not the address: %v", got)
	}
	w2 := newRogueWatch() // a restart
	w2.path = w.path
	w2.allow = nil
	if b, err := os.ReadFile(w.path); err != nil || !strings.Contains(string(b), otherMAC.String()) {
		t.Errorf("the allow-list is saved: %v %s", err, b)
	}
	if err := w.Allow(otherMAC.String(), false); err != nil || len(w.View().Allowed) != 0 {
		t.Errorf("removal: %v", err)
	}
	w.record(rep("192.168.1.77", otherMAC))
	if len(w.View().Servers) != 2 { // the forger from before and this one
		t.Error("after removal it is a rogue again")
	}
}

func TestRogueAllowValidates(t *testing.T) {
	w := newRogueWatch()
	w.path = ""
	w.selfMAC = func() string { return bridgeMAC.String() }
	if w.Allow("nonsense", true) == nil {
		t.Error("a bad MAC is refused")
	}
	if w.Allow(bridgeMAC.String(), true) == nil {
		t.Error("the box's own MAC never needs allowing")
	}
	for i := 0; i < 8; i++ {
		if err := w.Allow(fmt.Sprintf("02:00:00:00:01:%02x", i), true); err != nil {
			t.Fatal(err)
		}
	}
	if w.Allow("02:00:00:00:02:00", true) == nil {
		t.Error("at most 8")
	}
	if w.Allow("02:00:00:00:01:00", true) != nil {
		t.Error("re-allowing one already there is fine")
	}
}
