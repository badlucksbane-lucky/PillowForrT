package main

import (
	"encoding/binary"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestTapBPFExcludesOwnFlowAndFilters(t *testing.T) {
	lan := [4]byte{192, 168, 1, 20}
	router := [4]byte{192, 168, 1, 1}
	self, peer := uint16(3129), uint16(51000)
	arp := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06}, make([]byte, 28)...)
	cases := []struct {
		filter string
		name   string
		frame  []byte
		want   bool
	}{
		{"all", "own flow client->us", ipv4Frame(macA, 6, 64, lan, router, tcpHdr(peer, self, 0x10)), false},
		{"all", "own flow us->client", ipv4Frame(macA, 6, 64, router, lan, tcpHdr(self, peer, 0x10)), false},
		{"all", "other client to our page", ipv4Frame(macA, 6, 64, lan, router, tcpHdr(40000, self, 0x02)), true},
		{"all", "ours to another port", ipv4Frame(macA, 6, 64, router, lan, tcpHdr(self, 40001, 0x10)), true},
		{"all", "web", ipv4Frame(macA, 6, 64, lan, router, tcpHdr(peer, 443, 0x02)), true}, // same client port, different server port: not our flow
		{"all", "udp", ipv4Frame(macA, 17, 64, lan, router, udpHdr(5000, 53)), true},
		{"all", "arp", arp, true},
		{"arp", "arp", arp, true},
		{"arp", "tcp", ipv4Frame(macA, 6, 64, lan, router, tcpHdr(1, 2, 0x02)), false},
		{"dns", "dns query", ipv4Frame(macA, 17, 64, lan, router, udpHdr(5000, 53)), true},
		{"dns", "dns answer", ipv4Frame(macA, 17, 64, router, lan, udpHdr(53, 5000)), true},
		{"dns", "other udp", ipv4Frame(macA, 17, 64, lan, router, udpHdr(5000, 123)), false},
		{"dns", "tcp 53", ipv4Frame(macA, 6, 64, lan, router, tcpHdr(5000, 53, 0x02)), false},
		{"dns", "own flow", ipv4Frame(macA, 6, 64, lan, router, tcpHdr(peer, self, 0x10)), false},
		{"dhcp", "discover", ipv4Frame(macA, 17, 64, [4]byte{0, 0, 0, 0}, [4]byte{255, 255, 255, 255}, udpHdr(68, 67)), true},
		{"dhcp", "offer", ipv4Frame(macA, 17, 64, router, lan, udpHdr(67, 68)), true},
		{"dhcp", "dns", ipv4Frame(macA, 17, 64, lan, router, udpHdr(5000, 53)), false},
		{"tls", "syn to 443", ipv4Frame(macA, 6, 64, lan, [4]byte{1, 1, 1, 1}, tcpHdr(40000, 443, 0x02)), true},
		{"tls", "from 443", ipv4Frame(macA, 6, 64, [4]byte{1, 1, 1, 1}, lan, tcpHdr(443, 40000, 0x12)), true},
		{"tls", "port 80", ipv4Frame(macA, 6, 64, lan, [4]byte{1, 1, 1, 1}, tcpHdr(40000, 80, 0x02)), false},
		{"tls", "arp", arp, false},
		{"icmp", "ping", ipv4Frame(macA, 1, 64, lan, router, make([]byte, 8)), true},
		{"icmp", "udp", ipv4Frame(macA, 17, 64, lan, router, udpHdr(1, 2)), false},
	}
	for _, c := range cases {
		prog := tapBPF(c.filter, self, peer)
		if got := runBPF(prog, c.frame) != 0; got != c.want {
			t.Errorf("%s/%s: accepted=%v want %v", c.filter, c.name, got, c.want)
		}
	}
	// every program ends in a return and every jump stays inside it
	for f := range tapFilters {
		prog := tapBPF(f, self, peer)
		if prog[len(prog)-1].Code != 0x06 {
			t.Errorf("%s: no final return", f)
		}
		for i, in := range prog {
			if in.Code == 0x15 && (i+1+int(in.Jt) >= len(prog) || i+1+int(in.Jf) >= len(prog)) {
				t.Errorf("%s: jump at %d leaves the program", f, i)
			}
		}
	}
}

func TestPcapFraming(t *testing.T) {
	h := pcapHeader(1600)
	if len(h) != 24 || binary.LittleEndian.Uint32(h[0:4]) != 0xa1b2c3d4 || binary.LittleEndian.Uint16(h[4:6]) != 2 || binary.LittleEndian.Uint16(h[6:8]) != 4 ||
		binary.LittleEndian.Uint32(h[16:20]) != 1600 || binary.LittleEndian.Uint32(h[20:24]) != 1 {
		t.Errorf("header % x", h)
	}
	ts := time.Unix(1700000000, 123456000)
	r := pcapRecord(ts, []byte{1, 2, 3}, 90)
	if len(r) != 19 || binary.LittleEndian.Uint32(r[0:4]) != 1700000000 || binary.LittleEndian.Uint32(r[4:8]) != 123456 || binary.LittleEndian.Uint32(r[8:12]) != 3 || binary.LittleEndian.Uint32(r[12:16]) != 90 || r[16] != 1 || r[18] != 3 {
		t.Errorf("record % x", r)
	}
}

func TestTapRefusedWhenOff(t *testing.T) {
	old := exports
	defer func() { exports = old }()
	exports = newExportStore(filepath.Join(t.TempDir(), "export.json"))
	rr := httptest.NewRecorder()
	handleTap(rr, httptest.NewRequest("GET", "/api/tap", nil))
	if rr.Code != 403 {
		t.Errorf("tap served while off: %d", rr.Code)
	}
	exports.SetTap(true)
	rr = httptest.NewRecorder()
	handleTap(rr, httptest.NewRequest("GET", "/api/tap?filter=bogus", nil))
	if rr.Code != 400 {
		t.Errorf("bad filter: %d", rr.Code)
	}
	if portOf("192.168.1.20:51000") != 51000 || portOf("nonsense") != 0 {
		t.Error("portOf")
	}
}
