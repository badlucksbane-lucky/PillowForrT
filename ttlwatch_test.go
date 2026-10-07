package main

import (
	"path/filepath"
	"testing"
	"time"
)

var (
	macA   = []byte{0xaa, 0x11, 0x22, 0x33, 0x44, 0x55}
	lanDev = [4]byte{192, 168, 1, 20}
	wanDst = [4]byte{93, 184, 216, 34}
)

func TestBPFFirstPacketsAcceptsOnlySYNAndDNS(t *testing.T) {
	prog := bpfFirstPackets()
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"tcp syn", ipv4Frame(macA, 6, 64, lanDev, wanDst, tcpHdr(40000, 443, 0x02)), true},
		{"tcp syn-ack", ipv4Frame(macA, 6, 64, lanDev, wanDst, tcpHdr(443, 40000, 0x12)), false},
		{"tcp ack (mid-stream)", ipv4Frame(macA, 6, 64, lanDev, wanDst, tcpHdr(40000, 443, 0x10)), false},
		{"udp to 53", ipv4Frame(macA, 17, 64, lanDev, [4]byte{192, 168, 1, 1}, udpHdr(5000, 53)), true},
		{"udp to 443 (quic)", ipv4Frame(macA, 17, 64, lanDev, wanDst, udpHdr(5000, 443)), false},
		{"icmp", ipv4Frame(macA, 1, 64, lanDev, wanDst, []byte{8, 0, 0, 0, 0, 0, 0, 0}), false},
		{"arp", append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06}, make([]byte, 28)...), false},
	}
	for _, c := range cases {
		if got := runBPF(prog, c.frame) != 0; got != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, got, c.want)
		}
	}
	// a TCP SYN with IP options: the header length index must be honoured
	f := ipv4Frame(macA, 6, 64, lanDev, wanDst, append(make([]byte, 4), tcpHdr(1, 443, 0x02)...))
	f[14] = 0x46
	if runBPF(prog, f) == 0 {
		t.Error("SYN behind IP options dropped")
	}
}

func TestTTLClass(t *testing.T) {
	for _, c := range []struct{ ttl, initial, hops int }{{64, 64, 0}, {63, 64, 1}, {128, 128, 0}, {127, 128, 1}, {255, 255, 0}, {254, 255, 1}, {32, 32, 0}, {120, 128, 8}} {
		in, hops, ok := ttlClass(c.ttl)
		if !ok || in != c.initial || hops != c.hops {
			t.Errorf("ttl %d: %d/%d/%v want %d/%d", c.ttl, in, hops, ok, c.initial, c.hops)
		}
	}
	for _, bad := range []int{0, 50, 100, 200} {
		if _, _, ok := ttlClass(bad); ok {
			t.Errorf("ttl %d should not be classed", bad)
		}
	}
}

func TestParseFirstPacket(t *testing.T) {
	mac, ip, ttl, ok := parseFirstPacket(ipv4Frame(macA, 6, 63, lanDev, wanDst, tcpHdr(1, 443, 0x02)))
	if !ok || mac != "aa:11:22:33:44:55" || ip != "192.168.1.20" || ttl != 63 {
		t.Fatalf("%s %s %d %v", mac, ip, ttl, ok)
	}
	if _, _, _, ok := parseFirstPacket([]byte{1, 2, 3}); ok {
		t.Error("short frame parsed")
	}
}

func TestTTLWatchObserve(t *testing.T) {
	newW := func() (*ttlWatch, *[]evt) {
		var got []evt
		w := newTTLWatch(filepath.Join(t.TempDir(), "ttl.json"))
		w.emit = func(e evt) { got = append(got, e) }
		return w, &got
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	t.Run("a device's own traffic never fires", func(t *testing.T) {
		w, got := newW()
		for i := 0; i < 200; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 64, now)
		}
		if len(*got) != 0 {
			t.Fatalf("%v", *got)
		}
		v := w.View()
		if len(v.Devices) != 1 || v.Devices[0].Direct != 200 || v.Devices[0].Behind != 0 || v.Devices[0].Classes["64"] != 200 {
			t.Fatalf("%+v", v.Devices)
		}
	})
	t.Run("one hop short, enough times, is forwarding", func(t *testing.T) {
		w, got := newW()
		for i := 0; i < ttlBehindMin-1; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 63, now)
		}
		if len(*got) != 0 {
			t.Fatal("fired below the threshold")
		}
		w.Observe("aa:11:22:33:44:55", "192.168.1.20", 127, now) // a Windows box behind it too: still one hop short
		if len(*got) != 1 || (*got)[0].Kind != "ttl_forwarding" || (*got)[0].Sev != sevAttention {
			t.Fatalf("%v", *got)
		}
		for i := 0; i < 100; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 63, now.Add(time.Hour))
		}
		if len(*got) != 1 {
			t.Error("a second event inside a day")
		}
		for i := 0; i < ttlBehindMin; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 63, now.Add(25*time.Hour))
		}
		if len(*got) != 2 {
			t.Error("no event after a day")
		}
		if v := w.View(); len(v.Findings) != 2 || v.Findings[0].Kind != "ttl_forwarding" {
			t.Errorf("%+v", v.Findings)
		}
	})
	t.Run("two initial TTLs from one address", func(t *testing.T) {
		w, got := newW()
		for i := 0; i < ttlTwoStacksMin; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 64, now)
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 128, now)
		}
		if len(*got) != 1 || (*got)[0].Kind != "ttl_two_stacks" {
			t.Fatalf("%v", *got)
		}
	})
	t.Run("the window resets the counters", func(t *testing.T) {
		w, got := newW()
		for i := 0; i < ttlBehindMin-1; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 63, now)
		}
		w.Observe("aa:11:22:33:44:55", "192.168.1.20", 63, now.Add(ttlWindow+time.Second))
		if len(*got) != 0 {
			t.Fatal("counts carried across the window")
		}
		if v := w.View(); v.Devices[0].Behind != 1 {
			t.Errorf("%+v", v.Devices)
		}
	})
	t.Run("the router's own frames and expected devices are skipped", func(t *testing.T) {
		w, got := newW()
		w.ownMAC = "aa:11:22:33:44:55"
		for i := 0; i < 50; i++ {
			w.Observe("aa:11:22:33:44:55", "192.168.1.20", 63, now)
			w.Observe("bb:11:22:33:44:55", "192.168.1.1", 63, now)
		}
		if err := w.IgnoreMAC("cc:11:22:33:44:55", true); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 50; i++ {
			w.Observe("cc:11:22:33:44:55", "192.168.1.30", 63, now)
		}
		if len(*got) != 0 || len(w.View().Devices) != 0 {
			t.Fatalf("%v %+v", *got, w.View().Devices)
		}
		if w.IgnoreMAC("not-a-mac", true) == nil {
			t.Error("bad MAC accepted")
		}
		w2 := newTTLWatch(w.path)
		if len(w2.View().Ignore) != 1 || w2.View().Ignore[0] != "cc:11:22:33:44:55" {
			t.Error("the ignore list did not persist")
		}
		w2.IgnoreMAC("cc:11:22:33:44:55", false)
		for i := 0; i < ttlBehindMin; i++ {
			w2.Observe("cc:11:22:33:44:55", "192.168.1.30", 63, now)
		}
		if len(w2.View().Findings) != 1 {
			t.Error("watching again did not resume")
		}
	})
}
