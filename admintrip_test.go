package main

import (
	"testing"
	"time"
)

func TestBPFAdminKnockAcceptsOnlySYNToAdminPorts(t *testing.T) {
	prog := bpfAdminKnock()
	router := [4]byte{192, 168, 1, 1}
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"syn to 81", ipv4Frame(macA, 6, 64, lanDev, router, tcpHdr(40000, 81, 0x02)), true},
		{"syn to 444", ipv4Frame(macA, 6, 64, lanDev, router, tcpHdr(40000, 444, 0x02)), true},
		{"syn to 443 (our page)", ipv4Frame(macA, 6, 64, lanDev, router, tcpHdr(40000, 443, 0x02)), false},
		{"syn to 80", ipv4Frame(macA, 6, 64, lanDev, router, tcpHdr(40000, 80, 0x02)), false},
		{"ack to 81", ipv4Frame(macA, 6, 64, lanDev, router, tcpHdr(40000, 81, 0x10)), false},
		{"syn-ack from 81", ipv4Frame(macA, 6, 64, router, lanDev, tcpHdr(81, 40000, 0x12)), false},
		{"udp to 81", ipv4Frame(macA, 17, 64, lanDev, router, udpHdr(5000, 81)), false},
		{"ipv6", append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0x11, 0x22, 0x33, 0x44, 0x55, 0x86, 0xdd}, make([]byte, 60)...), false},
	}
	for _, c := range cases {
		if got := runBPF(prog, c.frame) != 0; got != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, got, c.want)
		}
	}
}

func TestParseAdminKnock(t *testing.T) {
	mac, ip, port, ok := parseAdminKnock(ipv4Frame(macA, 6, 64, lanDev, [4]byte{192, 168, 1, 1}, tcpHdr(40000, 444, 0x02)))
	if !ok || mac != "aa:11:22:33:44:55" || ip != "192.168.1.20" || port != 444 {
		t.Fatalf("%s %s %d %v", mac, ip, port, ok)
	}
	if _, _, _, ok := parseAdminKnock(make([]byte, 20)); ok {
		t.Error("short frame parsed")
	}
}

func TestAdminTripObserve(t *testing.T) {
	var got []evt
	armed := true
	a := newAdminTrip()
	a.emit = func(e evt) { got = append(got, e) }
	a.armed = func() bool { return armed }
	a.nameOf = func(mac string) string {
		if mac == "aa:11:22:33:44:55" {
			return "laptop"
		}
		return ""
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }

	a.Observe("aa:11:22:33:44:55", "192.168.1.20", 81, now)
	if len(got) != 1 || got[0].Kind != "stock_admin_probe" || got[0].Sev != sevAttention {
		t.Fatalf("%v", got)
	}
	if got[0].Text != "192.168.1.20 (laptop) knocked on the stock admin's port 81, which is switched off: nothing on the network has a reason to, so something is looking for the factory login page." {
		t.Errorf("text: %s", got[0].Text)
	}
	if got[0].Public == "" || got[0].Public != "Something on the network probed the router's switched-off factory admin port" {
		t.Errorf("public text names nothing: %q", got[0].Public)
	}
	a.Observe("aa:11:22:33:44:55", "192.168.1.20", 444, now.Add(time.Minute))
	if len(got) != 1 {
		t.Error("a second event from the same source inside 10 minutes")
	}
	a.Observe("bb:11:22:33:44:55", "192.168.1.21", 444, now.Add(time.Minute))
	if len(got) != 2 {
		t.Error("another source must get its own event")
	}
	a.Observe("aa:11:22:33:44:55", "192.168.1.20", 81, now.Add(11*time.Minute))
	if len(got) != 3 {
		t.Error("no event after the cool-down")
	}
	v := a.View()
	if !v.Armed || len(v.Knocks) != 4 || v.Knocks[0].Port != 81 || v.Sources != 2 {
		t.Errorf("%+v", v)
	}

	// the router's own addresses, and a stock admin that is still on, are never a finding
	a.Observe("cc:11:22:33:44:55", "192.168.1.1", 81, now.Add(time.Hour))
	armed = false
	a.Observe("dd:11:22:33:44:55", "192.168.1.40", 81, now.Add(time.Hour))
	if len(got) != 3 || len(a.View().Knocks) != 4 {
		t.Errorf("%v", got)
	}
	if a.View().Armed {
		t.Error("the view must say it is not armed")
	}
}
