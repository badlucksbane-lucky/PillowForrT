package main

import (
	"strings"
	"testing"
)

const devARP = "IP address       HW type     Flags       HW address            Mask     Device\n" +
	"192.168.1.2     0x1         0x2         00:00:5e:00:53:03     *        bridge0\n" +
	"192.168.1.20    0x1         0x2         00:00:5e:00:53:02     *        bridge0\n" +
	"192.168.1.77    0x1         0x2         02:11:22:33:44:55     *        bridge0\n" +
	"192.168.1.99    0x1         0x0         00:00:00:00:00:00     *        bridge0\n"

func TestBuildDevices(t *testing.T) {
	in := devInputs{
		ARP:          devARP,
		Leases:       "1790990000 00:00:5e:00:53:02 192.168.1.20 moto2-host *\n1790990000 00:00:5e:00:53:04 192.168.1.120 iphone-of-ben *\n1790990000 00:00:5e:00:53:03 192.168.1.2 * *\n",
		NDP:          "2600:100a:b03e:ff2:5551:9cb6:fe78:7b98 lladdr 00:00:5e:00:53:02 REACHABLE\nfe80::1 lladdr 00:00:5e:00:53:02 REACHABLE\nfd00::5 lladdr 00:00:5e:00:53:02 STALE\n",
		Stations:     []wifiStation{{MAC: "00:00:5e:00:53:02", Connected: 120}, {MAC: "02:11:22:33:44:55", Connected: 30}},
		Five:         map[string]bool{"02:11:22:33:44:55": true},
		Reservations: []reservation{{MAC: "00:00:5e:00:53:02", IP: "192.168.1.20", Name: "phone-b"}, {MAC: "00:00:5e:00:53:01", IP: "192.168.1.10", Name: "phone-c"}},
		Blocked:      []string{"02:11:22:33:44:55"},
		FW:           fwView{CutNow: []string{"00:00:5e:00:53:02"}, Paused: []fwPauseView{{MAC: "00:00:5e:00:53:02", Until: "Fri 09:00"}}, Sched: []fwSchedView{{fwSched: fwSched{MAC: "00:00:5e:00:53:02"}}, {fwSched: fwSched{MAC: "00:00:5e:00:53:01"}}}},
	}
	ds := buildDevices(in)
	by := map[string]devView{}
	for _, d := range ds {
		by[d.MAC] = d
	}
	if len(ds) != 5 { // pi, moto2, the random-MAC guest, the iPhone (lease only), the phone (reservation only); the incomplete ARP row is ignored
		t.Fatalf("%d devices: %+v", len(ds), ds)
	}
	m := by["00:00:5e:00:53:02"]
	if m.Name != "phone-b" || m.Hostname != "moto2-host" || !m.Wifi || m.Band != "2.4 GHz" || m.ConnectedS != 120 || !m.CutNow || m.PausedUntil != "Fri 09:00" || m.Schedules != 1 || !m.Reserved || m.RandomMAC {
		t.Errorf("moto2 %+v", m)
	}
	if len(m.IPv6) != 1 || !strings.HasPrefix(m.IPv6[0], "2600:") {
		t.Errorf("only the global IPv6 address belongs here (not fe80, not ULA): %v", m.IPv6)
	}
	g := by["02:11:22:33:44:55"]
	if g.Band != "5 GHz" || !g.RandomMAC || !g.Blocked || g.Reserved {
		t.Errorf("guest %+v", g)
	}
	if i := by["00:00:5e:00:53:04"]; i.Online || i.IP != "192.168.1.120" || i.Hostname != "iphone-of-ben" {
		t.Errorf("iphone (lease only) %+v", i)
	}
	if p := by["00:00:5e:00:53:01"]; p.Online || p.IP != "192.168.1.10" || p.Schedules != 1 {
		t.Errorf("pixel (reservation only) %+v", p)
	}
	if !ds[0].Online || ds[len(ds)-1].Online {
		t.Errorf("online devices must come first: %+v", ds)
	}
	if p := by["00:00:5e:00:53:03"]; p.Hostname != "" || p.Wifi {
		t.Errorf("pi %+v", p)
	}
}

func TestIsRandomMAC(t *testing.T) {
	if !isRandomMAC("02:11:22:33:44:55") || isRandomMAC("00:00:5e:00:53:02") || isRandomMAC("junk") {
		t.Error("isRandomMAC")
	}
	if !isRandomMAC("a6:74:00:00:00:01") { // 0xa6 has the locally-administered bit (the personal Moto's randomized MAC)
		t.Error("a6:... should count as private")
	}
}
