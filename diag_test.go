package main

import (
	"strings"
	"testing"
	"time"
)

func healthy() diagInputs {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	drift := 2 * time.Second
	svcs := serviceTable(map[string]bool{"tinyfwd": true, "dnsmasq": true, "wland": true, "dropbear": true, "goahead": true, "upgrade": true},
		map[string]bool{"upgrade": true}, []string{"hostapd -B /tmp/hostapd_wlan0.conf", "hostapd -B /tmp/hostapd_wlan1.conf", "QCMAP_ConnectionManager x", "sh ./wpad-guard.sh"})
	return diagInputs{Now: now, HasRoute: true, DNSMS: 40, BlockAns: []string{"0.0.0.0"}, FilterMode: "both", Upstream: upstreamState{Mode: "doh"}, ClockDrift: &drift,
		TCP:  []tcpProbe{{"1.1.1.1:443", 50, ""}, {"8.8.8.8:443", 60, ""}, {"9.9.9.9:443", 55, ""}},
		TCP6: &tcpProbe{"v6", 70, ""},
		Cell: cellView{Up: true, IPv4: "100.110.98.3", CGNAT: true, IPv6: "2600::1"},
		Sys:  sysView{Services: svcs, MemTotalKB: 163736, MemAvailKB: 80000, Load: [3]float64{1.2, 1, 1}, Temps: []sysTemp{{"a", 49}}, Disks: []sysDisk{{"System", "/", 100, 10, ""}, {"Data", "/data", 1000, 800, ""}}, Battery: sysBattery{Known: true, MV: 3730}},
		Wifi: wifiView{Live: wifiLive{"ENABLED", 3, 2422}, Live5: &wifiLive{"ENABLED", 149, 5745}, Clients: make([]wifiStation, 4)}, Wifi5On: true,
		Pool: dhcpPool{"192.168.1.100", "192.168.1.200", 86400}, Leases: 5,
		Lists:  []listData{{Name: "oisd", Entries: 100, Updated: now.Add(-time.Hour)}},
		Chains: map[string]bool{"HS_MACBLOCK": true, "HS_FW": true, "HS_FWIN": true, "HS_FWOUT": true, "HS_KILL": true},
		Cert:   certView{DaysLeft: 799}, SSH: sshView{Keys: []sshKey{{}}}, Snapshots: []snapInfo{{Created: now.Add(-time.Hour).Format(time.RFC3339)}}, Uptime: time.Hour}
}

func find(cs []diagCheck, id string) diagCheck {
	for _, c := range cs {
		if c.ID == id {
			return c
		}
	}
	return diagCheck{ID: "MISSING:" + id}
}

func TestDiagHealthyBoxHasNoWarnings(t *testing.T) {
	cs := evaluate(healthy())
	for _, c := range cs {
		if c.Status == "warn" || c.Status == "fail" {
			t.Errorf("a healthy box shows %s %s: %s", c.Status, c.ID, c.Detail)
		}
	}
	if c := diagCounts(cs); c["ok"] < 15 || c["fail"] != 0 {
		t.Errorf("%v", c)
	}
}

func TestDiagThresholds(t *testing.T) {
	type tc struct {
		name, id, want string
		mod            func(*diagInputs)
	}
	mem := func(kb int) func(*diagInputs) { return func(in *diagInputs) { in.Sys.MemAvailKB = kb } }
	temp := func(c float64) func(*diagInputs) { return func(in *diagInputs) { in.Sys.Temps = []sysTemp{{"a", c}} } }
	drift := func(d time.Duration) func(*diagInputs) { return func(in *diagInputs) { in.ClockDrift = &d } }
	for _, c := range []tc{
		{"link down", "uplink.link", "fail", func(in *diagInputs) { in.Cell.Up = false }},
		{"no route", "uplink.link", "fail", func(in *diagInputs) { in.HasRoute = false }},
		{"none reachable", "uplink.reach", "fail", func(in *diagInputs) {
			in.TCP = []tcpProbe{{"a", 0, "unreachable"}, {"b", 0, "unreachable"}}
		}},
		{"slow", "uplink.reach", "warn", func(in *diagInputs) { in.TCP = []tcpProbe{{"a", 500, ""}, {"b", 600, ""}, {"c", 450, ""}} }},
		{"one target down", "uplink.reach", "warn", func(in *diagInputs) { in.TCP[2].Err = "unreachable" }},
		{"no v6 address", "uplink.ipv6", "info", func(in *diagInputs) { in.TCP6 = nil }},
		{"v6 unreachable", "uplink.ipv6", "warn", func(in *diagInputs) { in.TCP6.Err = "unreachable" }},
		{"dns fails", "dns.local", "fail", func(in *diagInputs) { in.DNSErr = "no answer" }},
		{"dns slow", "dns.local", "warn", func(in *diagInputs) { in.DNSMS = 2000 }},
		{"ad not blocked", "dns.filter", "warn", func(in *diagInputs) { in.BlockAns = []string{"142.250.1.1"} }},
		{"filter off", "dns.filter", "info", func(in *diagInputs) { in.FilterMode = "off" }},
		{"doh failing", "dns.upstream", "warn", func(in *diagInputs) { in.Upstream.Mode = "failing" }},
		{"clock off 10 min", "time.clock", "warn", drift(10 * time.Minute)},
		{"clock off 3 h", "time.clock", "fail", drift(-3 * time.Hour)},
		{"clock unknown", "time.clock", "info", func(in *diagInputs) { in.ClockDrift = nil; in.ClockErr = "no answer" }},
		{"mem low", "box.mem", "warn", mem(30 * 1024)},
		{"mem critical", "box.mem", "fail", mem(10 * 1024)},
		{"load", "box.load", "warn", func(in *diagInputs) { in.Sys.Load[0] = 3 }},
		{"warm", "box.temp", "warn", temp(66)},
		{"hot", "box.temp", "fail", temp(80)},
		{"data disk full", "box.disk./data", "warn", func(in *diagInputs) { in.Sys.Disks[1].FreeB = 50 }},
		{"battery low", "box.battery", "warn", func(in *diagInputs) { in.Sys.Battery.MV = 3400 }},
		{"pool nearly full", "dhcp.pool", "warn", func(in *diagInputs) { in.Leases = 90 }},
		{"reservations off", "dhcp.resv", "warn", func(in *diagInputs) { in.ResvOff = 1 }},
		{"radio down", "wifi.bands", "fail", func(in *diagInputs) { in.Wifi.Live.Hostapd = "DISABLED" }},
		{"5ghz on but down", "wifi.bands", "fail", func(in *diagInputs) { in.Wifi.Live5.Hostapd = "COUNTRY_UPDATE" }},
		{"chain missing", "fw.hooks", "warn", func(in *diagInputs) { in.Chains["HS_FW"] = false }},
		{"kill chain missing, vpn on", "fw.hooks", "warn", func(in *diagInputs) {
			in.Chains["HS_KILL"] = false
			in.VPN = &vpnStatus{Registered: true, Enabled: true, Up: true}
		}},
		{"kill chain missing, vpn off", "fw.hooks", "ok", func(in *diagInputs) { in.Chains["HS_KILL"] = false }},
		{"stock admin on", "sec.stockadmin", "info", func(in *diagInputs) { in.StockAdmin = &stockAdminView{} }},
		{"stock admin off", "sec.stockadmin", "ok", func(in *diagInputs) { in.StockAdmin = &stockAdminView{Off: true, RulesIn: true} }},
		{"stock admin off, rules missing", "sec.stockadmin", "warn", func(in *diagInputs) { in.StockAdmin = &stockAdminView{Off: true} }},
		{"stock dnsmasq running", "dns.dnsmasq", "warn", func(in *diagInputs) { in.Dnsmasq = &dnsmasqInfo{Running: true, Ours: false, HookWanted: true} }},
		{"dnsmasq without the hook", "dns.dnsmasq", "warn", func(in *diagInputs) { in.Dnsmasq = &dnsmasqInfo{Running: true, Ours: true, HookWanted: true} }},
		{"dnsmasq without a hook script on disk", "dns.dnsmasq", "ok", func(in *diagInputs) { in.Dnsmasq = &dnsmasqInfo{Running: true, Ours: true} }},
		{"dnsmasq all good", "dns.dnsmasq", "ok", func(in *diagInputs) {
			in.Dnsmasq = &dnsmasqInfo{Running: true, Ours: true, Hook: true, HookWanted: true}
		}},
		{"dnsmasq down", "dns.dnsmasq", "fail", func(in *diagInputs) { in.Dnsmasq = &dnsmasqInfo{} }},
		{"stale lists", "dns.lists", "warn", func(in *diagInputs) { in.Lists[0].Updated = in.Now.Add(-100 * time.Hour) }},
		{"empty list", "dns.lists", "warn", func(in *diagInputs) { in.Lists[0].Entries = 0 }},
		{"cert close", "sec.cert", "warn", func(in *diagInputs) { in.Cert.DaysLeft = 30 }},
		{"cert missing name", "sec.cert", "warn", func(in *diagInputs) { in.Cert.Missing = []string{"orbic"} }},
		{"no ssh keys", "sec.ssh", "fail", func(in *diagInputs) { in.SSH.Keys = nil }},
		{"ssh hammering", "sec.ssh", "warn", func(in *diagInputs) { in.SSH.Summary.Failed = 50 }},
		{"no snapshot", "sec.backup", "warn", func(in *diagInputs) { in.Snapshots = nil }},
		{"old snapshot", "sec.backup", "info", func(in *diagInputs) { in.Snapshots[0].Created = in.Now.Add(-40 * 24 * time.Hour).Format(time.RFC3339) }},
		{"vpn down", "vpn", "warn", func(in *diagInputs) { in.VPN = &vpnStatus{Registered: true, Enabled: true, Up: false} }},
		{"vpn stale", "vpn", "warn", func(in *diagInputs) { in.VPN = &vpnStatus{Registered: true, Enabled: true, Up: true, HandshakeS: 500} }},
		{"vpn off", "vpn", "info", func(in *diagInputs) { in.VPN = &vpnStatus{Registered: true} }},
		{"fota running", "svc.fota", "warn", func(in *diagInputs) {
			in.Sys.Services = serviceTable(map[string]bool{"upgrade": true}, map[string]bool{}, nil)
		}},
	} {
		in := healthy()
		c.mod(&in)
		if got := find(evaluate(in), c.id); got.Status != c.want {
			t.Errorf("%s: %s is %q (%s), want %q", c.name, c.id, got.Status, got.Detail, c.want)
		}
	}
	// a service down is named; the 5 GHz radio being off is not a failure when the network is off
	in := healthy()
	in.Sys.Services = serviceTable(map[string]bool{"tinyfwd": true, "dnsmasq": true, "wland": true, "goahead": true, "upgrade": true}, map[string]bool{"upgrade": true}, []string{"hostapd_wlan0.conf", "QCMAP_ConnectionManager", "wpad-guard.sh"})
	in.Wifi5On = false
	in.Wifi.Live5 = &wifiLive{"", 0, 0}
	c := find(evaluate(in), "svc.all")
	if c.Status != "fail" || !strings.Contains(c.Detail, "dropbear") || strings.Contains(c.Detail, "hostapd,") {
		t.Errorf("services: %+v", c)
	}
	if b := find(evaluate(in), "wifi.bands"); b.Status != "ok" {
		t.Errorf("5 GHz off must not fail the radios: %+v", b)
	}
}

func TestDiagReportIsShareable(t *testing.T) {
	in := healthy()
	in.Cell.IPv6 = "2600:100a:b03e:ff2:5551:9cb6:fe78:7b98"
	in.Sys.Temps = []sysTemp{{"a", 80}}
	cs := evaluate(in)
	r := diagResult{RanAt: "now", TookMS: 5, Version: "x", Checks: cs, Counts: diagCounts(cs)}
	txt := diagReport(r)
	for _, bad := range []string{"2600:", "aa:bb", "ExampleNet", "psk", "PRIVATE", "100.110", "fe78"} {
		if bad != "" && strings.Contains(txt, bad) {
			t.Errorf("the report contains %q", bad)
		}
	}
	if !strings.Contains(txt, "[FAIL] Temperature") || !strings.Contains(txt, "-> Too hot") || !strings.Contains(txt, "== Internet ==") || !strings.Contains(txt, "No device names") {
		t.Errorf("report shape:\n%s", txt)
	}
}
