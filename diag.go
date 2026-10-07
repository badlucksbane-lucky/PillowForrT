package main

// Diagnostics: one click runs every check we can make about the Orbic and says, in plain words, what is fine, what deserves a look and what is broken. The checks run on the box
// itself (network probes included) and read the same state the pages show. The text report is for sharing: it never contains device names, MACs, SMS, keys, passwords or full
// IPv6 addresses, and it names no one. The evaluation is a pure function of the gathered inputs (`evaluate`), so every threshold is unit-tested.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type diagCheck struct {
	ID     string `json:"id"`
	Group  string `json:"group"`
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail | info
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

type diagResult struct {
	RanAt   string         `json:"ran_at"`
	TookMS  int64          `json:"took_ms"`
	Version string         `json:"version"`
	Checks  []diagCheck    `json:"checks"`
	Counts  map[string]int `json:"counts"`
}

type tcpProbe struct {
	Target string
	MS     float64
	Err    string
}

type diagInputs struct {
	Now        time.Time
	TCP        []tcpProbe // IPv4 targets
	TCP6       *tcpProbe  // nil when the box has no global IPv6 address
	HasRoute   bool
	DNSMS      float64
	DNSErr     string
	BlockAns   []string // what the filter answered for a known ad domain
	BlockErr   string
	FilterMode string
	Upstream   upstreamState
	ClockDrift *time.Duration // upstream Date header minus our clock; nil if it could not be fetched
	ClockErr   string
	Sys        sysView
	Cell       cellView
	Wifi       wifiView
	Wifi5On    bool
	Pool       dhcpPool
	Leases     int // active leases now
	ResvOff    int // reserved devices online at a different address
	Lists      []listData
	Chains     map[string]bool // firewall chains and hooks present, by name
	VPN        *vpnStatus
	Cert       certView
	SSH        sshView
	Snapshots  []snapInfo
	Uptime     time.Duration
	StockAdmin *stockAdminView
	Canary     *canaryView
	Dnsmasq    *dnsmasqInfo
	Rogue      *rogueView
	Speed      *speedView
	Link       *linkView
	Tor        *torView
	ARP        *arpView
	Steer      *steerView
	Chain      *eventChain // the event log's hash chain, when the store is up
}

func ck(id, group, name, status, detail, hint string) diagCheck {
	return diagCheck{ID: id, Group: group, Name: name, Status: status, Detail: detail, Hint: hint}
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s) == 0 {
		return 0
	}
	return s[len(s)/2]
}

func evaluate(in diagInputs) []diagCheck {
	var out []diagCheck
	add := func(c diagCheck) { out = append(out, c) }

	// ---- internet ----
	switch {
	case !in.Cell.Up:
		add(ck("uplink.link", "Internet", "Cellular link", "fail", "the uplink interface is down", "Check the SIM and the carrier signal; the Orbic reconnects by itself, a reboot is the last resort."))
	case in.Cell.IPv4 == "" || !in.HasRoute:
		add(ck("uplink.link", "Internet", "Cellular link", "fail", "the link is up but there is no address or default route", "The data session may have dropped: wait a minute, then check the cellular card."))
	default:
		d := "up, with an IPv4 address and a default route"
		if in.Cell.CGNAT {
			d += " (carrier-grade NAT: shared, nothing can reach in from outside)"
		}
		add(ck("uplink.link", "Internet", "Cellular link", "ok", d, ""))
	}
	var okMS []float64
	var bad []string
	for _, p := range in.TCP {
		if p.Err == "" {
			okMS = append(okMS, p.MS)
		} else {
			bad = append(bad, p.Target)
		}
	}
	switch {
	case len(okMS) == 0:
		add(ck("uplink.reach", "Internet", "Reaching the internet", "fail", fmt.Sprintf("none of the %d test servers answered", len(in.TCP)), "The carrier may be down or the data session stuck."))
	case median(okMS) > 400:
		add(ck("uplink.reach", "Internet", "Reaching the internet", "warn", fmt.Sprintf("slow: %.0f ms to the nearest servers", median(okMS)), "Weak signal or a busy tower: try moving the Orbic."))
	case len(bad) > 0:
		add(ck("uplink.reach", "Internet", "Reaching the internet", "warn", fmt.Sprintf("%.0f ms, but %d of %d test servers did not answer", median(okMS), len(bad), len(in.TCP)), "One server may be blocked or down; if it persists, check the carrier."))
	default:
		add(ck("uplink.reach", "Internet", "Reaching the internet", "ok", fmt.Sprintf("%.0f ms to %d of %d test servers", median(okMS), len(okMS), len(in.TCP)), ""))
	}
	switch {
	case in.TCP6 == nil:
		add(ck("uplink.ipv6", "Internet", "IPv6", "info", "no global IPv6 address on the uplink", ""))
	case in.TCP6.Err != "":
		add(ck("uplink.ipv6", "Internet", "IPv6", "warn", "the uplink has an IPv6 address but IPv6 servers are unreachable", "Devices that prefer IPv6 fall back to IPv4, usually without trouble."))
	default:
		add(ck("uplink.ipv6", "Internet", "IPv6", "ok", fmt.Sprintf("reachable, %.0f ms", in.TCP6.MS), ""))
	}
	switch {
	case in.DNSErr != "":
		add(ck("dns.local", "DNS", "Name lookups", "fail", "a normal lookup failed: "+in.DNSErr, "Check the DNS filter card and the upstream state; DoH may be down."))
	case in.DNSMS > 1500:
		add(ck("dns.local", "DNS", "Name lookups", "warn", fmt.Sprintf("working but slow: %.0f ms", in.DNSMS), ""))
	default:
		add(ck("dns.local", "DNS", "Name lookups", "ok", fmt.Sprintf("a lookup through the filter took %.0f ms", in.DNSMS), ""))
	}
	switch {
	case in.FilterMode == "off":
		add(ck("dns.filter", "DNS", "Ad and tracker blocking", "info", "the DNS filter is switched off", ""))
	case in.BlockErr != "":
		add(ck("dns.filter", "DNS", "Ad and tracker blocking", "warn", "could not test: "+in.BlockErr, ""))
	case len(in.BlockAns) > 0 && (in.BlockAns[0] == "0.0.0.0" || in.BlockAns[0] == "::"):
		add(ck("dns.filter", "DNS", "Ad and tracker blocking", "ok", "a known ad domain is blocked ("+in.FilterMode+")", ""))
	default:
		add(ck("dns.filter", "DNS", "Ad and tracker blocking", "warn", "a known ad domain was NOT blocked", "The lists may not be loaded yet: see the lists on the DNS filter card."))
	}
	if in.Upstream.Mode == "plain-fallback" {
		add(ck("dns.upstream", "DNS", "Encrypted DNS", "warn", "DoH is failing: lookups are leaving as plain DNS", "Usually clears when the uplink recovers; if it does not, check that port 443 is reachable."))
	} else {
		add(ck("dns.upstream", "DNS", "Encrypted DNS", "ok", "lookups go out over DoH", ""))
	}
	switch {
	case in.ClockDrift == nil:
		add(ck("time.clock", "Internet", "Clock", "info", "could not check the clock against a server ("+in.ClockErr+")", ""))
	case abs(*in.ClockDrift) < time.Minute:
		add(ck("time.clock", "Internet", "Clock", "ok", fmt.Sprintf("within %.0f seconds of a reference server", abs(*in.ClockDrift).Seconds()), ""))
	case abs(*in.ClockDrift) < time.Hour:
		add(ck("time.clock", "Internet", "Clock", "warn", fmt.Sprintf("off by %.0f minutes", abs(*in.ClockDrift).Minutes()), "Schedules and certificates depend on the clock; it normally resyncs by itself."))
	default:
		add(ck("time.clock", "Internet", "Clock", "fail", fmt.Sprintf("off by %.1f hours", abs(*in.ClockDrift).Hours()), "Certificates and schedules will misbehave until it is corrected."))
	}

	// ---- home network ----
	sv := map[string]sysService{}
	for _, s := range in.Sys.Services {
		sv[s.Name] = s
	}
	var down []string
	for _, s := range in.Sys.Services {
		if s.State == "running" || s.State == "held" {
			continue
		}
		if strings.HasPrefix(s.Name, "hostapd, 5") && !in.Wifi5On {
			continue
		}
		down = append(down, strings.Fields(s.Name)[0])
	}
	if len(down) > 0 {
		add(ck("svc.all", "Services", "Services", "fail", "not running: "+strings.Join(down, ", "), "The guard restarts most of these within a minute; if one stays down, see the system card and the logs."))
	} else {
		add(ck("svc.all", "Services", "Services", "ok", "every service that should run is running", ""))
	}
	if u, ok := sv["carrier updates (upgrade)"]; ok && u.State != "held" {
		if u.State == "running" {
			add(ck("svc.fota", "Services", "Carrier firmware updates", "warn", "the update daemon is running, not held", "The guard stops it within a minute."))
		}
	} else if ok {
		add(ck("svc.fota", "Services", "Carrier firmware updates", "ok", "held stopped: the carrier cannot push a firmware update", ""))
	}
	b24 := in.Wifi.Live.Hostapd == "ENABLED"
	b5 := in.Wifi.Live5 != nil && in.Wifi5On && in.Wifi.Live5.Hostapd == "ENABLED"
	switch {
	case !b24:
		add(ck("wifi.bands", "Wi-Fi", "Wi-Fi radios", "fail", "the 2.4 GHz radio is not up ("+in.Wifi.Live.Hostapd+")", "Use the Wi-Fi card's Undo, or reboot from the system card."))
	case in.Wifi5On && !b5:
		add(ck("wifi.bands", "Wi-Fi", "Wi-Fi radios", "fail", "the 5 GHz network is switched on but the radio is not up", "Turn it off and on again on the Wi-Fi card."))
	default:
		d := fmt.Sprintf("2.4 GHz up on channel %d", in.Wifi.Live.Channel)
		if b5 {
			d += fmt.Sprintf(", 5 GHz up on channel %d", in.Wifi.Live5.Channel)
		}
		add(ck("wifi.bands", "Wi-Fi", "Wi-Fi radios", "ok", d, ""))
	}
	add(ck("wifi.clients", "Wi-Fi", "Connected devices", "info", fmt.Sprintf("%d device(s) on the Wi-Fi", len(in.Wifi.Clients)), ""))
	size := int(ipNum(in.Pool.End)) - int(ipNum(in.Pool.Start)) + 1
	switch {
	case size <= 0:
		add(ck("dhcp.pool", "Home network", "Address pool", "warn", "could not read the DHCP pool", ""))
	case in.Leases*100/size > 80:
		add(ck("dhcp.pool", "Home network", "Address pool", "warn", fmt.Sprintf("%d of %d addresses in use", in.Leases, size), "Widen the pool or shorten the lease time on the DHCP pool card."))
	default:
		add(ck("dhcp.pool", "Home network", "Address pool", "ok", fmt.Sprintf("%d of %d addresses in use", in.Leases, size), ""))
	}
	if in.ResvOff > 0 {
		add(ck("dhcp.resv", "Home network", "Reserved addresses", "warn", fmt.Sprintf("%d reserved device(s) are online at a different address", in.ResvOff), "Use Move now on the DHCP reservations card, or toggle the device's Wi-Fi."))
	} else {
		add(ck("dhcp.resv", "Home network", "Reserved addresses", "ok", "every online reserved device has its reserved address", ""))
	}
	missing := []string{}
	need := []string{"HS_MACBLOCK", "HS_FW", "HS_FWIN", "HS_FWOUT"}
	if in.VPN != nil && in.VPN.Enabled { // the kill-switch chain is only hooked in while the VPN is on (after a reboot it appears with the VPN, not at boot)
		need = append(need, "HS_KILL")
	}
	for _, c := range need {
		if !in.Chains[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		add(ck("fw.hooks", "Home network", "Firewall rules", "warn", "our firewall chains are not all hooked in: "+strings.Join(missing, ", "), "They are re-asserted within 20 seconds; if this persists, check the services."))
	} else {
		add(ck("fw.hooks", "Home network", "Firewall rules", "ok", "our firewall chains are in place", ""))
	}
	var stale, empty []string
	for _, l := range in.Lists {
		switch {
		case l.Err != "":
			add(ck("list."+l.Name, "DNS", "Block list "+l.Name, "warn", "the last update failed: "+l.Err, "It retries by itself; use Update lists now on the DNS card."))
		case l.Entries == 0:
			empty = append(empty, l.Name)
		case !l.Updated.IsZero() && in.Now.Sub(l.Updated) > 72*time.Hour:
			stale = append(stale, l.Name)
		}
	}
	switch {
	case len(empty) > 0 && in.FilterMode != "off":
		add(ck("dns.lists", "DNS", "Block lists", "warn", "no entries loaded for: "+strings.Join(empty, ", "), "Use Update lists now on the DNS card."))
	case len(stale) > 0:
		add(ck("dns.lists", "DNS", "Block lists", "warn", "not updated for over 3 days: "+strings.Join(stale, ", "), "Use Update lists now on the DNS card."))
	default:
		add(ck("dns.lists", "DNS", "Block lists", "ok", "loaded and recent", ""))
	}
	switch {
	case in.VPN == nil || !in.VPN.Registered:
		add(ck("vpn", "VPN", "VPN", "info", "no VPN is registered", ""))
	case !in.VPN.Enabled:
		add(ck("vpn", "VPN", "VPN", "info", "registered but switched off", ""))
	case !in.VPN.Up:
		add(ck("vpn", "VPN", "VPN", "warn", "switched on but the tunnel is down", "Devices set to exit through it are blocked while the kill switch is on; use the VPN card."))
	case in.VPN.HandshakeS > 240:
		add(ck("vpn", "VPN", "VPN", "warn", fmt.Sprintf("up, but the last handshake was %d s ago", in.VPN.HandshakeS), "The tunnel may be stale."))
	default:
		add(ck("vpn", "VPN", "VPN", "ok", "tunnel up", ""))
	}

	// ---- the box ----
	switch am := in.Sys.MemAvailKB / 1024; {
	case am < 20:
		add(ck("box.mem", "The Orbic itself", "Memory", "fail", fmt.Sprintf("only %d MB available", am), "Something is using too much: reboot from the system card."))
	case am < 40:
		add(ck("box.mem", "The Orbic itself", "Memory", "warn", fmt.Sprintf("%d MB available of %d", am, in.Sys.MemTotalKB/1024), ""))
	default:
		add(ck("box.mem", "The Orbic itself", "Memory", "ok", fmt.Sprintf("%d MB available of %d", am, in.Sys.MemTotalKB/1024), ""))
	}
	if in.Sys.Load[0] > 2.5 {
		add(ck("box.load", "The Orbic itself", "Load", "warn", fmt.Sprintf("load %.2f on one core", in.Sys.Load[0]), "Busy for now; if it stays high, look at what is running."))
	} else {
		add(ck("box.load", "The Orbic itself", "Load", "ok", fmt.Sprintf("load %.2f on one core", in.Sys.Load[0]), ""))
	}
	maxT := 0.0
	for _, t := range in.Sys.Temps {
		if t.C > maxT {
			maxT = t.C
		}
	}
	switch {
	case maxT >= 75:
		add(ck("box.temp", "The Orbic itself", "Temperature", "fail", fmt.Sprintf("%.0f°C", maxT), "Too hot: move it somewhere cooler and out of the sun."))
	case maxT >= 65:
		add(ck("box.temp", "The Orbic itself", "Temperature", "warn", fmt.Sprintf("%.0f°C", maxT), "Warm: give it some airflow."))
	default:
		add(ck("box.temp", "The Orbic itself", "Temperature", "ok", fmt.Sprintf("%.0f°C at the hottest sensor", maxT), ""))
	}
	for _, d := range in.Sys.Disks {
		if d.TotalB == 0 {
			continue
		}
		used := int((d.TotalB - d.FreeB) * 100 / d.TotalB)
		id := "box.disk." + d.Path
		switch {
		case d.Path == "/":
			add(ck(id, "The Orbic itself", d.Name, "info", fmt.Sprintf("%d%% full: fixed by the firmware, nothing should be added", used), ""))
		case used >= 90:
			add(ck(id, "The Orbic itself", d.Name, "warn", fmt.Sprintf("%d%% full", used), "Free some space."))
		default:
			add(ck(id, "The Orbic itself", d.Name, "ok", fmt.Sprintf("%d%% full", used), ""))
		}
	}
	if in.Sys.Battery.Known {
		if in.Sys.Battery.MV < 3500 {
			add(ck("box.battery", "The Orbic itself", "Battery", "warn", fmt.Sprintf("%.2f V: low", float64(in.Sys.Battery.MV)/1000), "Keep it on power."))
		} else {
			add(ck("box.battery", "The Orbic itself", "Battery", "ok", fmt.Sprintf("%.2f V", float64(in.Sys.Battery.MV)/1000), ""))
		}
	}
	switch {
	case len(in.Cert.Missing) > 0:
		add(ck("sec.cert", "Security", "Web page certificate", "warn", "does not cover: "+strings.Join(in.Cert.Missing, ", "), "It renews itself within hours; or press Renew now."))
	case in.Cert.DaysLeft < 60:
		add(ck("sec.cert", "Security", "Web page certificate", "warn", fmt.Sprintf("%d days left", in.Cert.DaysLeft), "It renews itself; or press Renew now."))
	default:
		add(ck("sec.cert", "Security", "Web page certificate", "ok", fmt.Sprintf("%d days left", in.Cert.DaysLeft), ""))
	}
	switch {
	case len(in.SSH.Keys) == 0:
		add(ck("sec.ssh", "Security", "SSH access", "fail", "no authorised keys: ssh login is impossible", "Recovery is over the USB cable."))
	case in.SSH.Summary.Failed > 10:
		add(ck("sec.ssh", "Security", "SSH access", "warn", fmt.Sprintf("%d failed login attempts since the last reboot", in.SSH.Summary.Failed), "Look at the audit log on the SSH card."))
	default:
		add(ck("sec.ssh", "Security", "SSH access", "ok", fmt.Sprintf("%d key(s), %d failed attempts since the last reboot", len(in.SSH.Keys), in.SSH.Summary.Failed), ""))
	}
	switch {
	case len(in.Snapshots) == 0:
		add(ck("sec.backup", "Security", "Settings backup", "warn", "no settings snapshot exists", "Save one on the Backup card, and download a copy."))
	default:
		newest := time.Time{}
		for _, s := range in.Snapshots {
			if t, err := time.Parse(time.RFC3339, s.Created); err == nil && t.After(newest) {
				newest = t
			}
		}
		if !newest.IsZero() && in.Now.Sub(newest) > 30*24*time.Hour {
			add(ck("sec.backup", "Security", "Settings backup", "info", fmt.Sprintf("the newest snapshot is %d days old", int(in.Now.Sub(newest).Hours()/24)), "Save a fresh one if you changed settings since."))
		} else {
			add(ck("sec.backup", "Security", "Settings backup", "ok", fmt.Sprintf("%d snapshot(s) kept", len(in.Snapshots)), ""))
		}
	}
	if in.StockAdmin != nil {
		switch {
		case in.StockAdmin.Off && !in.StockAdmin.RulesIn:
			add(ck("sec.stockadmin", "Security", "Stock admin", "warn", "switched off, but the firewall rules that shut it out are not in place", "They are re-applied within 20 seconds; if this persists, look at the services."))
		case in.StockAdmin.Off:
			add(ck("sec.stockadmin", "Security", "Stock admin", "ok", "switched off for the network: its ports are shut and 192.168.1.1 shows this page", ""))
		default:
			add(ck("sec.stockadmin", "Security", "Stock admin", "info", "still reachable on the network: its software is old and has a public history of weaknesses", "Switch it off on the system card (the SIM PIN is the one thing it is still needed for)."))
		}
	}
	if d := in.Dnsmasq; d != nil {
		switch {
		case !d.Running:
			add(ck("dns.dnsmasq", "Home network", "DHCP and DNS server", "fail", "dnsmasq is not running", "The guard and the swap script restart it; if it stays down, reboot from the system card."))
		case !d.Ours:
			add(ck("dns.dnsmasq", "Home network", "DHCP and DNS server", "warn", "running the stock dnsmasq 2.73, not our 2.91: per-device DNS counts and the DHCP hook are off", "The upgrade retries by itself every 5 minutes after a failed start (3 tries, then it stops: see dnsmasq-swap.log)."))
		case d.HookWanted && !d.Hook:
			add(ck("dns.dnsmasq", "Home network", "DHCP and DNS server", "warn", "dnsmasq 2.91 is running but without the DHCP hook (arrival and vendor details are not being learned)", "The swap script re-attaches it within a minute."))
		default:
			add(ck("dns.dnsmasq", "Home network", "DHCP and DNS server", "ok", "our dnsmasq 2.91 is running with the DHCP hook attached", ""))
		}
	}
	if in.Canary != nil && in.Canary.Enabled {
		switch {
		case !in.Canary.AliasOK || !in.Canary.CaptureOK:
			add(ck("sec.canary", "Security", "Canary address", "warn", "the decoy address is not fully in place (address "+yn(in.Canary.AliasOK)+", watcher "+yn(in.Canary.CaptureOK)+")", "It is re-applied every 20 seconds; if this persists, look at the canary card."))
		case len(in.Canary.Sources) > 0:
			add(ck("sec.canary", "Security", "Canary address", "warn", fmt.Sprintf("%d source(s) have touched the decoy address in the last hour", len(in.Canary.Sources)), "Something on the network is looking around: see the canary card."))
		default:
			add(ck("sec.canary", "Security", "Canary address", "ok", "the decoy address is in place and nothing has touched it", ""))
		}
	}
	if in.Chain != nil && in.Chain.Length > 0 {
		if in.Chain.OK {
			add(ck("sec.eventlog", "Security", "Event log", "ok", fmt.Sprintf("the hash chain holds across %d linked events", in.Chain.Length), ""))
		} else {
			add(ck("sec.eventlog", "Security", "Event log", "warn", fmt.Sprintf("the hash chain is broken at event %d: the log on flash was edited, truncated or corrupted", in.Chain.BrokenAt), "A root shell could have done this, or a bad write; clearing the log from the page starts a fresh chain."))
		}
	}
	if t := in.Tor; t != nil && (t.Enabled || len(t.Devices) > 0) {
		switch {
		case !t.Installed:
			add(ck("sec.tor", "Security", "Tor", "warn", "Tor is switched on but its program is not installed on the Orbic", "Deploy it with orbic-proxy/deploy-tor.sh."))
		case t.Ready:
			add(ck("sec.tor", "Security", "Tor", "ok", fmt.Sprintf("Tor is ready (%d device(s) routed through it, %.0f MB in use)", len(t.Devices), t.RSSMB), ""))
		case len(t.Devices) > 0:
			add(ck("sec.tor", "Security", "Tor", "fail", fmt.Sprintf("%d device(s) are set to use Tor but Tor is not ready (%s): they have no internet until it is", len(t.Devices), torState(*t)), "This is deliberate (fail closed). Look at the Tor card; unassign a device to give it its direct line back."))
		default:
			add(ck("sec.tor", "Security", "Tor", "warn", "Tor is switched on but not ready ("+torState(*t)+")", "It needs a minute or two after starting; see the Tor card."))
		}
	}
	if l := in.Link; l != nil && l.Probes > 0 {
		d := fmt.Sprintf("last 24 hours: %.1f%% of checks failed, %d outage(s), average connect %.0f ms", l.LossPct, l.Outages24, l.AvgMs)
		if l.LossPct >= 2 || l.Outages24 > 0 {
			add(ck("uplink.history", "Internet", "Link quality", "warn", d, "See the latency and loss history card for when."))
		} else {
			add(ck("uplink.history", "Internet", "Link quality", "ok", d, ""))
		}
	}
	if sp := in.Speed; sp != nil && sp.Enabled && sp.Last != nil {
		switch {
		case sp.Last.Err != "":
			add(ck("uplink.speed", "Internet", "Speed test", "warn", "the last speed test failed: "+sp.Last.Err, "A one-off failure is normal on a weak signal; if it repeats, look at the cellular card."))
		default:
			add(ck("uplink.speed", "Internet", "Speed test", "ok", fmt.Sprintf("last test %s down, %s up", fmtMbit(sp.Last.Down), fmtMbit(sp.Last.Up)), ""))
		}
	}
	if a := in.ARP; a != nil {
		switch {
		case a.Alerts > 0:
			var first arpFinding
			for _, f := range a.Findings {
				if f.Kind != "arp_flip" {
					first = f
					break
				}
			}
			add(ck("sec.arp", "Security", "ARP spoofing", "fail", fmt.Sprintf("%d address claim(s) in the last day look like impersonation (latest: %s claimed by %s)", a.Alerts, first.IP, first.MAC), "See the ARP watch card; find the device with that MAC."))
		case !a.CaptureOK:
			add(ck("sec.arp", "Security", "ARP spoofing", "warn", "the ARP watcher is not running", "It retries every minute."))
		case a.Sweeps > 0:
			add(ck("sec.arp", "Security", "ARP spoofing", "warn", fmt.Sprintf("%d host scan(s) of the LAN in the last day (one device asking for 20 or more addresses within a minute)%s", a.Sweeps, plural(len(a.Findings)-a.Sweeps, ", and %d address(es) quickly changed owner")), "A new phone or a discovery app does this once; a scanner or a worm keeps doing it. See the ARP watch card for the device."))
		case len(a.Findings) > 0:
			add(ck("sec.arp", "Security", "ARP spoofing", "warn", fmt.Sprintf("%d address(es) quickly changed owner in the last day", len(a.Findings)), "Often a device rejoining under a new random MAC; see the ARP watch card."))
		default:
			add(ck("sec.arp", "Security", "ARP spoofing", "ok", fmt.Sprintf("no impersonation seen (%d address claims watched)", a.Claims), ""))
		}
	}
	if st := in.Steer; st != nil {
		switch {
		case st.Alerts > 0:
			add(ck("sec.steer", "Security", "Other routers", "fail", fmt.Sprintf("%d router advertisement(s) or redirect(s) from %d device(s) other than the Orbic in the last day (latest: %s)", st.Alerts, st.Sources, st.Messages[0].MAC), "See the Steering watch card; find that device, or allow it there if it is a router you run yourself."))
		case !st.CaptureOK:
			add(ck("sec.steer", "Security", "Other routers", "warn", "the steering watcher is not running", "It retries every minute."))
		default:
			add(ck("sec.steer", "Security", "Other routers", "ok", fmt.Sprintf("only the Orbic has announced a route (%d of its own seen)", st.Honest), ""))
		}
	}
	if r := in.Rogue; r != nil {
		switch {
		case len(r.Servers) > 0:
			add(ck("sec.rogue_dhcp", "Security", "Other DHCP servers", "fail", fmt.Sprintf("%d other DHCP server(s) answered on the network in the last day (first: %s, %s)", len(r.Servers), r.Servers[0].IP, r.Servers[0].MAC), "See the Rogue DHCP card for the address and MAC; unplug or find that device."))
		case !r.CaptureOK:
			add(ck("sec.rogue_dhcp", "Security", "Other DHCP servers", "warn", "the DHCP watcher is not running", "It retries every minute."))
		default:
			add(ck("sec.rogue_dhcp", "Security", "Other DHCP servers", "ok", fmt.Sprintf("only the Orbic has answered DHCP (%d replies seen)", r.Honest), ""))
		}
	}
	add(ck("tinyfwd", "The Orbic itself", "Web page and proxy", "info", fmt.Sprintf("tinyfwd %s, running for %s", version, in.Uptime.Round(time.Minute)), ""))
	return out
}

// dnsmasqInfo says which dnsmasq is serving the house and whether our hook script is attached.
type dnsmasqInfo struct{ Running, Ours, Hook, HookWanted bool }

func readDnsmasq() *dnsmasqInfo {
	b, err := os.ReadFile("/data/dnsmasq.pid")
	if err != nil {
		return &dnsmasqInfo{}
	}
	pid := strings.TrimSpace(string(b))
	exe, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil {
		return &dnsmasqInfo{}
	}
	cmd, _ := os.ReadFile("/proc/" + pid + "/cmdline")
	d := &dnsmasqInfo{Running: true, Ours: exe == "/data/proxy/dnsmasq", Hook: strings.Contains(string(cmd), "--dhcp-script=/data/proxy/dhcp-hook.sh")}
	if fi, err := os.Stat("/data/proxy/dhcp-hook.sh"); err == nil && fi.Mode()&0o111 != 0 {
		d.HookWanted = true
	}
	return d
}

func yn(b bool) string {
	if b {
		return "ok"
	}
	return "missing"
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func diagCounts(cs []diagCheck) map[string]int {
	m := map[string]int{"ok": 0, "warn": 0, "fail": 0, "info": 0}
	for _, c := range cs {
		m[c.Status]++
	}
	return m
}

// diagReport renders the shareable text report (see the header: nothing personal goes in).
func diagReport(r diagResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Orbic diagnostics report\nRun: %s   tinyfwd %s   took %d ms\n", r.RanAt, r.Version, r.TookMS)
	fmt.Fprintf(&b, "Result: %d ok, %d to look at, %d broken, %d notes\n", r.Counts["ok"], r.Counts["warn"], r.Counts["fail"], r.Counts["info"])
	fmt.Fprintf(&b, "(No device names, MACs, messages, keys or passwords are included.)\n")
	group := ""
	mark := map[string]string{"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "info": "INFO"}
	for _, c := range r.Checks {
		if c.Group != group {
			group = c.Group
			fmt.Fprintf(&b, "\n== %s ==\n", group)
		}
		fmt.Fprintf(&b, "[%s] %s: %s\n", mark[c.Status], c.Name, c.Detail)
		if c.Hint != "" && (c.Status == "warn" || c.Status == "fail") {
			fmt.Fprintf(&b, "       -> %s\n", c.Hint)
		}
	}
	return b.String()
}

// ---- gathering (the only part that touches the network and the system) ----

func tcpTime(network, addr string) tcpProbe {
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	// the daemon itself runs with -4 (dialUpstream turns every dial into IPv4), so the IPv6 probe must dial directly to test what the uplink can really do
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	p := tcpProbe{Target: addr, MS: float64(time.Since(t0).Microseconds()) / 1000}
	if err != nil {
		p.Err = "unreachable"
		return p
	}
	c.Close()
	return p
}

func lookupVia(host string) ([]string, float64, error) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "127.0.0.1:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t0 := time.Now()
	a, err := r.LookupHost(ctx, host)
	return a, float64(time.Since(t0).Microseconds()) / 1000, err
}

func clockDrift() (*time.Duration, string) {
	c := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12}, DialContext: dialUpstream}}
	t0 := time.Now()
	resp, err := c.Head("https://1.1.1.1/")
	if err != nil {
		return nil, "no answer"
	}
	resp.Body.Close()
	t, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return nil, "no date in the answer"
	}
	d := t.Sub(t0.Add(time.Since(t0) / 2))
	return &d, ""
}

func chainsPresent() map[string]bool {
	m := map[string]bool{}
	f, _ := run("iptables", "-S")
	for _, c := range []string{"HS_MACBLOCK", "HS_FW", "HS_FWIN", "HS_FWOUT", "HS_KILL"} {
		m[c] = strings.Contains(f, "-j "+c+"\n") || strings.HasSuffix(strings.TrimSpace(f), "-j "+c)
	}
	return m
}

func activeLeases(now time.Time) int {
	b, _ := os.ReadFile(*leasesFile)
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 {
			var exp int64
			fmt.Sscan(f[0], &exp)
			if exp == 0 || exp > now.Unix() {
				n++
			}
		}
	}
	return n
}

func gatherDiag() diagInputs {
	now := time.Now()
	in := diagInputs{Now: now, Uptime: time.Since(startTime)}
	in.Cell = readCell()
	route, _ := os.ReadFile("/proc/net/route")
	in.HasRoute = strings.Contains(string(route), "rmnet_data0\t00000000")
	var wg sync.WaitGroup
	var mu sync.Mutex
	probe := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	targets := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	in.TCP = make([]tcpProbe, len(targets))
	for i, t := range targets {
		i, t := i, t
		probe(func() { p := tcpTime("tcp4", t); mu.Lock(); in.TCP[i] = p; mu.Unlock() })
	}
	if in.Cell.IPv6 != "" {
		probe(func() { p := tcpTime("tcp6", "[2606:4700:4700::1111]:443"); mu.Lock(); in.TCP6 = &p; mu.Unlock() })
	}
	probe(func() {
		_, ms, err := lookupVia("example.com")
		mu.Lock()
		in.DNSMS = ms
		if err != nil {
			in.DNSErr = "no answer"
		}
		mu.Unlock()
	})
	probe(func() {
		a, _, err := lookupVia("doubleclick.net")
		mu.Lock()
		in.BlockAns = a
		if err != nil {
			in.BlockErr = "no answer"
		}
		mu.Unlock()
	})
	probe(func() { d, e := clockDrift(); mu.Lock(); in.ClockDrift, in.ClockErr = d, e; mu.Unlock() })
	in.Sys = readSystem()
	if wifi != nil {
		names, ipOf := lanNames()
		in.Wifi, _ = wifi.View(names, ipOf)
		raw, _ := os.ReadFile(wifi.env.xmlPath)
		in.Wifi5On = parseWifiSettings(string(raw)).Five.Enabled
	}
	if poolMgr != nil {
		if pv, err := poolMgr.View(); err == nil {
			in.Pool = pv.dhcpPool
		}
	}
	in.Leases = activeLeases(now)
	if dhcpMgr != nil {
		arp, _ := os.ReadFile("/proc/net/arp")
		v := dhcpMgr.View(string(arp), "", nil, "")
		for _, r := range v.Reservations {
			if r.SeenAs != "" {
				in.ResvOff++
			}
		}
	}
	if dnsProxy != nil {
		in.FilterMode = dnsProxy.Filter.Mode()
		in.Upstream = dnsProxy.Up.State()
		in.Lists = dnsProxy.Filter.Lists()
	}
	in.Chains = chainsPresent()
	if vpn != nil {
		st := vpn.Status()
		in.VPN = &st
	}
	if certMgr != nil {
		in.Cert = certMgr.View()
	}
	if sshMgr != nil {
		in.SSH = sshMgr.View()
	}
	if stockMgr != nil {
		v := stockMgr.View()
		in.StockAdmin = &v
	}
	if canaryMgr != nil {
		v := canaryMgr.View()
		in.Canary = &v
	}
	if events != nil {
		c := events.Chain()
		in.Chain = &c
	}
	if rogueMgr != nil {
		v := rogueMgr.View()
		in.Rogue = &v
	}
	if speedMgr != nil {
		v := speedMgr.View()
		in.Speed = &v
	}
	if linkMgr != nil {
		v := linkMgr.View(24)
		in.Link = &v
	}
	if torMgrG != nil {
		v := torMgrG.View()
		in.Tor = &v
	}
	if arpMgr != nil {
		v := arpMgr.View()
		in.ARP = &v
	}
	if steerMgr != nil {
		v := steerMgr.View()
		in.Steer = &v
	}
	if _, err := os.Stat("/data/dnsmasq.pid"); err == nil {
		in.Dnsmasq = readDnsmasq()
	}
	if snaps != nil {
		in.Snapshots = snaps.List()
	}
	wg.Wait()
	return in
}

// plural formats n into format when n is above zero and gives "" otherwise, for an optional clause in a sentence.
func plural(n int, format string) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(format, n)
}

var (
	diagMu   sync.Mutex
	diagLast *diagResult
)

func runDiag() diagResult {
	t0 := time.Now()
	in := gatherDiag()
	cs := evaluate(in)
	r := diagResult{RanAt: t0.In(schedLoc()).Format("2006-01-02 15:04:05 MST"), TookMS: time.Since(t0).Milliseconds(), Version: version, Checks: cs, Counts: diagCounts(cs)}
	diagMu.Lock()
	diagLast = &r
	diagMu.Unlock()
	return r
}

// torState says in a few words why Tor is not ready.
func torState(t torView) string {
	switch {
	case t.Yielding:
		return "paused to protect the router's memory"
	case !t.Enabled:
		return "switched off"
	case !t.Running:
		if t.Err != "" {
			return t.Err
		}
		return "not running"
	default:
		return fmt.Sprintf("connecting, %d%%", t.Boot)
	}
}
