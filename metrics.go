package main

// /metrics: the box's numbers in the Prometheus text format (version 0.0.4), for Prometheus, Grafana Agent, VictoriaMetrics or a plain `curl`. Served on the same two
// listeners as /status.json (plain HTTP on the LAN: http://192.168.1.254/metrics or :3128/metrics, and the HTTPS page), LAN-only like everything else here, and **aggregate
// only**: no device names, MACs, IP addresses, host names, message text or keys, so it is safe to scrape without a login (anything per-device stays behind the login). The
// text is built at most every 10 seconds (the expensive reads run once per interval, however many scrapers ask). Counters reset when tinyfwd or the box restarts, which
// Prometheus' rate() expects.

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type mbuilder struct {
	b    strings.Builder
	seen map[string]bool
}

func newMB() *mbuilder { return &mbuilder{seen: map[string]bool{}} }

func escLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

// metric writes one sample, with its HELP and TYPE lines the first time the name is used. labels are key, value pairs.
func (m *mbuilder) metric(name, typ, help string, v float64, labels ...string) {
	if !m.seen[name] {
		m.seen[name] = true
		fmt.Fprintf(&m.b, "# HELP %s %s\n# TYPE %s %s\n", name, strings.ReplaceAll(help, "\n", " "), name, typ)
	}
	m.b.WriteString(name)
	if len(labels) >= 2 {
		m.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				m.b.WriteByte(',')
			}
			fmt.Fprintf(&m.b, `%s="%s"`, labels[i], escLabel(labels[i+1]))
		}
		m.b.WriteByte('}')
	}
	m.b.WriteByte(' ')
	m.b.WriteString(strconv.FormatFloat(math.Round(v*1e6)/1e6, 'g', -1, 64)) // six decimals: no float noise in the output
	m.b.WriteByte('\n')
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metricsIn is everything the text is built from; every field is optional (a missing source just means no samples for it).
type metricsIn struct {
	Now            time.Time
	Version        string
	DaemonUptime   float64
	Goroutines     int
	HeapBytes      uint64
	Uplink         *uplinkState
	Cell           *cellView
	Sys            *sysView
	UsageDown      float64
	UsageUp        float64
	UsageSet       bool
	ProxyConnsTot  uint64
	ProxyConnsAct  int64
	ProxyUp        uint64
	ProxyDown      uint64
	DNS            *dnsM
	Wifi24Up       *bool
	Wifi5Up        *bool
	Wifi24Clients  int
	Wifi5Clients   int
	Leases         int
	PoolSize       int
	Reservations   int
	BlockedDevices int
	BlockedDests   int
	Schedules      int
	PausedDevices  int
	VPN            *vpnStatus
	CertNotAfter   int64
	CertDaysLeft   int
	SSHLogins      int
	SSHFailed      int
	EventsUnseen   int
	StockAdminOff  *bool
	GraphSamples   int
	Dnsmasq        *dnsmasqInfo
	Rogue          *rogueView
	Speed          *speedView
	Link           *linkView
	Tor            *torView
	ARP            *arpView
	Steer          *steerView
}

type dnsM struct {
	Queries, Blocked, Cached, DoH, Errors uint64
	CacheEntries                          int
	Fallback                              bool
	Lists                                 []listData
	Mode                                  string
}

func buildMetrics(in metricsIn) string {
	m := newMB()
	m.metric("pillowforrt_build_info", "gauge", "tinyfwd version (the value is always 1).", 1, "version", in.Version)
	m.metric("pillowforrt_daemon_uptime_seconds", "gauge", "Seconds since tinyfwd started.", in.DaemonUptime)
	m.metric("pillowforrt_daemon_goroutines", "gauge", "Goroutines in tinyfwd.", float64(in.Goroutines))
	m.metric("pillowforrt_daemon_heap_bytes", "gauge", "Go heap in use by tinyfwd.", float64(in.HeapBytes))
	if u := in.Uplink; u != nil {
		m.metric("pillowforrt_uplink_up", "gauge", "1 if the last probe of the cellular uplink answered.", b2f(u.OK))
		m.metric("pillowforrt_uplink_latency_seconds", "gauge", "Latency of the last successful uplink probe (TCP connect).", u.LatencyMs/1000)
		m.metric("pillowforrt_uplink_consecutive_failures", "gauge", "Failed uplink probes in a row.", float64(u.Fails))
		m.metric("pillowforrt_uplink_last_check_timestamp_seconds", "gauge", "Unix time of the last uplink probe.", float64(u.Checked))
	}
	if c := in.Cell; c != nil {
		m.metric("pillowforrt_uplink_interface_up", "gauge", "1 if the cellular data interface is up.", b2f(c.Up))
		m.metric("pillowforrt_uplink_receive_bytes_total", "counter", "Bytes received on the cellular interface since boot.", float64(c.RxBytes))
		m.metric("pillowforrt_uplink_transmit_bytes_total", "counter", "Bytes sent on the cellular interface since boot.", float64(c.TxBytes))
		m.metric("pillowforrt_uplink_receive_packets_total", "counter", "Packets received on the cellular interface since boot.", float64(c.RxPackets))
		m.metric("pillowforrt_uplink_transmit_packets_total", "counter", "Packets sent on the cellular interface since boot.", float64(c.TxPackets))
		m.metric("pillowforrt_uplink_receive_errors_total", "counter", "Receive errors on the cellular interface.", float64(c.RxErrors))
		m.metric("pillowforrt_uplink_transmit_errors_total", "counter", "Transmit errors on the cellular interface.", float64(c.TxErrors))
		m.metric("pillowforrt_uplink_receive_drops_total", "counter", "Receive drops on the cellular interface.", float64(c.RxDrops))
		m.metric("pillowforrt_uplink_transmit_drops_total", "counter", "Transmit drops on the cellular interface.", float64(c.TxDrops))
		m.metric("pillowforrt_uplink_cgnat", "gauge", "1 if the uplink address is carrier-grade NAT (nothing can reach in).", b2f(c.CGNAT))
	}
	if in.UsageSet {
		m.metric("pillowforrt_data_cycle_receive_bytes", "gauge", "Bytes downloaded in the current billing cycle (counted by the vantage node).", in.UsageDown)
		m.metric("pillowforrt_data_cycle_transmit_bytes", "gauge", "Bytes uploaded in the current billing cycle.", in.UsageUp)
	}
	m.metric("pillowforrt_proxy_connections_total", "counter", "Proxy connections accepted since tinyfwd started.", float64(in.ProxyConnsTot))
	m.metric("pillowforrt_proxy_connections_active", "gauge", "Proxy connections open now.", float64(in.ProxyConnsAct))
	m.metric("pillowforrt_proxy_upload_bytes_total", "counter", "Bytes the proxy sent upstream.", float64(in.ProxyUp))
	m.metric("pillowforrt_proxy_download_bytes_total", "counter", "Bytes the proxy received from upstream.", float64(in.ProxyDown))
	if s := in.Sys; s != nil {
		m.metric("pillowforrt_uptime_seconds", "gauge", "Seconds since the box booted.", float64(s.UptimeS))
		m.metric("pillowforrt_load1", "gauge", "1-minute load average (one core).", s.Load[0])
		m.metric("pillowforrt_load5", "gauge", "5-minute load average.", s.Load[1])
		m.metric("pillowforrt_load15", "gauge", "15-minute load average.", s.Load[2])
		m.metric("pillowforrt_memory_total_bytes", "gauge", "Total RAM.", float64(s.MemTotalKB)*1024)
		m.metric("pillowforrt_memory_available_bytes", "gauge", "Available RAM.", float64(s.MemAvailKB)*1024)
		for _, t := range s.Temps {
			m.metric("pillowforrt_temperature_celsius", "gauge", "Temperature of a thermal sensor.", t.C, "sensor", t.Name)
		}
		for _, d := range s.Disks {
			m.metric("pillowforrt_filesystem_size_bytes", "gauge", "Size of a filesystem.", float64(d.TotalB), "mount", d.Path)
			m.metric("pillowforrt_filesystem_free_bytes", "gauge", "Free space on a filesystem.", float64(d.FreeB), "mount", d.Path)
		}
		if s.Battery.Known {
			m.metric("pillowforrt_battery_voltage_volts", "gauge", "Battery voltage as the firmware logs it.", float64(s.Battery.MV)/1000)
			m.metric("pillowforrt_battery_level", "gauge", "Battery level on the firmware's own scale.", float64(s.Battery.Level))
			m.metric("pillowforrt_battery_temperature_celsius", "gauge", "Battery temperature.", float64(s.Battery.TempC))
		}
		for _, sv := range s.Services {
			slug := serviceSlug(sv.Name)
			if slug == "hostapd_5ghz" && in.Wifi5Up == nil {
				continue // the 5 GHz network is switched off: its absence is not a failure
			}
			m.metric("pillowforrt_service_up", "gauge", "1 if the service is running (or held stopped on purpose).", b2f(sv.State == "running" || sv.State == "held"), "service", slug)
		}
	}
	if in.Wifi24Up != nil {
		m.metric("pillowforrt_wifi_radio_up", "gauge", "1 if the Wi-Fi radio is up.", b2f(*in.Wifi24Up), "band", "2.4ghz")
		m.metric("pillowforrt_wifi_clients", "gauge", "Devices associated with the radio.", float64(in.Wifi24Clients), "band", "2.4ghz")
	}
	if in.Wifi5Up != nil {
		m.metric("pillowforrt_wifi_radio_up", "gauge", "1 if the Wi-Fi radio is up.", b2f(*in.Wifi5Up), "band", "5ghz")
		m.metric("pillowforrt_wifi_clients", "gauge", "Devices associated with the radio.", float64(in.Wifi5Clients), "band", "5ghz")
	}
	m.metric("pillowforrt_dhcp_leases_active", "gauge", "DHCP leases currently active.", float64(in.Leases))
	m.metric("pillowforrt_dhcp_pool_size", "gauge", "Addresses in the dynamic DHCP pool.", float64(in.PoolSize))
	m.metric("pillowforrt_dhcp_reservations", "gauge", "DHCP reservations.", float64(in.Reservations))
	m.metric("pillowforrt_firewall_blocked_devices", "gauge", "Devices on the block list.", float64(in.BlockedDevices))
	m.metric("pillowforrt_firewall_blocked_destinations", "gauge", "Blocked destination addresses or ranges.", float64(in.BlockedDests))
	m.metric("pillowforrt_firewall_schedules", "gauge", "Internet schedules.", float64(in.Schedules))
	m.metric("pillowforrt_firewall_paused_devices", "gauge", "Devices whose internet is paused right now.", float64(in.PausedDevices))
	if d := in.DNS; d != nil {
		m.metric("pillowforrt_dns_queries_total", "counter", "DNS queries answered since tinyfwd started.", float64(d.Queries))
		m.metric("pillowforrt_dns_blocked_total", "counter", "DNS queries blocked by the filter.", float64(d.Blocked))
		m.metric("pillowforrt_dns_cached_total", "counter", "DNS queries answered from the cache.", float64(d.Cached))
		m.metric("pillowforrt_dns_upstream_doh_total", "counter", "Queries sent upstream over DoH.", float64(d.DoH))
		m.metric("pillowforrt_dns_errors_total", "counter", "DNS errors.", float64(d.Errors))
		m.metric("pillowforrt_dns_cache_entries", "gauge", "Entries in the DNS cache.", float64(d.CacheEntries))
		m.metric("pillowforrt_dns_upstream_failing", "gauge", "1 if encrypted DNS is failing and lookups are being refused (nothing is ever sent as plain DNS).", b2f(d.Fallback))
		m.metric("pillowforrt_dns_filter_enabled", "gauge", "1 if the DNS filter is on (any mode but off).", b2f(d.Mode != "off" && d.Mode != ""))
		for _, l := range d.Lists {
			m.metric("pillowforrt_dns_list_entries", "gauge", "Entries in a block list.", float64(l.Entries), "list", l.Name)
			if !l.Updated.IsZero() {
				m.metric("pillowforrt_dns_list_age_seconds", "gauge", "Seconds since a block list was last updated.", in.Now.Sub(l.Updated).Seconds(), "list", l.Name)
			}
		}
	}
	if v := in.VPN; v != nil && v.Registered {
		m.metric("pillowforrt_vpn_enabled", "gauge", "1 if the VPN exit is switched on.", b2f(v.Enabled))
		m.metric("pillowforrt_vpn_up", "gauge", "1 if the VPN tunnel is up.", b2f(v.Up))
		m.metric("pillowforrt_vpn_handshake_age_seconds", "gauge", "Seconds since the last VPN handshake.", float64(v.HandshakeS))
		m.metric("pillowforrt_vpn_receive_bytes_total", "counter", "Bytes received through the VPN.", float64(v.Rx))
		m.metric("pillowforrt_vpn_transmit_bytes_total", "counter", "Bytes sent through the VPN.", float64(v.Tx))
	}
	if in.CertNotAfter > 0 {
		m.metric("pillowforrt_web_certificate_expiry_timestamp_seconds", "gauge", "Unix time the web page certificate expires.", float64(in.CertNotAfter))
		m.metric("pillowforrt_web_certificate_days_left", "gauge", "Days until the web page certificate expires.", float64(in.CertDaysLeft))
	}
	m.metric("pillowforrt_ssh_logins", "gauge", "Successful ssh logins since the last reboot (the log is in RAM).", float64(in.SSHLogins))
	m.metric("pillowforrt_ssh_failed_attempts", "gauge", "Failed ssh login attempts since the last reboot.", float64(in.SSHFailed))
	m.metric("pillowforrt_events_unseen_attention", "gauge", "Events that need attention and have not been marked seen.", float64(in.EventsUnseen))
	if in.StockAdminOff != nil {
		m.metric("pillowforrt_stock_admin_off", "gauge", "1 if the stock admin is switched off for the network.", b2f(*in.StockAdminOff))
	}
	if d := in.Dnsmasq; d != nil {
		m.metric("pillowforrt_dnsmasq_running", "gauge", "1 if dnsmasq (DHCP and DNS) is running.", b2f(d.Running))
		m.metric("pillowforrt_dnsmasq_upgraded", "gauge", "1 if the running dnsmasq is our 2.91 build, not the stock 2.73.", b2f(d.Ours))
		m.metric("pillowforrt_dnsmasq_dhcp_hook", "gauge", "1 if dnsmasq runs our DHCP hook script.", b2f(d.Hook))
	}
	if r := in.Rogue; r != nil {
		m.metric("pillowforrt_rogue_dhcp_servers", "gauge", "Other DHCP servers that answered on the network in the last day (should be 0).", float64(len(r.Servers)))
	}
	if st := in.Steer; st != nil {
		m.metric("pillowforrt_steer_alerts", "gauge", "IPv6 router advertisements and ICMP redirects from anything other than the box in the last day (should be 0).", float64(st.Alerts))
	}
	if sp := in.Speed; sp != nil && sp.Last != nil && sp.Last.Err == "" {
		m.metric("pillowforrt_speedtest_download_bytes_per_second", "gauge", "Download rate of the last scheduled speed test (a small test, for trends).", sp.Last.Down)
		m.metric("pillowforrt_speedtest_upload_bytes_per_second", "gauge", "Upload rate of the last speed test.", sp.Last.Up)
		m.metric("pillowforrt_speedtest_timestamp_seconds", "gauge", "Unix time of the last speed test.", float64(sp.Last.T))
	}
	if a := in.ARP; a != nil {
		m.metric("pillowforrt_arp_spoof_alerts", "gauge", "Gateway-impersonation and reserved-address conflicts seen in the last 24 hours (should be 0).", float64(a.Alerts))
		m.metric("pillowforrt_arp_address_changes", "gauge", "Addresses that quickly changed owner in the last 24 hours.", float64(len(a.Findings)-a.Alerts-a.Sweeps))
		m.metric("pillowforrt_arp_sweeps", "gauge", "Host scans of the LAN seen in the last 24 hours (one device asking for 20 or more addresses within a minute).", float64(a.Sweeps))
	}
	if l := in.Link; l != nil && l.Probes > 0 {
		m.metric("pillowforrt_uplink_probe_loss_ratio_24h", "gauge", "Share of uplink probes (a TCP connect every 30 s) that failed in the last 24 hours.", l.LossPct/100)
		m.metric("pillowforrt_uplink_outages_24h", "gauge", "Uplink outages (3 failed probes in a row) that began in the last 24 hours.", float64(l.Outages24))
	}
	if t := in.Tor; t != nil && (t.Enabled || len(t.Devices) > 0) {
		m.metric("pillowforrt_tor_running", "gauge", "1 if the Tor client process is running.", b2f(t.Running))
		m.metric("pillowforrt_tor_ready", "gauge", "1 if Tor has finished bootstrapping.", b2f(t.Ready))
		m.metric("pillowforrt_tor_devices", "gauge", "Devices whose traffic is forced through Tor.", float64(len(t.Devices)))
		m.metric("pillowforrt_tor_memory_bytes", "gauge", "Resident memory of the Tor process.", t.RSSMB*1024*1024)
		m.metric("pillowforrt_tor_restarts_total", "counter", "Unexpected Tor restarts since tinyfwd started.", float64(t.Restarts))
	}
	m.metric("pillowforrt_graph_samples", "gauge", "Samples in the one-hour graph ring.", float64(in.GraphSamples))
	return m.b.String()
}

// serviceSlug turns a display name into a unique, stable label value.
func serviceSlug(name string) string {
	switch {
	case strings.HasPrefix(name, "tinyfwd"):
		return "tinyfwd"
	case strings.HasPrefix(name, "dnsmasq"):
		return "dnsmasq"
	case strings.HasPrefix(name, "hostapd, 2.4"):
		return "hostapd_2_4ghz"
	case strings.HasPrefix(name, "hostapd, 5"):
		return "hostapd_5ghz"
	case strings.HasPrefix(name, "wland"):
		return "wland"
	case strings.HasPrefix(name, "QCMAP"):
		return "qcmap"
	case strings.HasPrefix(name, "dropbear"):
		return "dropbear"
	case strings.HasPrefix(name, "guard"):
		return "guard"
	case strings.HasPrefix(name, "stock admin"):
		return "stock_admin"
	case strings.HasPrefix(name, "carrier updates"):
		return "carrier_updates"
	}
	return strings.ToLower(strings.Fields(name)[0])
}

// gatherMetrics reads the live state; every source is nil-safe.
func gatherMetrics() metricsIn {
	now := time.Now()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	in := metricsIn{Now: now, Version: version, DaemonUptime: now.Sub(startTime).Seconds(), Goroutines: runtime.NumGoroutine(), HeapBytes: ms.HeapAlloc,
		ProxyConnsTot: uint64(connsTotal.Load()), ProxyConnsAct: int64(connsActive.Load()), ProxyUp: uint64(proxyUp.Load()), ProxyDown: uint64(proxyDown.Load())}
	uplinkMu.Lock()
	u := uplink
	uplinkMu.Unlock()
	in.Uplink = &u
	c := readCell()
	in.Cell = &c
	sy := readSystem()
	in.Sys = &sy
	usageMu.Lock()
	in.UsageDown, in.UsageUp, in.UsageSet = float64(usage.Down), float64(usage.Up), true
	usageMu.Unlock()
	if wifi != nil {
		if raw, err := os.ReadFile(wifi.env.xmlPath); err == nil {
			on5 := parseWifiSettings(string(raw)).Five.Enabled
			up24 := wifi.env.hostapdState() == "ENABLED"
			in.Wifi24Up = &up24
			if on5 && wifi.env.hostapdState5 != nil {
				up5 := wifi.env.hostapdState5() == "ENABLED"
				in.Wifi5Up = &up5
			}
		}
		all := parseStations(wifi.env.stations())
		five := map[string]bool{}
		if wifi.env.stations5 != nil {
			for _, s := range parseStations(wifi.env.stations5()) {
				five[s.MAC] = true
			}
		}
		for _, s := range all {
			if five[s.MAC] {
				in.Wifi5Clients++
			} else {
				in.Wifi24Clients++
			}
		}
	}
	in.Leases = activeLeases(now)
	if poolMgr != nil {
		if pv, err := poolMgr.View(); err == nil {
			if n := int(ipNum(pv.End)) - int(ipNum(pv.Start)) + 1; n > 0 {
				in.PoolSize = n
			}
		}
	}
	if dhcpMgr != nil {
		in.Reservations = len(dhcpMgr.List())
	}
	if macMgr != nil {
		in.BlockedDevices = len(macMgr.List())
	}
	if fwMgr != nil {
		v := fwMgr.View(nil)
		in.BlockedDests, in.Schedules, in.PausedDevices = len(v.Dest), len(v.Sched), len(v.Paused)
	}
	if dnsProxy != nil {
		in.DNS = &dnsM{Queries: dnsProxy.Stats.Queries.Load(), Blocked: dnsProxy.Stats.Blocked.Load(), Cached: dnsProxy.Stats.Cached.Load(), DoH: dnsProxy.Stats.DoH.Load(),
			Errors: dnsProxy.Stats.Errors.Load(), CacheEntries: dnsProxy.Cache.Len(), Fallback: dnsProxy.Up.Failing(),
			Lists: dnsProxy.Filter.Lists(), Mode: dnsProxy.Filter.Mode()}
	}
	if vpn != nil {
		st := vpn.Status()
		in.VPN = &st
	}
	if certMgr != nil {
		cv := certMgr.View()
		in.CertNotAfter, in.CertDaysLeft = cv.NotAfter, cv.DaysLeft
	}
	if sshMgr != nil {
		sv := sshMgr.View()
		in.SSHLogins, in.SSHFailed = sv.Summary.Logins, sv.Summary.Failed
	}
	if events != nil {
		in.EventsUnseen, _ = events.Counts()
	}
	if stockMgr != nil {
		off := stockMgr.Off()
		in.StockAdminOff = &off
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
	graphs.mu.Lock()
	in.GraphSamples = len(graphs.fine)
	graphs.mu.Unlock()
	return in
}

var metricsCache struct {
	mu   sync.Mutex
	at   time.Time
	text string
}

// serveMetrics answers a scrape; the text is rebuilt at most every 10 seconds.
func serveMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	metricsCache.mu.Lock()
	if time.Since(metricsCache.at) > 10*time.Second || metricsCache.text == "" {
		metricsCache.text, metricsCache.at = buildMetrics(gatherMetrics()), time.Now()
	}
	text := metricsCache.text
	metricsCache.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		w.Write([]byte(text))
	}
}

// metricNames lists the metric names in a text exposition (for tests and tooling).
func metricNames(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		n := l
		if i := strings.IndexAny(l, "{ "); i > 0 {
			n = l[:i]
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
