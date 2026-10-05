package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// the Prometheus text format: a sample is  name{label="v",...} value
var sampleRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*"(,[a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*")*)?\})? [-+]?([0-9]+(\.[0-9]+)?([eE][-+]?[0-9]+)?|Inf|NaN)$`)

func richInput() metricsIn {
	t := true
	f := false
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	return metricsIn{Now: now, Version: "0.25.0", DaemonUptime: 100, Goroutines: 30, HeapBytes: 5e6,
		Uplink: &uplinkState{OK: true, LatencyMs: 55.5, Fails: 0, Checked: 1790000000},
		Cell:   &cellView{Up: true, CGNAT: true, RxBytes: 1000, TxBytes: 500, RxPackets: 10, TxPackets: 5},
		Sys: &sysView{UptimeS: 5000, Load: [3]float64{1.5, 1.2, 1}, MemTotalKB: 163736, MemAvailKB: 80000,
			Temps: []sysTemp{{"tsens_tz_sensor0", 48}, {"pa_therm0", 37}}, Disks: []sysDisk{{Name: "System", Path: "/", TotalB: 100, FreeB: 10}, {Name: "Data", Path: "/data", TotalB: 1000, FreeB: 800}},
			Battery: sysBattery{Known: true, MV: 3894, Level: 3, TempC: 40},
			Services: []sysService{{Name: "tinyfwd (proxy, DNS filter, this page)", State: "running"}, {Name: "hostapd, 2.4 GHz", State: "running"}, {Name: "hostapd, 5 GHz", State: "running"},
				{Name: "stock admin (goahead, port 81/444)", State: "running"}, {Name: "carrier updates (upgrade)", State: "held"}, {Name: "dropbear (ssh)", State: "not running"}}},
		UsageDown: 7e9, UsageUp: 8e8, UsageSet: true, ProxyConnsTot: 97, ProxyConnsAct: 3, ProxyUp: 1000, ProxyDown: 5000,
		Wifi24Up: &t, Wifi5Up: &f, Wifi24Clients: 4, Wifi5Clients: 1, Leases: 6, PoolSize: 101, Reservations: 5, BlockedDevices: 1, BlockedDests: 2, Schedules: 1, PausedDevices: 0,
		DNS: &dnsM{Queries: 200, Blocked: 20, Cached: 90, DoH: 100, Plain: 0, Errors: 1, CacheEntries: 40, Mode: "both", Lists: []listData{{Name: "oisd", Entries: 1000, Updated: now.Add(-time.Hour)}, {Name: "stevenblack", Entries: 0}}},
		VPN: &vpnStatus{Registered: true, Enabled: false}, CertNotAfter: 1850000000, CertDaysLeft: 799, SSHLogins: 300, SSHFailed: 2, EventsUnseen: 0, StockAdminOff: &t, GraphSamples: 360}
}

func TestMetricsFormat(t *testing.T) {
	text := buildMetrics(richInput())
	helped, typed := map[string]int{}, map[string]string{}
	for i, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "# HELP "):
			helped[strings.Fields(l)[2]]++
		case strings.HasPrefix(l, "# TYPE "):
			f := strings.Fields(l)
			typed[f[2]] = f[3]
			if f[3] != "gauge" && f[3] != "counter" {
				t.Errorf("line %d: unknown type %q", i, f[3])
			}
		case strings.HasPrefix(l, "#"):
			t.Errorf("line %d: stray comment %q", i, l)
		default:
			if !sampleRe.MatchString(l) {
				t.Errorf("line %d is not a valid sample: %q", i, l)
			}
			n := l[:strings.IndexAny(l, "{ ")]
			if typed[n] == "" {
				t.Errorf("line %d: %s has no TYPE before its first sample", i, n)
			}
		}
	}
	for n, c := range helped {
		if c != 1 || typed[n] == "" {
			t.Errorf("%s: %d HELP lines, type %q", n, c, typed[n])
		}
	}
	for n, ty := range typed {
		if strings.HasSuffix(n, "_total") != (ty == "counter") {
			t.Errorf("%s is a %s: a name ends in _total exactly when it is a counter", n, ty)
		}
		if !strings.HasPrefix(n, "orbic_") {
			t.Errorf("%s lacks the orbic_ prefix", n)
		}
	}
	for _, want := range []string{`orbic_build_info{version="0.25.0"} 1`, "orbic_uplink_up 1", "orbic_uplink_latency_seconds 0.0555", `orbic_temperature_celsius{sensor="pa_therm0"} 37`,
		`orbic_service_up{service="tinyfwd"} 1`, `orbic_service_up{service="carrier_updates"} 1`, `orbic_service_up{service="dropbear"} 0`, `orbic_wifi_radio_up{band="5ghz"} 0`,
		`orbic_dns_list_entries{list="stevenblack"} 0`, `orbic_dns_list_age_seconds{list="oisd"} 3600`, "orbic_memory_available_bytes 8.192e+07", "orbic_stock_admin_off 1",
		`orbic_filesystem_free_bytes{mount="/data"} 800`} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing sample %q", want)
		}
	}
	series := map[string]bool{}
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		id := l[:strings.LastIndex(l, " ")]
		if series[id] {
			t.Errorf("duplicate series %q (Prometheus rejects the scrape)", id)
		}
		series[id] = true
	}
	if !strings.Contains(text, `orbic_service_up{service="hostapd_2_4ghz"} 1`) || strings.Contains(text, `service="hostapd_5ghz"`) == false {
		t.Error("the two radios need distinct service labels while 5 GHz is on")
	}
	in5 := richInput()
	in5.Wifi5Up = nil
	if strings.Contains(buildMetrics(in5), `service="hostapd_5ghz"`) {
		t.Error("with the 5 GHz network off, its hostapd is not a failing service and must not be reported")
	}
	if strings.Contains(text, "orbic_dns_list_age_seconds{list=\"stevenblack\"}") {
		t.Error("a list that was never updated has no age")
	}
	if !strings.Contains(text, "orbic_vpn_enabled 0\n") || !strings.Contains(text, "orbic_vpn_up 0\n") {
		t.Error("a registered but switched-off VPN reports enabled 0 and up 0")
	}
	in := richInput()
	in.VPN = &vpnStatus{Registered: false}
	if strings.Contains(buildMetrics(in), "orbic_vpn_") {
		t.Error("an unregistered VPN has no metrics at all")
	}
}

func TestMetricsHoldNothingPersonal(t *testing.T) {
	text := buildMetrics(richInput())
	for _, bad := range []string{"192.168.", "aa:bb", "examplenet", "ExampleNet", "moto", "pixel", "iphone", "psk", "token", "password"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(bad)) {
			t.Errorf("the scrape must stay aggregate: it contains %q", bad)
		}
	}
	// every label that is used: only fixed vocabularies (sensor, mount, service, band, list, version)
	re := regexp.MustCompile(`([a-z_]+)="`)
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		switch m[1] {
		case "sensor", "mount", "service", "band", "list", "version":
		default:
			t.Errorf("unexpected label %q", m[1])
		}
	}
}

func TestMetricsEscapingAndEmpty(t *testing.T) {
	m := newMB()
	m.metric("orbic_x", "gauge", "h", 1, "k", "a\"b\\c\nd")
	if !strings.Contains(m.b.String(), `orbic_x{k="a\"b\\c\nd"} 1`) {
		t.Errorf("label escaping: %q", m.b.String())
	}
	min := buildMetrics(metricsIn{Version: "x"}) // no sources at all: still valid, just fewer lines
	for _, l := range strings.Split(strings.TrimRight(min, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") && !sampleRe.MatchString(l) {
			t.Errorf("invalid line with no sources: %q", l)
		}
	}
	if names := metricNames(min); len(names) < 5 || strings.Contains(strings.Join(names, ","), "orbic_uplink_up") {
		t.Errorf("%v", names)
	}
}

func TestServeMetrics(t *testing.T) {
	metricsCache.text = ""
	rec := httptest.NewRecorder()
	serveMetrics(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "orbic_build_info{version=") || !strings.Contains(body, "orbic_daemon_goroutines") {
		t.Errorf("a live scrape lacks the basics:\n%s", body[:min(len(body), 400)])
	}
	rec2 := httptest.NewRecorder()
	serveMetrics(rec2, httptest.NewRequest("GET", "/metrics", nil))
	if rec2.Body.String() != body {
		t.Error("two scrapes within 10 seconds must return the same cached text")
	}
	rec3 := httptest.NewRecorder()
	serveMetrics(rec3, httptest.NewRequest("POST", "/metrics", nil))
	if rec3.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec3.Code)
	}
	if rec4 := httptest.NewRecorder(); func() int { serveMetrics(rec4, httptest.NewRequest("HEAD", "/metrics", nil)); return rec4.Body.Len() }() != 0 {
		t.Error("HEAD must have no body")
	}
}
