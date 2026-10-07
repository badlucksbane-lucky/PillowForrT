package main

// The Orbic's view: GET /status.json reports what it sees from its vantage point
// (outside the companion computer's NAT, on the carrier's edge). POST|GET /beat is a companion computer's heartbeat;
// if the beats stop, the Orbic notices from outside and runs the event hook.

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const version = "0.48.0"

var startTime = time.Now()

// ---- uplink probe: can the Orbic itself reach the internet, and how fast ----

type uplinkState struct {
	OK        bool    `json:"ok"`
	LatencyMs float64 `json:"latency_ms"`
	LastOK    int64   `json:"last_ok"`
	Fails     int     `json:"consecutive_fails"`
	Target    string  `json:"target"`
	Checked   int64   `json:"checked"`
}

var (
	uplinkMu sync.Mutex
	uplink   uplinkState
)

func probeLoop() {
	uplink.Target = *probeTarget
	for {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp4", *probeTarget, 5*time.Second)
		ms := float64(time.Since(t0).Microseconds()) / 1000
		uplinkMu.Lock()
		uplink.Checked = time.Now().Unix()
		if err == nil {
			c.Close()
			uplink.OK, uplink.LatencyMs, uplink.LastOK, uplink.Fails = true, ms, uplink.Checked, 0
		} else {
			uplink.OK = false
			uplink.Fails++
		}
		uplinkMu.Unlock()
		if linkMgr != nil {
			linkMgr.Record(err == nil, ms)
		}
		time.Sleep(30 * time.Second)
	}
}

// ---- heartbeat from a companion computer ----

type beatState struct {
	Armed   bool   `json:"armed"` // a beat has been seen since this daemon started
	Last    int64  `json:"last"`
	From    string `json:"from"`
	AgeS    int64  `json:"age_s"`
	Silent  bool   `json:"silent"`
	Since   int64  `json:"silent_since,omitempty"`
	Events  int    `json:"events"` // times the silence hook has fired
	Timeout int64  `json:"silent_after_s"`
}

var (
	beatMu sync.Mutex
	beat   beatState
)

// beatStep advances the heartbeat state machine and returns the event to fire, if any
// ("silent" or "recover"). now is a parameter so it can be tested.
func beatStep(b *beatState, now time.Time, timeout time.Duration, newBeat bool, from string) string {
	if newBeat {
		b.Armed, b.Last, b.From = true, now.Unix(), from
		if b.Silent {
			b.Silent, b.Since = false, 0
			return "recover"
		}
		return ""
	}
	if b.Armed && !b.Silent && now.Sub(time.Unix(b.Last, 0)) > timeout {
		b.Silent, b.Since = true, now.Unix()
		b.Events++
		return "silent"
	}
	return ""
}

func fireEvent(ev string) {
	log.Printf("heartbeat event: %s", ev)
	if *eventHook == "" {
		return
	}
	cmd := exec.Command(*eventHook, ev)
	cmd.Env = append(os.Environ(), "ORBIC_EVENT="+ev)
	go func() {
		out, err := cmd.CombinedOutput()
		log.Printf("event hook %s %s: err=%v out=%q", *eventHook, ev, err, strings.TrimSpace(string(out)))
	}()
}

func watchdogLoop() {
	for {
		time.Sleep(15 * time.Second)
		beatMu.Lock()
		ev := beatStep(&beat, time.Now(), *silentAfter, false, "")
		beatMu.Unlock()
		if ev != "" {
			fireEvent(ev)
		}
	}
}

// tokenOK: does the request carry the heartbeat token? With no token file configured the token is OFF and nothing matches (fail closed: "no file" once meant
// "accept any header", which let a made-up X-Beat-Token unlock the per-device detail in /status.json).
func tokenOK(r *http.Request) bool {
	if *beatTokenFile == "" {
		return false
	}
	want, err := os.ReadFile(*beatTokenFile)
	if err != nil || len(strings.TrimSpace(string(want))) == 0 {
		return false // a configured token file that is missing means nobody may beat
	}
	got := r.Header.Get("X-Beat-Token")
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(want))), []byte(got)) == 1
}

func handleBeat(w http.ResponseWriter, r *http.Request) {
	if *beatTokenFile == "" { // off unless an operator configures a token file
		http.NotFound(w, r)
		return
	}
	if !tokenOK(r) {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	from := r.URL.Query().Get("from")
	if len(from) > 32 {
		from = from[:32]
	}
	beatMu.Lock()
	ev := beatStep(&beat, time.Now(), *silentAfter, true, from)
	beatMu.Unlock()
	if ev != "" {
		fireEvent(ev)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{\"ok\":true}\n"))
}

// ---- /status.json ----

func procFloat(path string, field int) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if field >= len(f) {
		return 0
	}
	v, _ := strconv.ParseFloat(f[field], 64)
	return v
}

func memAvailKB() uint64 {
	b, err := os.ReadFile(filepath.Join(*procDir, "meminfo"))
	if err != nil {
		return 0
	}
	var sum uint64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == "MemFree:" || f[0] == "Buffers:" || f[0] == "Cached:") {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			sum += v
		}
	}
	return sum
}

func maxTempC() float64 {
	zones, _ := filepath.Glob(filepath.Join(*sysDir, "class/thermal/thermal_zone*/temp"))
	var m float64
	for _, z := range zones {
		if v, ok := readUint(z); ok && float64(v) > m {
			m = float64(v)
		}
	}
	return m // the Orbic reports whole degrees C
}

// wifiClients counts distinct IPs in the ARP table on the hotspot bridge.
func wifiClients() int {
	b, err := os.ReadFile(filepath.Join(*procDir, "net/arp"))
	if err != nil {
		return 0
	}
	n := 0
	for i, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if i > 0 && len(f) >= 6 && f[5] == "bridge0" && f[2] != "0x0" {
			n++
		}
	}
	return n
}

func serveStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	usageMu.Lock()
	u := usage
	u.ProxyUp += proxyUp.Load()
	u.ProxyDown += proxyDown.Load()
	usageMu.Unlock()
	uplinkMu.Lock()
	up := uplink
	uplinkMu.Unlock()
	beatMu.Lock()
	hb := beat
	hb.Timeout = int64(silentAfter.Seconds())
	if hb.Armed {
		hb.AgeS = now.Unix() - hb.Last
	}
	beatMu.Unlock()

	budget := map[string]any{"cap_gb": *capGB}
	if *capGB > 0 {
		capB := *capGB * 1e9
		used := float64(u.Down + u.Up)
		budget["used_gb"] = used / 1e9
		budget["left_gb"] = (capB - used) / 1e9
		budget["pct"] = 100 * used / capB
		cs := time.Unix(u.CycleStart, 0)
		if days := now.Sub(cs).Hours() / 24; days >= 1 {
			budget["gb_per_day"] = used / 1e9 / days
		}
	}

	out := map[string]any{
		"node":    "orbic",
		"class":   "vantage",
		"version": version,
		"time":    now.Unix(),
		"system": map[string]any{
			"uptime_s":     int64(procFloat(filepath.Join(*procDir, "uptime"), 0)),
			"load1":        procFloat(filepath.Join(*procDir, "loadavg"), 0),
			"mem_avail_kb": memAvailKB(),
			"temp_c_max":   maxTempC(),
			"daemon_up_s":  int64(now.Sub(startTime).Seconds()),
		},
		"uplink":       up,
		"usage":        u,
		"budget":       budget,
		"wifi_clients": wifiClients(),
		"proxy": map[string]any{
			"conns_total":  connsTotal.Load(),
			"conns_active": connsActive.Load(),
			"up":           proxyUp.Load(),
			"down":         proxyDown.Load(),
			"top_hosts":    top(hostStats, 15),
			"clients":      top(clientStats, 10),
		},
		"heartbeat": hb,
		"dns":       dnsStatus(),
	}
	if *beatTokenFile == "" {
		delete(out, "heartbeat")
	}
	if events != nil { // counts only: no text, no device, nothing personal
		unseen, last := events.Counts()
		out["alerts"] = map[string]any{"unseen_attention": unseen, "last_attention": last}
	}
	if !statusDetailOK(r) { // plain /status.json (the companion computer's watcher, the owner's vantage view): no browsing or per-device detail
		if p, ok := out["proxy"].(map[string]any); ok {
			delete(p, "top_hosts")
			delete(p, "clients")
		}
		out["dns"] = dnsSummary()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(out)
}
