package main

// Traffic accounting: per-host and per-client byte counts for what the proxy carries,
// plus the modem's own byte counters (ground truth for the data plan, covers traffic
// that never touches the proxy) kept per billing cycle and persisted across reboots.

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type hostStat struct {
	Up    uint64 `json:"up"`   // client -> internet
	Down  uint64 `json:"down"` // internet -> client
	Conns uint64 `json:"conns"`
}

var (
	statMu      sync.Mutex
	hostStats   = map[string]*hostStat{}
	clientStats = map[string]*hostStat{}
	connsTotal  atomic.Int64
	connsActive atomic.Int64
	proxyUp     atomic.Uint64
	proxyDown   atomic.Uint64
)

const maxHosts = 400

// account records one finished transfer for a client and a destination host.
func account(client, host string, up, down uint64, newConn bool) {
	proxyUp.Add(up)
	proxyDown.Add(down)
	statMu.Lock()
	defer statMu.Unlock()
	for _, e := range []struct {
		m map[string]*hostStat
		k string
	}{{hostStats, host}, {clientStats, client}} {
		s := e.m[e.k]
		if s == nil {
			s = &hostStat{}
			e.m[e.k] = s
		}
		s.Up += up
		s.Down += down
		if newConn {
			s.Conns++
		}
	}
	if len(hostStats) > maxHosts {
		pruneHosts(hostStats, maxHosts-100)
	}
}

// pruneHosts drops the smallest entries until keep remain.
func pruneHosts(m map[string]*hostStat, keep int) {
	type kv struct {
		k string
		n uint64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v.Up + v.Down})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n })
	for i := keep; i < len(all); i++ {
		delete(m, all[i].k)
	}
}

type topEntry struct {
	Name string `json:"name"`
	hostStat
}

func top(m map[string]*hostStat, n int) []topEntry {
	statMu.Lock()
	defer statMu.Unlock()
	all := make([]topEntry, 0, len(m))
	for k, v := range m {
		all = append(all, topEntry{k, *v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Up+all[i].Down > all[j].Up+all[j].Down })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// countedCopy copies src to dst and returns the byte count (errors just end the copy).
func countedCopy(dst io.Writer, src io.Reader) uint64 {
	n, _ := io.Copy(dst, src)
	return uint64(n)
}

// ---- modem counters, per billing cycle ----

type usageState struct {
	CycleStart int64  `json:"cycle_start"` // unix time the current cycle began
	Cycle      string `json:"cycle"`       // YYYY-MM-DD of the cycle start
	Down       uint64 `json:"down"`        // modem rx bytes this cycle
	Up         uint64 `json:"up"`          // modem tx bytes this cycle
	LastRawRx  uint64 `json:"last_raw_rx"`
	LastRawTx  uint64 `json:"last_raw_tx"`
	ProxyUp    uint64 `json:"proxy_up"`
	ProxyDown  uint64 `json:"proxy_down"`
	Updated    int64  `json:"updated"`
	Armed      bool   `json:"armed"` // false until the first sample sets a baseline
}

var (
	usageMu sync.Mutex
	usage   usageState
)

// cycleStart returns the start of the billing cycle containing now. Days above 28 are
// clamped so every month has the day.
func cycleStart(now time.Time, day int) time.Time {
	if day < 1 {
		day = 1
	}
	if day > 28 {
		day = 28
	}
	y, m, d := now.Date()
	if d < day {
		m--
		if m < time.January {
			m = time.December
			y--
		}
	}
	return time.Date(y, m, day, 0, 0, 0, 0, now.Location())
}

// delta is the growth of a counter, treating a smaller reading as a reset (reboot).
func delta(raw, last uint64) uint64 {
	if raw >= last {
		return raw - last
	}
	return raw
}

// sampleUsage folds a new pair of raw modem counters into the cycle totals.
func sampleUsage(st *usageState, rawRx, rawTx uint64, now time.Time, day int) {
	cs := cycleStart(now, day)
	if st.CycleStart != cs.Unix() {
		st.CycleStart = cs.Unix()
		st.Cycle = cs.Format("2006-01-02")
		st.Down, st.Up, st.ProxyUp, st.ProxyDown = 0, 0, 0, 0
	}
	if st.Armed {
		st.Down += delta(rawRx, st.LastRawRx)
		st.Up += delta(rawTx, st.LastRawTx)
	}
	st.Armed = true
	st.LastRawRx, st.LastRawTx = rawRx, rawTx
	st.Updated = now.Unix()
}

func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil
}

func loadState() {
	if *statePath == "" {
		return
	}
	b, err := os.ReadFile(*statePath)
	if err != nil {
		return
	}
	usageMu.Lock()
	defer usageMu.Unlock()
	if err := json.Unmarshal(b, &usage); err != nil {
		log.Printf("state unreadable (%v); starting fresh", err)
		usage = usageState{}
	}
}

func saveState() {
	if *statePath == "" {
		return
	}
	usageMu.Lock()
	snap := usage
	snap.ProxyUp += proxyUp.Load()
	snap.ProxyDown += proxyDown.Load()
	usageMu.Unlock()
	b, _ := json.Marshal(snap)
	tmp := *statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("state write: %v", err)
		return
	}
	if err := os.Rename(tmp, *statePath); err != nil {
		log.Printf("state rename: %v", err)
	}
}

// usageLoop samples the modem counters every 30 s and saves the state every 5 min.
func usageLoop() {
	rx := filepath.Join(*sysDir, "class/net", *rmnetIface, "statistics/rx_bytes")
	tx := filepath.Join(*sysDir, "class/net", *rmnetIface, "statistics/tx_bytes")
	tick := time.NewTicker(30 * time.Second)
	n := 0
	for {
		if a, ok := readUint(rx); ok {
			if b, ok := readUint(tx); ok {
				usageMu.Lock()
				sampleUsage(&usage, a, b, time.Now(), *cycleDay)
				usageMu.Unlock()
			}
		}
		n++
		if n%10 == 0 {
			saveState()
		}
		<-tick.C
	}
}
