package main

// Beacon-interval detection: C2 malware and trackers that "phone home" tend to do it on a fixed or near-fixed schedule, which is a different shape from ordinary browsing (bursty,
// irregular) even when the destination itself is unremarkable. This rides egress.go's existing conntrack sampling (Sample already walks every new LAN->outside flow every 10
// seconds to check the service allow-list) and, for each (source, destination) pair, keeps the times of new connections over the last two hours. A run of connections whose
// spacing is both regular (low coefficient of variation) and in a plausible beacon range (30 seconds to an hour; outside that is either sampling noise or an unremarkable daily
// check-in) is "to look at".
// This is the noisiest detector in the house on purpose: IMAP idle pings, chat-app heartbeats, smart-home cloud polling and backup software are ALL regular, and nothing here can
// tell a beacon from a benign poll by shape alone. It fires as sevAttention, never sevAlert, at most once an hour per pair, and the page should let a destination be marked
// "expected" the same way canary.go lets a MAC be ignored. Honest limit: only visible for forwarded (LAN->WAN) flows the 10-second sampler catches; a connection that opens and
// closes between samples, or a destination that changes IP each time (common CDN behaviour), is invisible here.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	beaconHorizon    = 2 * time.Hour
	beaconMinSamples = 7 // 6 intervals: enough that one slow page load does not look periodic
	beaconMinPeriod  = 30 * time.Second
	beaconMaxPeriod  = time.Hour
	beaconMaxCV      = 0.15 // coefficient of variation (stddev/mean): how tightly spaced the intervals must be
	beaconEventEvery = time.Hour
)

// beaconStats reports the mean interval and its coefficient of variation for a run of connection times. ok is false with fewer than two intervals or a non-positive mean.
func beaconStats(times []time.Time) (mean, cv float64, ok bool) {
	if len(times) < 2 {
		return 0, 0, false
	}
	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })
	gaps := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		gaps = append(gaps, sorted[i].Sub(sorted[i-1]).Seconds())
	}
	var sum float64
	for _, g := range gaps {
		sum += g
	}
	mean = sum / float64(len(gaps))
	if mean <= 0 {
		return mean, 0, false
	}
	var sq float64
	for _, g := range gaps {
		d := g - mean
		sq += d * d
	}
	stddev := math.Sqrt(sq / float64(len(gaps)))
	return mean, stddev / mean, true
}

// beaconLooksLikeOne applies the thresholds to one pair's stats.
func beaconLooksLikeOne(n int, mean, cv float64, ok bool) bool {
	return ok && n >= beaconMinSamples && mean >= beaconMinPeriod.Seconds() && mean <= beaconMaxPeriod.Seconds() && cv <= beaconMaxCV
}

type beaconPair struct {
	times     []time.Time
	lastEvent time.Time
}

type beaconFinding struct {
	T      int64   `json:"t"`
	MAC    string  `json:"mac,omitempty"`
	Src    string  `json:"src"`
	Dst    string  `json:"dst"`
	Period float64 `json:"period_s"`
	CV     float64 `json:"cv"`
	N      int     `json:"n"`
}

type beaconState struct {
	Ignore []string `json:"ignore,omitempty"` // "src|dst" pairs marked expected (the page's equivalent of canary.go's Ignore)
}

type beaconWatch struct {
	mu     sync.Mutex
	path   string
	st     beaconState
	pairs  map[string]*beaconPair // "src|dst"
	finds  []beaconFinding
	now    func() time.Time
	emit   func(evt)
	nameOf func(mac string) string
}

func newBeaconWatch(path string) *beaconWatch {
	w := &beaconWatch{path: path, pairs: map[string]*beaconPair{}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		nameOf: func(mac string) string {
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					if r.MAC == mac {
						return r.Name
					}
				}
			}
			return ""
		}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &w.st)
	}
	return w
}

func (w *beaconWatch) save() {
	b, _ := json.Marshal(w.st)
	writeFileAtomic(w.path, b, 0o600)
}

func (w *beaconWatch) ignored(src, dst string) bool {
	key := src + "|" + dst
	for _, x := range w.st.Ignore {
		if x == key {
			return true
		}
	}
	return false
}

// Observe is called from egress.go's Sample for every NEW forwarded flow (the same point torbypass.go hooks): a repeat on an already-open connection is not a new beacon tick.
func (w *beaconWatch) Observe(mac, src, dst string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ignored(src, dst) {
		return
	}
	key := src + "|" + dst
	for k, p := range w.pairs { // forget pairs quiet past the horizon
		if len(p.times) == 0 || now.Sub(p.times[len(p.times)-1]) > beaconHorizon {
			delete(w.pairs, k)
		}
	}
	p := w.pairs[key]
	if p == nil {
		if len(w.pairs) >= 4096 { // a flood of distinct destinations must not grow memory without bound
			return
		}
		p = &beaconPair{}
		w.pairs[key] = p
	}
	p.times = append(p.times, now)
	cut := now.Add(-beaconHorizon)
	i := 0
	for i < len(p.times) && p.times[i].Before(cut) {
		i++
	}
	p.times = p.times[i:]

	mean, cv, ok := beaconStats(p.times)
	if !beaconLooksLikeOne(len(p.times), mean, cv, ok) {
		return
	}
	if now.Sub(p.lastEvent) < beaconEventEvery {
		return
	}
	p.lastEvent = now
	w.finds = append(w.finds, beaconFinding{T: now.Unix(), MAC: mac, Src: src, Dst: dst, Period: mean, CV: cv, N: len(p.times)})
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := src
	if n := w.nameOf(mac); n != "" {
		who = fmt.Sprintf("%s (%s)", n, src)
	} else if mac != "" {
		who = fmt.Sprintf("%s (%s)", src, mac)
	}
	w.emit(evt{T: now.Unix(), Kind: "beacon_pattern", Sev: sevAttention, Text: fmt.Sprintf("%s has connected to %s every ~%.0fs, %d times, with very even spacing: that is the shape of a check-in beacon, though plenty of ordinary apps (chat heartbeats, cloud sync, IMAP idle) look the same.", who, dst, mean, len(p.times)), Public: "A device is contacting the same address on a very regular schedule"})
}

// Ignore marks a (src, dst) pair as expected, so it never fires again (until the pair is forgotten past the horizon and the page re-adds it if it still matters).
func (w *beaconWatch) Ignore(src, dst string, add bool) {
	key := src + "|" + dst
	w.mu.Lock()
	defer w.mu.Unlock()
	var keep []string
	found := false
	for _, x := range w.st.Ignore {
		if x == key {
			found = true
			if add {
				keep = append(keep, x)
			}
		} else {
			keep = append(keep, x)
		}
	}
	if add && !found {
		keep = append(keep, key)
	}
	w.st.Ignore = keep
	w.save()
}

type beaconView struct {
	Findings []beaconFinding `json:"findings"`
	Ignore   []string        `json:"ignore"`
}

func (w *beaconWatch) View() beaconView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := beaconView{Findings: []beaconFinding{}, Ignore: append([]string{}, w.st.Ignore...)}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var beaconMgr *beaconWatch
