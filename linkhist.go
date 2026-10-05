package main

// Uplink latency and loss history. The live graphs keep a day in RAM; this keeps weeks, on flash, in hourly buckets, so "was last Tuesday's evening bad?" has an answer. Fed by the
// 30-second uplink probe (a TCP connect to 1.1.1.1:443): per hour it keeps how many probes ran, how many failed (the loss), and the average and worst connect time. It also keeps an
// outage log (three failed probes in a row = an outage, from the first failure until the first success) and raises an "uplink_flaky" event when the link is lossy without being down
// (4 or more of the last 20 probes failed, not all in a row). A probe is a TCP connect, so "loss" here means a connect that did not complete in 5 seconds, not a lost packet.
// Hours with no probes (the daemon was not running) stay gaps, never zeros. About 35 days are kept, 15 minutes of data at most lost to a restart.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	linkKeepHours  = 24 * 35
	linkSaveEvery  = 15 * time.Minute
	linkOutageFail = 3  // probes in a row
	linkWindow     = 20 // probes in the flaky window
	linkFlakyFails = 4
)

type linkBucket struct {
	T     int64   `json:"t"` // start of the hour, unix
	N     int     `json:"n"`
	Fail  int     `json:"fail"`
	SumMs float64 `json:"sum_ms"`
	MaxMs float64 `json:"max_ms"`
}

type linkOutage struct {
	Start int64 `json:"start"`
	Secs  int64 `json:"secs"`
	Open  bool  `json:"open,omitempty"`
}

type linkHist struct {
	mu        sync.Mutex
	path      string
	buckets   []linkBucket
	outages   []linkOutage
	recent    []bool
	consec    int
	firstFail int64
	now       func() time.Time
	emit      func(evt)
	lastSave  time.Time
	flakyAt   time.Time
}

func newLinkHist(path string) *linkHist {
	h := &linkHist{path: path, now: time.Now, emit: func(e evt) {
		if events != nil {
			events.Add([]evt{e})
		}
	}}
	if b, err := os.ReadFile(path); err == nil {
		var f struct {
			B []linkBucket `json:"buckets"`
			O []linkOutage `json:"outages"`
		}
		if json.Unmarshal(b, &f) == nil {
			h.buckets, h.outages = f.B, f.O
			for i := range h.outages { // an outage open at the last save: the daemon was restarted, so its end is unknown
				if h.outages[i].Open {
					h.outages[i].Open = false
				}
			}
		}
	}
	h.lastSave = h.now()
	return h
}

func (h *linkHist) save() {
	b, _ := json.Marshal(struct {
		B []linkBucket `json:"buckets"`
		O []linkOutage `json:"outages"`
	}{h.buckets, h.outages})
	writeFileAtomic(h.path, b, 0o600)
	h.lastSave = h.now()
}

// Record takes one probe result (ms is the connect time when ok).
func (h *linkHist) Record(ok bool, ms float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	hour := now.Unix() - now.Unix()%3600
	if n := len(h.buckets); n == 0 || h.buckets[n-1].T != hour {
		h.buckets = append(h.buckets, linkBucket{T: hour})
		if len(h.buckets) > linkKeepHours {
			h.buckets = h.buckets[len(h.buckets)-linkKeepHours:]
		}
	}
	b := &h.buckets[len(h.buckets)-1]
	b.N++
	changed := false
	if ok {
		b.SumMs += ms
		if ms > b.MaxMs {
			b.MaxMs = ms
		}
		if n := len(h.outages); n > 0 && h.outages[n-1].Open {
			h.outages[n-1].Open = false
			h.outages[n-1].Secs = now.Unix() - h.outages[n-1].Start
			changed = true
		}
		h.consec = 0
	} else {
		b.Fail++
		if h.consec == 0 {
			h.firstFail = now.Unix()
		}
		h.consec++
		if h.consec == linkOutageFail {
			h.outages = append(h.outages, linkOutage{Start: h.firstFail, Open: true})
			if len(h.outages) > 50 {
				h.outages = h.outages[len(h.outages)-50:]
			}
			changed = true
		}
	}
	h.recent = append(h.recent, ok)
	if len(h.recent) > linkWindow {
		h.recent = h.recent[len(h.recent)-linkWindow:]
	}
	if flaky, fails := flakyVerdict(h.recent, h.consec); flaky && now.Sub(h.flakyAt) > 30*time.Minute {
		h.flakyAt = now
		h.emit(evt{T: now.Unix(), Kind: "uplink_flaky", Sev: sevAttention, Text: fmt.Sprintf("The internet link is flaky: %d of the last %d checks failed, though it is not fully down.", fails, len(h.recent)), Public: "The internet connection is unreliable"})
	}
	if changed || now.Sub(h.lastSave) >= linkSaveEvery {
		h.save()
	}
}

// flakyVerdict: lossy but not down: at least 4 of a full window of 20 failed, and the link is not in a run of failures right now (that is the "down" event's job).
func flakyVerdict(recent []bool, consec int) (bool, int) {
	if len(recent) < linkWindow {
		return false, 0
	}
	f := 0
	for _, ok := range recent {
		if !ok {
			f++
		}
	}
	return f >= linkFlakyFails && consec < linkOutageFail, f
}

type linkDay struct {
	Day     string  `json:"day"` // local date
	Probes  int     `json:"probes"`
	LossPct float64 `json:"loss_pct"`
	AvgMs   float64 `json:"avg_ms"`
	MaxMs   float64 `json:"max_ms"`
	Outages int     `json:"outages"`
}

type linkView struct {
	Available bool         `json:"available"`
	Hours     int          `json:"hours"`
	T         []int64      `json:"t"`
	Avg       []*float64   `json:"avg"`  // ms; null = no probes that hour
	Max       []*float64   `json:"max"`  // ms
	Loss      []*float64   `json:"loss"` // percent
	Probes    int          `json:"probes"`
	LossPct   float64      `json:"loss_pct"`
	AvgMs     float64      `json:"avg_ms"`
	Outages24 int          `json:"outages_24h"`
	Days      []linkDay    `json:"days"`
	Outages   []linkOutage `json:"outages"`
	OutageNow bool         `json:"outage_now"`
}

func lossPct(fail, n int) float64 {
	if n == 0 {
		return 0
	}
	return 100 * float64(fail) / float64(n)
}

// View covers the last `hours` hours (24, 168 or 720), one slot per hour so that missing hours show as gaps.
func (h *linkHist) View(hours int) linkView {
	h.mu.Lock()
	defer h.mu.Unlock()
	if hours < 1 || hours > linkKeepHours {
		hours = 24
	}
	now := h.now()
	cur := now.Unix() - now.Unix()%3600
	v := linkView{Available: true, Hours: hours, T: []int64{}, Avg: []*float64{}, Max: []*float64{}, Loss: []*float64{}, Days: []linkDay{}, Outages: []linkOutage{}}
	by := map[int64]linkBucket{}
	for _, b := range h.buckets {
		by[b.T] = b
	}
	var fail, n int
	var sum float64
	for i := hours - 1; i >= 0; i-- {
		t := cur - int64(i)*3600
		v.T = append(v.T, t)
		b, ok := by[t]
		if !ok || b.N == 0 {
			v.Avg, v.Max, v.Loss = append(v.Avg, nil), append(v.Max, nil), append(v.Loss, nil)
			continue
		}
		l := lossPct(b.Fail, b.N)
		v.Loss = append(v.Loss, &l)
		n += b.N
		fail += b.Fail
		if got := b.N - b.Fail; got > 0 {
			a, m := b.SumMs/float64(got), b.MaxMs
			v.Avg, v.Max = append(v.Avg, &a), append(v.Max, &m)
			sum += b.SumMs
		} else {
			v.Avg, v.Max = append(v.Avg, nil), append(v.Max, nil)
		}
	}
	v.Probes, v.LossPct = n, lossPct(fail, n)
	if got := n - fail; got > 0 {
		v.AvgMs = sum / float64(got)
	}
	// per local day, newest first, last 7 days
	type acc struct {
		probes, fail, good, outages int
		sum, max                    float64
	}
	days := map[string]*acc{}
	var order []string
	for _, b := range h.buckets {
		d := time.Unix(b.T, 0).In(schedLoc()).Format("2006-01-02")
		x := days[d]
		if x == nil {
			x = &acc{}
			days[d] = x
			order = append(order, d)
		}
		x.probes += b.N
		x.fail += b.Fail
		x.good += b.N - b.Fail
		x.sum += b.SumMs
		if b.MaxMs > x.max {
			x.max = b.MaxMs
		}
	}
	for _, o := range h.outages {
		if x := days[time.Unix(o.Start, 0).In(schedLoc()).Format("2006-01-02")]; x != nil {
			x.outages++
		}
		if now.Unix()-o.Start < 24*3600 {
			v.Outages24++
		}
	}
	sort.Strings(order)
	for i := len(order) - 1; i >= 0 && len(v.Days) < 7; i-- {
		x := days[order[i]]
		d := linkDay{Day: order[i], Probes: x.probes, LossPct: lossPct(x.fail, x.probes), MaxMs: x.max, Outages: x.outages}
		if x.good > 0 {
			d.AvgMs = x.sum / float64(x.good)
		}
		v.Days = append(v.Days, d)
	}
	for i := len(h.outages) - 1; i >= 0 && len(v.Outages) < 10; i-- {
		o := h.outages[i]
		if o.Open {
			o.Secs = now.Unix() - o.Start
			v.OutageNow = true
		}
		v.Outages = append(v.Outages, o)
	}
	return v
}

var linkMgr *linkHist
