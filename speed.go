package main

// Uplink speed history: every few hours the Orbic times a small download and upload over the cellular link (Cloudflare's speed endpoints), keeps the results on flash so the
// history survives restarts, and charts them. The point is the trend (is the evening slower, did the carrier throttle, did moving the antenna help), not a lab number: the test is
// deliberately small (1 MB down, 256 KB up, about 5 MB a day at the default every 6 hours), so TCP slow start keeps it under the link's peak, but every test is the same size so
// the history compares like with like. A test never runs while the link is down, while the house is using the link (it would measure the house, not the carrier) or when the
// plan is nearly used up; "Test now" on the page overrides the busy check and marks the result. A download far below the recent median raises a "slow" event.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	speedDownBytes = 1_000_000
	speedUpBytes   = 256_000
	speedKeep      = 600
	speedBusyBPS   = 150_000.0 // bytes/s of other traffic above which the scheduled test waits
)

type speedRec struct {
	T     int64   `json:"t"`
	Down  float64 `json:"down,omitempty"` // bytes per second
	Up    float64 `json:"up,omitempty"`
	LatMs float64 `json:"lat_ms,omitempty"` // time to the first byte of the download
	Busy  bool    `json:"busy,omitempty"`   // the house was using the link: a manual test run anyway
	Err   string  `json:"err,omitempty"`
}

type speedSettings struct {
	Enabled   bool `json:"enabled"`
	IntervalH int  `json:"interval_h"`
}

type speedTester struct {
	mu       sync.Mutex
	path     string
	set      speedSettings
	hist     []speedRec
	running  bool
	now      func() time.Time
	emit     func(evt)
	measure  func() speedRec // the network part, replaceable in tests
	busy     func() bool     // is the house using the link
	linkUp   func() bool
	planFull func() bool
	lastRun  time.Time
	nextTry  time.Time
}

func newSpeedTester(path string) *speedTester {
	s := &speedTester{path: path, set: speedSettings{Enabled: true, IntervalH: 6}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		busy: func() bool {
			graphs.mu.Lock()
			defer graphs.mu.Unlock()
			if n := len(graphs.fine); n > 0 {
				l := graphs.fine[n-1]
				return l.Rate && l.RX+l.TX > speedBusyBPS
			}
			return false
		},
		linkUp: func() bool { uplinkMu.Lock(); defer uplinkMu.Unlock(); return uplink.OK },
		planFull: func() bool {
			if *capGB <= 0 {
				return false
			}
			usageMu.Lock()
			defer usageMu.Unlock()
			return float64(usage.Down+usage.Up) >= 0.95**capGB*1e9
		}}
	s.measure = measureSpeed
	if b, err := os.ReadFile(path); err == nil {
		var f struct {
			Set  speedSettings `json:"set"`
			Hist []speedRec    `json:"hist"`
		}
		if json.Unmarshal(b, &f) == nil {
			if f.Set.IntervalH > 0 {
				s.set = f.Set
			}
			s.hist = f.Hist
		}
	}
	return s
}

func (s *speedTester) save() {
	b, _ := json.Marshal(struct {
		Set  speedSettings `json:"set"`
		Hist []speedRec    `json:"hist"`
	}{s.set, s.hist})
	writeFileAtomic(s.path, b, 0o600)
}

// measureSpeed does the real test. Download rate is timed from the first byte to the last (so the connection set-up and the server's think time are not counted); upload is the
// whole request, since the server only answers once it has everything.
func measureSpeed() speedRec {
	r := speedRec{T: time.Now().Unix()}
	c := &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12}, DialContext: dialUpstream, DisableKeepAlives: true}}
	t0 := time.Now()
	resp, err := c.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", speedDownBytes))
	if err != nil {
		r.Err = "download: " + shortErr(err)
		return r
	}
	r.LatMs = float64(time.Since(t0).Microseconds()) / 1000
	t1 := time.Now()
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	el := time.Since(t1).Seconds()
	if err != nil || n < speedDownBytes/2 || el <= 0 {
		r.Err = "download cut short"
		return r
	}
	r.Down = float64(n) / el
	t2 := time.Now()
	up, err := c.Post("https://speed.cloudflare.com/__up", "application/octet-stream", bytes.NewReader(make([]byte, speedUpBytes)))
	if err != nil {
		r.Err = "upload: " + shortErr(err)
		return r
	}
	io.Copy(io.Discard, up.Body)
	up.Body.Close()
	if el := time.Since(t2).Seconds(); el > 0 && up.StatusCode < 300 {
		r.Up = float64(speedUpBytes) / el
	} else {
		r.Err = fmt.Sprintf("upload answered %d", up.StatusCode)
	}
	return r
}

func shortErr(err error) string {
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	s := err.Error()
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// slowVerdict says whether a new download is far below what this link has been doing: under 30% of the median of the last 8 good tests, with at least 4 to compare against.
func slowVerdict(prev []speedRec, down float64) (bool, float64) {
	var v []float64
	for i := len(prev) - 1; i >= 0 && len(v) < 8; i-- {
		if prev[i].Err == "" && prev[i].Down > 0 {
			v = append(v, prev[i].Down)
		}
	}
	if len(v) < 4 || down <= 0 {
		return false, 0
	}
	m := median(v)
	return down < 0.3*m, m
}

func fmtMbit(bps float64) string { return fmt.Sprintf("%.1f Mbit/s", bps*8/1e6) }

// Run performs one test (scheduled or manual) and records it. It returns an error only when it did not start.
func (s *speedTester) run(manual bool) error {
	busy, err := s.begin(manual)
	if err != nil {
		return err
	}
	s.finish(busy)
	return nil
}

// begin checks the conditions and claims the tester; the caller must then call finish.
func (s *speedTester) begin(manual bool) (bool, error) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return false, errors.New("a test is already running")
	}
	if manual && s.now().Sub(s.lastRun) < 2*time.Minute {
		s.mu.Unlock()
		return false, errors.New("a test ran less than two minutes ago")
	}
	if !s.linkUp() {
		s.mu.Unlock()
		return false, errors.New("the uplink is down")
	}
	if s.planFull() {
		s.mu.Unlock()
		return false, errors.New("the data plan is nearly used up (95%)")
	}
	busy := s.busy()
	if busy && !manual {
		s.mu.Unlock()
		return false, errors.New("the house is using the link")
	}
	s.running, s.lastRun = true, s.now()
	s.mu.Unlock()
	return busy, nil
}

func (s *speedTester) finish(busy bool) {
	rec := s.measure()
	rec.Busy = busy
	s.mu.Lock()
	s.running = false
	prev := append([]speedRec(nil), s.hist...)
	s.hist = append(s.hist, rec)
	if len(s.hist) > speedKeep {
		s.hist = s.hist[len(s.hist)-speedKeep:]
	}
	s.save()
	s.mu.Unlock()
	if rec.Err == "" && !rec.Busy {
		if slow, m := slowVerdict(prev, rec.Down); slow {
			s.emit(evt{T: rec.T, Kind: "uplink_slow", Sev: sevAttention, Text: fmt.Sprintf("The internet link is much slower than usual: %s down now against about %s in recent tests.", fmtMbit(rec.Down), fmtMbit(m)), Public: "The internet connection is much slower than usual"})
		}
	}
}

// due says whether a scheduled test should be tried now.
func (s *speedTester) due() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set.Enabled || s.running || s.now().Before(s.nextTry) {
		return false
	}
	var last int64
	if n := len(s.hist); n > 0 {
		last = s.hist[n-1].T
	}
	return s.now().Sub(time.Unix(last, 0)) >= time.Duration(s.set.IntervalH)*time.Hour
}

func (s *speedTester) Loop() {
	time.Sleep(3 * time.Minute) // let the box settle after a boot
	for {
		if s.due() {
			if err := s.run(false); err != nil { // busy or link trouble: try again in 15 minutes, not at once
				s.mu.Lock()
				s.nextTry = s.now().Add(15 * time.Minute)
				s.mu.Unlock()
			}
		}
		time.Sleep(time.Minute)
	}
}

func (s *speedTester) Set(enabled bool, hours int) error {
	if hours != 1 && hours != 3 && hours != 6 && hours != 12 && hours != 24 {
		return errors.New("the interval must be 1, 3, 6, 12 or 24 hours")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set = speedSettings{Enabled: enabled, IntervalH: hours}
	s.save()
	return nil
}

type speedView struct {
	Available bool        `json:"available"`
	Enabled   bool        `json:"enabled"`
	IntervalH int         `json:"interval_h"`
	Running   bool        `json:"running"`
	PerDayMB  float64     `json:"data_per_day_mb"`
	Last      *speedRec   `json:"last,omitempty"`
	MedianDn  float64     `json:"median_down,omitempty"`
	BestDn    float64     `json:"best_down,omitempty"`
	T         []int64     `json:"t"`
	Down      []*float64  `json:"down"`
	Up        []*float64  `json:"up"`
	Lat       []*float64  `json:"lat"`
	Busy      []bool      `json:"busy"`
	Errors    []speedRec  `json:"errors"`
	ByHour    [24]float64 `json:"by_hour"` // median download by local hour of day (0 = no data)
	Hist      int         `json:"count"`
}

func (s *speedTester) View() speedView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := speedView{Available: true, Enabled: s.set.Enabled, IntervalH: s.set.IntervalH, Running: s.running, T: []int64{}, Down: []*float64{}, Up: []*float64{}, Lat: []*float64{}, Busy: []bool{}, Errors: []speedRec{}, Hist: len(s.hist)}
	v.PerDayMB = 24 / float64(s.set.IntervalH) * float64(speedDownBytes+speedUpBytes) / 1e6
	start := 0
	if len(s.hist) > 200 {
		start = len(s.hist) - 200
	}
	var good []float64
	hours := map[int][]float64{}
	for i := range s.hist {
		r := s.hist[i]
		if r.Err == "" && r.Down > 0 && !r.Busy {
			good = append(good, r.Down)
			if r.Down > v.BestDn {
				v.BestDn = r.Down
			}
			h := time.Unix(r.T, 0).In(schedLoc()).Hour()
			hours[h] = append(hours[h], r.Down)
		}
		if i < start {
			continue
		}
		v.T = append(v.T, r.T)
		v.Busy = append(v.Busy, r.Busy)
		if r.Err != "" {
			v.Down, v.Up, v.Lat = append(v.Down, nil), append(v.Up, nil), append(v.Lat, nil)
			if len(v.Errors) < 5 {
				v.Errors = append(v.Errors, r)
			}
			continue
		}
		d, u, l := r.Down, r.Up, r.LatMs
		v.Down, v.Up, v.Lat = append(v.Down, &d), append(v.Up, &u), append(v.Lat, &l)
	}
	sort.Slice(v.Errors, func(i, j int) bool { return v.Errors[i].T > v.Errors[j].T })
	if n := len(s.hist); n > 0 {
		l := s.hist[n-1]
		v.Last = &l
	}
	v.MedianDn = median(good)
	for h, vals := range hours {
		v.ByHour[h] = median(vals)
	}
	return v
}

var speedMgr *speedTester
