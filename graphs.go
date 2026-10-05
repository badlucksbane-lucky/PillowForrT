package main

// Live graphs: a small ring of samples kept in RAM (lost at restart, never written to flash). Every 10 seconds the sampler records the uplink's download and upload rate (from the
// interface counters), the uplink latency (the probe's last answer), DNS queries and blocked queries, Wi-Fi clients and the hottest sensor. 360 of those make the 1-hour view;
// every minute they are folded into a coarse ring of 1,440 samples for the 24-hour view. Missing values are null, never zero: a gap is a gap.

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	graphFine   = 360  // 10 s samples: one hour
	graphCoarse = 1440 // 60 s samples: one day
	graphStep   = 10 * time.Second
)

type gsample struct {
	T       int64
	RX, TX  float64 // bytes per second on the uplink
	Lat     float64 // ms; <0 = no answer / unknown
	Q, Blk  float64 // DNS queries and blocked ones per minute
	Clients float64 // Wi-Fi devices; <0 = unknown
	Temp    float64 // hottest sensor, C; <0 = unknown
	Rate    bool    // RX/TX/Q/Blk are real rates (false for the very first sample)
}

type graphStore struct {
	mu     sync.Mutex
	fine   []gsample
	coarse []gsample
	pend   []gsample // fine samples of the minute being built
}

func newGraphStore() *graphStore { return &graphStore{} }

func (g *graphStore) Add(s gsample) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fine = append(g.fine, s)
	if len(g.fine) > graphFine {
		g.fine = g.fine[len(g.fine)-graphFine:]
	}
	g.pend = append(g.pend, s)
	if len(g.pend) >= int(time.Minute/graphStep) {
		g.coarse = append(g.coarse, foldSamples(g.pend))
		if len(g.coarse) > graphCoarse {
			g.coarse = g.coarse[len(g.coarse)-graphCoarse:]
		}
		g.pend = nil
	}
}

// foldSamples turns a minute of fine samples into one: rates averaged, latency averaged over the answers, counts and temperature as the last/maximum.
func foldSamples(in []gsample) gsample {
	out := gsample{T: in[len(in)-1].T, Lat: -1, Clients: -1, Temp: -1}
	var nr, nl int
	var lat float64
	for _, s := range in {
		if s.Rate {
			out.RX += s.RX
			out.TX += s.TX
			out.Q += s.Q
			out.Blk += s.Blk
			nr++
		}
		if s.Lat >= 0 {
			lat += s.Lat
			nl++
		}
		if s.Clients >= 0 {
			out.Clients = s.Clients
		}
		if s.Temp > out.Temp {
			out.Temp = s.Temp
		}
	}
	if nr > 0 {
		out.RX, out.TX = out.RX/float64(nr), out.TX/float64(nr)
		out.Q, out.Blk = out.Q/float64(nr), out.Blk/float64(nr) // a mean of per-minute rates is still per minute
		out.Rate = true
	}
	if nl > 0 {
		out.Lat = lat / float64(nl)
	}
	return out
}

type graphView struct {
	IntervalS int        `json:"interval_s"`
	T         []int64    `json:"t"`
	RX        []*float64 `json:"rx"` // bytes per second
	TX        []*float64 `json:"tx"`
	Lat       []*float64 `json:"lat"`
	Q         []*float64 `json:"q"` // per minute
	Blk       []*float64 `json:"blk"`
	Clients   []*float64 `json:"clients"`
	Temp      []*float64 `json:"temp"`
}

func pf(v float64, ok bool) *float64 {
	if !ok {
		return nil
	}
	r := float64(int64(v*100+0.5)) / 100
	return &r
}

// View returns the one-hour (fine) or one-day (coarse) series, oldest first.
func (g *graphStore) View(day bool) graphView {
	g.mu.Lock()
	src := g.fine
	step := int(graphStep / time.Second)
	if day {
		src, step = g.coarse, 60
	}
	src = append([]gsample(nil), src...)
	g.mu.Unlock()
	v := graphView{IntervalS: step, T: []int64{}, RX: []*float64{}, TX: []*float64{}, Lat: []*float64{}, Q: []*float64{}, Blk: []*float64{}, Clients: []*float64{}, Temp: []*float64{}}
	for _, s := range src {
		v.T = append(v.T, s.T)
		v.RX = append(v.RX, pf(s.RX, s.Rate))
		v.TX = append(v.TX, pf(s.TX, s.Rate))
		v.Lat = append(v.Lat, pf(s.Lat, s.Lat >= 0))
		v.Q = append(v.Q, pf(s.Q, s.Rate))
		v.Blk = append(v.Blk, pf(s.Blk, s.Rate))
		v.Clients = append(v.Clients, pf(s.Clients, s.Clients >= 0))
		v.Temp = append(v.Temp, pf(s.Temp, s.Temp >= 0))
	}
	return v
}

// rate turns two counter readings into a per-second rate; a counter that went backwards (a reset) gives no rate.
func rate(prev, cur uint64, dt float64) (float64, bool) {
	if cur < prev || dt <= 0 {
		return 0, false
	}
	return float64(cur-prev) / dt, true
}

// ---- the sampler ----

var graphs = newGraphStore()

func maxTemp() float64 {
	best := -1.0
	zs, _ := os.ReadDir("/sys/class/thermal")
	for _, z := range zs {
		if !strings.HasPrefix(z.Name(), "thermal_zone") {
			continue
		}
		b, err := os.ReadFile("/sys/class/thermal/" + z.Name() + "/temp")
		if err != nil {
			continue
		}
		if t, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
			if t > 1000 {
				t /= 1000
			}
			if t > best {
				best = t
			}
		}
	}
	return best
}

func wifiClientCount() float64 {
	if wifi == nil {
		return -1
	}
	return float64(len(parseStations(wifi.env.stations())))
}

func graphLoop() {
	var prevRX, prevTX, prevQ, prevB uint64
	var prevT time.Time
	var lastChecked int64
	lastLat := -1.0
	clients := -1.0
	var clientsAt time.Time
	for {
		now := time.Now()
		s := gsample{T: now.Unix(), Lat: -1, Clients: -1, Temp: maxTemp()}
		nd, _ := os.ReadFile("/proc/net/dev")
		rb, _, _, _, tb, _, _, _, ok := parseNetDev(string(nd), "rmnet_data0")
		var q, b uint64
		if dnsProxy != nil {
			q, b = dnsProxy.Stats.Queries.Load(), dnsProxy.Stats.Blocked.Load()
		}
		if ok && !prevT.IsZero() {
			dt := now.Sub(prevT).Seconds()
			rx, ok1 := rate(prevRX, rb, dt)
			tx, ok2 := rate(prevTX, tb, dt)
			qs, ok3 := rate(prevQ, q, dt)
			bs, ok4 := rate(prevB, b, dt)
			if ok1 && ok2 {
				s.RX, s.TX, s.Rate = rx, tx, true
				if ok3 && ok4 {
					s.Q, s.Blk = qs*60, bs*60
				}
			}
		}
		prevRX, prevTX, prevQ, prevB, prevT = rb, tb, q, b, now
		uplinkMu.Lock()
		up := uplink
		uplinkMu.Unlock()
		if up.OK && up.Checked > lastChecked {
			lastChecked, lastLat = up.Checked, up.LatencyMs
		}
		switch {
		case !up.OK && up.Checked > 0:
			lastLat = -1 // the probe failed: a gap, not a stale number
		}
		if lastLat >= 0 && now.Unix()-lastChecked < 75 {
			s.Lat = lastLat
		}
		if now.Sub(clientsAt) > 30*time.Second {
			clients, clientsAt = wifiClientCount(), now
		}
		s.Clients = clients
		graphs.Add(s)
		time.Sleep(graphStep)
	}
}
