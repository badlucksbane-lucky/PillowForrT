package main

import (
	"encoding/json"
	"testing"
)

func fine(t int64, rx float64) gsample {
	return gsample{T: t, RX: rx, TX: rx / 2, Lat: 50, Q: 30, Blk: 6, Clients: 4, Temp: 50, Rate: true}
}

func TestGraphRingsAndFolding(t *testing.T) {
	g := newGraphStore()
	for i := 0; i < graphFine+40; i++ {
		g.Add(fine(int64(i)*10, 1000))
	}
	h := g.View(false)
	if len(h.T) != graphFine || h.T[0] != 40*10 || h.IntervalS != 10 {
		t.Fatalf("the hour view must hold the newest %d samples: %d from t=%d", graphFine, len(h.T), h.T[0])
	}
	d := g.View(true)
	if len(d.T) != (graphFine+40)/6 || d.IntervalS != 60 {
		t.Errorf("one coarse sample per six fine ones: %d", len(d.T))
	}
	if *d.RX[0] != 1000 || *d.TX[0] != 500 || *d.Q[0] != 30 || *d.Lat[0] != 50 || *d.Clients[0] != 4 || *d.Temp[0] != 50 {
		t.Errorf("a minute of identical samples must fold to the same values: %+v", d)
	}
	for i := 0; i < graphCoarse*6+30; i++ {
		g.Add(fine(int64(i), 1))
	}
	if n := len(g.View(true).T); n != graphCoarse {
		t.Errorf("coarse ring not capped: %d", n)
	}
}

func TestFoldAveragesAndKeepsGaps(t *testing.T) {
	in := []gsample{
		{T: 1, Rate: true, RX: 100, TX: 10, Q: 60, Blk: 6, Lat: 40, Clients: 3, Temp: 48},
		{T: 2, Rate: true, RX: 300, TX: 30, Q: 120, Blk: 12, Lat: -1, Clients: -1, Temp: 55},
		{T: 3, Rate: false, Lat: 80, Clients: -1, Temp: 50},
	}
	f := foldSamples(in)
	if f.RX != 200 || f.TX != 20 || f.Q != 90 || f.Blk != 9 || !f.Rate {
		t.Errorf("rates must average over the samples that have one: %+v", f)
	}
	if f.Lat != 60 || f.Clients != 3 || f.Temp != 55 || f.T != 3 {
		t.Errorf("latency averages over the answers, clients keep the last known, temperature the maximum: %+v", f)
	}
	empty := foldSamples([]gsample{{T: 1, Lat: -1, Clients: -1, Temp: -1}})
	if empty.Rate || empty.Lat != -1 || empty.Clients != -1 || empty.Temp != -1 {
		t.Errorf("a minute with nothing in it must stay empty, not zero: %+v", empty)
	}
}

func TestGraphNullsNotZeros(t *testing.T) {
	g := newGraphStore()
	g.Add(gsample{T: 1, Lat: -1, Clients: -1, Temp: -1}) // the very first sample has no rates
	g.Add(fine(11, 1000))
	b, _ := json.Marshal(g.View(false))
	var m map[string][]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"rx", "tx", "lat", "q", "blk", "clients", "temp"} {
		if m[k][0] != nil || m[k][1] == nil {
			t.Errorf("%s: first must be null, second a number: %v", k, m[k])
		}
	}
}

func TestRate(t *testing.T) {
	if r, ok := rate(1000, 3000, 10); !ok || r != 200 {
		t.Errorf("%v %v", r, ok)
	}
	if _, ok := rate(5000, 100, 10); ok {
		t.Error("a counter that went backwards (a reset) must give no rate")
	}
	if _, ok := rate(1, 2, 0); ok {
		t.Error("no elapsed time")
	}
}
