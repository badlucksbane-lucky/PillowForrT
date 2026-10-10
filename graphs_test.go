package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fine(t int64, rx float64) gsample {
	return gsample{T: t, RX: rx, TX: rx / 2, Lat: 50, Q: 30, Blk: 6, Clients: 4, Temp: 50, CPU: 30, CPUSelf: 10, Mem: 100, MemSelf: 40, Rate: true}
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
	if *d.RX[0] != 1000 || *d.TX[0] != 500 || *d.Q[0] != 30 || *d.Lat[0] != 50 || *d.Clients[0] != 4 || *d.Temp[0] != 50 ||
		*d.CPU[0] != 30 || *d.CPUSelf[0] != 10 || *d.Mem[0] != 100 || *d.MemSelf[0] != 40 {
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
		{T: 1, Rate: true, RX: 100, TX: 10, Q: 60, Blk: 6, Lat: 40, Clients: 3, Temp: 48, CPU: 20, CPUSelf: 5, Mem: 100, MemSelf: 40},
		{T: 2, Rate: true, RX: 300, TX: 30, Q: 120, Blk: 12, Lat: -1, Clients: -1, Temp: 55, CPU: 40, CPUSelf: 15, Mem: 120, MemSelf: 42},
		{T: 3, Rate: false, Lat: 80, Clients: -1, Temp: 50, CPU: -1, CPUSelf: -1, Mem: -1, MemSelf: -1},
	}
	f := foldSamples(in)
	if f.RX != 200 || f.TX != 20 || f.Q != 90 || f.Blk != 9 || !f.Rate {
		t.Errorf("rates must average over the samples that have one: %+v", f)
	}
	if f.Lat != 60 || f.Clients != 3 || f.Temp != 55 || f.T != 3 {
		t.Errorf("latency averages over the answers, clients keep the last known, temperature the maximum: %+v", f)
	}
	if f.CPU != 30 || f.CPUSelf != 10 || f.Mem != 120 || f.MemSelf != 42 {
		t.Errorf("CPU averages over the readings that exist, memory keeps the peak: %+v", f)
	}
	empty := foldSamples([]gsample{{T: 1, Lat: -1, Clients: -1, Temp: -1, CPU: -1, CPUSelf: -1, Mem: -1, MemSelf: -1}})
	if empty.Rate || empty.Lat != -1 || empty.Clients != -1 || empty.Temp != -1 || empty.CPU != -1 || empty.CPUSelf != -1 || empty.Mem != -1 || empty.MemSelf != -1 {
		t.Errorf("a minute with nothing in it must stay empty, not zero: %+v", empty)
	}
}

func TestGraphNullsNotZeros(t *testing.T) {
	g := newGraphStore()
	g.Add(gsample{T: 1, Lat: -1, Clients: -1, Temp: -1, CPU: -1, CPUSelf: -1, Mem: -1, MemSelf: -1}) // the very first sample has no rates
	g.Add(fine(11, 1000))
	b, _ := json.Marshal(g.View(false))
	var m map[string][]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"rx", "tx", "lat", "q", "blk", "clients", "temp", "cpu", "cpu_self", "mem", "mem_self"} {
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

func TestMemoryReadersUseTheProcFixture(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "self"), 0o755)
	// 160000 kB total; 2000 free + 0 buffers + 58000 cached = 60000 kB available, so 100000 kB (97.66 MB) is in use
	os.WriteFile(filepath.Join(dir, "meminfo"), []byte("MemTotal:  160000 kB\nMemFree:  2000 kB\nBuffers:  0 kB\nCached:  58000 kB\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "self/statm"), []byte("20000 12800 300 10 0 5000 0\n"), 0o644)
	old := *procDir
	*procDir = dir
	defer func() { *procDir = old }()
	if got := memUsedMB(); got < 97.6 || got > 97.7 {
		t.Errorf("memory in use %v MB, want 97.66", got)
	}
	if got, want := selfRSSMB(), 12800*float64(os.Getpagesize())/(1<<20); got != want {
		t.Errorf("resident %v MB, want %v", got, want)
	}
	*procDir = filepath.Join(dir, "missing")
	if memUsedMB() != -1 || selfRSSMB() != -1 {
		t.Error("an unreadable /proc must give -1 (unknown), never 0")
	}
}
