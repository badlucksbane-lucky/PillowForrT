package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseCPULine(t *testing.T) {
	// a real line from the box: waiting for I/O (the 5th number) is idle, not busy
	c, ok := parseCPULine("cpu  486369 4742 760788 3444837 1091 0 76884 0 0 0")
	if !ok {
		t.Fatal("not parsed")
	}
	if want := uint64(486369 + 4742 + 760788 + 0 + 76884 + 0); c.busy != want {
		t.Errorf("busy %d, want %d", c.busy, want)
	}
	if want := c.busy + 3444837 + 1091; c.total != want {
		t.Errorf("total %d, want %d", c.total, want)
	}
	if _, ok := parseCPULine("cpu0 1 2 3 4 5"); ok {
		t.Error("a per-CPU line must not be taken for the total")
	}
	if _, ok := parseCPULine("cpu  1 2 x 4 5"); ok {
		t.Error("a garbled number must not parse")
	}
	if c, ok := parseCPULine("cpu  10 0 5 80 5"); !ok || c.busy != 15 || c.total != 100 { // an older kernel gives fewer columns
		t.Errorf("short line: %+v %v", c, ok)
	}
}

func TestBusyShareIgnoresIOWait(t *testing.T) {
	prev, _ := parseCPULine("cpu  100 0 100 1000 0 0 0 0")
	// 200 ticks passed: 20 working, 10 idle, 170 waiting for I/O. The old load average would have called that busy; this must not.
	cur, _ := parseCPULine("cpu  110 0 110 1010 170 0 0 0")
	f, ok := busyShare(prev, cur)
	if !ok || f < 0.099 || f > 0.101 {
		t.Errorf("share %v %v, want 0.10", f, ok)
	}
	cur, _ = parseCPULine("cpu  190 0 200 1010 0 0 0 0") // 180 working out of 190
	if f, ok := busyShare(prev, cur); !ok || f < 0.94 || f > 0.96 {
		t.Errorf("a busy interval: %v %v", f, ok)
	}
	if _, ok := busyShare(cur, prev); ok {
		t.Error("readings out of order must be ignored")
	}
	if _, ok := busyShare(prev, prev); ok {
		t.Error("no time passed: no answer")
	}
}

func TestBusyAverageOverTheWindow(t *testing.T) {
	btBusy.mu.Lock()
	btBusy.n, btBusy.i = 0, 0
	btBusy.mu.Unlock()
	for _, f := range []float64{1, 1, 1, 0.2, 0.2, 0.2, 0.2, 0.2} { // only the last btBusyWindow (5) count
		btBusyAdd(f)
	}
	btBusy.mu.Lock()
	var sum float64
	for _, f := range btBusy.ring[:btBusy.n] {
		sum += f
	}
	got := sum / float64(btBusy.n)
	btBusy.mu.Unlock()
	if got < 0.199 || got > 0.201 {
		t.Errorf("average %v, want 0.2 once the early busy samples have rolled off", got)
	}
}

func TestReadCPUTimesOnThisMachine(t *testing.T) {
	if _, ok := readCPUTimes(); !ok {
		t.Skip("no /proc/stat here")
	}
	if f := btBusyNow(); f < 0 || f > 1 {
		t.Errorf("busy share out of range: %v", f)
	}
}

// Under the limit the bridge takes new peers whatever the load average says; over it, it refuses at every door.
func TestBridgeShedsOnBusyShareNotLoadAverage(t *testing.T) {
	m, srv, origin := muxServer(t)
	peer := echoServer(t)
	btAllowed.add([]string{peer})
	old := btLoadNow
	defer func() { btLoadNow = old }()

	btLoadNow = func() float64 { return 0.2 } // a quiet CPU: accepted, however high loadAvg1 is
	ws, st := wsDial(t, srv, "/api/bt/mux", origin)
	if !strings.Contains(st, "101") {
		t.Fatalf("a quiet box must accept: %q", st)
	}
	ws.send(muxFrame(muxOpen, 1, []byte(peer)))
	ws.send(muxFrame(muxData, 1, []byte("hi")))
	if got := ws.recvData(t, 1, 2); string(got) != "hi" {
		t.Fatalf("%q", got)
	}

	btLoadNow = func() float64 { return 0.97 } // a saturated CPU: a new peer on the open socket is refused, a new socket is refused
	ws.send(muxFrame(muxOpen, 2, []byte(peer)))
	if typ, id, p := ws.recvFrame(t); typ != muxClose || id != 2 || p[0] != muxFailed {
		t.Fatalf("a new peer on a saturated box must be refused: %d %d %v", typ, id, p)
	}
	if _, st := wsDial(t, srv, "/api/bt/mux", origin); !strings.Contains(st, "503") {
		t.Fatalf("a new socket on a saturated box must be refused: %q", st)
	}
	ws.send(muxFrame(muxData, 1, []byte("ok")))
	if got := ws.recvData(t, 1, 2); string(got) != "ok" {
		t.Fatalf("a peer already open carries on: %q", got)
	}
	if m.conns.Load() != 1 {
		t.Fatalf("conns %d", m.conns.Load())
	}

	// the same for the lookup and the per-peer socket
	btLoadNow = func() float64 { return 0.97 }
	rec := btPeersReq(btReadyMgr())
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "busy") {
		t.Errorf("a lookup on a saturated box: %d %q", rec.Code, rec.Body.String())
	}
}

func TestBridgeLimitIsAShareOfTheCore(t *testing.T) {
	if btLoadLimit <= 0 || btLoadLimit >= 1 {
		t.Errorf("btLoadLimit %v: it is compared with a share of the CPU, 0 to 1", btLoadLimit)
	}
}
