package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func muxServer(t *testing.T) (*btMgr, *httptest.Server, string) {
	t.Helper()
	btTest(t)
	m := &btMgr{enabled: true, state: func() ownState { return ownState{MullvadWanted: true, TunnelUp: true} }}
	srv := httptest.NewServer(http.HandlerFunc(m.mux))
	t.Cleanup(srv.Close)
	return m, srv, "https://" + srv.Listener.Addr().String()
}

func muxFrame(typ byte, id uint16, p []byte) []byte {
	return append([]byte{typ, byte(id >> 8), byte(id)}, p...)
}

// recvFrame reads the next WebSocket message and splits it into a mux frame.
func (w *wsTestClient) recvFrame(t *testing.T) (byte, uint16, []byte) {
	t.Helper()
	w.c.SetReadDeadline(time.Now().Add(4 * time.Second))
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			t.Fatalf("read: %v", err)
		}
		l := int(h[1] & 0x7f)
		if l == 126 {
			var e [2]byte
			io.ReadFull(w.br, e[:])
			l = int(binary.BigEndian.Uint16(e[:]))
		}
		p := make([]byte, l)
		io.ReadFull(w.br, p)
		if h[0]&0x0f != 2 {
			t.Fatalf("expected a binary message, got opcode %d", h[0]&0x0f)
		}
		if len(p) < muxHdr {
			t.Fatalf("short frame %v", p)
		}
		return p[0], binary.BigEndian.Uint16(p[1:3]), p[muxHdr:]
	}
}

// recvData collects n bytes of DATA for one stream, failing on anything else for it.
func (w *wsTestClient) recvData(t *testing.T, id uint16, n int) []byte {
	t.Helper()
	var out []byte
	for len(out) < n {
		typ, got, p := w.recvFrame(t)
		if got != id || typ != muxData {
			t.Fatalf("wanted data for stream %d, got type %d for stream %d (%q)", id, typ, got, p)
		}
		out = append(out, p...)
	}
	return out
}

func waitConns(t *testing.T, m *btMgr, want int32) {
	t.Helper()
	for i := 0; i < 40; i++ {
		if m.conns.Load() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("conns %d, want %d", m.conns.Load(), want)
}

func TestMuxCarriesManyPeersOnOneSocket(t *testing.T) {
	m, srv, origin := muxServer(t)
	a, b := echoServer(t), echoServer(t)
	btAllowed.add([]string{a, b})
	ws, st := wsDial(t, srv, "/api/bt/mux", origin)
	if !strings.Contains(st, "101") {
		t.Fatalf("handshake: %q", st)
	}
	ws.send(muxFrame(muxOpen, 1, []byte(a)))
	ws.send(muxFrame(muxOpen, 2, []byte(b)))
	for _, n := range []int{5, 300, 20000, 50000} { // chunks come back in pieces of up to 16 KB
		for _, id := range []uint16{1, 2} {
			msg := make([]byte, n)
			for i := range msg {
				msg[i] = byte(i*7) + byte(id)
			}
			ws.send(muxFrame(muxData, id, msg))
			if got := ws.recvData(t, id, n); string(got) != string(msg) {
				t.Fatalf("stream %d: %d bytes came back different", id, n)
			}
		}
	}
	if m.conns.Load() != 2 || m.muxes.Load() != 1 {
		t.Fatalf("two peers on one socket: conns %d muxes %d", m.conns.Load(), m.muxes.Load())
	}
	ws.send(muxFrame(muxPing, 0, nil))
	ws.send(muxFrame(muxClose, 1, nil)) // the page ends one peer: its slot is freed and the other carries on
	waitConns(t, m, 1)
	ws.send(muxFrame(muxData, 2, []byte("still here")))
	if got := ws.recvData(t, 2, 10); string(got) != "still here" {
		t.Fatalf("the other stream must carry on: %q", got)
	}
	ws.c.Close() // the page goes away: every stream and the socket slot are freed
	waitConns(t, m, 0)
	time.Sleep(100 * time.Millisecond)
	if m.muxes.Load() != 0 {
		t.Fatalf("muxes %d", m.muxes.Load())
	}
}

func TestMuxRefusesWhatConnRefuses(t *testing.T) {
	m, srv, origin := muxServer(t)
	peer := echoServer(t)
	btAllowed.add([]string{peer})
	if _, st := wsDial(t, srv, "/api/bt/mux", "https://evil.example"); !strings.Contains(st, "403") {
		t.Fatalf("a foreign Origin must be refused: %q", st)
	}
	if _, st := wsDial(t, srv, "/api/bt/mux", ""); !strings.Contains(st, "403") {
		t.Fatalf("no Origin and no token must be refused: %q", st)
	}
	ws, st := wsDial(t, srv, "/api/bt/mux", origin)
	if !strings.Contains(st, "101") {
		t.Fatalf("handshake: %q", st)
	}
	for name, f := range map[string][]byte{
		"a peer this box never handed out": muxFrame(muxOpen, 7, []byte("127.0.0.1:1")),
		"a private address off the list":   muxFrame(muxOpen, 8, []byte("192.168.1.5:6881")),
		"not an address":                   muxFrame(muxOpen, 9, []byte("example.com:80")),
		"stream 0":                         muxFrame(muxOpen, 0, []byte(peer)),
	} {
		ws.send(f)
		typ, _, p := ws.recvFrame(t)
		if typ != muxClose || len(p) != 1 || p[0] != muxFailed {
			t.Fatalf("%s must be refused with a failed CLOSE: type %d %v", name, typ, p)
		}
	}
	ws.send(muxFrame(muxOpen, 3, []byte(peer)))
	ws.send(muxFrame(muxOpen, 3, []byte(peer))) // the same id twice
	if typ, id, _ := ws.recvFrame(t); typ != muxClose || id != 3 {
		t.Fatalf("a duplicate id must be refused: type %d id %d", typ, id)
	}
	ws.send(muxFrame(muxData, 3, []byte("ok")))
	if got := ws.recvData(t, 3, 2); string(got) != "ok" {
		t.Fatalf("the first stream with that id must be unaffected: %q", got)
	}
	if m.conns.Load() != 1 {
		t.Fatalf("refused streams must not hold slots: %d", m.conns.Load())
	}
}

func TestMuxSocketCap(t *testing.T) {
	_, srv, origin := muxServer(t)
	var open []*wsTestClient
	for i := 0; i < btMaxMux; i++ {
		ws, st := wsDial(t, srv, "/api/bt/mux", origin)
		if !strings.Contains(st, "101") {
			t.Fatalf("socket %d: %q", i, st)
		}
		open = append(open, ws)
	}
	if _, st := wsDial(t, srv, "/api/bt/mux", origin); !strings.Contains(st, "503") {
		t.Fatalf("one more than %d sockets must be refused: %q", btMaxMux, st)
	}
}

func TestMuxDialFailureAndEarlyBytes(t *testing.T) {
	m, srv, origin := muxServer(t)
	peer := echoServer(t)
	btAllowed.add([]string{peer, "8.8.8.8:6881"})
	real := btDialTCP
	btDialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == "8.8.8.8:6881" {
			return nil, io.ErrClosedPipe
		}
		select { // a slow peer
		case <-time.After(700 * time.Millisecond):
			return real(ctx, addr)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ws, _ := wsDial(t, srv, "/api/bt/mux", origin)
	ws.send(muxFrame(muxOpen, 1, []byte("8.8.8.8:6881")))
	if typ, id, p := ws.recvFrame(t); typ != muxClose || id != 1 || p[0] != muxFailed {
		t.Fatalf("an unreachable peer must end in a failed CLOSE: %d %d %v", typ, id, p)
	}
	waitConns(t, m, 0)
	ws.send(muxFrame(muxOpen, 2, []byte(peer)))
	ws.send(muxFrame(muxData, 2, []byte("sent before the dial finished")))
	if got := ws.recvData(t, 2, 29); string(got) != "sent before the dial finished" {
		t.Fatalf("bytes sent during the dial must reach the peer once it is up: %q", got)
	}
}

func TestMuxPeerEndingIsReported(t *testing.T) {
	m, srv, origin := muxServer(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Write([]byte("bye"))
			c.Close()
		}
	}()
	btAllowed.add([]string{l.Addr().String()})
	ws, _ := wsDial(t, srv, "/api/bt/mux", origin)
	ws.send(muxFrame(muxOpen, 5, []byte(l.Addr().String())))
	if got := ws.recvData(t, 5, 3); string(got) != "bye" {
		t.Fatalf("data before the end: %q", got)
	}
	if typ, id, p := ws.recvFrame(t); typ != muxClose || id != 5 || p[0] != muxEnded {
		t.Fatalf("the peer ending must be a CLOSE with reason 0: %d %d %v", typ, id, p)
	}
	waitConns(t, m, 0)
}

// One peer whose socket never drains must lose its own stream and nothing else.
func TestMuxStalledPeerDoesNotStallOthers(t *testing.T) {
	m, srv, origin := muxServer(t)
	good := echoServer(t)
	btAllowed.add([]string{good, "8.8.4.4:6881"})
	real := btDialTCP
	var stuck net.Conn
	var mu sync.Mutex
	btDialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == "8.8.4.4:6881" {
			a, b := net.Pipe() // nothing reads b, so a write to a blocks
			mu.Lock()
			stuck = b
			mu.Unlock()
			return a, nil
		}
		return real(ctx, addr)
	}
	t.Cleanup(func() {
		mu.Lock()
		if stuck != nil {
			stuck.Close()
		}
		mu.Unlock()
	})
	ws, _ := wsDial(t, srv, "/api/bt/mux", origin)
	ws.send(muxFrame(muxOpen, 1, []byte("8.8.4.4:6881")))
	ws.send(muxFrame(muxOpen, 2, []byte(good)))
	for i := 0; i < muxQueue+8; i++ {
		ws.send(muxFrame(muxData, 1, []byte("x")))
	}
	ws.send(muxFrame(muxData, 2, []byte("fine")))
	var gotClose, gotData bool
	for !(gotClose && gotData) {
		typ, id, p := ws.recvFrame(t)
		switch {
		case typ == muxClose && id == 1:
			gotClose = true
		case typ == muxData && id == 2 && string(p) == "fine":
			gotData = true
		default:
			t.Fatalf("unexpected frame type %d stream %d %q", typ, id, p)
		}
	}
	waitConns(t, m, 1)
}

func TestMuxRejectsAnUnknownFrameType(t *testing.T) {
	m, srv, origin := muxServer(t)
	ws, _ := wsDial(t, srv, "/api/bt/mux", origin)
	ws.send(muxFrame(99, 1, nil))
	ws.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := ws.br.ReadByte(); err == nil {
		t.Fatal("the socket must be closed on a frame it does not know")
	}
	time.Sleep(100 * time.Millisecond)
	if m.muxes.Load() != 0 {
		t.Fatalf("muxes %d", m.muxes.Load())
	}
}

// TestMuxServeForJS is not a test: with MUX_SERVE=1 it serves the real multiplexer (with a few made-up peers) for scripts/dev/mux-test.mjs, which drives the browser shim
// (btclient/net-shim.js) against it. It prints one line of JSON and runs until /quit is fetched (or two minutes pass).
func TestMuxServeForJS(t *testing.T) {
	if os.Getenv("MUX_SERVE") == "" {
		t.Skip("serves the multiplexer for scripts/dev/mux-test.mjs; set MUX_SERVE=1")
	}
	btTest(t)
	m := &btMgr{enabled: true, state: func() ownState { return ownState{MullvadWanted: true, TunnelUp: true} }}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/bt/mux", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "" {
			r.Header.Set("X-UI-Token", "test") // Node's WebSocket sends no Origin; a script is allowed with a token
		}
		m.mux(w, r)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]int32{"conns": m.conns.Load(), "muxes": m.muxes.Load()})
	})
	quit := make(chan struct{})
	mux.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) { close(quit) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	a, b := echoServer(t), echoServer(t)
	bye, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bye.Close()
	go func() {
		for {
			c, err := bye.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("bye"))
			c.Close()
		}
	}()
	btAllowed.add([]string{a, b, bye.Addr().String()})
	fmt.Printf("{\"url\":%q,\"echoA\":%q,\"echoB\":%q,\"bye\":%q,\"offList\":\"8.8.8.8:6881\"}\n", srv.URL, a, b, bye.Addr().String())
	select {
	case <-quit:
	case <-time.After(2 * time.Minute):
	}
}
