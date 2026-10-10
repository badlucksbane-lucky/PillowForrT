package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func roomServer(t *testing.T) (*roomMgr, *httptest.Server, string) {
	t.Helper()
	old := roomGrace
	roomGrace = 300 * time.Millisecond
	t.Cleanup(func() { roomGrace = old })
	m := &roomMgr{rooms: map[string]*room{}}
	srv := httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(srv.Close)
	return m, srv, "https://" + srv.Listener.Addr().String()
}

// recvJSON reads the next WebSocket text message as a JSON object.
func (w *wsTestClient) recvJSON(t *testing.T) map[string]any {
	t.Helper()
	w.c.SetReadDeadline(time.Now().Add(4 * time.Second))
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
	if h[0]&0x0f != 1 {
		t.Fatalf("expected a text message, got opcode %d", h[0]&0x0f)
	}
	var out map[string]any
	if err := json.Unmarshal(p, &out); err != nil {
		t.Fatalf("not JSON: %q", p)
	}
	return out
}

func roomJoin(t *testing.T, srv *httptest.Server, origin, code, name string) (*wsTestClient, map[string]any) {
	t.Helper()
	ws, st := wsDial(t, srv, "/api/room", origin)
	if !strings.Contains(st, "101") {
		t.Fatalf("handshake: %q", st)
	}
	ws.send(roomJSON(map[string]string{"t": "join", "room": code, "name": name}))
	return ws, ws.recvJSON(t)
}

func TestRoomIntroducesRelaysAndForgets(t *testing.T) {
	m, srv, origin := roomServer(t)
	a, ha := roomJoin(t, srv, origin, "", "TV")
	code, _ := ha["room"].(string)
	if ha["t"] != "hello" || len(code) != 4 || ha["id"] != "p1" || len(ha["peers"].([]any)) != 0 {
		t.Fatalf("creating a room: %v", ha)
	}
	b, hb := roomJoin(t, srv, origin, code, "Pixel")
	if hb["id"] != "p2" || len(hb["peers"].([]any)) != 1 {
		t.Fatalf("joining: %v", hb)
	}
	if j := a.recvJSON(t); j["t"] != "join" || j["id"] != "p2" || j["name"] != "Pixel" {
		t.Fatalf("the first page must hear of the second: %v", j)
	}
	b.send(roomJSON(map[string]any{"t": "to", "to": "p1", "d": map[string]string{"sdp": "offer"}}))
	if f := a.recvJSON(t); f["t"] != "from" || f["from"] != "p2" || f["d"].(map[string]any)["sdp"] != "offer" {
		t.Fatalf("relay to a peer: %v", f)
	}
	b.send(roomJSON(map[string]any{"t": "to", "to": "p2", "d": 7})) // to yourself: the relay round trip
	if f := b.recvJSON(t); f["from"] != "p2" || f["d"].(float64) != 7 {
		t.Fatalf("relay to self: %v", f)
	}
	b.send(roomJSON(map[string]any{"t": "to", "to": "p9", "d": 1})) // nobody there: dropped, socket stays up
	b.send([]byte(`{"t":"ping"}`))
	if p := b.recvJSON(t); p["t"] != "pong" {
		t.Fatalf("ping must be answered: %v", p)
	}
	b.c.Close()
	if l := a.recvJSON(t); l["t"] != "away" || l["id"] != "p2" {
		t.Fatalf("a dropped socket is away first: %v", l)
	}
	if l := a.recvJSON(t); l["t"] != "leave" || l["id"] != "p2" {
		t.Fatalf("leave after the grace period: %v", l)
	}
	a.c.Close()
	for i := 0; i < 40; i++ {
		m.mu.Lock()
		n := len(m.rooms)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("an empty room must be forgotten")
}

func TestRoomRefusals(t *testing.T) {
	m, srv, origin := roomServer(t)
	if _, h := roomJoin(t, srv, origin, "ZZZZ", "x"); h["t"] != "err" || h["m"] != "no such room" {
		t.Fatalf("unknown room: %v", h)
	}
	_, h := roomJoin(t, srv, origin, "", "host")
	code := h["room"].(string)
	for i := 1; i < roomMaxPeers; i++ {
		if _, g := roomJoin(t, srv, origin, code, "p"); g["t"] != "hello" {
			t.Fatalf("peer %d: %v", i, g)
		}
	}
	if _, g := roomJoin(t, srv, origin, code, "late"); g["t"] != "err" || g["m"] != "room is full" {
		t.Fatalf("full room: %v", g)
	}
	for i := 1; i < roomMaxRooms; i++ {
		roomJoin(t, srv, origin, "", "r")
	}
	if _, g := roomJoin(t, srv, origin, "", "one too many"); g["t"] != "err" || g["m"] != "too many rooms" {
		t.Fatalf("room cap: %v", g)
	}
	_ = m
	if _, st := wsDial(t, srv, "/api/room", "https://evil.example"); !strings.Contains(st, "403") {
		t.Fatalf("a foreign origin must be refused: %q", st)
	}
}

// TestRoomServeForJS serves the room page and channel over plain HTTP for scripts/dev/room-test.mjs.
func TestRoomServeForJS(t *testing.T) {
	if os.Getenv("ROOM_SERVE") == "" {
		t.Skip("serves the room channel for scripts/dev/room-test.mjs; set ROOM_SERVE=1")
	}
	old := wsOriginScheme
	wsOriginScheme = "http"
	defer func() { wsOriginScheme = old }()
	oldGrace := roomGrace
	roomGrace = 4 * time.Second // short, so the script can watch a place expire
	defer func() { roomGrace = oldGrace }()
	m := &roomMgr{rooms: map[string]*room{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/room", m.serve)
	mux.HandleFunc("/room/room.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, roomClientJS) })
	mux.HandleFunc("/room/qr.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, roomQRJS) })
	mux.HandleFunc("/room-test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, roomTestHTML)
	})
	quit := make(chan struct{})
	mux.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) { close(quit) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	fmt.Printf("{\"url\":%q}\n", srv.URL)
	select {
	case <-quit:
	case <-time.After(2 * time.Minute):
	}
}

func roomResume(t *testing.T, srv *httptest.Server, origin, code, id, token string) (*wsTestClient, map[string]any) {
	t.Helper()
	ws, st := wsDial(t, srv, "/api/room", origin)
	if !strings.Contains(st, "101") {
		t.Fatalf("handshake: %q", st)
	}
	ws.send(roomJSON(map[string]string{"t": "join", "room": code, "name": "again", "id": id, "token": token}))
	return ws, ws.recvJSON(t)
}

func TestRoomResumeKeepsThePlace(t *testing.T) {
	m, srv, origin := roomServer(t)
	roomGrace = 5 * time.Second
	a, ha := roomJoin(t, srv, origin, "", "TV")
	code := ha["room"].(string)
	b, hb := roomJoin(t, srv, origin, code, "Pixel")
	a.recvJSON(t) // join
	if hb["token"] == "" || hb["grace"].(float64) != 5 {
		t.Fatalf("hello must carry a token and the grace period: %v", hb)
	}
	b.c.Close()
	if l := a.recvJSON(t); l["t"] != "away" || l["id"] != "p2" {
		t.Fatalf("away: %v", l)
	}
	b2, h2 := roomResume(t, srv, origin, code, "p2", hb["token"].(string))
	if h2["t"] != "hello" || h2["id"] != "p2" || h2["resumed"] != true || len(h2["peers"].([]any)) != 1 {
		t.Fatalf("resume: %v", h2)
	}
	if l := a.recvJSON(t); l["t"] != "back" || l["id"] != "p2" {
		t.Fatalf("back: %v", l)
	}
	b2.send(roomJSON(map[string]any{"t": "to", "to": "p1", "d": "hi"}))
	if f := a.recvJSON(t); f["from"] != "p2" || f["d"] != "hi" {
		t.Fatalf("a resumed page must be able to send: %v", f)
	}
	// the old grace timer must not take the place away after a resume
	roomGrace = 300 * time.Millisecond
	time.Sleep(400 * time.Millisecond)
	m.mu.Lock()
	n := len(m.rooms[code].peers)
	m.mu.Unlock()
	if n != 2 {
		t.Fatalf("both places must remain, have %d", n)
	}
	if _, bad := roomResume(t, srv, origin, code, "p2", "wrong"); bad["m"] != "expired" {
		t.Fatalf("a wrong token must be refused: %v", bad)
	}
}

func TestRoomResumeReplacesADeadSocketQuietly(t *testing.T) {
	_, srv, origin := roomServer(t)
	roomGrace = 5 * time.Second
	a, ha := roomJoin(t, srv, origin, "", "TV")
	code := ha["room"].(string)
	_, hb := roomJoin(t, srv, origin, code, "Pixel") // its socket stays open: the box has not noticed anything wrong
	a.recvJSON(t)
	b2, h2 := roomResume(t, srv, origin, code, "p2", hb["token"].(string))
	if h2["resumed"] != true {
		t.Fatalf("resume over a live socket: %v", h2)
	}
	b2.send(roomJSON(map[string]any{"t": "to", "to": "p1", "d": 1}))
	if f := a.recvJSON(t); f["t"] != "from" { // not away, not back: nobody saw a gap
		t.Fatalf("others must not be told of a swap: %v", f)
	}
}

func TestRoomGraceEndsAndByeIsImmediate(t *testing.T) {
	m, srv, origin := roomServer(t)
	a, ha := roomJoin(t, srv, origin, "", "TV")
	code := ha["room"].(string)
	b, hb := roomJoin(t, srv, origin, code, "Pixel")
	a.recvJSON(t)
	b.c.Close()
	a.recvJSON(t) // away
	if l := a.recvJSON(t); l["t"] != "leave" {
		t.Fatalf("expiry: %v", l)
	}
	if _, g := roomResume(t, srv, origin, code, "p2", hb["token"].(string)); g["m"] != "expired" {
		t.Fatalf("a place given up cannot be resumed: %v", g)
	}
	c, _ := roomJoin(t, srv, origin, code, "Moto")
	a.recvJSON(t) // join
	c.send([]byte(`{"t":"bye"}`))
	if l := a.recvJSON(t); l["t"] != "leave" || l["id"] != "p3" { // no away first
		t.Fatalf("bye leaves at once: %v", l)
	}
	a.c.Close() // the last page: its place is kept, then the room goes
	time.Sleep(600 * time.Millisecond)
	m.mu.Lock()
	n := len(m.rooms)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("a room with nobody left must be forgotten, have %d", n)
	}
}

func TestRoomLANAddress(t *testing.T) {
	cases := map[string]string{"192.168.1.254:443": "192.168.1.254", "10.0.0.7:3129": "10.0.0.7", "172.20.1.1:80": "172.20.1.1", "127.0.0.1:443": "", "8.8.8.8:443": "", "[fe80::1]:443": "", "[::1]:443": "", "garbage": ""}
	for in, want := range cases {
		a, _ := net.ResolveTCPAddr("tcp", in)
		var addr net.Addr
		if a != nil {
			addr = a
		}
		if got := roomLAN(addr); got != want {
			t.Errorf("roomLAN(%q) = %q, want %q", in, got, want)
		}
	}
	if roomLAN(nil) != "" {
		t.Error("nil address")
	}
}
