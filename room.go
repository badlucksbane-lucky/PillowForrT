package main

// The room channel (/api/room): a WebSocket where devices on the LAN meet by a 4-letter room code. The box only introduces them and, when two pages cannot reach each other directly, passes
// their messages along. Frames are JSON text, nothing is stored or logged, and a room lives only while someone is in it.
//
// A page that loses its socket (a phone sleeping, Wi-Fi roaming, a reload) is not forgotten at once: its place in the room is kept for roomGrace, and it comes back with the id and token the
// box gave it. Only a page that says "bye", or stays away past the grace period, is announced as gone.
//
//	page -> box   {"t":"join","room":"ABCD","name":"Pixel"}   join a room; an empty room creates one
//	              {"t":"join","room":"ABCD","name":"Pixel","id":"p2","token":"..."}   come back to the same place
//	              {"t":"to","to":"p2","d":<any>}              send d to one peer (yourself too: that is the box round trip)
//	              {"t":"ping"}                                answered with pong; keeps an idle socket open
//	              {"t":"bye"}                                 leave now, no grace
//	box -> page   {"t":"hello","id":"p1","token":"..","room":"ABCD","resumed":false,"grace":60,"lan":"192.168.1.254","peers":[{"id":"p2","name":"TV","away":false}]}
//	              "lan" is the box's own LAN address (its services address, 192.168.1.254, for either of its two; absent when not a private IPv4 address): the address to put in a join link, because every phone can use it
//	              even when one cannot use the box's name (a phone whose proxy settings cannot tunnel to it).
//	              {"t":"join","id":"p3","name":"Phone"}  {"t":"away","id":"p3"}  {"t":"back","id":"p3"}  {"t":"leave","id":"p3"}
//	              {"t":"from","from":"p2","d":<any>}          what a peer sent with "to"
//	              {"t":"pong"}
//	              {"t":"err","m":"..."}                       then the socket closes: "no such room", "expired" (the place was given up; join afresh), "room is full", "too many rooms"
//
// WebRTC offers, answers and ICE candidates travel as "d". The same path is the fallback transport when WebRTC cannot connect.

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	roomMaxRooms = 8
	roomMaxPeers = 8
	roomMaxMsg   = 16 << 10
	roomQueue    = 64               // messages waiting for one page's socket before that page is dropped
	roomRate     = 100              // messages a page may send in one second
	roomIdle     = 90 * time.Second // pages ping every 25 s; a socket silent for this long is treated as gone (the place is kept for roomGrace)
	roomAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ"
)

var roomGrace = 60 * time.Second // how long a page's place is kept after its socket goes (a variable so tests can shorten it)

// roomConn is one WebSocket. A peer may use several over its life.
type roomConn struct {
	c    net.Conn
	wmu  sync.Mutex // one writer to the socket at a time (wsRead answers pings under it too)
	out  chan []byte
	done chan struct{} // closed when the socket is finished; out is never closed, so a late send cannot panic
	once sync.Once
}

func newRoomConn(c net.Conn) *roomConn {
	rc := &roomConn{c: c, out: make(chan []byte, roomQueue), done: make(chan struct{})}
	go rc.writer()
	return rc
}

// send queues a frame for the page; a page whose queue is full is dropped rather than made to wait.
func (rc *roomConn) send(msg []byte) {
	select {
	case rc.out <- msg:
	default:
		rc.c.Close()
	}
}

func (rc *roomConn) close() {
	rc.once.Do(func() { close(rc.done) })
	rc.c.Close()
}

func (rc *roomConn) writer() {
	for {
		var msg []byte
		select {
		case msg = <-rc.out:
		case <-rc.done:
			return
		}
		buf := make([]byte, wsMaxHeader+len(msg))
		hl := wsHeader(buf[:wsMaxHeader], 0x1, len(msg))
		copy(buf[wsMaxHeader:], msg)
		rc.wmu.Lock()
		rc.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := rc.c.Write(buf[wsMaxHeader-hl:])
		rc.wmu.Unlock()
		if err != nil {
			rc.c.Close()
			return
		}
	}
}

// roomLAN returns the address to put in a join link: this end of the connection when it is a private IPv4 address, or "". The box has two LAN addresses, the router address and the services
// address (defaultDNSLocal: the one its name points to, and the one the phones are signed in at); a connection to the services address is redirected to the router address, so the socket
// reports that one, and either maps to the services address.
func roomLAN(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return ""
	}
	for _, own := range defaultDNSLocal {
		if ip.String() == own {
			return defaultDNSLocal[0]
		}
	}
	return ip.String()
}

// roomPeer is a place in a room. Its fields are guarded by roomMgr.mu.
type roomPeer struct {
	id, name, token string
	conn            *roomConn   // nil while the page is away
	timer           *time.Timer // gives the place up when the grace period ends
}

type room struct {
	code  string
	peers map[string]*roomPeer
	next  int
}

type roomMgr struct {
	mu    sync.Mutex
	rooms map[string]*room
}

var roomMgrG = &roomMgr{rooms: map[string]*room{}}

type roomIn struct {
	T     string          `json:"t"`
	Room  string          `json:"room"`
	Name  string          `json:"name"`
	ID    string          `json:"id"`
	Token string          `json:"token"`
	To    string          `json:"to"`
	D     json.RawMessage `json:"d"`
}

type roomInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Away bool   `json:"away"`
}

func roomJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func newRoomCode() string {
	var b [4]byte
	rand.Read(b[:])
	for i := range b {
		b[i] = roomAlphabet[int(b[i])%len(roomAlphabet)]
	}
	return string(b[:])
}

func newRoomToken() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// tell sends msg to every page in the room that is connected, except one. The caller holds m.mu.
func (rm *room) tell(except *roomPeer, msg []byte) {
	for _, o := range rm.peers {
		if o != except && o.conn != nil {
			o.conn.send(msg)
		}
	}
}

// others lists the places in the room except one. The caller holds m.mu.
func (rm *room) others(except *roomPeer) []roomInfo {
	out := []roomInfo{}
	for _, o := range rm.peers {
		if o != except {
			out = append(out, roomInfo{o.id, o.name, o.conn == nil})
		}
	}
	return out
}

// join puts a page in a room, creating it when code is empty.
func (m *roomMgr) join(code, name string, rc *roomConn) (*room, *roomPeer, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rm := m.rooms[code]
	switch {
	case code == "":
		if len(m.rooms) >= roomMaxRooms {
			return nil, nil, "too many rooms"
		}
		for {
			code = newRoomCode()
			if m.rooms[code] == nil {
				break
			}
		}
		rm = &room{code: code, peers: map[string]*roomPeer{}}
		m.rooms[code] = rm
	case rm == nil:
		return nil, nil, "no such room"
	case len(rm.peers) >= roomMaxPeers:
		return nil, nil, "room is full"
	}
	rm.next++
	p := &roomPeer{id: "p" + strconv.Itoa(rm.next), name: name, token: newRoomToken(), conn: rc}
	rm.tell(nil, roomJSON(map[string]string{"t": "join", "id": p.id, "name": p.name}))
	rm.peers[p.id] = p
	return rm, p, ""
}

// resume gives a page back its place, even when the box has not noticed that its old socket died.
func (m *roomMgr) resume(code, id, token string, rc *roomConn) (*room, *roomPeer, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rm := m.rooms[code]
	if rm == nil {
		return nil, nil, "no such room"
	}
	p := rm.peers[id]
	if p == nil || subtle.ConstantTimeCompare([]byte(p.token), []byte(token)) != 1 {
		return nil, nil, "expired"
	}
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	old := p.conn
	p.conn = rc
	if old != nil {
		old.close() // its serve loop ends and finds it is no longer the page's socket
	} else {
		rm.tell(p, roomJSON(map[string]string{"t": "back", "id": p.id}))
	}
	return rm, p, ""
}

// detach is called when a socket ends: the place is kept for the grace period unless a newer socket has taken it.
func (m *roomMgr) detach(rm *room, p *roomPeer, rc *roomConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.conn != rc || rm.peers[p.id] != p {
		return
	}
	p.conn = nil
	rm.tell(p, roomJSON(map[string]string{"t": "away", "id": p.id}))
	p.timer = time.AfterFunc(roomGrace, func() { m.expire(rm, p) })
}

func (m *roomMgr) expire(rm *room, p *roomPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.conn == nil {
		m.remove(rm, p)
	}
}

// remove takes a place out of its room, tells the rest, and forgets the room when it is empty. The caller holds m.mu.
func (m *roomMgr) remove(rm *room, p *roomPeer) {
	if rm.peers[p.id] != p {
		return
	}
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	delete(rm.peers, p.id)
	rm.tell(nil, roomJSON(map[string]string{"t": "leave", "id": p.id}))
	if len(rm.peers) == 0 {
		delete(m.rooms, rm.code)
	}
}

func (m *roomMgr) bye(rm *room, p *roomPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remove(rm, p)
}

func (m *roomMgr) route(rm *room, from *roomPeer, to string, d json.RawMessage) {
	m.mu.Lock()
	var dst *roomConn
	if o := rm.peers[to]; o != nil {
		dst = o.conn
	}
	m.mu.Unlock()
	if dst != nil { // a page that is away misses what was sent meanwhile; the pages re-negotiate when it is back
		dst.send(roomJSON(map[string]any{"t": "from", "from": from.id, "d": d}))
	}
}

func (m *roomMgr) serve(w http.ResponseWriter, r *http.Request) {
	if !wsOriginOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if btLoadNow() > btLoadLimit {
		http.Error(w, "the box is busy", http.StatusServiceUnavailable)
		return
	}
	c, rw, err := wsAccept(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rc := newRoomConn(c)
	var rm *room
	var p *roomPeer
	defer func() {
		if p != nil {
			m.detach(rm, p, rc)
		}
		rc.close()
	}()
	fail := func(why string) {
		rc.send(roomJSON(map[string]string{"t": "err", "m": why}))
		time.Sleep(50 * time.Millisecond) // let the error frame out before the socket closes
	}
	var in []byte
	var winStart time.Time
	var winCount int
	for {
		c.SetReadDeadline(time.Now().Add(roomIdle))
		msg, err := wsRead(rw.Reader, c, &rc.wmu, in)
		in = msg
		if err != nil {
			return
		}
		if now := time.Now(); now.Sub(winStart) > time.Second {
			winStart, winCount = now, 0
		}
		if winCount++; winCount > roomRate || len(msg) > roomMaxMsg {
			fail("too fast or too big")
			return
		}
		var f roomIn
		if json.Unmarshal(msg, &f) != nil {
			return
		}
		switch {
		case f.T == "ping":
			rc.send([]byte(`{"t":"pong"}`))
		case f.T == "join" && p == nil:
			if len(f.Name) > 24 {
				f.Name = f.Name[:24]
			}
			var why string
			resumed := f.ID != ""
			if resumed {
				rm, p, why = m.resume(f.Room, f.ID, f.Token, rc)
			} else {
				rm, p, why = m.join(f.Room, f.Name, rc)
			}
			if why != "" {
				fail(why)
				return
			}
			m.mu.Lock()
			hello := roomJSON(map[string]any{"t": "hello", "id": p.id, "token": p.token, "room": rm.code, "resumed": resumed, "grace": int(roomGrace / time.Second), "lan": roomLAN(c.LocalAddr()), "peers": rm.others(p)})
			m.mu.Unlock()
			rc.send(hello)
		case f.T == "to" && p != nil:
			m.route(rm, p, f.To, f.D)
		case f.T == "bye" && p != nil:
			m.bye(rm, p)
			p = nil
			return
		default:
			return
		}
	}
}

//go:embed roomtest.html
var roomTestHTML string

//go:embed roomclient/room.js
var roomClientJS []byte

//go:embed roomclient/qr.js
var roomQRJS []byte

// The spike page (/room-test): two devices join a room and measure whether WebRTC reaches directly across this box's Wi-Fi, and how fast the box relay is by comparison. It is built on
// the room client (/room/room.js), so it doubles as a check of the library on a real phone.
func (u *webUI) roomTestPage(w http.ResponseWriter, r *http.Request) {
	if u.auth.Session(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secureHeaders(w)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, roomTestHTML)
}
