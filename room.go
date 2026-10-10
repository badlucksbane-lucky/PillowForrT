package main

// The room channel (/api/room): a WebSocket where devices on the LAN meet by a 4-letter room code. The box only introduces them and, when two pages cannot reach each other directly, passes
// their messages along. Frames are JSON text, nothing is stored or logged, and a room lives only while someone is in it.
//
//	page -> box   {"t":"join","room":"ABCD","name":"Pixel"}   join a room; an empty room creates one
//	              {"t":"to","to":"p2","d":<any>}              send d to one peer (yourself too: that is the relay round trip)
//	              {"t":"ping"}                                keeps an idle socket open
//	box -> page   {"t":"hello","id":"p1","room":"ABCD","peers":[{"id":"p2","name":"TV"}]}
//	              {"t":"join","id":"p3","name":"Phone"}  {"t":"leave","id":"p3"}
//	              {"t":"from","from":"p2","d":<any>}          what a peer sent with "to"
//	              {"t":"err","m":"..."}                       then the socket closes
//
// WebRTC offers, answers and ICE candidates travel as "d". The same path is the fallback transport when WebRTC cannot connect.

import (
	"crypto/rand"
	_ "embed"
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
	roomIdle     = 10 * time.Minute // pages ping every 30 s
	roomAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ"
)

type roomPeer struct {
	id, name string
	c        net.Conn
	wmu      sync.Mutex // one writer to the socket at a time (wsRead answers pings under it too)
	out      chan []byte
	done     chan struct{} // closed when the page is gone; out is never closed, so a late send cannot panic
	once     sync.Once
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
	T    string          `json:"t"`
	Room string          `json:"room"`
	Name string          `json:"name"`
	To   string          `json:"to"`
	D    json.RawMessage `json:"d"`
}

type roomInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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

// send queues a frame for the page; a page whose queue is full is dropped rather than made to wait.
func (p *roomPeer) send(msg []byte) {
	select {
	case p.out <- msg:
	default:
		p.c.Close()
	}
}

func (p *roomPeer) writer() {
	for {
		var msg []byte
		select {
		case msg = <-p.out:
		case <-p.done:
			return
		}
		buf := make([]byte, wsMaxHeader+len(msg))
		hl := wsHeader(buf[:wsMaxHeader], 0x1, len(msg))
		copy(buf[wsMaxHeader:], msg)
		p.wmu.Lock()
		p.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, err := p.c.Write(buf[wsMaxHeader-hl:])
		p.wmu.Unlock()
		if err != nil {
			p.c.Close()
			return
		}
	}
}

// join puts a page in a room, creating it when code is empty. It returns the peers already there.
func (m *roomMgr) join(code, name string, p *roomPeer) (*room, []roomInfo, string) {
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
	p.id, p.name = "p"+strconv.Itoa(rm.next), name
	var others []roomInfo
	for _, o := range rm.peers {
		others = append(others, roomInfo{o.id, o.name})
		o.send(roomJSON(map[string]string{"t": "join", "id": p.id, "name": p.name}))
	}
	rm.peers[p.id] = p
	return rm, others, ""
}

func (m *roomMgr) leave(rm *room, p *roomPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(rm.peers, p.id)
	for _, o := range rm.peers {
		o.send(roomJSON(map[string]string{"t": "leave", "id": p.id}))
	}
	if len(rm.peers) == 0 {
		delete(m.rooms, rm.code)
	}
}

func (m *roomMgr) route(rm *room, from *roomPeer, to string, d json.RawMessage) {
	m.mu.Lock()
	dst := rm.peers[to]
	m.mu.Unlock()
	if dst != nil {
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
	p := &roomPeer{c: c, out: make(chan []byte, roomQueue), done: make(chan struct{})}
	go p.writer()
	var rm *room
	defer func() {
		if rm != nil {
			m.leave(rm, p)
		}
		c.Close()
		p.once.Do(func() { close(p.done) })
	}()
	fail := func(why string) { p.send(roomJSON(map[string]string{"t": "err", "m": why})) }
	var in []byte
	var winStart time.Time
	var winCount int
	for {
		c.SetReadDeadline(time.Now().Add(roomIdle))
		msg, err := wsRead(rw.Reader, c, &p.wmu, in)
		in = msg
		if err != nil {
			return
		}
		if now := time.Now(); now.Sub(winStart) > time.Second {
			winStart, winCount = now, 0
		}
		if winCount++; winCount > roomRate || len(msg) > roomMaxMsg {
			fail("too fast or too big")
			time.Sleep(50 * time.Millisecond) // let the error frame out before the socket closes
			return
		}
		var f roomIn
		if json.Unmarshal(msg, &f) != nil {
			return
		}
		switch {
		case f.T == "ping":
		case f.T == "join" && rm == nil:
			if len(f.Name) > 24 {
				f.Name = f.Name[:24]
			}
			room, others, why := m.join(f.Room, f.Name, p)
			if why != "" {
				fail(why)
				time.Sleep(50 * time.Millisecond)
				return
			}
			rm = room
			if others == nil {
				others = []roomInfo{}
			}
			p.send(roomJSON(map[string]any{"t": "hello", "id": p.id, "room": rm.code, "peers": others}))
		case f.T == "to" && rm != nil:
			m.route(rm, p, f.To, f.D)
		default:
			return
		}
	}
}

//go:embed roomtest.html
var roomTestHTML string

// The spike page (/room-test): two devices join a room and measure whether WebRTC reaches directly across this box's Wi-Fi, and how fast the box relay is by comparison.
func (u *webUI) roomTestPage(w http.ResponseWriter, r *http.Request) {
	if u.auth.Session(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secureHeaders(w)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, roomTestHTML)
}
