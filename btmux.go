package main

// The multiplexed torrent bridge: the same job as conn in btbridge.go, but all of a page's peers share ONE WebSocket (/api/bt/mux), so the page pays one TLS handshake (pure-Go ECDSA on
// the A7) instead of one per peer. Each WebSocket message is one frame:
//
//	byte 0     type: 1 OPEN, 2 DATA, 3 CLOSE, 4 PING
//	bytes 1-2  stream id, big endian (0 is never a stream)
//	bytes 3-   OPEN: "ip:port" of the peer. DATA: bytes for that peer, or from it. CLOSE: from the box, one reason byte (0 the peer ended, 1 it could not be reached); from the page, nothing.
//	           PING (page to box, every minute): nothing; it keeps the idle timer from ending a socket that only receives.
//
// It keeps every rule of conn: the page's login and Origin, only peers this box handed out and only public addresses, dialled through the tunnel only, the same connection cap and
// load shedding, the same byte limiter, nothing stored or logged. A stream that cannot keep up (its peer's socket does not drain) is closed, so it cannot stall the others.

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	muxOpen  = 1
	muxData  = 2
	muxClose = 3
	muxPing  = 4

	muxEnded  = 0 // CLOSE reason: the peer ended the connection
	muxFailed = 1 // CLOSE reason: the peer could not be reached, or was refused

	muxHdr   = 3  // type and stream id
	muxQueue = 32 // messages waiting for one peer's socket before that stream is dropped
	btMaxMux = 4  // multiplexed sockets at once
)

type muxConn struct {
	m       *btMgr
	c       net.Conn
	wmu     sync.Mutex // one writer to the WebSocket at a time
	mu      sync.Mutex
	streams map[uint16]*muxStream
}

type muxStream struct {
	mc     *muxConn
	id     uint16
	mu     sync.Mutex
	closed bool
	tc     net.Conn // set once the dial succeeds
	out    chan []byte
}

// write sends one finished WebSocket frame to the page.
func (mc *muxConn) write(frame []byte) error {
	mc.wmu.Lock()
	mc.c.SetWriteDeadline(time.Now().Add(60 * time.Second)) // a page that stopped reading must not hold the box's goroutines for ever
	_, err := mc.c.Write(frame)
	mc.wmu.Unlock()
	return err
}

func (mc *muxConn) sendControl(typ byte, id uint16, extra ...byte) {
	buf := make([]byte, wsMaxHeader+muxHdr+len(extra))
	buf[wsMaxHeader], buf[wsMaxHeader+1], buf[wsMaxHeader+2] = typ, byte(id>>8), byte(id)
	copy(buf[wsMaxHeader+muxHdr:], extra)
	hl := wsHeader(buf[:wsMaxHeader], 0x2, muxHdr+len(extra))
	mc.write(buf[wsMaxHeader-hl:])
}

func (mc *muxConn) get(id uint16) *muxStream {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.streams[id]
}

// finish ends a stream once: closes its sockets, frees its slot, and tells the page when the box is the one ending it.
func (s *muxStream) finish(notify bool, reason byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.out)
	if s.tc != nil {
		s.tc.Close()
	}
	s.mu.Unlock()
	s.mc.mu.Lock()
	delete(s.mc.streams, s.id)
	s.mc.mu.Unlock()
	s.mc.m.conns.Add(-1)
	if notify {
		s.mc.sendControl(muxClose, s.id, reason)
	}
}

// send queues bytes for the peer; a stream whose queue is full is dropped rather than made to wait.
func (s *muxStream) send(msg []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	select {
	case s.out <- msg:
		s.mu.Unlock()
	default:
		s.mu.Unlock()
		s.finish(true, muxEnded)
	}
}

// run dials the peer, then carries the page's queued bytes to it; bytes sent while the dial was running wait in the queue.
func (s *muxStream) run(peer string) {
	ctx, cancel := context.WithTimeout(context.Background(), btDialWait)
	tc, err := btDialTCP(ctx, peer)
	cancel()
	if err != nil {
		s.finish(true, muxFailed)
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		tc.Close()
		return
	}
	s.tc = tc
	s.mu.Unlock()
	go s.pump(tc)
	for msg := range s.out { // page -> peer
		tc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := tc.Write(msg); err != nil {
			s.finish(true, muxEnded)
			return
		}
	}
}

// pump carries the peer's bytes to the page, each chunk as one frame built in place.
func (s *muxStream) pump(tc net.Conn) {
	buf := make([]byte, wsMaxHeader+muxHdr+16<<10)
	buf[wsMaxHeader], buf[wsMaxHeader+1], buf[wsMaxHeader+2] = muxData, byte(s.id>>8), byte(s.id)
	for {
		tc.SetReadDeadline(time.Now().Add(btIdle))
		n, err := tc.Read(buf[wsMaxHeader+muxHdr:])
		if n > 0 {
			btLimit.wait(n)
			hl := wsHeader(buf[:wsMaxHeader], 0x2, muxHdr+n)
			if werr := s.mc.write(buf[wsMaxHeader-hl : wsMaxHeader+muxHdr+n]); werr != nil {
				s.mc.c.Close() // the page is gone: the reader loop ends and every stream with it
				s.finish(false, 0)
				return
			}
		}
		if err != nil {
			s.finish(true, muxEnded)
			return
		}
	}
}

// open starts a stream if the peer is one this box handed out and a slot is free; otherwise it tells the page the peer failed.
func (mc *muxConn) open(id uint16, peer string) {
	host, ps, err := net.SplitHostPort(peer)
	ip := net.ParseIP(host)
	var port int
	if err == nil {
		_, err = parsePort(ps, &port)
	}
	mc.mu.Lock()
	_, dup := mc.streams[id]
	mc.mu.Unlock()
	if id == 0 || dup || err != nil || ip == nil || !btPeerOK(ip, port) || !btAllowed.ok(peer) || btLoadNow() > btLoadLimit {
		mc.sendControl(muxClose, id, muxFailed)
		return
	}
	if mc.m.conns.Add(1) > btMaxConns {
		mc.m.conns.Add(-1)
		mc.sendControl(muxClose, id, muxFailed)
		return
	}
	s := &muxStream{mc: mc, id: id, out: make(chan []byte, muxQueue)}
	mc.mu.Lock()
	mc.streams[id] = s
	mc.mu.Unlock()
	go s.run(peer)
}

func (m *btMgr) mux(w http.ResponseWriter, r *http.Request) {
	if why := m.Ready(); why != "" {
		http.Error(w, why, http.StatusServiceUnavailable)
		return
	}
	if !wsOriginOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if btLoadNow() > btLoadLimit {
		http.Error(w, "the box is busy", http.StatusServiceUnavailable)
		return
	}
	if m.muxes.Add(1) > btMaxMux {
		m.muxes.Add(-1)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer m.muxes.Add(-1)
	c, rw, err := wsAccept(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mc := &muxConn{m: m, c: c, streams: map[uint16]*muxStream{}}
	defer func() { // the page went away: end every stream it had, without telling it
		c.Close()
		mc.mu.Lock()
		all := make([]*muxStream, 0, len(mc.streams))
		for _, s := range mc.streams {
			all = append(all, s)
		}
		mc.mu.Unlock()
		for _, s := range all {
			s.finish(false, 0)
		}
	}()
	var in []byte // the page's messages are read into this one buffer
	for {
		c.SetReadDeadline(time.Now().Add(btIdle))
		msg, err := wsRead(rw.Reader, c, &mc.wmu, in)
		in = msg
		if err != nil || len(msg) < muxHdr {
			return
		}
		id := binary.BigEndian.Uint16(msg[1:3])
		switch msg[0] {
		case muxOpen:
			mc.open(id, string(msg[muxHdr:]))
		case muxData:
			if s := mc.get(id); s != nil {
				s.send(append([]byte(nil), msg[muxHdr:]...)) // msg is reused by the next read
			}
		case muxClose:
			if s := mc.get(id); s != nil {
				s.finish(false, 0)
			}
		case muxPing:
		default:
			return
		}
	}
}
