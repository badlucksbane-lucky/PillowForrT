package main

// The torrent bridge: the half of the browser torrent client that lives on the box. The page's torrent engine (btclient/) opens ONE WebSocket to /api/bt/mux (btmux.go) and carries every
// peer over it; /api/bt/conn below is the older form, one WebSocket per peer, kept for the dev scripts. Either dials the peer by TCP through the Mullvad tunnel and copies bytes both ways.
// It is not a general proxy:
//   - it needs the page's login, and a WebSocket handshake whose Origin is this box's own page (cookies ride along, so another site must not be able to open one);
//   - it dials only ip:port pairs this box handed out itself for a recent lookup (/api/bt/peers), so a page cannot ask for an arbitrary address or port;
//   - it dials through the tunnel only (the socket is bound to mullvad0), so with the tunnel down nothing is dialled and nothing leaks;
//   - private, loopback and carrier-grade addresses are never dialled, and the number of open connections and their idle time are capped.
// Nothing is stored: no peer list survives a restart, and nothing about what is played is logged.

import (
	"bufio"
	"context"
	"crypto/sha1"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed btclient/btclient.js
var btClientJS []byte

//go:embed btclient/audio.js
var btAudioJS []byte

//go:embed btclient/sw.js
var btSWJS []byte

const (
	btMaxConns   = 96
	btIdle       = 3 * time.Minute
	btDialWait   = 8 * time.Second
	btAllowTTL   = 30 * time.Minute
	btAllowMax   = 3000
	wsMaxMessage = 128 << 10 // a BitTorrent message is a 16 KB block plus a few bytes; this leaves room for large extension messages
)

// Limits that keep the player from starving the rest of the box (one Cortex-A7 core: every bridged byte is sealed twice in pure Go, by WireGuard and by TLS).
var (
	btRate      = 2.5e6 // bytes a second from all peers together to the pages; the peers' TCP windows fill and they slow down, so this costs a little speed and not the DNS
	btBurst     = 128e3
	btLoadLimit = 4.0 // no new peer connection (and no new lookup) while the one-minute load average is above this; connections already open carry on
	btLoadNow   = loadAvg1
	btLimit     = &btLimiter{rate: &btRate, burst: &btBurst}
	btLookups   = make(chan struct{}, 2) // peer lookups at once: each is up to 12 tracker sockets plus a DHT walk for 25 s
)

// btLimiter is a token bucket shared by every bridge connection.
type btLimiter struct {
	mu          sync.Mutex
	rate, burst *float64
	tokens      float64
	last        time.Time
}

// wait takes n bytes from the bucket, sleeping if it is overdrawn.
func (l *btLimiter) wait(n int) {
	l.mu.Lock()
	now := time.Now()
	if l.last.IsZero() {
		l.tokens = *l.burst
	} else {
		l.tokens += now.Sub(l.last).Seconds() * *l.rate
	}
	if l.tokens > *l.burst {
		l.tokens = *l.burst
	}
	l.last = now
	l.tokens -= float64(n)
	var d time.Duration
	if l.tokens < 0 {
		d = time.Duration(-l.tokens / *l.rate * float64(time.Second))
	}
	l.mu.Unlock()
	if d > 0 {
		time.Sleep(d)
	}
}

// btPeerCache remembers what a lookup found for a short while, so a page that asks again (it re-announces while it has few peers) is answered without another round of trackers and DHT.
var btPeerCache = struct {
	sync.Mutex
	m map[[20]byte]btCached
}{m: map[[20]byte]btCached{}}

type btCached struct {
	peers []string
	at    time.Time
}

const (
	btCacheTTL  = 90 * time.Second
	btCacheKeep = 16
	btCacheMax  = 120 // peers kept for one hash
)

func btCacheGet(h [20]byte) ([]string, bool) {
	btPeerCache.Lock()
	defer btPeerCache.Unlock()
	c, ok := btPeerCache.m[h]
	return c.peers, ok && time.Since(c.at) < btCacheTTL
}

func btCachePut(h [20]byte, peers []string) {
	if len(peers) > btCacheMax {
		peers = peers[:btCacheMax]
	}
	btPeerCache.Lock()
	defer btPeerCache.Unlock()
	if len(btPeerCache.m) >= btCacheKeep {
		for k, c := range btPeerCache.m {
			if time.Since(c.at) >= btCacheTTL {
				delete(btPeerCache.m, k)
			}
		}
		if len(btPeerCache.m) >= btCacheKeep {
			btPeerCache.m = map[[20]byte]btCached{}
		}
	}
	btPeerCache.m[h] = btCached{peers: peers, at: time.Now()}
}

// ---- the peers this box handed out ----

type btAllowList struct {
	mu sync.Mutex
	m  map[string]time.Time
}

var btAllowed = &btAllowList{m: map[string]time.Time{}}

func (a *btAllowList) add(peers []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.m) > btAllowMax {
		for k, t := range a.m {
			if now.After(t) {
				delete(a.m, k)
			}
		}
		if len(a.m) > btAllowMax {
			a.m = map[string]time.Time{}
		}
	}
	for _, p := range peers {
		a.m[p] = now.Add(btAllowTTL)
	}
}

func (a *btAllowList) ok(peer string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.m[peer]
	return ok && time.Now().Before(t)
}

// ---- settings and state ----

type btMgr struct {
	mu      sync.Mutex
	path    string
	enabled bool
	upload  string       // what the page's torrent client may upload while a stream plays: off (the default), low or normal
	conns   atomic.Int32 // peers open now, over either kind of socket
	muxes   atomic.Int32 // multiplexed sockets open now (btmux.go)
	state   func() ownState
}

var btMgrG *btMgr

func newBTMgr(path string) *btMgr {
	m := &btMgr{path: path, state: liveOwnState, upload: "off"}
	if b, err := os.ReadFile(path); err == nil {
		var c struct {
			Enabled bool   `json:"enabled"`
			Upload  string `json:"upload"`
		}
		if json.Unmarshal(b, &c) == nil {
			m.enabled = c.Enabled
			if validUpload(c.Upload) {
				m.upload = c.Upload
			}
		}
	}
	return m
}

func (m *btMgr) Enabled() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.enabled }

func validUpload(u string) bool { return u == "off" || u == "low" || u == "normal" }

func (m *btMgr) Upload() string { m.mu.Lock(); defer m.mu.Unlock(); return m.upload }

func (m *btMgr) saveLocked() {
	if m.path != "" {
		b, _ := json.Marshal(map[string]any{"enabled": m.enabled, "upload": m.upload})
		writeFileAtomic(m.path, b, 0o600)
	}
}

func (m *btMgr) SetEnabled(on bool) {
	m.mu.Lock()
	m.enabled = on
	m.saveLocked()
	m.mu.Unlock()
}

func (m *btMgr) SetUpload(u string) error {
	if !validUpload(u) {
		return errors.New("upload is off, low or normal")
	}
	m.mu.Lock()
	m.upload = u
	m.saveLocked()
	m.mu.Unlock()
	return nil
}

func (m *btMgr) view() map[string]any {
	return map[string]any{"available": true, "enabled": m.Enabled(), "ready": m.Ready(), "conns": m.conns.Load(), "upload": m.Upload()}
}

// Ready says why the bridge cannot be used now ("" when it can). Only the Mullvad tunnel will do: BitTorrent shows the exit address to every peer.
func (m *btMgr) Ready() string {
	if !m.Enabled() {
		return "Torrent playback is off"
	}
	if err := searchPathReady(spMullvad, m.state()); err != nil {
		return err.Error()
	}
	return ""
}

// ---- a minimal RFC 6455 server side ----

var wsOriginScheme = "https" // a test serving plain HTTP changes it

func wsOriginOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return r.Header.Get("X-UI-Token") != "" // a script, not a page
	}
	u, err := url.Parse(o)
	return err == nil && u.Scheme == wsOriginScheme && strings.EqualFold(u.Host, r.Host)
}

func wsAccept(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || r.Header.Get("Sec-WebSocket-Key") == "" {
		return nil, nil, errors.New("not a WebSocket request")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("this connection cannot be upgraded")
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	c.SetDeadline(time.Time{}) // the server's read and write timeouts were set for an ordinary request
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	if err := rw.Flush(); err != nil {
		c.Close()
		return nil, nil, err
	}
	return c, rw, nil
}

// wsRead returns the next data message (binary or text, fragments joined), answering pings itself. io.EOF means the peer closed. The message is built in buf's memory
// (grown only when a message is bigger than any before it), so the result is valid until the next call; callers keep the returned slice as the next buf.
func wsRead(br *bufio.Reader, c net.Conn, wmu *sync.Mutex, buf []byte) ([]byte, error) {
	msg := buf[:0]
	for {
		var h [2]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			return msg, err
		}
		fin, op, masked, n := h[0]&0x80 != 0, h[0]&0x0f, h[1]&0x80 != 0, uint64(h[1]&0x7f)
		switch n {
		case 126:
			var e [2]byte
			if _, err := io.ReadFull(br, e[:]); err != nil {
				return msg, err
			}
			n = uint64(binary.BigEndian.Uint16(e[:]))
		case 127:
			var e [8]byte
			if _, err := io.ReadFull(br, e[:]); err != nil {
				return msg, err
			}
			n = binary.BigEndian.Uint64(e[:])
		}
		if !masked || n > wsMaxMessage || uint64(len(msg))+n > wsMaxMessage || (op >= 0x8 && n > 125) { // a browser always masks; anything else, or anything huge, is not one
			return msg, errors.New("bad WebSocket frame")
		}
		var key [4]byte
		if _, err := io.ReadFull(br, key[:]); err != nil {
			return msg, err
		}
		at := len(msg)
		if need := at + int(n); need > cap(msg) {
			grown := make([]byte, at, need)
			copy(grown, msg)
			msg = grown
		}
		p := msg[at : at+int(n)]
		if _, err := io.ReadFull(br, p); err != nil {
			return msg, err
		}
		for i := range p {
			p[i] ^= key[i&3]
		}
		switch op {
		case 0x8:
			return msg[:at], io.EOF
		case 0x9:
			wmu.Lock()
			wsWrite(c, 0xA, append([]byte(nil), p...))
			wmu.Unlock()
			msg = msg[:at]
		case 0xA:
			msg = msg[:at]
		case 0x0, 0x1, 0x2:
			msg = msg[:at+int(n)]
			if fin {
				return msg, nil
			}
		default:
			return msg, errors.New("bad WebSocket opcode")
		}
	}
}

// wsHeader writes the frame header for an n-byte payload into the end of dst (which must be at least wsMaxHeader long) and returns the header's length;
// the header then ends where the payload starts, so the caller reads the payload straight after it and sends header and payload in one Write.
func wsHeader(dst []byte, op byte, n int) int {
	switch {
	case n < 126:
		dst[len(dst)-2], dst[len(dst)-1] = 0x80|op, byte(n)
		return 2
	case n < 1<<16:
		copy(dst[len(dst)-4:], []byte{0x80 | op, 126, byte(n >> 8), byte(n)})
		return 4
	}
	copy(dst[len(dst)-10:], []byte{0x80 | op, 127, 0, 0, 0, 0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	return 10
}

const wsMaxHeader = 10

// wsWrite sends one small frame (close, pong, error). The data path does not use it: it builds the frame in place (see conn).
func wsWrite(w io.Writer, op byte, p []byte) error {
	buf := make([]byte, wsMaxHeader+len(p))
	hl := wsHeader(buf[:wsMaxHeader], op, len(p))
	copy(buf[wsMaxHeader:], p)
	_, err := w.Write(buf[wsMaxHeader-hl:])
	return err
}

// ---- the bridge ----

func (m *btMgr) conn(w http.ResponseWriter, r *http.Request) {
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
	peer := r.URL.Query().Get("peer")
	host, ps, err := net.SplitHostPort(peer)
	ip := net.ParseIP(host)
	var port int
	if err == nil {
		_, err = parsePort(ps, &port)
	}
	if err != nil || ip == nil || !btPeerOK(ip, port) || !btAllowed.ok(peer) {
		http.Error(w, "not a peer from this box's lookup", http.StatusForbidden)
		return
	}
	if m.conns.Add(1) > btMaxConns {
		m.conns.Add(-1)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer m.conns.Add(-1)
	// Answer the browser at once and dial afterwards. A browser lets only one WebSocket to the same server be "connecting" at a time, so dialling first made every dead peer (up to the
	// dial timeout) hold up all the others behind it: in practice one peer at a time. The page's first bytes (the BitTorrent handshake) wait in the socket until the dial is done.
	c, rw, err := wsAccept(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer c.Close()
	var wmu sync.Mutex
	ctx, cancel := context.WithTimeout(context.Background(), btDialWait)
	tc, err := btDialTCP(ctx, peer)
	cancel()
	if err != nil { // the peer is unreachable: say so by closing (1011), which the page treats as a failed peer
		wmu.Lock()
		wsWrite(c, 0x8, []byte{0x03, 0xf3})
		wmu.Unlock()
		return
	}
	defer tc.Close()
	go func() { // peer -> page
		buf := make([]byte, wsMaxHeader+16<<10) // the frame header is built in the first bytes, so each chunk goes out in one Write with no copy
		for {
			tc.SetReadDeadline(time.Now().Add(btIdle))
			n, err := tc.Read(buf[wsMaxHeader:])
			if n > 0 {
				btLimit.wait(n)
				hl := wsHeader(buf[:wsMaxHeader], 0x2, n)
				wmu.Lock()
				_, werr := c.Write(buf[wsMaxHeader-hl : wsMaxHeader+n])
				wmu.Unlock()
				if werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		wmu.Lock()
		wsWrite(c, 0x8, nil)
		wmu.Unlock()
		c.Close()
	}()
	var in []byte // the page's messages are read into this one buffer
	for {         // page -> peer
		c.SetReadDeadline(time.Now().Add(btIdle))
		msg, err := wsRead(rw.Reader, c, &wmu, in)
		in = msg
		if err != nil {
			return
		}
		tc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := tc.Write(msg); err != nil {
			return
		}
	}
}

func parsePort(s string, out *int) (int, error) {
	n := 0
	if s == "" || len(s) > 5 {
		return 0, errors.New("bad port")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("bad port")
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return n, nil
}

// peers streams what the trackers and the DHT find as lines of JSON, as they are found, for up to 25 seconds.
func (m *btMgr) peers(w http.ResponseWriter, r *http.Request) {
	if why := m.Ready(); why != "" {
		writeJSON(w, 503, map[string]string{"error": why})
		return
	}
	hs := strings.ToLower(r.URL.Query().Get("h"))
	if !validHash(hs) {
		writeJSON(w, 400, map[string]string{"error": "bad info hash"})
		return
	}
	var hash [20]byte
	for i := range hash {
		hash[i] = hexByte(hs[2*i])<<4 | hexByte(hs[2*i+1])
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	fl, _ := w.(http.Flusher)
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	if cached, fresh := btCacheGet(hash); fresh && len(cached) > 0 { // asked again soon: the same answer, no new round of trackers
		btAllowed.add(cached)
		enc.Encode(btFound{Peers: cached, Src: "cache"})
		enc.Encode(map[string]bool{"done": true})
		return
	}
	select {
	case btLookups <- struct{}{}:
		defer func() { <-btLookups }()
	default:
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, 503, map[string]string{"error": "other lookups are running; trying again shortly"})
		return
	}
	if btLoadNow() > btLoadLimit {
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, 503, map[string]string{"error": "the box is busy"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	var found []string
	btPeers(ctx, hash, r.URL.Query()["tr"], func(f btFound) {
		mu.Lock()
		defer mu.Unlock()
		found = append(found, f.Peers...)
		enc.Encode(f)
		if fl != nil {
			fl.Flush()
		}
	})
	mu.Lock()
	enc.Encode(map[string]bool{"done": true})
	if len(found) > 0 {
		btCachePut(hash, found)
	}
	mu.Unlock()
}

var btHashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validHash(h string) bool { return btHashRe.MatchString(h) }

func hexByte(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

func handleBTAPI(w http.ResponseWriter, r *http.Request, path string) {
	handleBTAPIWith(btMgrG, w, r, path)
}

func handleBTAPIWith(m *btMgr, w http.ResponseWriter, r *http.Request, path string) {
	if m == nil {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	switch {
	case path == "bt" && r.Method == http.MethodGet:
		writeJSON(w, 200, m.view())
	case path == "bt/set" && r.Method == http.MethodPost:
		var b struct {
			Enabled *bool   `json:"enabled"`
			Upload  *string `json:"upload"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if b.Upload != nil {
			if err := m.SetUpload(*b.Upload); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
		}
		if b.Enabled != nil {
			m.SetEnabled(*b.Enabled)
		}
		writeJSON(w, 200, m.view())
	case path == "bt/peers" && r.Method == http.MethodGet:
		m.peers(w, r)
	case path == "bt/conn" && r.Method == http.MethodGet:
		m.conn(w, r)
	case path == "bt/mux" && r.Method == http.MethodGet:
		m.mux(w, r)
	default:
		http.Error(w, "not found", 404)
	}
}

func serveBTAsset(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}
