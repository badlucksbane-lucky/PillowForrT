package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// btTest points the bridge's network hooks at the loopback for one test and puts them back after.
func btTest(t *testing.T) {
	t.Helper()
	oa, or, od, ol, ob := btAllowPrivate, btResolve, btDialTCP, btListenUDP, btDHTBootstrap
	btAllowPrivate = true
	btResolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	btDialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", addr)
	}
	btListenUDP = func() (net.PacketConn, error) { return net.ListenPacket("udp4", "127.0.0.1:0") }
	t.Cleanup(func() { btAllowPrivate, btResolve, btDialTCP, btListenUDP, btDHTBootstrap = oa, or, od, ol, ob })
}

func compact(peers ...string) []byte {
	var b []byte
	for _, p := range peers {
		h, ps, _ := net.SplitHostPort(p)
		var port int
		fmt.Sscan(ps, &port)
		b = append(b, net.ParseIP(h).To4()...)
		b = append(b, byte(port>>8), byte(port))
	}
	return b
}

var testHash = [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

func fakeUDPTracker(t *testing.T, peers ...string) (port int, gotHash chan [20]byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	gotHash = make(chan [20]byte, 4)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			switch {
			case n == 16 && binary.BigEndian.Uint64(buf[0:8]) == 0x41727101980 && binary.BigEndian.Uint32(buf[8:12]) == 0:
				r := make([]byte, 16)
				copy(r[4:8], buf[12:16])
				copy(r[8:], []byte("CONNID12"))
				pc.WriteTo(r, from)
			case n >= 98 && string(buf[0:8]) == "CONNID12" && binary.BigEndian.Uint32(buf[8:12]) == 1:
				var h [20]byte
				copy(h[:], buf[16:36])
				gotHash <- h
				r := make([]byte, 20)
				binary.BigEndian.PutUint32(r[0:4], 1)
				copy(r[4:8], buf[12:16])
				binary.BigEndian.PutUint32(r[8:12], 1800)
				r = append(r, compact(peers...)...)
				pc.WriteTo(r, from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, gotHash
}

func TestAnnounceUDP(t *testing.T) {
	btTest(t)
	port, got := fakeUDPTracker(t, "8.8.8.8:51413", "9.9.9.9:6881")
	u, _ := url.Parse(fmt.Sprintf("udp://tracker.test:%d/announce", port))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	peers, err := announceUDP(ctx, u, testHash)
	if err != nil || len(peers) != 2 || peers[0] != "8.8.8.8:51413" {
		t.Fatalf("%v %v", peers, err)
	}
	if h := <-got; h != testHash {
		t.Fatal("the tracker was sent a different info hash")
	}
}

func TestAnnounceHTTP(t *testing.T) {
	btTest(t)
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Write([]byte("d8:intervali1800e5:peers12:" + string(compact("1.2.3.4:6881", "192.168.1.9:6881")) + "e"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL + "/announce")
	btAllowPrivate = false // the private peer in the answer must be dropped
	btResolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	btDialTCP = func(ctx context.Context, addr string) (net.Conn, error) {
		return net.Dial("tcp4", srv.Listener.Addr().String())
	}
	peers, err := announceHTTP(context.Background(), u, testHash)
	if err != nil || len(peers) != 1 || peers[0] != "1.2.3.4:6881" {
		t.Fatalf("%v %v", peers, err)
	}
	if !strings.Contains(query, "info_hash=%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f%10%11%12%13%14") || !strings.Contains(query, "compact=1") {
		t.Fatalf("query %q", query)
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("d14:failure reason9:not found" + "e")) })
	if _, err := announceHTTP(context.Background(), u, testHash); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("a failure reason should be an error: %v", err)
	}
}

func TestDHTLookup(t *testing.T) {
	btTest(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			v, err := bdecode(buf[:n])
			if err != nil {
				continue
			}
			m, _ := bdict(v)
			a, _ := bdict(m["a"])
			if q, _ := bstr(m, "q"); q != "get_peers" {
				continue
			}
			if ih, _ := bstr(a, "info_hash"); ih != string(testHash[:]) {
				continue
			}
			tid, _ := bstr(m, "t")
			vals := string(compact("5.6.7.8:4000"))
			pc.WriteTo([]byte(fmt.Sprintf("d1:rd2:id20:%s5:token1:x6:valuesl6:%see1:t%d:%s1:y1:re", strings.Repeat("n", 20), vals, len(tid), tid)), from)
		}
	}()
	btDHTBootstrap = []string{pc.LocalAddr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var got []string
	var mu sync.Mutex
	if err := dhtLookup(ctx, testHash, func(p []string) { mu.Lock(); got = append(got, p...); mu.Unlock() }); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "5.6.7.8:4000" {
		t.Fatalf("peers %v", got)
	}
}

func TestCleanTrackers(t *testing.T) {
	got := cleanTrackers([]string{"wss://tracker.openwebtorrent.com", "udp://a.example:1337/announce", "http://b.example/announce", "udp://nope.example", "ftp://x/y", "udp://a.example:1337/announce"})
	if got[0] != "udp://a.example:1337/announce" || got[1] != "http://b.example/announce" {
		t.Fatalf("%v", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "wss:") || strings.HasPrefix(g, "ftp:") || strings.Contains(g, "nope.example") {
			t.Errorf("kept %s", g)
		}
	}
	if len(got) != 2+len(btDefaultTrackers) {
		t.Errorf("want the defaults added once: %v", got)
	}
}

func TestBTPublic(t *testing.T) {
	for ip, want := range map[string]bool{"8.8.8.8": true, "192.168.1.5": false, "10.1.2.3": false, "127.0.0.1": false, "169.254.1.1": false, "100.64.1.1": false, "198.18.0.4": false, "224.0.0.1": false, "0.0.0.0": false, "::1": false, "240.0.0.1": false} {
		if btPublic(net.ParseIP(ip)) != want {
			t.Errorf("%s should be %v", ip, want)
		}
	}
}

// ---- the bridge ----

type wsTestClient struct {
	c  net.Conn
	br *bufio.Reader
}

func wsDial(t *testing.T, srv *httptest.Server, path, origin string) (*wsTestClient, string) {
	t.Helper()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	rand.Read(key)
	req := "GET " + path + " HTTP/1.1\r\nHost: " + srv.Listener.Addr().String() + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n"
	if origin != "" {
		req += "Origin: " + origin + "\r\n"
	}
	c.Write([]byte(req + "\r\n"))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	return &wsTestClient{c, br}, strings.TrimSpace(status)
}

func (w *wsTestClient) send(p []byte) {
	h := []byte{0x82}
	switch {
	case len(p) < 126:
		h = append(h, 0x80|byte(len(p)))
	default:
		h = append(h, 0x80|126, byte(len(p)>>8), byte(len(p)))
	}
	key := [4]byte{9, 8, 7, 6}
	h = append(h, key[:]...)
	m := make([]byte, len(p))
	for i := range p {
		m[i] = p[i] ^ key[i&3]
	}
	w.c.Write(append(h, m...))
}

func (w *wsTestClient) recv(t *testing.T, n int) []byte {
	t.Helper()
	var out []byte
	w.c.SetReadDeadline(time.Now().Add(4 * time.Second))
	for len(out) < n {
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
		if h[0]&0x0f == 2 {
			out = append(out, p...)
		}
	}
	return out
}

func echoServer(t *testing.T) string {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func TestBridgeCarriesBytes(t *testing.T) {
	btTest(t)
	m := &btMgr{enabled: true, state: func() ownState { return ownState{MullvadWanted: true, TunnelUp: true} }}
	srv := httptest.NewServer(http.HandlerFunc(m.conn))
	defer srv.Close()
	peer := echoServer(t)
	origin := "https://" + srv.Listener.Addr().String()

	if _, st := wsDial(t, srv, "/api/bt/conn?peer="+peer, origin); !strings.Contains(st, "403") {
		t.Fatalf("a peer this box never handed out must be refused: %q", st)
	}
	btAllowed.add([]string{peer})
	if _, st := wsDial(t, srv, "/api/bt/conn?peer="+peer, "https://evil.example"); !strings.Contains(st, "403") {
		t.Fatalf("a foreign Origin must be refused: %q", st)
	}
	if _, st := wsDial(t, srv, "/api/bt/conn?peer="+peer, ""); !strings.Contains(st, "403") {
		t.Fatalf("no Origin and no token must be refused: %q", st)
	}
	if _, st := wsDial(t, srv, "/api/bt/conn?peer=127.0.0.1:1", origin); !strings.Contains(st, "403") {
		t.Fatalf("a peer not on the list: %q", st)
	}
	ws, st := wsDial(t, srv, "/api/bt/conn?peer="+peer, origin)
	if !strings.Contains(st, "101") {
		t.Fatalf("handshake: %q", st)
	}
	for _, n := range []int{5, 300, 20000} {
		msg := make([]byte, n)
		rand.Read(msg)
		ws.send(msg)
		if got := ws.recv(t, n); string(got) != string(msg) {
			t.Fatalf("echo of %d bytes came back different", n)
		}
	}
	if m.conns.Load() != 1 {
		t.Fatalf("conns %d", m.conns.Load())
	}
	ws.c.Close()
	time.Sleep(300 * time.Millisecond)
	if m.conns.Load() != 0 {
		t.Fatalf("a closed bridge must free its slot: %d", m.conns.Load())
	}
}

func TestBridgeNeedsMullvadAndPublicPeers(t *testing.T) {
	btTest(t)
	m := &btMgr{enabled: true, state: func() ownState { return ownState{} }}
	srv := httptest.NewServer(http.HandlerFunc(m.conn))
	defer srv.Close()
	peer := echoServer(t)
	btAllowed.add([]string{peer})
	origin := "https://" + srv.Listener.Addr().String()
	if _, st := wsDial(t, srv, "/api/bt/conn?peer="+peer, origin); !strings.Contains(st, "503") {
		t.Fatalf("with the tunnel down nothing may be dialled: %q", st)
	}
	m.state = func() ownState { return ownState{MullvadWanted: true, TunnelUp: true} }
	btAllowPrivate = false
	btAllowed.add([]string{"192.168.1.50:6881", "127.0.0.1:9"})
	for _, p := range []string{"192.168.1.50:6881", "127.0.0.1:9", "10.0.0.1:80"} {
		if _, st := wsDial(t, srv, "/api/bt/conn?peer="+p, origin); !strings.Contains(st, "403") {
			t.Fatalf("%s is private: %q", p, st)
		}
	}
	m.enabled = false
	if why := m.Ready(); !strings.Contains(why, "off") {
		t.Fatal(why)
	}
}

func TestPeersStream(t *testing.T) {
	btTest(t)
	port, _ := fakeUDPTracker(t, "8.8.4.4:5000")
	btDHTBootstrap = nil
	m := &btMgr{enabled: true, state: func() ownState { return ownState{MullvadWanted: true, TunnelUp: true} }}
	srv := httptest.NewServer(http.HandlerFunc(m.peers))
	defer srv.Close()
	hs := fmt.Sprintf("%x", testHash)
	trk := url.QueryEscape(fmt.Sprintf("udp://t.test:%d/announce", port))
	resp, err := http.Get(srv.URL + "/?h=" + hs + "&tr=" + trk)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"peers":["8.8.4.4:5000"]`) || !strings.Contains(string(b), `"done":true`) {
		t.Fatalf("stream: %s", b)
	}
	if !btAllowed.ok("8.8.4.4:5000") {
		t.Fatal("peers handed out must be allowed on the bridge")
	}
	resp, _ = http.Get(srv.URL + "/?h=zz")
	if resp.StatusCode != 400 {
		t.Fatalf("a bad hash: %d", resp.StatusCode)
	}
}

func TestBTSettings(t *testing.T) {
	p := t.TempDir() + "/bt.json"
	m := newBTMgr(p)
	if m.Enabled() {
		t.Fatal("off by default")
	}
	if m.Upload() != "off" {
		t.Fatal("upload must default to off")
	}
	m.SetEnabled(true)
	if !newBTMgr(p).Enabled() {
		t.Fatal("not saved")
	}
	if m.SetUpload("loud") == nil {
		t.Fatal("a bad upload mode must be refused")
	}
	if err := m.SetUpload("low"); err != nil {
		t.Fatal(err)
	}
	if r := newBTMgr(p); r.Upload() != "low" || !r.Enabled() {
		t.Fatalf("upload and enabled must both survive a restart: %q %v", r.Upload(), r.Enabled())
	}
	w := httptest.NewRecorder()
	handleBTAPIWith(m, w, httptest.NewRequest("POST", "/api/bt/set", strings.NewReader(`{"upload":"normal"}`)), "bt/set")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"upload":"normal"`) || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handleBTAPIWith(m, w, httptest.NewRequest("POST", "/api/bt/set", strings.NewReader(`{"upload":"x"}`)), "bt/set")
	if w.Code != 400 {
		t.Fatal("bad mode accepted")
	}
}

func TestCertInstallDER(t *testing.T) {
	cm, _, err := newCertManager(t.TempDir(), []string{"pillowforrt"}, []net.IP{net.ParseIP("192.168.1.1")})
	if err != nil {
		t.Fatal(err)
	}
	p, err := cm.PEM()
	if err != nil {
		t.Fatal(err)
	}
	der, err := certInstallDER(p)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || len(c.DNSNames) == 0 || c.DNSNames[0] != "pillowforrt" {
		t.Fatalf("not the box certificate: %v", err)
	}
	if _, err := certInstallDER([]byte("not a pem")); err == nil {
		t.Fatal("garbage must be refused")
	}
	if _, err := certInstallDER([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("only a certificate may be handed out, never a key")
	}
}
