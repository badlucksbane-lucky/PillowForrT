package main

// Finding peers for the browser torrent client (browse.html + btclient/): the page cannot talk UDP, so this box asks the trackers and the DHT for it and hands back plain ip:port peers.
// Everything here leaves through the Mullvad tunnel only: UDP sockets and TCP dials are bound to mullvad0 (tunnelOnlyControl), and names are looked up through Mullvad's DoH, so with the
// tunnel down nothing is sent at all. Peers and trackers on private, loopback or carrier-grade addresses are dropped, so none of this can be pointed at the LAN.
//
//   UDP trackers   BEP 15 (connect, then announce)
//   HTTP trackers  BEP 3, compact answers
//   DHT            BEP 5, an iterative get_peers lookup from the public bootstrap nodes
//
// This box is a leech that never listens: the port announced is a placeholder, and nothing connects in.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Replaceable for tests.
var (
	btAllowPrivate = false
	btResolve      = btResolveReal
	btDialTCP      = func(ctx context.Context, addr string) (net.Conn, error) { return dialTunnelOnly(ctx, "tcp4", addr) }
	btListenUDP    = func() (net.PacketConn, error) {
		lc := net.ListenConfig{Control: tunnelOnlyControl}
		return lc.ListenPacket(context.Background(), "udp4", "")
	}
)

const (
	btAnnouncePort = 6881
	btWantPeers    = 80
)

var btDefaultTrackers = []string{
	"udp://tracker.opentrackr.org:1337/announce", "udp://open.tracker.cl:1337/announce",
	"udp://tracker.torrent.eu.org:451/announce", "udp://exodus.desync.com:6969/announce",
}

var btDHTBootstrap = []string{"router.bittorrent.com:6881", "router.utorrent.com:6881", "dht.transmissionbt.com:6881", "dht.libtorrent.org:25401"}

var errBTDown = errors.New("the Mullvad tunnel is down")

// btPublic says whether an address may be spoken to: a public unicast IPv4 address (anything else is the LAN, this box, or something it must not reach).
func btPublic(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil || ip4.IsMulticast() || ip4.IsUnspecified() || ip4[0] == 0 || ip4[0] >= 240 {
		return false
	}
	if btAllowPrivate {
		return true
	}
	return !privateAnswer(ip4) && proxyDestOK(ip4)
}

func btPeerOK(ip net.IP, port int) bool { return port >= 1 && port <= 65535 && btPublic(ip) }

// ---- names, through Mullvad's DoH ----

var btDNS struct {
	sync.Mutex
	m map[string]btDNSHit
}

type btDNSHit struct {
	ips []net.IP
	exp time.Time
}

func btResolveReal(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !btPublic(ip) {
			return nil, errors.New("not a public address")
		}
		return []net.IP{ip}, nil
	}
	host = strings.ToLower(host)
	btDNS.Lock()
	if h, ok := btDNS.m[host]; ok && time.Now().Before(h.exp) {
		btDNS.Unlock()
		return h.ips, nil
	}
	btDNS.Unlock()
	if vpn == nil {
		return nil, errBTDown
	}
	q := searchDNSQuery(host)
	if q == nil {
		return nil, errors.New("bad host name")
	}
	resp, err := vpn.ResolveDNS(q)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range aRecordIPs(resp) {
		if btPublic(a) {
			ips = append(ips, a)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no public address for " + host)
	}
	btDNS.Lock()
	if btDNS.m == nil || len(btDNS.m) > 200 {
		btDNS.m = map[string]btDNSHit{}
	}
	btDNS.m[host] = btDNSHit{ips: ips, exp: time.Now().Add(10 * time.Minute)}
	btDNS.Unlock()
	return ips, nil
}

func tlsClientConfig() *tls.Config {
	return &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12}
}

func btRandPeerID() []byte {
	id := make([]byte, 20)
	copy(id, "-HS0001-")
	rand.Read(id[8:])
	return id
}

func btCompactPeers(b []byte) []string {
	var out []string
	for ; len(b) >= 6; b = b[6:] {
		ip, port := net.IP(b[:4]), int(binary.BigEndian.Uint16(b[4:6]))
		if btPeerOK(ip, port) {
			out = append(out, net.JoinHostPort(ip.String(), fmt.Sprint(port)))
		}
	}
	return out
}

// ---- trackers ----

// cleanTrackers keeps the udp, http and https trackers a page asked for (the page cannot use wss ones), adds the defaults, and caps the list.
func cleanTrackers(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range append(append([]string(nil), in...), btDefaultTrackers...) {
		u, err := url.Parse(strings.TrimSpace(t))
		if err != nil || u.Hostname() == "" || len(t) > 300 {
			continue
		}
		switch u.Scheme {
		case "udp", "http", "https":
		default:
			continue
		}
		if p := u.Port(); p == "0" || (u.Scheme == "udp" && p == "") {
			continue
		}
		key := u.Scheme + "://" + strings.ToLower(u.Host) + u.Path
		if seen[key] || len(out) >= 12 {
			continue
		}
		seen[key] = true
		out = append(out, u.String())
	}
	return out
}

func announceUDP(ctx context.Context, u *url.URL, hash [20]byte) ([]string, error) {
	ips, err := btResolve(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	port := 80
	if p := u.Port(); p != "" {
		fmt.Sscan(p, &port)
	}
	pc, err := btListenUDP()
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	dst := &net.UDPAddr{IP: ips[0], Port: port}
	exchange := func(req []byte, minLen int, action uint32, tid uint32) ([]byte, error) {
		buf := make([]byte, 4096)
		for try := 0; try < 2; try++ {
			if dl, ok := ctx.Deadline(); ok && time.Until(dl) < time.Second {
				break
			}
			if _, err := pc.WriteTo(req, dst); err != nil {
				return nil, err
			}
			pc.SetReadDeadline(time.Now().Add(4 * time.Second))
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					break
				}
				if ua, ok := from.(*net.UDPAddr); !ok || !ua.IP.Equal(dst.IP) || n < 8 {
					continue
				}
				a, t := binary.BigEndian.Uint32(buf[0:4]), binary.BigEndian.Uint32(buf[4:8])
				if t != tid {
					continue
				}
				if a == 3 {
					return nil, errors.New("tracker: " + string(buf[8:n]))
				}
				if a == action && n >= minLen {
					return append([]byte(nil), buf[:n]...), nil
				}
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errors.New("tracker did not answer")
	}
	var r4 [4]byte
	rand.Read(r4[:])
	tid := binary.BigEndian.Uint32(r4[:])
	req := make([]byte, 16)
	binary.BigEndian.PutUint64(req[0:8], 0x41727101980)
	binary.BigEndian.PutUint32(req[8:12], 0)
	binary.BigEndian.PutUint32(req[12:16], tid)
	resp, err := exchange(req, 16, 0, tid)
	if err != nil {
		return nil, err
	}
	conn := resp[8:16]
	rand.Read(r4[:])
	tid = binary.BigEndian.Uint32(r4[:])
	ann := make([]byte, 98)
	copy(ann[0:8], conn)
	binary.BigEndian.PutUint32(ann[8:12], 1)
	binary.BigEndian.PutUint32(ann[12:16], tid)
	copy(ann[16:36], hash[:])
	copy(ann[36:56], btRandPeerID())
	binary.BigEndian.PutUint64(ann[64:72], 1<<31) // left: a placeholder, so the tracker counts us as a leecher
	binary.BigEndian.PutUint32(ann[80:84], 2)     // event: started
	rand.Read(ann[88:92])                         // key
	binary.BigEndian.PutUint32(ann[92:96], btWantPeers)
	binary.BigEndian.PutUint16(ann[96:98], btAnnouncePort)
	resp, err = exchange(ann, 20, 1, tid)
	if err != nil {
		return nil, err
	}
	return btCompactPeers(resp[20:]), nil
}

func pctBytes(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		fmt.Fprintf(&s, "%%%02x", c)
	}
	return s.String()
}

func announceHTTP(ctx context.Context, u *url.URL, hash [20]byte) ([]string, error) {
	q := "info_hash=" + pctBytes(hash[:]) + "&peer_id=" + pctBytes(btRandPeerID()) + fmt.Sprintf("&port=%d&uploaded=0&downloaded=0&left=2147483648&compact=1&numwant=%d&event=started", btAnnouncePort, btWantPeers)
	full := *u
	if full.RawQuery != "" {
		full.RawQuery += "&" + q
	} else {
		full.RawQuery = q
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig: tlsClientConfig(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := btResolve(ctx, host) // vets every address: public only
			if err != nil {
				return nil, err
			}
			var last error
			for _, ip := range ips {
				c, err := btDialTCP(ctx, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		}}
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, full.String(), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	v, err := bdecode(b)
	if err != nil {
		return nil, errors.New("tracker sent a bad answer")
	}
	m, _ := bdict(v)
	if f, ok := bstr(m, "failure reason"); ok {
		return nil, errors.New("tracker: " + clip(f, 80))
	}
	switch p := m["peers"].(type) {
	case string:
		return btCompactPeers([]byte(p)), nil
	case []any:
		var out []string
		for _, e := range p {
			d, _ := bdict(e)
			ip, _ := bstr(d, "ip")
			port, _ := bint(d, "port")
			if a := net.ParseIP(ip); a != nil && btPeerOK(a, int(port)) {
				out = append(out, net.JoinHostPort(a.String(), fmt.Sprint(port)))
			}
		}
		return out, nil
	}
	return nil, nil
}

// ---- DHT ----

type dhtNode struct {
	id   [20]byte
	addr *net.UDPAddr
}

func xorLess(a, b, target [20]byte) bool {
	for i := range a {
		x, y := a[i]^target[i], b[i]^target[i]
		if x != y {
			return x < y
		}
	}
	return false
}

func dhtQuery(tid []byte, self, hash [20]byte) []byte {
	var b bytes.Buffer
	b.WriteString("d1:ad2:id20:")
	b.Write(self[:])
	b.WriteString("9:info_hash20:")
	b.Write(hash[:])
	b.WriteString("e1:q9:get_peers1:t2:")
	b.Write(tid)
	b.WriteString("1:y1:qe")
	return b.Bytes()
}

// dhtLookup walks the DHT toward the hash, asking the nodes closest to it for peers, and calls emit with each batch of peers found. It stops at the context's end, with enough peers, or
// when a round brings no closer node.
func dhtLookup(ctx context.Context, hash [20]byte, emit func([]string)) error {
	pc, err := btListenUDP()
	if err != nil {
		return err
	}
	defer pc.Close()
	var self [20]byte
	rand.Read(self[:])
	cands := map[string]*dhtNode{}
	queried := map[string]bool{}
	var order []*dhtNode
	addNode := func(id [20]byte, ip net.IP, port int) {
		if !btPeerOK(ip, port) {
			return
		}
		k := net.JoinHostPort(ip.String(), fmt.Sprint(port))
		if cands[k] != nil || len(cands) >= 500 {
			return
		}
		n := &dhtNode{id: id, addr: &net.UDPAddr{IP: ip, Port: port}}
		cands[k] = n
		order = append(order, n)
	}
	for _, h := range btDHTBootstrap {
		host, ps, _ := net.SplitHostPort(h)
		var port int
		fmt.Sscan(ps, &port)
		if ips, err := btResolve(ctx, host); err == nil {
			addNode([20]byte{}, ips[0], port)
		}
	}
	if len(order) == 0 {
		return errors.New("no DHT bootstrap node answered a lookup")
	}
	rctx, rstop := context.WithCancel(ctx) // stops the reader as soon as the lookup is over, not only at the deadline
	defer rstop()
	found := 0
	seenPeer := map[string]bool{}
	pending := map[string]bool{}
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, from, err := pc.ReadFrom(buf)
			if rctx.Err() != nil {
				return
			}
			if err != nil {
				continue
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			v, err := bdecode(buf[:n])
			if err != nil {
				continue
			}
			m, _ := bdict(v)
			r, _ := bdict(m["r"])
			if y, _ := bstr(m, "y"); y != "r" || r == nil {
				continue
			}
			mu.Lock()
			if !pending[ua.String()] { // an answer we did not ask for
				mu.Unlock()
				continue
			}
			var batch []string
			if vals, ok := r["values"].([]any); ok {
				for _, e := range vals {
					if s, ok := e.(string); ok {
						for _, p := range btCompactPeers([]byte(s)) {
							if !seenPeer[p] {
								seenPeer[p] = true
								batch = append(batch, p)
							}
						}
					}
				}
			}
			if ns, ok := bstr(r, "nodes"); ok {
				for b := []byte(ns); len(b) >= 26; b = b[26:] {
					var id [20]byte
					copy(id[:], b[:20])
					addNode(id, net.IP(append([]byte(nil), b[20:24]...)), int(binary.BigEndian.Uint16(b[24:26])))
				}
			}
			found += len(batch)
			mu.Unlock()
			if len(batch) > 0 {
				emit(batch)
			}
		}
	}()
	defer func() { rstop(); <-done }()
	for round := 0; round < 12 && ctx.Err() == nil; round++ {
		mu.Lock()
		sort.Slice(order, func(i, j int) bool { return xorLess(order[i].id, order[j].id, hash) })
		var wave []*dhtNode
		for _, n := range order {
			if k := n.addr.String(); !queried[k] {
				queried[k] = true
				pending[k] = true
				wave = append(wave, n)
				if len(wave) == 8 {
					break
				}
			}
		}
		enough := found >= 100
		mu.Unlock()
		if len(wave) == 0 || enough {
			break
		}
		for _, n := range wave {
			var tid [2]byte
			rand.Read(tid[:])
			pc.WriteTo(dhtQuery(tid[:], self, hash), n.addr)
		}
		select {
		case <-ctx.Done():
		case <-time.After(1500 * time.Millisecond):
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(1200 * time.Millisecond): // late answers to the last wave
	}
	return nil
}

// ---- all of it together ----

type btFound struct {
	Peers []string `json:"peers,omitempty"`
	Src   string   `json:"src,omitempty"`
	Err   string   `json:"err,omitempty"`
}

// btPeers asks every tracker and the DHT at once and calls emit with each new batch (duplicates removed, every peer vetted). It returns when all have answered or the context ends.
func btPeers(ctx context.Context, hash [20]byte, trackers []string, emit func(btFound)) {
	var mu sync.Mutex
	seen := map[string]bool{}
	push := func(src string, peers []string) {
		mu.Lock()
		var fresh []string
		for _, p := range peers {
			if !seen[p] {
				seen[p] = true
				fresh = append(fresh, p)
			}
		}
		mu.Unlock()
		if len(fresh) > 0 {
			btAllowed.add(fresh)
			emit(btFound{Peers: fresh, Src: src})
		}
	}
	var wg sync.WaitGroup
	for _, t := range cleanTrackers(trackers) {
		u, err := url.Parse(t)
		if err != nil {
			continue
		}
		wg.Add(1)
		go func(u *url.URL) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			var peers []string
			var err error
			if u.Scheme == "udp" {
				peers, err = announceUDP(c, u, hash)
			} else {
				peers, err = announceHTTP(c, u, hash)
			}
			if err != nil {
				emit(btFound{Src: u.Host, Err: searchErrText(err, "")})
				return
			}
			push(u.Host, peers)
		}(u)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dhtLookup(ctx, hash, func(p []string) { push("dht", p) }); err != nil {
			emit(btFound{Src: "dht", Err: searchErrText(err, "")})
		}
	}()
	wg.Wait()
}
