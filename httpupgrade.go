package main

// HTTP to HTTPS upgrade, with a note of every time it would have fallen back. Port 80 stays an allowed outbound service (egress.go), but a device's port-80 connections to
// anything outside the LAN are first REDIRECTed (nat, HS_HTTPUP) to this small listener on the LAN address, which answers with a 307 to the https:// form of the same URL.
// Nothing is proxied or decrypted: the request line and Host header stop here, and the device repeats the request over TLS on port 443 by itself.
//   - A fall-back is the same device asking this box for the same host on port 80 again within two minutes, with no TLS connection from it to that address in the connection
//     table: the HTTPS attempt did not work (no HTTPS there, a certificate the browser refused, a client that does not follow redirects) and the client came back to plain
//     HTTP. That is counted, noted as an info event (no names, no addresses), and the device is let through to that one address for two minutes, by a rule in HS_HTTPUP
//     (the packets still take the normal FORWARD path, so the exits, kill switch and allow-list apply to them). If the TLS connection IS there, the repeat was just a repeat
//     and is upgraded again.
//   - A 307 and no-store, not 301, so a browser never caches the upgrade past the moment HTTPS stops working.
//   - A client that does not follow redirects and never retries (curl without -L, some IoT firmware) fails on the 307. That is what the per-device skip list and the
//     global switch are for; the page shows how many redirects were served and how many fell back.
//   - IPv4 only (the kernel has no ip6 nat table). Only port 80: HTTP on 8080 and the like is not touched.
//   - The Host is checked against a strict character set before it goes into Location, so the answer cannot carry a header injection, and the redirect goes back to the
//     client that asked and names only what that client sent. Only counters are kept.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	httpUpPort     = 3130
	httpUpMaxConns = 32
	httpUpMaxURI   = 8192
	httpUpWindow   = 2 * time.Minute // how long a redirect is remembered, and how long a fall-back pass lasts
	httpUpMaxSeen  = 2000
	httpUpMaxPass  = 64
)

var httpUpHostRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$`)

// httpExempt lets one device's port-80 connections to one address through, until the time shown.
type httpExempt struct {
	Client, Dst string
	Until       time.Time
}

type httpUpgrader struct {
	mu    sync.Mutex
	now   func() time.Time
	seen  map[string]time.Time // client|host -> when it was sent to https
	noted map[string]time.Time // client -> last event, so one chatty device is one line
	// replaceable for tests and set up in main.go
	httpsUp func(client, dst string) bool                   // the connection table shows a finished TLS-port connection from client to dst
	exempt  func(client, dst string, until time.Time) error // lets that pair through port 80
	emit    func(evt)

	Redirected, Refused, FellBack atomic.Uint64
}

var httpUp = newHTTPUpgrader()

func newHTTPUpgrader() *httpUpgrader {
	return &httpUpgrader{now: time.Now, seen: map[string]time.Time{}, noted: map[string]time.Time{}}
}

// httpUpgradeURL builds the https:// address for a request that arrived on port 80 (host is the Host header, uri the request target). ok is false for anything that is not a
// plain host name or IP literal with an origin-form path.
func httpUpgradeURL(host, uri string) (string, bool) {
	h := host
	if strings.HasPrefix(h, "[") {
		end := strings.Index(h, "]")
		if end < 0 {
			return "", false
		}
		ip := net.ParseIP(h[1:end])
		if ip == nil || !strings.Contains(h[1:end], ":") {
			return "", false
		}
		if rest := h[end+1:]; rest != "" && !validPortSuffix(rest) {
			return "", false
		}
		h = h[:end+1]
	} else {
		if i := strings.LastIndex(h, ":"); i >= 0 {
			if !validPortSuffix(h[i:]) {
				return "", false
			}
			h = h[:i]
		}
		if !httpUpHostRe.MatchString(h) {
			return "", false
		}
	}
	if uri == "" || uri == "*" {
		uri = "/"
	}
	if uri[0] != '/' || len(uri) > httpUpMaxURI {
		return "", false
	}
	for i := 0; i < len(uri); i++ {
		if uri[i] <= 0x20 || uri[i] >= 0x7f {
			return "", false
		}
	}
	return "https://" + h + uri, true
}

func validPortSuffix(s string) bool {
	if len(s) < 2 || len(s) > 6 || s[0] != ':' {
		return false
	}
	n, err := strconv.Atoi(s[1:])
	return err == nil && n >= 0 && n <= 65535
}

// decide is the whole policy for one request. It returns the status, the Location (empty for an error) and a line for the body.
func (u *httpUpgrader) decide(client, dst, host, uri string) (int, string, string) {
	https, ok := httpUpgradeURL(host, uri)
	if !ok {
		u.Refused.Add(1)
		return http.StatusBadRequest, "", "This request could not be turned into an https:// address."
	}
	rest := https[len("https://"):]
	key := client + "|" + strings.ToLower(rest[:strings.IndexByte(rest, '/')])
	now := u.now()
	u.mu.Lock()
	u.pruneLocked(now)
	t, again := u.seen[key]
	again = again && now.Sub(t) < httpUpWindow
	u.mu.Unlock()

	if again && !(dst != "" && u.httpsUp != nil && u.httpsUp(client, dst)) {
		u.FellBack.Add(1)
		u.note(client, now)
		if dst == "" || u.exempt == nil {
			return http.StatusServiceUnavailable, "", "The HTTPS address did not work and plain HTTP could not be let through; try again."
		}
		if err := u.exempt(client, dst, now.Add(httpUpWindow)); err != nil {
			log.Printf("http upgrade: pass: %v", err)
			return http.StatusServiceUnavailable, "", "The HTTPS address did not work and plain HTTP could not be let through; try again."
		}
		u.mu.Lock()
		delete(u.seen, key)
		u.mu.Unlock()
		back := "http://" + rest
		return http.StatusTemporaryRedirect, back, "The HTTPS address did not work; letting plain HTTP through once: " + back
	}
	u.mu.Lock()
	u.seen[key] = now
	u.mu.Unlock()
	u.Redirected.Add(1)
	return http.StatusTemporaryRedirect, https, "Plain HTTP is upgraded on this network. Use " + https
}

func (u *httpUpgrader) pruneLocked(now time.Time) {
	if len(u.seen) < httpUpMaxSeen {
		return
	}
	for k, t := range u.seen {
		if now.Sub(t) >= httpUpWindow {
			delete(u.seen, k)
		}
	}
	if len(u.seen) >= httpUpMaxSeen { // a flood of distinct hosts: forget everything rather than grow
		u.seen = map[string]time.Time{}
	}
}

// note raises one info event per device per ten minutes. The text never names the device, the host or an address.
func (u *httpUpgrader) note(client string, now time.Time) {
	u.mu.Lock()
	last, seen := u.noted[client]
	if seen && now.Sub(last) < 10*time.Minute {
		u.mu.Unlock()
		return
	}
	if len(u.noted) > 500 {
		u.noted = map[string]time.Time{}
	}
	u.noted[client] = now
	u.mu.Unlock()
	if u.emit != nil {
		u.emit(evt{T: now.Unix(), Kind: "http_fallback", Sev: sevInfo,
			Text:   "A device's HTTPS upgrade did not work, so it fell back to plain HTTP and was let through",
			Public: "A plain HTTP page was let through after its HTTPS upgrade did not work"})
	}
}

type origDstKey struct{}

func (u *httpUpgrader) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, uri := r.Host, r.RequestURI
		if r.URL != nil && r.URL.IsAbs() { // a client that thinks it is talking to a proxy
			host, uri = r.URL.Host, r.URL.RequestURI()
		}
		client, _, _ := net.SplitHostPort(r.RemoteAddr)
		dst, _ := r.Context().Value(origDstKey{}).(string)
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Connection", "close")
		status, loc, body := http.StatusBadRequest, "", "This request could not be turned into an https:// address."
		if r.Method == http.MethodConnect {
			u.Refused.Add(1)
		} else {
			status, loc, body = u.decide(client, dst, host, uri)
		}
		if loc != "" {
			h.Set("Location", loc)
		}
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			fmt.Fprintln(w, body)
		}
	})
}

// originalDst asks the kernel where a REDIRECTed connection was really going (SO_ORIGINAL_DST). "" when it cannot say.
func originalDst(c net.Conn) string {
	if lc, ok := c.(*limitConn); ok {
		c = lc.Conn
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return ""
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return ""
	}
	var out string
	raw.Control(func(fd uintptr) {
		// the kernel fills a sockaddr_in; IPv6Mreq is 20 bytes of room for it: family (2), port (2), address (4)
		mr, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, 80)
		if err != nil || mr.Multiaddr[0] != syscall.AF_INET || mr.Multiaddr[1] != 0 { // little-endian family
			return
		}
		out = net.IPv4(mr.Multiaddr[4], mr.Multiaddr[5], mr.Multiaddr[6], mr.Multiaddr[7]).String()
	})
	return out
}

// conntrackHasTLS reports whether the connection table (/proc/net/nf_conntrack text) holds a TLS-port connection from client to dst that got past the handshake's first
// packet: established, closing or in TIME_WAIT, anything but an unanswered SYN.
func conntrackHasTLS(table, client, dst string) bool {
	want := "src=" + client + " dst=" + dst + " "
	for _, l := range strings.Split(table, "\n") {
		if !strings.Contains(l, " tcp ") || !strings.Contains(l, want) || !strings.Contains(l, "dport=443 ") {
			continue
		}
		if strings.Contains(l, "ESTABLISHED") || strings.Contains(l, "TIME_WAIT") || strings.Contains(l, "FIN_WAIT") || strings.Contains(l, "CLOSE") || strings.Contains(l, "[ASSURED]") {
			return true
		}
	}
	return false
}

// limitListener caps concurrent connections: this box has one slow core and a few MB to spare.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, rel: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once sync.Once
	rel  func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.rel)
	return err
}

// serveHTTPUpgrade listens on the LAN address (never the cellular side) and serves the redirect. A listener that cannot bind leaves the NAT rule pointing at a closed port:
// port 80 then fails fast, so main.go starts this before the rules can exist.
func serveHTTPUpgrade(addr string) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Printf("http upgrade: %v", err)
		return
	}
	srv := &http.Server{
		Handler:           httpUp.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, origDstKey{}, originalDst(c))
		},
	}
	srv.SetKeepAlivesEnabled(false)
	if err := srv.Serve(&limitListener{Listener: ln, sem: make(chan struct{}, httpUpMaxConns)}); err != nil {
		log.Printf("http upgrade: %v", err)
	}
}

// AddHTTPExempt lets client's port-80 connections to dst through until the time shown (the fall-back pass). Both must be IPv4 addresses and dst must be outside the LAN.
func (m *egressMgr) AddHTTPExempt(client, dst string, until time.Time) error {
	c, d := net.ParseIP(client), net.ParseIP(dst)
	_, lan, _ := net.ParseCIDR(lanCIDR)
	if c == nil || d == nil || c.To4() == nil || d.To4() == nil || lan.Contains(d) || !d.IsGlobalUnicast() {
		return fmt.Errorf("not a pass I can make: %s -> %s", client, dst)
	}
	m.mu.Lock()
	var keep []httpExempt
	for _, x := range m.cfg.httpExempt { // copy on write: Reconcile renders from a snapshot of the slice header
		if x.Client != client || x.Dst != dst {
			keep = append(keep, x)
		}
	}
	if len(keep) >= httpUpMaxPass {
		m.mu.Unlock()
		return fmt.Errorf("too many passes at once")
	}
	m.cfg.httpExempt = append(keep, httpExempt{client, dst, until})
	m.mu.Unlock()
	return m.reconcile()
}

func (m *egressMgr) pruneExemptLocked() {
	var keep []httpExempt
	for _, x := range m.cfg.httpExempt {
		if x.Until.After(m.now()) {
			keep = append(keep, x)
		}
	}
	m.cfg.httpExempt = keep
}

// httpUpgradeNat renders the nat block (iptables-restore syntax, IPv4 only) that sends port-80 connections to the listener. The chain is always declared so that turning the
// feature off, or switching the list off, flushes it. Order matters: the LAN first (the PAC page on :80 of the services address and anything local keeps working), then the
// devices left out, then the fall-back passes, then the redirect.
func httpUpgradeNat(c egressCfg) string {
	var b strings.Builder
	b.WriteString("*nat\n:HS_HTTPUP - [0:0]\n")
	if c.Mode != "off" && !c.NoHTTPUpgrade {
		fmt.Fprintf(&b, "-A HS_HTTPUP -d %s -j RETURN\n", lanCIDR)
		skip := append([]string(nil), c.HTTPSkip...)
		sort.Strings(skip)
		for _, mac := range skip {
			fmt.Fprintf(&b, "-A HS_HTTPUP -m mac --mac-source %s -j RETURN\n", mac)
		}
		for _, x := range c.httpExempt {
			fmt.Fprintf(&b, "-A HS_HTTPUP -s %s -d %s -j RETURN\n", x.Client, x.Dst)
		}
		fmt.Fprintf(&b, "-A HS_HTTPUP -p tcp --dport 80 -j REDIRECT --to-ports %d\n", httpUpPort)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}
