package main

// The DNS pipeline behind dnsmasq: filter -> cache -> encrypted upstream (DoH to Quad9), falling back to plain DNS with a visible warning.
//   client -> dnsmasq (DHCP names, local names) -> this stub on 127.0.0.1:5354 -> Quad9 over HTTPS
// Stats are in RAM only (no query history on flash).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- statistics (RAM only) ----------

type dnsEvent struct {
	T      time.Time `json:"t"`
	Name   string    `json:"name"`
	Client string    `json:"client,omitempty"`
	Type   uint16    `json:"type"`
	Result string    `json:"result"` // blocked | cached | doh | plain | error
	List   string    `json:"list,omitempty"`
	MS     float64   `json:"ms"`
}

type kv struct {
	Name  string `json:"name"`
	Count uint32 `json:"count"`
}

type DNSStats struct {
	Queries, Blocked, Cached, DoH, Plain, VPN, Tor, Errors atomic.Uint64
	Since                                                  time.Time
	mu                                                     sync.Mutex
	topBlocked, topQueried                                 map[string]uint32
	clients                                                map[string]*clientStat
	ring                                                   [300]dnsEvent
	n                                                      int
}

func NewDNSStats() *DNSStats {
	return &DNSStats{Since: time.Now(), topBlocked: map[string]uint32{}, topQueried: map[string]uint32{}, clients: map[string]*clientStat{}}
}

func bump(m map[string]uint32, k string) {
	m[k]++
	if len(m) > 3000 { // keep it bounded: drop the singletons
		for n, c := range m {
			if c <= 1 && n != k {
				delete(m, n)
			}
		}
	}
}

func (s *DNSStats) Record(ev dnsEvent) {
	s.mu.Lock()
	s.ring[s.n%len(s.ring)] = ev
	s.n++
	bump(s.topQueried, ev.Name)
	if ev.Result == "blocked" {
		bump(s.topBlocked, ev.Name)
	}
	if ev.Client != "" {
		c := s.clients[ev.Client]
		if c == nil && len(s.clients) < 64 { // bounded: a LAN has a handful of devices
			c = &clientStat{}
			s.clients[ev.Client] = c
		}
		if c != nil {
			c.Queries++
			c.Last = ev.T
			if ev.Result == "blocked" {
				c.Blocked++
			}
		}
	}
	s.mu.Unlock()
}

func topCounts(m map[string]uint32, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, c := range m {
		out = append(out, kv{k, c})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || (out[i].Count == out[j].Count && out[i].Name < out[j].Name)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type statsSnapshot struct {
	Queries, Blocked, Cached, DoH, Plain, VPN, Errors uint64
	Since                                             time.Time
	TopBlocked, TopQueried                            []kv
	Clients                                           []clientView
	Recent                                            []dnsEvent
}

func (s *DNSStats) Snapshot(topN, recentN int) statsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn := statsSnapshot{Queries: s.Queries.Load(), Blocked: s.Blocked.Load(), Cached: s.Cached.Load(), DoH: s.DoH.Load(),
		Plain: s.Plain.Load(), VPN: s.VPN.Load(), Errors: s.Errors.Load(), Since: s.Since, TopBlocked: topCounts(s.topBlocked, topN), TopQueried: topCounts(s.topQueried, topN)}
	for ip, c := range s.clients {
		sn.Clients = append(sn.Clients, clientView{IP: ip, clientStat: *c})
	}
	sortClients(sn.Clients)
	cnt := s.n
	if cnt > len(s.ring) {
		cnt = len(s.ring)
	}
	if recentN > cnt {
		recentN = cnt
	}
	for i := 0; i < recentN; i++ {
		sn.Recent = append(sn.Recent, s.ring[(s.n-1-i+len(s.ring)*2)%len(s.ring)])
	}
	return sn
}

// ---------- cache ----------

type cent struct {
	resp    []byte
	at, exp time.Time
}

type dnsCache struct {
	mu  sync.Mutex
	m   map[string]*cent
	max int
}

func newDNSCache(max int) *dnsCache { return &dnsCache{m: map[string]*cent{}, max: max} }

func cacheKey(q dnsQuery) string { return fmt.Sprintf("%s/%d/%d", q.Name, q.Type, q.Class) }

func (c *dnsCache) get(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[key]
	if e == nil {
		return nil, false
	}
	if !now.Before(e.exp) {
		delete(c.m, key)
		return nil, false
	}
	out := append([]byte(nil), e.resp...)
	decrementTTL(out, uint32(now.Sub(e.at)/time.Second))
	return out, true
}

func (c *dnsCache) put(key string, resp []byte, now time.Time) {
	if len(resp) < 12 || resp[2]&0x02 != 0 || (rcodeOf(resp) != 0 && rcodeOf(resp) != 3) { // truncated or an error: do not keep
		return
	}
	ttl, ok := minTTL(resp)
	if !ok {
		ttl = 30
	}
	if ttl < 10 {
		ttl = 10
	}
	if ttl > 3600 {
		ttl = 3600
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for k, e := range c.m { // first drop the expired, then (if still full) a tenth of the rest
			if !now.Before(e.exp) {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < c.max*9/10 {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[key] = &cent{resp: append([]byte(nil), resp...), at: now, exp: now.Add(time.Duration(ttl) * time.Second)}
}

// ---------- upstream: DoH first, plain DNS as a visible fallback ----------

type upstreamConfig struct {
	DoHURLs      []string
	Roots        *x509.CertPool
	Plain        func() []string // plain resolvers "ip:53", tried in order when DoH is down
	DoHTimeout   time.Duration
	PlainTimeout time.Duration
	ProbeEvery   time.Duration
	// PlainAfter: how long encrypted DNS must keep failing (queries failing back to back, gaps under 30 s) before queries are allowed out as plain DNS.
	// 0 = at the first failure (the old behaviour); > 0 = hold off that long, answering SERVFAIL meanwhile (the cache still answers); < 0 = never fall back to plain.
	PlainAfter time.Duration
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
}

type Upstream struct {
	cfg                 upstreamConfig
	client              *http.Client
	mu                  sync.Mutex
	fb                  bool
	fbSince             time.Time
	lastErr             string
	lastOK              time.Time
	failSince, lastFail time.Time // the current run of failing encrypted lookups (see upstreamConfig.PlainAfter)
	probing             bool
	DoHOK               atomic.Uint64
	DoHFail             atomic.Uint64
	PlainOK             atomic.Uint64
	lastMS              atomic.Int64
}

func newUpstream(cfg upstreamConfig) *Upstream {
	if cfg.DoHTimeout == 0 {
		cfg.DoHTimeout = 2 * time.Second
	}
	if cfg.PlainTimeout == 0 {
		cfg.PlainTimeout = 2 * time.Second
	}
	if cfg.ProbeEvery == 0 {
		cfg.ProbeEvery = 15 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{RootCAs: cfg.Roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		DialContext:           cfg.Dial,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       2 * time.Minute,
		TLSHandshakeTimeout:   cfg.DoHTimeout,
		ResponseHeaderTimeout: cfg.DoHTimeout,
	}
	return &Upstream{cfg: cfg, client: &http.Client{Transport: tr}}
}

type upstreamState struct {
	Mode      string    `json:"mode"` // doh | plain-fallback
	Warning   string    `json:"warning,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	LastOK    time.Time `json:"last_doh_ok,omitempty"`
	DoHOK     uint64    `json:"doh_ok"`
	DoHFail   uint64    `json:"doh_fail"`
	PlainOK   uint64    `json:"plain_ok"`
	LastMS    int64     `json:"last_doh_ms"`
	Resolvers []string  `json:"doh_resolvers"`
}

func (u *Upstream) State() upstreamState {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := upstreamState{Mode: "doh", LastOK: u.lastOK, DoHOK: u.DoHOK.Load(), DoHFail: u.DoHFail.Load(), PlainOK: u.PlainOK.Load(), LastMS: u.lastMS.Load(), Resolvers: u.cfg.DoHURLs}
	if u.fb {
		st.Mode, st.Since = "plain-fallback", u.fbSince
		st.Warning = "Encrypted DNS (DoH) is failing: queries are going out as plain DNS. Last error: " + u.lastErr
	}
	return st
}

// holdOff reports whether this failed encrypted lookup should be answered with an error rather than sent out as plain DNS (upstreamConfig.PlainAfter). A run of failures is queries failing back to
// back with gaps under 30 s; the first failure after a longer quiet spell starts a new run.
func (u *Upstream) holdOff(err error) bool {
	if u.cfg.PlainAfter == 0 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	u.lastErr = err.Error()
	if u.lastFail.IsZero() || now.Sub(u.lastFail) > 30*time.Second {
		u.failSince = now
	}
	u.lastFail = now
	return u.cfg.PlainAfter < 0 || now.Sub(u.failSince) < u.cfg.PlainAfter
}

func (u *Upstream) inFallback() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.fb
}

func (u *Upstream) doh(q []byte) ([]byte, string, error) {
	var last error
	for _, url := range u.cfg.DoHURLs {
		b, err := u.dohOne(url, q)
		if err == nil {
			return b, url, nil
		}
		last = err
	}
	return nil, "", last
}

// dohOne asks one DoH resolver. The resolver cross-check (dnsxcheck.go) uses it to ask the resolver that did not answer a query.
func (u *Upstream) dohOne(url string, q []byte) ([]byte, error) {
	body := append([]byte(nil), q...)
	setID(body, 0) // RFC 8484: id 0 makes the request cache-friendly; the caller restores the client's id
	ctx, cancel := context.WithTimeout(context.Background(), u.cfg.DoHTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	t0 := time.Now()
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	b, rerr := io.ReadAll(io.LimitReader(resp.Body, 65536))
	resp.Body.Close()
	switch {
	case rerr != nil:
		return nil, rerr
	case resp.StatusCode != 200:
		return nil, fmt.Errorf("%s answered HTTP %d", url, resp.StatusCode)
	case len(b) < 12 || b[2]&0x80 == 0:
		return nil, fmt.Errorf("%s sent a bad DNS message", url)
	}
	u.lastMS.Store(time.Since(t0).Milliseconds())
	return b, nil
}

func (u *Upstream) plainServers() []string {
	if u.cfg.Plain != nil {
		if s := u.cfg.Plain(); len(s) > 0 {
			return s
		}
	}
	return []string{"9.9.9.9:53"}
}

func (u *Upstream) plain(q []byte) ([]byte, error) {
	var last error
	for _, srv := range u.plainServers() {
		c, err := net.DialTimeout("udp4", srv, u.cfg.PlainTimeout)
		if err != nil {
			last = err
			continue
		}
		c.SetDeadline(time.Now().Add(u.cfg.PlainTimeout))
		c.Write(q)
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		c.Close()
		if err != nil {
			last = err
			continue
		}
		if n >= 12 && buf[2]&0x02 != 0 { // truncated: retry over TCP
			if b, err := plainTCP(srv, q, u.cfg.PlainTimeout); err == nil {
				return b, nil
			}
		}
		return buf[:n], nil
	}
	if last == nil {
		last = errors.New("no plain resolver answered")
	}
	return nil, last
}

func plainTCP(srv string, q []byte, to time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("tcp4", srv, to)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(to))
	c.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	b := make([]byte, int(h[0])<<8|int(h[1]))
	_, err = io.ReadFull(c, b)
	return b, err
}

func (u *Upstream) enterFallback(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastErr = err.Error()
	if !u.fb {
		u.fb, u.fbSince = true, time.Now()
	}
	if !u.probing {
		u.probing = true
		go u.probeLoop()
	}
}

// probeLoop retries DoH with a harmless query until it works again, then clears the warning.
func (u *Upstream) probeLoop() {
	probe := mkProbeQuery()
	for {
		time.Sleep(u.cfg.ProbeEvery)
		if _, _, err := u.doh(probe); err == nil {
			u.mu.Lock()
			u.fb, u.probing, u.lastOK = false, false, time.Now()
			u.mu.Unlock()
			return
		}
	}
}

func mkProbeQuery() []byte {
	b := []byte{0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split("dns.quad9.net", ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

// Resolve answers q (a client query with its own id). via is "doh" or "plain".
func (u *Upstream) Resolve(q []byte) ([]byte, string, error) {
	b, via, _, err := u.ResolveFrom(q)
	return b, via, err
}

// ResolveFrom is Resolve, also naming the DoH resolver that answered (empty for a plain answer).
func (u *Upstream) ResolveFrom(q []byte) ([]byte, string, string, error) {
	if !u.inFallback() {
		b, url, err := u.doh(q)
		if err == nil {
			u.DoHOK.Add(1)
			u.mu.Lock()
			u.lastOK = time.Now()
			u.failSince, u.lastFail = time.Time{}, time.Time{} // a success ends any run of failures
			u.mu.Unlock()
			return b, "doh", url, nil
		}
		u.DoHFail.Add(1)
		if u.holdOff(err) {
			return nil, "", "", err // encrypted DNS is failing, but not for long enough to send anything in the clear: the client gets a SERVFAIL and retries
		}
		u.enterFallback(err)
	}
	b, err := u.plain(q)
	if err != nil {
		return nil, "", "", err
	}
	u.PlainOK.Add(1)
	return b, "plain", "", nil
}

// ---------- the pipeline ----------

type DNSProxy struct {
	Filter   *Filter
	Up       *Upstream
	Cache    *dnsCache
	Stats    *DNSStats
	BlockTTL uint32
	Neigh    *neighbours // optional: ties a device's IPv6 address to its IPv4 one
	VPN      *VPN        // optional: a device whose exit is Mullvad resolves through the tunnel
	Tor      *torMgr     // optional: .onion names, and every name a Tor device asks, are answered by Tor and never go to a public resolver
}

func (p *DNSProxy) Handle(q []byte) []byte {
	t0 := time.Now()
	dq, err := parseQuery(q)
	if err != nil {
		var id uint16
		if len(q) >= 2 {
			id = uint16(q[0])<<8 | uint16(q[1])
		}
		return buildRcode(q, dnsQuery{ID: id}, 1) // FORMERR
	}
	p.Stats.Queries.Add(1)
	client, q := splitClient(q, dq.QEnd) // who asked (from dnsmasq's add-subnet), and the query without it: a device address never goes upstream
	if p.Neigh != nil && client != "" {
		client = p.Neigh.canonical(client)
	}
	ev := dnsEvent{T: t0, Name: dq.Name, Type: dq.Type, Client: client}
	finish := func(res string) {
		ev.Result, ev.MS = res, float64(time.Since(t0).Microseconds())/1000
		p.Stats.Record(ev)
	}
	if dq.Class == qclassI {
		if blocked, list := p.Filter.MatchFor(client, dq.Name, t0); blocked {
			p.Stats.Blocked.Add(1)
			ev.List = list
			finish("blocked")
			return buildBlocked(q, dq, p.BlockTTL)
		}
	}
	if dq.Class == qclassI {
		if resp, ok := p.Tor.DNS(client, dq, q); ok {
			p.Stats.Tor.Add(1)
			finish("tor")
			return resp
		}
	}
	if dnsCanaryMgr != nil && dq.Class == qclassI { // a decoy name or a tunneling-shaped run of lookups is worth flagging whatever the query resolves to
		dnsCanaryMgr.Observe(client, dq.Name, false, t0)
	}
	key := cacheKey(dq)
	viaVPN := p.VPN.UseVPNDNS(client)
	if viaVPN {
		key = "vpn|" + key // another resolver, another answer set
	}
	if resp, ok := p.Cache.get(key, t0); ok {
		setID(resp, dq.ID)
		if hit, by := p.cnameBlocked(client, resp, t0); hit {
			p.Stats.Blocked.Add(1)
			ev.List = by
			finish("blocked")
			return buildBlocked(q, dq, p.BlockTTL)
		}
		p.Stats.Cached.Add(1)
		if dgaMgr != nil && dq.Class == qclassI && rcodeOf(resp) == 3 {
			dgaMgr.Observe(client, dq.Name, t0)
		}
		if dnsMITMMgr != nil && dq.Class == qclassI {
			dnsMITMMgr.Observe(client, dq.Name, resp, t0)
		}
		finish("cached")
		return resp
	}
	var resp []byte
	var via, fromURL string
	if viaVPN {
		resp, err = p.VPN.ResolveDNS(q)
		via = "vpn"
	} else {
		resp, via, fromURL, err = p.Up.ResolveFrom(q)
	}
	if err != nil {
		p.Stats.Errors.Add(1)
		finish("error")
		return buildRcode(q, dq, 2) // SERVFAIL
	}
	setID(resp, dq.ID)
	p.Cache.put(key, resp, time.Now())
	if dnsCanaryMgr != nil && via == "plain" && dq.Class == qclassI {
		dnsCanaryMgr.Observe(client, dq.Name, true, t0)
	}
	if via == "doh" {
		p.Stats.DoH.Add(1)
		if dnsXMgr != nil && dq.Class == qclassI && dq.Type == 1 {
			dnsXMgr.Observe(client, dq.Name, fromURL, q, resp, t0)
		}
	} else if via == "vpn" {
		p.Stats.VPN.Add(1)
	} else {
		p.Stats.Plain.Add(1)
	}
	if hit, by := p.cnameBlocked(client, resp, t0); hit {
		p.Stats.Blocked.Add(1)
		ev.List = by
		finish("blocked")
		return buildBlocked(q, dq, p.BlockTTL)
	}
	if dgaMgr != nil && dq.Class == qclassI && rcodeOf(resp) == 3 {
		dgaMgr.Observe(client, dq.Name, t0)
	}
	if dnsMITMMgr != nil && dq.Class == qclassI {
		dnsMITMMgr.Observe(client, dq.Name, resp, t0)
	}
	finish(via)
	return resp
}

// cnameBlocked: a tracker hidden behind an innocent name ("CNAME cloaking") is caught by checking every CNAME target in the answer against the same filter.
func (p *DNSProxy) cnameBlocked(client string, resp []byte, now time.Time) (bool, string) {
	for _, t := range cnameTargets(resp) {
		if blocked, by := p.Filter.MatchFor(client, t, now); blocked {
			return true, "cname:" + by
		}
	}
	return false, ""
}

// carrierResolvers reads the plain resolvers the modem learned (the same ones dnsmasq used before the stub).
func carrierResolvers(path string) func() []string {
	return func() []string {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var out []string
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) == 2 && f[0] == "nameserver" && net.ParseIP(f[1]) != nil && net.ParseIP(f[1]).To4() != nil {
				out = append(out, f[1]+":53")
			}
		}
		return out
	}
}

func (c *dnsCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
