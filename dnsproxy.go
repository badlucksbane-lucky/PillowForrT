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
	Result string    `json:"result"` // blocked | rebind | cached | doh | plain | vpn | tor | error
	List   string    `json:"list,omitempty"`
	MS     float64   `json:"ms"`
}

type kv struct {
	Name  string `json:"name"`
	Count uint32 `json:"count"`
}

type DNSStats struct {
	Queries, Blocked, Cached, DoH, VPN, Tor, Errors, HardBlock atomic.Uint64
	Since                                                      time.Time
	mu                                                         sync.Mutex
	topBlocked, topQueried                                     map[string]uint32
	clients                                                    map[string]*clientStat
	ring                                                       [300]dnsEvent
	n                                                          int
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
	Queries, Blocked, Cached, DoH, VPN, Errors uint64
	Since                                      time.Time
	TopBlocked, TopQueried                     []kv
	Clients                                    []clientView
	Recent                                     []dnsEvent
}

func (s *DNSStats) Snapshot(topN, recentN int) statsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn := statsSnapshot{Queries: s.Queries.Load(), Blocked: s.Blocked.Load(), Cached: s.Cached.Load(), DoH: s.DoH.Load(),
		VPN: s.VPN.Load(), Errors: s.Errors.Load(), Since: s.Since, TopBlocked: topCounts(s.topBlocked, topN), TopQueried: topCounts(s.topQueried, topN)}
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

// ---------- upstream: encrypted DNS (DoH) only ----------
// There is no plain-DNS path. A name lookup is answered by DoH or refused (SERVFAIL); it is never sent in the clear, and nothing here can be configured to. (The old fallback to the carrier's
// resolvers, its grace period and its flags are gone: the firewall refused that traffic anyway, see dnsguard.go, so the code only ever looked like a way out.)

type upstreamConfig struct {
	DoHURLs    []string
	Roots      *x509.CertPool
	DoHTimeout time.Duration
	ProbeEvery time.Duration
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	// optional: the timeout to use now (a slower route needs longer), and a number that changes when the route does, so connections opened under the old route are closed
	TimeoutFor func() time.Duration
	RouteGen   func() uint64
	// optional: dials for the one bootstrap lookup that is allowed while the route is blocked (ResolveBootstrap)
	BootDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// upstreamDownAfter is how many lookups in a row must fail (every resolver tried each time) before encrypted DNS is reported as down.
const upstreamDownAfter = 3

type Upstream struct {
	cfg       upstreamConfig
	client    *http.Client
	mu        sync.Mutex
	down      bool
	downSince time.Time
	consec    int // lookups failed in a row
	lastErr   string
	lastOK    time.Time
	probing   bool
	DoHOK     atomic.Uint64
	DoHFail   atomic.Uint64
	lastMS    atomic.Int64
	gen       uint64
	bootOnce  sync.Once
	bootCl    *http.Client
}

func newUpstream(cfg upstreamConfig) *Upstream {
	if cfg.DoHTimeout == 0 {
		cfg.DoHTimeout = 2 * time.Second
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
	if cfg.TimeoutFor != nil { // the per-request context sets the real limit; the transport's own must not cut a slower route short
		tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout = 20*time.Second, 20*time.Second
	}
	return &Upstream{cfg: cfg, client: &http.Client{Transport: tr}}
}

type upstreamState struct {
	Mode      string    `json:"mode"` // doh | failing
	Warning   string    `json:"warning,omitempty"`
	Since     time.Time `json:"since,omitempty"`
	LastOK    time.Time `json:"last_doh_ok,omitempty"`
	DoHOK     uint64    `json:"doh_ok"`
	DoHFail   uint64    `json:"doh_fail"`
	LastMS    int64     `json:"last_doh_ms"`
	Resolvers []string  `json:"doh_resolvers"`
}

func (u *Upstream) State() upstreamState {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := upstreamState{Mode: "doh", LastOK: u.lastOK, DoHOK: u.DoHOK.Load(), DoHFail: u.DoHFail.Load(), LastMS: u.lastMS.Load(), Resolvers: u.cfg.DoHURLs}
	if u.down {
		st.Mode, st.Since = "failing", u.downSince
		st.Warning = "Encrypted DNS (DoH) is failing: name lookups are being refused, and nothing is sent in the clear. Last error: " + u.lastErr
	}
	return st
}

// Failing says whether encrypted DNS is down (several lookups in a row failed and none has worked since).
func (u *Upstream) Failing() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.down
}

func (u *Upstream) doh(q []byte) ([]byte, string, error) {
	if u.cfg.RouteGen != nil { // the route changed (tunnel up or down, Tor ready): a pooled connection opened under the old one must not be reused
		g := u.cfg.RouteGen()
		u.mu.Lock()
		changed := g != u.gen
		u.gen = g
		u.mu.Unlock()
		if changed {
			u.client.CloseIdleConnections()
		}
	}
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
	to := u.cfg.DoHTimeout
	if u.cfg.TimeoutFor != nil {
		to = u.cfg.TimeoutFor()
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
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

// fail records a lookup that no resolver answered; after upstreamDownAfter in a row encrypted DNS is reported as down, and a probe starts to notice when it comes back.
func (u *Upstream) fail(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastErr = err.Error()
	if u.consec++; u.consec >= upstreamDownAfter && !u.down {
		u.down, u.downSince = true, time.Now()
	}
	if u.down && !u.probing {
		u.probing = true
		go u.probeLoop()
	}
}

// probeLoop retries DoH with a harmless query until it works again, then clears the warning (a busy house clears it sooner, with its own lookups).
func (u *Upstream) probeLoop() {
	probe := mkProbeQuery()
	for {
		time.Sleep(u.cfg.ProbeEvery)
		if _, _, err := u.doh(probe); err == nil {
			u.mu.Lock()
			u.down, u.probing, u.consec, u.lastOK = false, false, 0, time.Now()
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

// Resolve answers q (a client query with its own id) over DoH.
func (u *Upstream) Resolve(q []byte) ([]byte, string, error) {
	b, via, _, err := u.ResolveFrom(q)
	return b, via, err
}

// ResolveFrom is Resolve, also naming the DoH resolver that answered. A failure is returned as an error and the caller refuses the lookup; there is nothing else to try.
func (u *Upstream) ResolveFrom(q []byte) ([]byte, string, string, error) {
	b, url, err := u.doh(q)
	if err != nil {
		u.DoHFail.Add(1)
		u.fail(err)
		return nil, "", "", err
	}
	u.DoHOK.Add(1)
	u.mu.Lock()
	u.lastOK, u.consec, u.down = time.Now(), 0, false // a success ends any run of failures
	u.mu.Unlock()
	return b, "doh", url, nil
}

// ResolveBootstrap answers one query over DoH on the cellular link, bypassing the route (owndial.go: the lookup of api.mullvad.net while the route is blocked, so the tunnel can come back).
func (u *Upstream) ResolveBootstrap(q []byte) ([]byte, string, error) {
	u.bootOnce.Do(func() {
		dial := u.cfg.BootDial
		if dial == nil {
			dial = u.cfg.Dial
		}
		u.bootCl = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: u.cfg.Roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DialContext: dial,
			MaxIdleConns: 1, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second}}
	})
	var last error
	for _, url := range u.cfg.DoHURLs {
		body := append([]byte(nil), q...)
		setID(body, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := u.bootCl.Do(req)
		if err != nil {
			cancel()
			last = err
			continue
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		cancel()
		if rerr == nil && resp.StatusCode == 200 && len(b) >= 12 && b[2]&0x80 != 0 {
			return b, url, nil
		}
		last = fmt.Errorf("%s: bad answer", url)
	}
	return nil, "", last
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
	warnMu   sync.Mutex
	warnAt   map[string]time.Time
}

const hardBlockWarnEvery = 10 * time.Minute

// hardBlock records that a Tor or Mullvad device's lookup was refused because the encrypted path for it is not working. Nothing is sent in the clear instead (the device gets SERVFAIL),
// and the owner is told once per path per ten minutes, so a long outage is one event and not a flood.
func ownBlocked() bool { r, _ := ownRouteNow(); return r == routeBlock }

func (p *DNSProxy) hardBlock(path, client string, err error) {
	p.Stats.HardBlock.Add(1)
	p.warnMu.Lock()
	if p.warnAt == nil {
		p.warnAt = map[string]time.Time{}
	}
	now := time.Now()
	if t, ok := p.warnAt[path]; ok && now.Sub(t) < hardBlockWarnEvery {
		p.warnMu.Unlock()
		return
	}
	p.warnAt[path] = now
	p.warnMu.Unlock()
	if events == nil {
		return
	}
	why := "unknown"
	if err != nil {
		why = err.Error()
	}
	who := map[string]string{"tor": "Tor devices", "mullvad": "Mullvad devices"}[path]
	events.Add([]evt{{T: now.Unix(), Kind: "dns_hardblock", Sev: sevAttention,
		Text:   fmt.Sprintf("Encrypted DNS is not working for %s (last asked by %s: %s). Their lookups are being refused, not sent in the clear. Nothing falls back to plain DNS for them.", who, client, why),
		Public: "Name lookups for devices on a private path are blocked because encrypted DNS is down"}})
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
			if rcodeOf(resp) == 2 { // Tor is not ready or did not answer: SERVFAIL, never a public resolver
				p.hardBlock("tor", client, errors.New("Tor did not answer"))
			}
			if hit, by := p.cnameBlocked(client, resp, t0); hit { // the same list rules apply to what Tor answered: a cloaked tracker is as unwelcome over Tor
				p.Stats.Blocked.Add(1)
				ev.List = by
				finish("blocked")
				return buildBlocked(q, dq, p.BlockTTL)
			}
			if dq.Name != "onion" && !strings.HasSuffix(dq.Name, ".onion") { // an onion name's answer is the bridge's own private range, by design
				if _, refuse := rebindMgr.Refuse(dq.Name, resp); refuse {
					finish("rebind")
					return buildRcode(q, dq, 5)
				}
			}
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
		if dq.Class == qclassI {
			if _, refuse := rebindMgr.Refuse(dq.Name, resp); refuse {
				finish("rebind")
				return buildRcode(q, dq, 5) // REFUSED: a private address for a public name never reaches the device (rebind.go)
			}
		}
		finish("cached")
		return resp
	}
	var resp []byte
	var via, fromURL string
	switch {
	case viaVPN:
		resp, err = p.VPN.ResolveDNS(q)
		via = "vpn"
	case ownBootstrapName(dq.Name) && ownBlocked():
		resp, fromURL, err = p.Up.ResolveBootstrap(q)
		via = "doh"
	default:
		resp, via, fromURL, err = p.Up.ResolveFrom(q)
	}
	if err != nil {
		if viaVPN || p.VPN.ExitFor(client) == "mullvad" {
			p.hardBlock("mullvad", client, err)
		}
		p.Stats.Errors.Add(1)
		finish("error")
		return buildRcode(q, dq, 2) // SERVFAIL
	}
	setID(resp, dq.ID)
	p.Cache.put(key, resp, time.Now())
	if via == "doh" {
		p.Stats.DoH.Add(1)
		if dnsXMgr != nil && dq.Class == qclassI && dq.Type == 1 {
			dnsXMgr.Observe(client, dq.Name, fromURL, q, resp, t0)
		}
	} else if via == "vpn" {
		p.Stats.VPN.Add(1)
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
	if dq.Class == qclassI {
		if _, refuse := rebindMgr.Refuse(dq.Name, resp); refuse {
			finish("rebind")
			return buildRcode(q, dq, 5) // REFUSED, as above
		}
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

func (c *dnsCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
