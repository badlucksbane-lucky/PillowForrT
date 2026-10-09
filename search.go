package main

// A small metasearch on the box (the page is in searchpage.go, the engines in searchengines.go). A query fans out to the keyless engines that are switched on, the answers are merged and
// de-duplicated, and the page shows them. It is off until switched on, keeps nothing (no history, no result cache, and the query text is never logged), and fails closed.
//
// The query leaves by a path chosen in two parts, each one of direct, mullvad, tor, tormullvad:
//   proxy  how the connection to the engine is made. direct: the cellular link. mullvad: the tunnel only (the socket is bound to mullvad0, so a tunnel that is down means no connection).
//          tor: Tor's SOCKS port. tormullvad: Tor, and only while Tor is set to run over Mullvad (torvpn.go) and the tunnel is up.
//   dns    how the engine's name is looked up. direct: the house's encrypted DNS (DoH). mullvad: Mullvad's DoH through the tunnel. tor, tormullvad: Tor's DNS port.
// The name is resolved here by the chosen DNS and the connection is made to the address by the chosen proxy (the TLS name is still the engine's), so the two choices are independent. If
// the chosen path is not up the search is refused with the reason; there is no fallback to another path. Answers pointing at private addresses are dropped (the rebinding rule), and the
// proxy guard still keeps the connection off this box's own addresses.
//
// The result links go straight to the sites: opening one is made by the browser, over the device's own exit, not by this box.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	spDirect     = "direct"
	spMullvad    = "mullvad"
	spTor        = "tor"
	spTorMullvad = "tormullvad"
)

var searchModes = []string{spDirect, spMullvad, spTor, spTorMullvad}

func validSearchMode(m string) bool {
	for _, x := range searchModes {
		if x == m {
			return true
		}
	}
	return false
}

func searchModeLabel(m string) string {
	switch m {
	case spDirect:
		return "Direct"
	case spMullvad:
		return "Mullvad"
	case spTor:
		return "Tor"
	case spTorMullvad:
		return "Tor over Mullvad"
	}
	return m
}

type searchCfg struct {
	Enabled bool     `json:"enabled"`
	Proxy   string   `json:"proxy"`
	DNS     string   `json:"dns"`
	Engines []string `json:"engines"`
}

type searchMgr struct {
	mu    sync.Mutex
	path  string
	cfg   searchCfg
	slots chan struct{} // at most this many searches at once: each one holds a few sockets and a parsed page per engine, on a box with about 77 MB to share
	state func() ownState

	dmu    sync.Mutex
	dcache map[string]searchDNSHit
}

type searchDNSHit struct {
	ips []net.IPAddr
	exp time.Time
}

const (
	searchMaxQuery   = 200
	searchSlots      = 2
	searchDNSTTL     = 5 * time.Minute
	searchDNSMax     = 64
	searchMaxResults = 30
)

func newSearchMgr(path string) *searchMgr {
	m := &searchMgr{path: path, slots: make(chan struct{}, searchSlots), state: liveOwnState, dcache: map[string]searchDNSHit{},
		cfg: searchCfg{Proxy: spDirect, DNS: spDirect, Engines: []string{"wikipedia", "duckduckgo"}}}
	if b, err := os.ReadFile(path); err == nil {
		var c searchCfg
		if json.Unmarshal(b, &c) == nil {
			if !validSearchMode(c.Proxy) {
				c.Proxy = spDirect
			}
			if !validSearchMode(c.DNS) {
				c.DNS = spDirect
			}
			c.Engines = knownEngines(c.Engines)
			m.cfg = c
		}
	}
	return m
}

func knownEngines(ids []string) []string {
	out := []string{}
	for _, e := range searchEngines {
		for _, id := range ids {
			if id == e.ID {
				out = append(out, id)
				break
			}
		}
	}
	return out
}

func (m *searchMgr) saveLocked() {
	if m.path == "" {
		return
	}
	b, _ := json.Marshal(m.cfg)
	writeFileAtomic(m.path, b, 0o600)
}

func (m *searchMgr) Config() searchCfg {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.cfg
	c.Engines = append([]string(nil), c.Engines...)
	return c
}

type searchSet struct {
	Enabled *bool   `json:"enabled"`
	Proxy   *string `json:"proxy"`
	DNS     *string `json:"dns"`
	Engine  string  `json:"engine"`
	On      *bool   `json:"on"`
}

func (m *searchMgr) Set(s searchSet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Proxy != nil {
		if !validSearchMode(*s.Proxy) {
			return errors.New("unknown proxy")
		}
		m.cfg.Proxy = *s.Proxy
	}
	if s.DNS != nil {
		if !validSearchMode(*s.DNS) {
			return errors.New("unknown DNS")
		}
		m.cfg.DNS = *s.DNS
	}
	if s.Engine != "" {
		if len(knownEngines([]string{s.Engine})) == 0 || s.On == nil {
			return errors.New("unknown engine")
		}
		var keep []string
		for _, id := range m.cfg.Engines {
			if id != s.Engine {
				keep = append(keep, id)
			}
		}
		if *s.On {
			keep = append(keep, s.Engine)
		}
		m.cfg.Engines = knownEngines(keep)
	}
	if s.Enabled != nil {
		m.cfg.Enabled = *s.Enabled
	}
	m.saveLocked()
	m.dmu.Lock()
	m.dcache = map[string]searchDNSHit{} // names found by one DNS are not handed to another
	m.dmu.Unlock()
	return nil
}

// searchPathReady says whether a mode can carry traffic right now, and if not why. A pure function of the own-traffic state, so it is the same check for the proxy and the DNS.
func searchPathReady(mode string, st ownState) error {
	mullvad := func() error {
		switch {
		case !st.MullvadWanted:
			return errors.New("Mullvad is not switched on")
		case !st.TunnelUp:
			return errors.New("the Mullvad tunnel is down")
		}
		return nil
	}
	tor := func() error {
		switch {
		case !st.TorEnabled:
			return errors.New("Tor is not switched on")
		case !st.TorReady:
			return errors.New("Tor is not ready yet")
		}
		return nil
	}
	switch mode {
	case spDirect:
		return nil
	case spMullvad:
		return mullvad()
	case spTor:
		return tor()
	case spTorMullvad:
		if err := tor(); err != nil {
			return err
		}
		if !st.TorOverVPN {
			return errors.New("Tor over Mullvad is not ticked")
		}
		return mullvad()
	}
	return errors.New("unknown path")
}

// Ready lists, for every mode, why it cannot be used now ("" when it can).
func (m *searchMgr) Ready() map[string]string {
	st := m.state()
	out := map[string]string{}
	for _, md := range searchModes {
		if err := searchPathReady(md, st); err != nil {
			out[md] = err.Error()
		} else {
			out[md] = ""
		}
	}
	return out
}

// searchDNSQuery builds an A query for name, or nil if the name cannot be sent.
func searchDNSQuery(name string) []byte {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || len(name) > 253 {
		return nil
	}
	var id [2]byte
	rand.Read(id[:])
	b := []byte{id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

// searchAnswer turns a DNS response into the public addresses it holds.
func searchAnswer(resp []byte) ([]net.IPAddr, error) {
	if len(resp) < 12 {
		return nil, errors.New("short DNS answer")
	}
	if rc := resp[3] & 0x0f; rc != 0 {
		return nil, fmt.Errorf("DNS answered rcode %d", rc)
	}
	var out []net.IPAddr
	for _, ip := range aRecordIPs(resp) {
		if !privateAnswer(ip) {
			out = append(out, net.IPAddr{IP: ip})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no public address for that name")
	}
	return out, nil
}

// resolver returns the lookup function for a DNS mode.
func (m *searchMgr) resolver(mode string) func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return func(ctx context.Context, host string) ([]net.IPAddr, error) {
		key := mode + "/" + strings.ToLower(host)
		m.dmu.Lock()
		if h, ok := m.dcache[key]; ok && time.Now().Before(h.exp) {
			m.dmu.Unlock()
			return h.ips, nil
		}
		m.dmu.Unlock()
		if err := searchPathReady(mode, m.state()); err != nil {
			return nil, fmt.Errorf("DNS %s: %w", searchModeLabel(mode), err)
		}
		q := searchDNSQuery(host)
		if q == nil {
			return nil, errors.New("bad host name")
		}
		var resp []byte
		var err error
		switch mode {
		case spDirect:
			if dnsProxy == nil || dnsProxy.Up == nil {
				return nil, errors.New("DNS Direct: the encrypted DNS is not running")
			}
			resp, _, err = dnsProxy.Up.Resolve(q)
		case spMullvad:
			if vpn == nil {
				return nil, errors.New("DNS Mullvad: Mullvad is not set up")
			}
			resp, err = vpn.ResolveDNS(q)
		default: // tor, tormullvad
			resp, err = torResolve(q)
		}
		if err != nil {
			return nil, fmt.Errorf("DNS %s: %w", searchModeLabel(mode), err)
		}
		ips, err := searchAnswer(resp)
		if err != nil {
			return nil, fmt.Errorf("DNS %s: %w", searchModeLabel(mode), err)
		}
		m.dmu.Lock()
		if len(m.dcache) >= searchDNSMax {
			m.dcache = map[string]searchDNSHit{}
		}
		m.dcache[key] = searchDNSHit{ips: ips, exp: time.Now().Add(searchDNSTTL)}
		m.dmu.Unlock()
		return ips, nil
	}
}

func socksDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	return socksConnect(onionSocksAddr, host, port, 25*time.Second)
}

// dialer returns the connect function for a proxy mode, checked against the path's state at every connection.
func (m *searchMgr) dialer(proxy, dns string) dialFunc {
	look := m.resolver(dns)
	var d dialFunc
	switch proxy {
	case spMullvad:
		d = dialTunnelOnly
	case spTor, spTorMullvad:
		d = socksDial
	default:
		d = dialUpstream
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := searchPathReady(proxy, m.state()); err != nil {
			return nil, fmt.Errorf("proxy %s: %w", searchModeLabel(proxy), err)
		}
		return guardedDial(ctx, "tcp", addr, true, look, d)
	}
}

// client makes an HTTP client for one search. Nothing is pooled across searches (DisableKeepAlives and a transport per search), so a connection made under one path never carries another.
func (m *searchMgr) client(c searchCfg) *http.Client {
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            m.dialer(c.Proxy, c.DNS),
		TLSClientConfig:        &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    20 * time.Second,
		ResponseHeaderTimeout:  25 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" {
			return errors.New("redirect refused")
		}
		return nil
	}}
}

type searchResult struct {
	Title   string
	URL     string
	Snippet string
	Engines []string
	score   float64
}

type engineStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	N    int    `json:"n"`
	Err  string `json:"err,omitempty"`
	MS   int64  `json:"ms"`
}

type searchOutcome struct {
	Query   string
	Results []searchResult
	Engines []engineStatus
	Err     string
	Busy    bool
	Elapsed time.Duration
	Cfg     searchCfg
}

var errSearchBusy = errors.New("busy")

func cleanQuery(q string) string {
	q = strings.Join(strings.Fields(q), " ")
	for _, r := range q {
		if r < 0x20 {
			return ""
		}
	}
	if r := []rune(q); len(r) > searchMaxQuery {
		q = string(r[:searchMaxQuery])
	}
	return q
}

// Search runs one query. A path that is down is an error in the outcome, with no attempt made.
func (m *searchMgr) Search(ctx context.Context, q string) searchOutcome {
	cfg := m.Config()
	out := searchOutcome{Query: q, Cfg: cfg}
	switch {
	case !cfg.Enabled:
		out.Err = "Search is off"
		return out
	case q == "":
		return out
	case len(cfg.Engines) == 0:
		out.Err = "No engine is switched on"
		return out
	}
	st := m.state()
	if err := searchPathReady(cfg.Proxy, st); err != nil {
		out.Err = "Proxy " + searchModeLabel(cfg.Proxy) + ": " + err.Error()
		return out
	}
	if err := searchPathReady(cfg.DNS, st); err != nil {
		out.Err = "DNS " + searchModeLabel(cfg.DNS) + ": " + err.Error()
		return out
	}
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		out.Busy, out.Err = true, "Another search is running, try again in a moment"
		return out
	}
	t0 := time.Now()
	limit := 15 * time.Second
	if cfg.Proxy == spTor || cfg.Proxy == spTorMullvad || cfg.DNS == spTor || cfg.DNS == spTorMullvad {
		limit = 40 * time.Second // circuits take time
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cl := m.client(cfg)
	defer cl.CloseIdleConnections()

	type got struct {
		i   int
		res []searchResult
		st  engineStatus
	}
	var on []searchEngine
	for _, e := range searchEngines {
		for _, id := range cfg.Engines {
			if id == e.ID {
				on = append(on, e)
			}
		}
	}
	ch := make(chan got, len(on))
	for i, e := range on {
		go func(i int, e searchEngine) {
			s := engineStatus{ID: e.ID, Name: e.Name}
			t := time.Now()
			res, err := e.fetch(ctx, cl, q)
			s.MS = time.Since(t).Milliseconds()
			if err != nil {
				s.Err = searchErrText(err, q)
			}
			s.N = len(res)
			ch <- got{i, res, s}
		}(i, e)
	}
	per := make([][]searchResult, len(on))
	out.Engines = make([]engineStatus, len(on))
	for range on {
		g := <-ch
		per[g.i], out.Engines[g.i] = g.res, g.st
	}
	out.Results = mergeResults(per, on)
	out.Elapsed = time.Since(t0)
	return out
}

// searchErrText is an error for the page: the query is cut out of it, and it is kept short.
func searchErrText(err error, q string) string {
	s := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		s = ue.Err.Error()
	}
	if q != "" {
		s = strings.ReplaceAll(s, url.QueryEscape(q), "…")
		s = strings.ReplaceAll(s, q, "…")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		s = "timed out"
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

var trackingParams = map[string]bool{"fbclid": true, "gclid": true, "dclid": true, "msclkid": true, "mc_eid": true, "mc_cid": true, "igshid": true, "yclid": true, "_ga": true, "ref_src": true}

// normalizeResultURL cleans a result link of tracking parameters and fragments, and gives the key that two engines' links to the same page share. Only http and https links pass.
func normalizeResultURL(raw string) (clean, key string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", "", false
	}
	u.Fragment = ""
	if u.RawQuery != "" {
		qv := u.Query()
		for k := range qv {
			if strings.HasPrefix(strings.ToLower(k), "utm_") || trackingParams[strings.ToLower(k)] {
				qv.Del(k)
			}
		}
		u.RawQuery = qv.Encode()
	}
	clean = u.String()
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	p := strings.TrimSuffix(u.EscapedPath(), "/")
	key = host + p
	if u.RawQuery != "" {
		key += "?" + u.RawQuery
	}
	return clean, key, true
}

// mergeResults merges each engine's ordered list by reciprocal rank (a result several engines agree on rises), one entry per page.
func mergeResults(per [][]searchResult, engines []searchEngine) []searchResult {
	byKey := map[string]*searchResult{}
	var order []string
	for i, list := range per {
		for rank, r := range list {
			clean, key, ok := normalizeResultURL(r.URL)
			if !ok || strings.TrimSpace(r.Title) == "" {
				continue
			}
			add := 1.0 / float64(10+rank)
			if e, seen := byKey[key]; seen {
				e.score += add
				if len(r.Snippet) > len(e.Snippet) {
					e.Snippet = r.Snippet
				}
				e.Engines = append(e.Engines, engines[i].Name)
				continue
			}
			byKey[key] = &searchResult{Title: strings.TrimSpace(r.Title), URL: clean, Snippet: r.Snippet, Engines: []string{engines[i].Name}, score: add}
			order = append(order, key)
		}
	}
	out := make([]searchResult, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].score > out[b].score })
	if len(out) > searchMaxResults {
		out = out[:searchMaxResults]
	}
	return out
}

// searchGet fetches a page for an engine, at most 1 MB of it.
func searchGet(ctx context.Context, c *http.Client, u, ua, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Language", "en")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

var searchMgrG *searchMgr
