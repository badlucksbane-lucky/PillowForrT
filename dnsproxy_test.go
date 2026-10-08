package main

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// answerFor builds a response to query b: an A record 93.184.216.34 with the given TTL (or NXDOMAIN when nx).
func answerFor(b []byte, ttl uint32, nx bool) []byte {
	q, err := parseQuery(b)
	if err != nil {
		return nil
	}
	if nx {
		r := buildRcode(b, q, 3)
		return r
	}
	r := append(respHeader(q, 0, 1), b[12:q.QEnd]...)
	rec := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 93, 184, 216, 34}
	binary.BigEndian.PutUint32(rec[6:10], ttl)
	return append(r, rec...)
}

type fakeDoH struct {
	*httptest.Server
	hits  atomic.Int64
	fail  atomic.Bool
	ttl   uint32
	nx    atomic.Bool
	delay atomic.Int64
	last  atomic.Value // the last query body the upstream received
}

func newFakeDoH(t *testing.T) (*fakeDoH, *x509.CertPool) {
	f := &fakeDoH{ttl: 120}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if d := f.delay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		if f.fail.Load() {
			http.Error(w, "down", 500)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/dns-message" || len(body) < 12 || binary.BigEndian.Uint16(body[0:2]) != 0 {
			http.Error(w, "bad request (id must be 0)", 400)
			return
		}
		f.last.Store(append([]byte(nil), body...))
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answerFor(body, f.ttl, f.nx.Load()))
	}))
	f.EnableHTTP2 = true
	f.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(f.Server.Certificate())
	t.Cleanup(f.Close)
	return f, pool
}

func testProxyURLs(t *testing.T, urls []string, pool *x509.CertPool) *DNSProxy {
	f := NewFilter(t.TempDir())
	testSetList(f, defaultLists[0], []string{"blocked.example.com"}, "", "")
	f.SetMode("oisd")
	up := newUpstream(upstreamConfig{
		DoHURLs: urls, Roots: pool,
		DoHTimeout: 300 * time.Millisecond, ProbeEvery: 100 * time.Millisecond,
		Dial: (&net.Dialer{Timeout: time.Second}).DialContext,
	})
	return &DNSProxy{Filter: f, Up: up, Cache: newDNSCache(100), Stats: NewDNSStats(), BlockTTL: 30}
}

func testProxy(t *testing.T, doh *fakeDoH, pool *x509.CertPool) *DNSProxy {
	return testProxyURLs(t, []string{doh.URL}, pool)
}

func ask(p *DNSProxy, name string, id uint16) []byte {
	return p.Handle(mkQuery(name, qtA, id, true))
}

func addrOf(r []byte) string {
	recs, an, err := records(r)
	if err != nil || an == 0 || len(recs) == 0 {
		return "-"
	}
	rd := r[recs[0].ttlOff+6:]
	if len(rd) < 4 {
		return "-"
	}
	return net.IP(rd[:4]).String()
}

func TestDoHPathCacheAndIDs(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)

	r := ask(p, "example.org", 0xAAAA)
	if addrOf(r) != "93.184.216.34" || binary.BigEndian.Uint16(r[0:2]) != 0xAAAA {
		t.Fatalf("first answer wrong / id not restored: id %x addr %s", r[0:2], addrOf(r))
	}
	if doh.hits.Load() != 1 {
		t.Fatalf("hits doh=%d (the query must go out encrypted, once)", doh.hits.Load())
	}
	r = ask(p, "example.org", 0xBBBB)
	if doh.hits.Load() != 1 || binary.BigEndian.Uint16(r[0:2]) != 0xBBBB || addrOf(r) != "93.184.216.34" {
		t.Fatalf("second query should be cached with its own id: hits=%d id=%x", doh.hits.Load(), r[0:2])
	}
	if p.Stats.Cached.Load() != 1 || p.Stats.DoH.Load() != 1 {
		t.Fatalf("stats: cached %d doh %d", p.Stats.Cached.Load(), p.Stats.DoH.Load())
	}
	if st := p.Up.State(); st.Mode != "doh" || st.Warning != "" {
		t.Fatalf("state should be healthy: %+v", st)
	}
}

func TestBlockedNeverLeaves(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)
	r := ask(p, "sub.blocked.example.com", 1)
	if addrOf(r) != "0.0.0.0" || doh.hits.Load() != 0 {
		t.Fatalf("blocked name: addr %s doh=%d", addrOf(r), doh.hits.Load())
	}
	p.Filter.SetMode("off") // the switch is instant: the very next query is resolved
	if addrOf(ask(p, "blocked.example.com", 2)) != "93.184.216.34" {
		t.Fatal("mode off did not let the name through at once")
	}
	if p.Stats.Blocked.Load() != 1 {
		t.Fatalf("blocked counter %d", p.Stats.Blocked.Load())
	}
	sn := p.Stats.Snapshot(5, 10)
	if len(sn.TopBlocked) != 1 || sn.TopBlocked[0].Name != "sub.blocked.example.com" || len(sn.Recent) != 2 || sn.Recent[1].Result != "blocked" {
		t.Fatalf("snapshot: %+v", sn)
	}
}

// Encrypted DNS failing is a refused lookup and a visible warning, never an answer from anywhere else; it clears by itself when DoH comes back.
func TestFailingWarningAndRecovery(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)
	doh.fail.Store(true)

	for i := uint16(1); i < upstreamDownAfter; i++ {
		if rcodeOf(ask(p, fmt.Sprintf("n%d.example.net", i), i)) != 2 {
			t.Fatal("with DoH down the answer is SERVFAIL, from nowhere else")
		}
		if p.Up.Failing() {
			t.Fatalf("one or two failures are not an outage yet (after %d)", i)
		}
	}
	ask(p, "last.example.net", 9)
	st := p.Up.State()
	if st.Mode != "failing" || st.Warning == "" || !p.Up.Failing() {
		t.Fatalf("expected a visible warning after %d failures in a row: %+v", upstreamDownAfter, st)
	}
	if p.Stats.Errors.Load() != uint64(upstreamDownAfter) || p.Stats.DoH.Load() != 0 {
		t.Fatalf("errors %d doh %d", p.Stats.Errors.Load(), p.Stats.DoH.Load())
	}
	hits := doh.hits.Load()
	time.Sleep(450 * time.Millisecond) // the probe keeps trying (and failing) in the background
	if doh.hits.Load() <= hits {
		t.Fatal("the recovery probe is not running")
	}
	if !p.Up.Failing() {
		t.Fatal("recovered while DoH was still down")
	}
	doh.fail.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for p.Up.Failing() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := p.Up.State(); st.Mode != "doh" || st.Warning != "" {
		t.Fatalf("did not recover and clear the warning: %+v", st)
	}
	if addrOf(ask(p, "back.example.net", 10)) != "93.184.216.34" {
		t.Fatal("answers again after recovery")
	}
}

func TestAllUpstreamsDownIsServfailNotAHang(t *testing.T) {
	doh, pool := newFakeDoH(t)
	doh.fail.Store(true)
	p := testProxy(t, doh, pool) // nothing listens there
	t0 := time.Now()
	r := ask(p, "dead.example.net", 7)
	if rcodeOf(r) != 2 || binary.BigEndian.Uint16(r[0:2]) != 7 {
		t.Fatalf("want SERVFAIL with the client's id, got rcode %d", rcodeOf(r))
	}
	if time.Since(t0) > 3*time.Second {
		t.Fatalf("took %v", time.Since(t0))
	}
	if p.Stats.Errors.Load() != 1 {
		t.Fatalf("errors %d", p.Stats.Errors.Load())
	}
}

func TestCacheTTLAndNegative(t *testing.T) {
	c := newDNSCache(100)
	now := time.Now()
	qb := mkQuery("ttl.example.com", qtA, 1, true)
	q, _ := parseQuery(qb)
	c.put(cacheKey(q), answerFor(qb, 100, false), now)
	r, ok := c.get(cacheKey(q), now.Add(40*time.Second))
	if !ok {
		t.Fatal("expected a hit")
	}
	recs, _, _ := records(r)
	if ttl := binary.BigEndian.Uint32(r[recs[0].ttlOff:]); ttl > 61 || ttl < 59 {
		t.Fatalf("TTL after 40s should be ~60, got %d", ttl)
	}
	if _, ok := c.get(cacheKey(q), now.Add(101*time.Second)); ok {
		t.Fatal("an expired entry was served")
	}
	c.put(cacheKey(q), buildRcode(qb, q, 2), now) // SERVFAIL must never be cached
	if _, ok := c.get(cacheKey(q), now); ok {
		t.Fatal("SERVFAIL was cached")
	}
	c.put(cacheKey(q), answerFor(qb, 0, true), now) // NXDOMAIN is cached (30 s default when no SOA)
	if r, ok := c.get(cacheKey(q), now.Add(5*time.Second)); !ok || rcodeOf(r) != 3 {
		t.Fatal("NXDOMAIN not cached")
	}
	small := newDNSCache(10)
	for i := 0; i < 50; i++ {
		qq := mkQuery("h"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example.com", qtA, 1, true)
		dq, _ := parseQuery(qq)
		small.put(cacheKey(dq), answerFor(qq, 100, false), now)
	}
	small.mu.Lock()
	n := len(small.m)
	small.mu.Unlock()
	if n > 10 {
		t.Fatalf("cache grew past its cap: %d", n)
	}
}

func TestGarbageGetsFormerr(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)
	for _, g := range [][]byte{{}, {1}, {1, 2, 3, 4, 5}, make([]byte, 11), append(make([]byte, 12), 0xFF)} {
		r := p.Handle(g)
		if len(r) < 12 || rcodeOf(r) != 1 {
			t.Fatalf("garbage % x -> %v", g, r)
		}
	}
	if doh.hits.Load() != 0 {
		t.Fatal("garbage reached the upstream")
	}
}

func writeFile(path, data string) error { return os.WriteFile(path, []byte(data), 0o644) }

// A second provider covers the first one failing: the query is answered encrypted, with no failure run.
func TestSecondProviderCoversTheFirst(t *testing.T) {
	dead, pool := newFakeDoH(t)
	good, pool2 := newFakeDoH(t)
	pool.AddCert(good.Server.Certificate())
	_ = pool2
	dead.fail.Store(true)
	p := testProxyURLs(t, []string{dead.URL, good.URL}, pool)
	if addrOf(ask(p, "two.example.net", 1)) != "93.184.216.34" {
		t.Fatal("the second encrypted endpoint should have answered")
	}
	if p.Up.Failing() || p.Up.State().Mode != "doh" || p.Stats.Errors.Load() != 0 {
		t.Fatalf("a covered failure is not an outage: %+v", p.Up.State())
	}
}
