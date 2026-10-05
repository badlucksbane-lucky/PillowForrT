package main

import (
	"crypto/x509"
	"encoding/binary"
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

// fakePlain is a UDP resolver that answers every query.
func fakePlain(t *testing.T) (addr string, hits *atomic.Int64) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = &atomic.Int64{}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			hits.Add(1)
			if r := answerFor(buf[:n], 60, false); r != nil {
				setID(r, binary.BigEndian.Uint16(buf[0:2]))
				pc.WriteTo(r, a)
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String(), hits
}

func testProxy(t *testing.T, doh *fakeDoH, pool *x509.CertPool, plainAddr string) *DNSProxy {
	f := NewFilter(t.TempDir())
	testSetList(f, defaultLists[0], []string{"blocked.example.com"}, "", "")
	f.SetMode("oisd")
	up := newUpstream(upstreamConfig{
		DoHURLs: []string{doh.URL}, Roots: pool, Plain: func() []string { return []string{plainAddr} },
		DoHTimeout: 400 * time.Millisecond, PlainTimeout: 400 * time.Millisecond, ProbeEvery: 150 * time.Millisecond,
		Dial: (&net.Dialer{Timeout: time.Second}).DialContext,
	})
	return &DNSProxy{Filter: f, Up: up, Cache: newDNSCache(100), Stats: NewDNSStats(), BlockTTL: 30}
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
	plain, plainHits := fakePlain(t)
	p := testProxy(t, doh, pool, plain)

	r := ask(p, "example.org", 0xAAAA)
	if addrOf(r) != "93.184.216.34" || binary.BigEndian.Uint16(r[0:2]) != 0xAAAA {
		t.Fatalf("first answer wrong / id not restored: id %x addr %s", r[0:2], addrOf(r))
	}
	if doh.hits.Load() != 1 || plainHits.Load() != 0 {
		t.Fatalf("hits doh=%d plain=%d (the query must go out encrypted only)", doh.hits.Load(), plainHits.Load())
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
	plain, plainHits := fakePlain(t)
	p := testProxy(t, doh, pool, plain)
	r := ask(p, "sub.blocked.example.com", 1)
	if addrOf(r) != "0.0.0.0" || doh.hits.Load() != 0 || plainHits.Load() != 0 {
		t.Fatalf("blocked name: addr %s doh=%d plain=%d", addrOf(r), doh.hits.Load(), plainHits.Load())
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

func TestFallbackWarningAndRecovery(t *testing.T) {
	doh, pool := newFakeDoH(t)
	plain, plainHits := fakePlain(t)
	p := testProxy(t, doh, pool, plain)
	doh.fail.Store(true)

	r := ask(p, "one.example.net", 1)
	if addrOf(r) != "93.184.216.34" {
		t.Fatal("the query must still be answered through the plain fallback")
	}
	st := p.Up.State()
	if st.Mode != "plain-fallback" || st.Warning == "" || plainHits.Load() != 1 || p.Stats.Plain.Load() != 1 {
		t.Fatalf("expected a visible fallback warning: %+v plain=%d", st, plainHits.Load())
	}
	hitsAfterFirst := doh.hits.Load()
	ask(p, "two.example.net", 2) // while in fallback, queries go straight to plain: no DoH attempts of their own
	if plainHits.Load() != 2 {
		t.Fatalf("second query did not use plain: %d", plainHits.Load())
	}
	time.Sleep(450 * time.Millisecond) // the probe keeps trying (and failing) in the background
	if doh.hits.Load() <= hitsAfterFirst {
		t.Fatal("the recovery probe is not running")
	}
	if p.Up.State().Mode != "plain-fallback" {
		t.Fatal("recovered while DoH was still down")
	}
	doh.fail.Store(false)
	deadline := time.Now().Add(2 * time.Second)
	for p.Up.State().Mode != "doh" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := p.Up.State(); st.Mode != "doh" || st.Warning != "" {
		t.Fatalf("did not recover and clear the warning: %+v", st)
	}
	before := plainHits.Load()
	ask(p, "three.example.net", 3)
	if plainHits.Load() != before {
		t.Fatal("after recovery the query still went out as plain DNS")
	}
}

func TestAllUpstreamsDownIsServfailNotAHang(t *testing.T) {
	doh, pool := newFakeDoH(t)
	doh.fail.Store(true)
	p := testProxy(t, doh, pool, "127.0.0.1:1") // nothing listens there
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
	plain, _ := fakePlain(t)
	p := testProxy(t, doh, pool, plain)
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

func TestCarrierResolvers(t *testing.T) {
	path := t.TempDir() + "/resolv"
	data := "# c\nnameserver 198.51.100.1\nnameserver 2001:db8::1\nnameserver 198.51.100.2\nsearch x\n"
	if err := writeFile(path, data); err != nil {
		t.Fatal(err)
	}
	got := carrierResolvers(path)()
	if len(got) != 2 || got[0] != "198.51.100.1:53" || got[1] != "198.51.100.2:53" {
		t.Fatalf("%v (IPv6 must be skipped: the cellular link has no IPv6)", got)
	}
	if carrierResolvers(path+"-missing")() != nil {
		t.Fatal("a missing file should give nil")
	}
}

func writeFile(path, data string) error { return os.WriteFile(path, []byte(data), 0o644) }

// testProxyGrace is testProxy with the plain-fallback policy and a list of encrypted endpoints.
func testProxyGrace(t *testing.T, urls []string, pool *x509.CertPool, plainAddr string, plainAfter time.Duration) *DNSProxy {
	f := NewFilter(t.TempDir())
	testSetList(f, defaultLists[0], []string{"blocked.example.com"}, "", "")
	f.SetMode("oisd")
	up := newUpstream(upstreamConfig{
		DoHURLs: urls, Roots: pool, Plain: func() []string { return []string{plainAddr} },
		DoHTimeout: 300 * time.Millisecond, PlainTimeout: 300 * time.Millisecond, ProbeEvery: 100 * time.Millisecond, PlainAfter: plainAfter,
		Dial: (&net.Dialer{Timeout: time.Second}).DialContext,
	})
	return &DNSProxy{Filter: f, Up: up, Cache: newDNSCache(100), Stats: NewDNSStats(), BlockTTL: 30}
}

// A brief encrypted-DNS failure must not put anything on the wire in the clear; only a sustained one may (PlainAfter).
func TestGraceHoldsPlainBackThenAllowsItWhenSustained(t *testing.T) {
	doh, pool := newFakeDoH(t)
	plain, plainHits := fakePlain(t)
	p := testProxyGrace(t, []string{doh.URL}, pool, plain, 700*time.Millisecond)
	doh.fail.Store(true)

	r := ask(p, "a.example.net", 1)
	if rcodeOf(r) != 2 {
		t.Fatalf("inside the grace window the answer must be SERVFAIL, got rcode %d", rcodeOf(r))
	}
	if plainHits.Load() != 0 || p.Up.State().Mode != "doh" {
		t.Fatalf("plain DNS was used inside the grace window: hits=%d mode=%s", plainHits.Load(), p.Up.State().Mode)
	}
	deadline := time.Now().Add(4 * time.Second) // keep failing back to back: after PlainAfter the fallback is allowed
	var got string
	for i := uint16(2); time.Now().Before(deadline); i++ {
		got = addrOf(ask(p, "b.example.net", i))
		if got != "-" {
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	if got != "93.184.216.34" || plainHits.Load() == 0 || p.Up.State().Mode != "plain-fallback" {
		t.Fatalf("a sustained failure must fall back to plain: addr=%s hits=%d mode=%s", got, plainHits.Load(), p.Up.State().Mode)
	}
}

// One success ends a run of failures, so the next failure starts a fresh grace window instead of inheriting the old one.
func TestGraceRestartsAfterASuccess(t *testing.T) {
	doh, pool := newFakeDoH(t)
	plain, plainHits := fakePlain(t)
	p := testProxyGrace(t, []string{doh.URL}, pool, plain, 600*time.Millisecond)
	doh.fail.Store(true)
	ask(p, "x1.example.net", 1)
	time.Sleep(450 * time.Millisecond) // most of the grace window used up
	doh.fail.Store(false)
	if addrOf(ask(p, "x2.example.net", 2)) != "93.184.216.34" {
		t.Fatal("encrypted DNS recovered but the query did not succeed")
	}
	doh.fail.Store(true)
	time.Sleep(300 * time.Millisecond) // old failure is now past PlainAfter; a new run must not inherit it
	r := ask(p, "x3.example.net", 3)
	if rcodeOf(r) != 2 || plainHits.Load() != 0 {
		t.Fatalf("the grace window did not restart after a success: rcode=%d plainHits=%d", rcodeOf(r), plainHits.Load())
	}
}

// PlainAfter < 0 is the strict policy: never plain, however long the outage.
func TestNeverPlainPolicy(t *testing.T) {
	doh, pool := newFakeDoH(t)
	plain, plainHits := fakePlain(t)
	p := testProxyGrace(t, []string{doh.URL}, pool, plain, -1)
	doh.fail.Store(true)
	for i := uint16(1); i <= 6; i++ {
		if rcodeOf(ask(p, "strict.example.net", i)) != 2 {
			t.Fatal("the strict policy must answer SERVFAIL")
		}
		time.Sleep(150 * time.Millisecond)
	}
	if plainHits.Load() != 0 || p.Up.State().Mode != "doh" {
		t.Fatalf("plain DNS was used under the strict policy: hits=%d mode=%s", plainHits.Load(), p.Up.State().Mode)
	}
}

// A second provider covers the first one failing: the query is answered encrypted, with no fallback and no failure run.
func TestSecondProviderCoversTheFirst(t *testing.T) {
	dead, pool := newFakeDoH(t)
	good, pool2 := newFakeDoH(t)
	pool.AddCert(good.Server.Certificate())
	_ = pool2
	dead.fail.Store(true)
	plain, plainHits := fakePlain(t)
	p := testProxyGrace(t, []string{dead.URL, good.URL}, pool, plain, 60*time.Second)
	if addrOf(ask(p, "two.example.net", 1)) != "93.184.216.34" {
		t.Fatal("the second encrypted endpoint should have answered")
	}
	if plainHits.Load() != 0 || p.Up.State().Mode != "doh" || p.Stats.Plain.Load() != 0 {
		t.Fatalf("it went to plain although a second encrypted endpoint was up: hits=%d mode=%s", plainHits.Load(), p.Up.State().Mode)
	}
}
