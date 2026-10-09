package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

func twoResolvers(t *testing.T, hedge time.Duration) (*DNSProxy, *fakeDoH, *fakeDoH) {
	a, pool := newFakeDoH(t)
	b, poolB := newFakeDoH(t)
	pool.AddCert(b.Server.Certificate())
	_ = poolB
	p := testProxyURLs(t, []string{a.URL, b.URL}, pool)
	p.Up = newUpstream(upstreamConfig{DoHURLs: []string{a.URL, b.URL}, Roots: pool, DoHTimeout: 3 * time.Second, HedgeAfter: hedge, ProbeEvery: 100 * time.Millisecond,
		Dial: (&net.Dialer{Timeout: time.Second}).DialContext})
	return p, a, b
}

func TestSlowFirstResolverIsHedged(t *testing.T) {
	p, a, b := twoResolvers(t, 100*time.Millisecond)
	a.delay.Store(int64(1200 * time.Millisecond))
	t0 := time.Now()
	r := ask(p, "hedge.example.org", 0x1111)
	if d := time.Since(t0); d > 700*time.Millisecond || addrOf(r) != "93.184.216.34" {
		t.Errorf("answer %s after %v: the second resolver should have been asked at 100 ms", addrOf(r), d)
	}
	if b.hits.Load() != 1 || a.hits.Load() != 1 {
		t.Errorf("hits a=%d b=%d (the slow one is still asked first)", a.hits.Load(), b.hits.Load())
	}
}

func TestFailedFirstResolverMovesOnAtOnce(t *testing.T) {
	p, a, b := twoResolvers(t, 10*time.Second) // a hedge delay so long that only the failure can start the second
	a.fail.Store(true)
	t0 := time.Now()
	r := ask(p, "failover.example.org", 0x2222)
	if d := time.Since(t0); d > time.Second || addrOf(r) != "93.184.216.34" || b.hits.Load() != 1 {
		t.Errorf("answer %s after %v, b hits %d", addrOf(r), d, b.hits.Load())
	}
}

func TestOneUpstreamRequestForIdenticalLookupsInFlight(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)
	doh.delay.Store(int64(150 * time.Millisecond))
	var wg sync.WaitGroup
	got := make([][]byte, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) { defer wg.Done(); got[i] = ask(p, "burst.example.org", uint16(0x3000+i)) }(i)
	}
	wg.Wait()
	for i, r := range got {
		if addrOf(r) != "93.184.216.34" || uint16(r[0])<<8|uint16(r[1]) != uint16(0x3000+i) {
			t.Errorf("caller %d: %s id %x", i, addrOf(r), r[0:2])
		}
	}
	if doh.hits.Load() != 1 {
		t.Errorf("%d upstream requests for 8 identical lookups", doh.hits.Load())
	}
}

func TestFailedLookupIsRemembered(t *testing.T) {
	doh, pool := newFakeDoH(t)
	p := testProxy(t, doh, pool)
	doh.fail.Store(true)
	if rcodeOf(ask(p, "down.example.org", 1)) != 2 {
		t.Fatal("the first lookup must fail")
	}
	h := doh.hits.Load()
	if rcodeOf(ask(p, "down.example.org", 2)) != 2 || doh.hits.Load() != h {
		t.Errorf("a retry within moments must be refused without asking upstream again (hits %d -> %d)", h, doh.hits.Load())
	}
	doh.fail.Store(false)
	if addrOf(ask(p, "other.example.org", 3)) != "93.184.216.34" {
		t.Error("a different name must still be looked up")
	}
	p.fails.mu.Lock()
	for k, e := range p.fails.m { // time passes
		e.until = time.Now().Add(-time.Second)
		p.fails.m[k] = e
	}
	p.fails.mu.Unlock()
	if addrOf(ask(p, "down.example.org", 4)) != "93.184.216.34" {
		t.Error("after the memory runs out the name is looked up again")
	}
}
