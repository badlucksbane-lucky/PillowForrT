package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBTLimiterPacesBytes(t *testing.T) {
	rate, burst := 1e6, 10e3
	l := &btLimiter{rate: &rate, burst: &burst}
	t0 := time.Now()
	for i := 0; i < 30; i++ {
		l.wait(10_000) // 300 KB at 1 MB/s, less the first 10 KB burst
	}
	if d := time.Since(t0); d < 250*time.Millisecond || d > 900*time.Millisecond {
		t.Errorf("300 KB took %v at 1 MB/s", d)
	}
}

func btReadyMgr() *btMgr {
	return &btMgr{enabled: true, state: func() ownState { return ownState{MullvadWanted: true, TunnelUp: true} }}
}

const btTestHash = "08ada5a7a6183aae1e09d831df6748d566095a10"

func btPeersReq(m *btMgr) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handleBTAPIWith(m, rec, httptest.NewRequest("GET", "/api/bt/peers?h="+btTestHash, nil), "bt/peers")
	return rec
}

func TestBTPeersAnsweredFromCache(t *testing.T) {
	btTest(t)
	var h [20]byte
	for i := range h {
		h[i] = hexByte(btTestHash[2*i])<<4 | hexByte(btTestHash[2*i+1])
	}
	btCachePut(h, []string{"8.8.8.8:6881"})
	defer btCachePut(h, nil)
	btLookups <- struct{}{} // both lookup slots busy: a cached answer must not need one
	btLookups <- struct{}{}
	defer func() { <-btLookups; <-btLookups }()
	rec := btPeersReq(btReadyMgr())
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"src":"cache"`) || !strings.Contains(rec.Body.String(), "8.8.8.8:6881") || !strings.Contains(rec.Body.String(), `"done":true`) {
		t.Errorf("cache answer: %d %q", rec.Code, rec.Body.String())
	}
	if !btAllowed.ok("8.8.8.8:6881") {
		t.Error("cached peers must be on the dial list again")
	}
}

func TestBTPeersLookupLimitAndLoadShed(t *testing.T) {
	btTest(t)
	btCachePut([20]byte{1}, nil) // make sure the cache has nothing for the test hash
	btLookups <- struct{}{}
	btLookups <- struct{}{}
	rec := btPeersReq(btReadyMgr())
	<-btLookups
	<-btLookups
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "other lookups") {
		t.Errorf("a third lookup: %d %q", rec.Code, rec.Body.String())
	}
	old := btLoadNow
	btLoadNow = func() float64 { return 99 }
	defer func() { btLoadNow = old }()
	if rec := btPeersReq(btReadyMgr()); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "busy") {
		t.Errorf("lookup under load: %d %q", rec.Code, rec.Body.String())
	}
	m := btReadyMgr()
	srv := httptest.NewServer(http.HandlerFunc(m.conn))
	defer srv.Close()
	btAllowed.add([]string{"8.8.4.4:6881"})
	if _, st := wsDial(t, srv, "/api/bt/conn?peer=8.8.4.4:6881", "https://"+srv.Listener.Addr().String()); !strings.Contains(st, "503") {
		t.Errorf("a new bridge connection under load: %q", st)
	}
}
