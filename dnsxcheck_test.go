package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func nxResponse(name string) []byte {
	m := buildAResponse(name, net.IPv4(1, 2, 3, 4))
	m[3] = 0x83 // rcode 3
	m[7] = 0    // ancount 0
	return m[:len(m)-16]
}

type dxHarness struct {
	w      *dnsXWatch
	events []evt
	now    time.Time
	asked  []string
	answer map[string][]byte
	fail   bool
}

func newDXHarness() *dxHarness {
	h := &dxHarness{now: time.Unix(1_700_000_000, 0), answer: map[string][]byte{}}
	h.w = newDNSXWatch(nil)
	h.w.now = func() time.Time { return h.now }
	h.w.emit = func(e evt) { h.events = append(h.events, e) }
	h.w.macOf = func(string) string { return "" }
	h.w.nameOf = func(string) string { return "" }
	h.w.urls = func() []string {
		return []string{"https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"}
	}
	h.w.ask = func(url string, q []byte) ([]byte, error) {
		h.asked = append(h.asked, url)
		if h.fail {
			return nil, errors.New("down")
		}
		return h.answer[url], nil
	}
	return h
}

// observe sends one DoH answer through, with the sample counter forced so this one is taken, and waits for the check.
func (h *dxHarness) observe(name string, first []byte) {
	h.w.mu.Lock()
	h.w.seen = 0
	h.w.inFlight = false
	h.w.lastRun = time.Time{}
	h.w.mu.Unlock()
	h.w.Observe("192.168.1.20", name, "https://dns.quad9.net/dns-query", mkQuery(name, 1, 7, true), first, h.now)
	h.w.wg.Wait()
}

func TestDNSXCheckAgreeAndCDN(t *testing.T) {
	h := newDXHarness()
	h.answer["https://cloudflare-dns.com/dns-query"] = buildAResponse("example.com", net.IPv4(93, 184, 216, 34))
	h.observe("example.com", buildAResponse("example.com", net.IPv4(93, 184, 216, 34)))
	if len(h.asked) != 1 || h.asked[0] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("the OTHER resolver is asked: %v", h.asked)
	}
	if h.w.Agree != 1 || len(h.events) != 0 {
		t.Fatalf("same answer agrees: agree=%d events=%+v", h.w.Agree, h.events)
	}
	h.now = h.now.Add(time.Minute)
	h.answer["https://cloudflare-dns.com/dns-query"] = buildAResponse("cdn.example", net.IPv4(151, 101, 1, 1))
	h.observe("cdn.example", buildAResponse("cdn.example", net.IPv4(104, 16, 1, 1)))
	if h.w.Differ != 1 || len(h.events) != 0 {
		t.Fatalf("two public addresses, no overlap, is the CDN case: differ=%d events=%+v", h.w.Differ, h.events)
	}
}

func TestDNSXCheckExistsDisagreement(t *testing.T) {
	h := newDXHarness()
	h.answer["https://cloudflare-dns.com/dns-query"] = nxResponse("ghost.example")
	h.observe("ghost.example", buildAResponse("ghost.example", net.IPv4(203, 0, 113, 9)))
	if len(h.events) != 1 || h.events[0].Kind != "dns_xcheck_exists" || h.events[0].Sev != sevAttention {
		t.Fatalf("one says it exists, the other NXDOMAIN: %+v", h.events)
	}
	v := h.w.View()
	if v.Flagged != 1 || len(v.Findings) != 1 || v.Findings[0].Second != "cloudflare-dns.com" || v.Findings[0].Answer2[0] != "NXDOMAIN" {
		t.Fatalf("finding: %+v", v.Findings)
	}
	// the same name inside the hour is not even re-asked; after the hour it is, and the finding is counted but the event is not repeated within its own hour
	h.now = h.now.Add(10 * time.Minute)
	h.observe("ghost.example", buildAResponse("ghost.example", net.IPv4(203, 0, 113, 9)))
	if len(h.asked) != 1 {
		t.Fatalf("a name checked this hour is not re-asked: %v", h.asked)
	}
	h.now = h.now.Add(55 * time.Minute)
	h.observe("ghost.example", buildAResponse("ghost.example", net.IPv4(203, 0, 113, 9)))
	if len(h.asked) != 2 || h.w.Flagged != 2 || len(h.events) != 2 {
		t.Fatalf("after an hour it is asked and raised again: asked=%d flagged=%d events=%d", len(h.asked), h.w.Flagged, len(h.events))
	}
}

func TestDNSXCheckBogon(t *testing.T) {
	h2 := newDXHarness()
	h2.answer["https://cloudflare-dns.com/dns-query"] = buildAResponse("bank.example", net.IPv4(93, 184, 216, 34))
	h2.observe("bank.example", buildAResponse("bank.example", net.IPv4(192, 168, 1, 77)))
	if len(h2.events) != 1 || h2.events[0].Kind != "dns_xcheck_bogon" {
		t.Fatalf("private vs public: %+v", h2.events)
	}
	// both unroutable (a split-horizon name both resolvers know as private) agree in shape
	h3 := newDXHarness()
	h3.answer["https://cloudflare-dns.com/dns-query"] = buildAResponse("x.example", net.IPv4(10, 0, 0, 2))
	h3.observe("x.example", buildAResponse("x.example", net.IPv4(10, 0, 0, 1)))
	if len(h3.events) != 0 || h3.w.Differ != 1 {
		t.Fatalf("both private is not a shape disagreement: %+v", h3.events)
	}
}

func TestDNSXCheckSamplingAndFailures(t *testing.T) {
	h := newDXHarness()
	h.answer["https://cloudflare-dns.com/dns-query"] = buildAResponse("a.example", net.IPv4(1, 1, 1, 1))
	resp := buildAResponse("a.example", net.IPv4(1, 1, 1, 1))
	q := mkQuery("a.example", 1, 1, true)
	for i := 0; i < dnsXSampleEvery*3; i++ {
		h.now = h.now.Add(dnsXMinGap)
		h.w.Observe("192.168.1.20", "a.example", "https://dns.quad9.net/dns-query", q, resp, h.now)
		h.w.wg.Wait()
	}
	if len(h.asked) != 1 {
		t.Fatalf("one in %d, and a name already checked this hour is skipped: asked %d times", dnsXSampleEvery, len(h.asked))
	}
	// the second resolver failing is counted, never an event
	h.fail = true
	h.observe("b.example", resp)
	if h.w.Failed != 1 || len(h.events) != 0 {
		t.Fatalf("failure: failed=%d events=%+v", h.w.Failed, h.events)
	}
	// with one resolver there is nothing to compare against
	h.fail = false
	h.w.urls = func() []string { return []string{"https://dns.quad9.net/dns-query"} }
	before := len(h.asked)
	h.observe("c.example", resp)
	if len(h.asked) != before {
		t.Fatal("a single resolver should never be cross-checked against itself")
	}
}

func TestUnroutable(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "192.168.1.1", "172.16.0.9", "127.0.0.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "0.0.0.0", "224.0.0.1"} {
		if !unroutable(net.ParseIP(s)) {
			t.Fatalf("%s should be unroutable", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "93.184.216.34", "151.101.1.1"} {
		if unroutable(net.ParseIP(s)) {
			t.Fatalf("%s is public", s)
		}
	}
	if hostOf("https://dns.quad9.net/dns-query") != "dns.quad9.net" {
		t.Fatal("hostOf")
	}
}
