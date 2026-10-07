package main

import (
	"testing"
	"time"
)

func llmnrQuestion(name string) []byte {
	m := []byte{0x00, 0x00, 0x80, 0x00, 0, 1, 0, 0, 0, 0, 0, 0} // response, QDCOUNT=1
	m = append(m, mdnsName(name)...)
	m = append(m, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	return m
}

func TestParseResponderNames(t *testing.T) {
	isResp, names, ok := parseResponderNames(llmnrQuestion("printer"))
	if !ok || !isResp || len(names) != 1 || names[0] != "printer" {
		t.Fatalf("got isResp=%v names=%v ok=%v", isResp, names, ok)
	}
	// a query (QR bit clear) is parsed but not flagged as a response
	q := llmnrQuestion("printer")
	q[2] = 0x00
	isResp, _, ok = parseResponderNames(q)
	if !ok || isResp {
		t.Fatalf("expected a non-response, got isResp=%v ok=%v", isResp, ok)
	}
	if _, _, ok = parseResponderNames([]byte{1, 2, 3}); ok {
		t.Fatal("expected a too-short message to fail")
	}
}

func newLanPoisonHarness() (*lanPoisonWatch, *[]evt, *time.Time) {
	w := newLANPoisonWatch()
	var events []evt
	now := time.Unix(1_700_000_000, 0)
	w.emit = func(e evt) { events = append(events, e) }
	w.macOf = func(string) string { return "" }
	w.nameOf = func(string) string { return "" }
	w.now = func() time.Time { return now }
	return w, &events, &now
}

func TestLANPoisonWatchFiresOnManyNames(t *testing.T) {
	w, events, now := newLanPoisonHarness()
	for i := 0; i < poisonThreshold-1; i++ {
		w.observe("192.168.1.50", "name"+string(rune('a'+i)), *now)
	}
	if len(*events) != 0 {
		t.Fatalf("expected no event yet, got %d", len(*events))
	}
	w.observe("192.168.1.50", "onemore", *now)
	if len(*events) != 1 {
		t.Fatalf("expected exactly one event, got %d", len(*events))
	}
	if (*events)[0].Kind != "lan_name_poison" {
		t.Fatalf("unexpected kind %q", (*events)[0].Kind)
	}
	// throttled: answering more names right away does not raise a second event within the hour
	w.observe("192.168.1.50", "yet-another", *now)
	if len(*events) != 1 {
		t.Fatalf("expected the finding to stay throttled, got %d events", len(*events))
	}
}

func TestLANPoisonWatchIgnoresOffLAN(t *testing.T) {
	w, events, now := newLanPoisonHarness()
	for i := 0; i < poisonThreshold+1; i++ {
		w.observe("8.8.8.8", "name"+string(rune('a'+i)), *now)
	}
	if len(*events) != 0 {
		t.Fatalf("expected an off-LAN source to never raise, got %d events", len(*events))
	}
}

func TestLANPoisonWatchWindowExpires(t *testing.T) {
	w, events, now := newLanPoisonHarness()
	for i := 0; i < poisonThreshold; i++ {
		w.observe("192.168.1.50", "name"+string(rune('a'+i)), *now)
	}
	if len(*events) != 1 {
		t.Fatalf("expected one event, got %d", len(*events))
	}
	// an hour later, with a fresh set of names spread outside the window one at a time, the stale ones have aged out
	later := now.Add(poisonWindow + time.Second)
	*now = later
	w.lastEv["192.168.1.50"] = later.Add(-2 * time.Hour) // unthrottle for this test
	w.observe("192.168.1.50", "fresh", later)
	if len(w.answers["192.168.1.50"]) != 1 {
		t.Fatalf("expected the old answers to have aged out of the window, got %d", len(w.answers["192.168.1.50"]))
	}
}
