package main

import (
	"net"
	"testing"
	"time"
)

// buildAResponse assembles a minimal DNS response: question name A/IN, then one A answer (compressed to the question) holding ip.
func buildAResponse(name string, ip net.IP) []byte {
	var q []byte
	for _, l := range splitLabels(name) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	m := append([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, q...)
	m = append(m, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	m = append(m, ip.To4()...)
	return m
}

func splitLabels(name string) []string {
	var out []string
	cur := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestARecordIPs(t *testing.T) {
	m := buildAResponse("example.com", net.ParseIP("93.184.216.34"))
	got := aRecordIPs(m)
	if len(got) != 1 || !got[0].Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("got %v", got)
	}
	// truncated message must not panic or invent addresses
	if ips := aRecordIPs(m[:20]); len(ips) > 1 {
		t.Errorf("truncated message yielded %v", ips)
	}
	aRecordIPs(nil)
	aRecordIPs([]byte{1, 2, 3})
}

func TestDNSMITMObserve(t *testing.T) {
	var got []evt
	w := newDNSMITMWatch()
	w.emit = func(e evt) { got = append(got, e) }
	now := time.Now()

	t.Run("an ordinary public answer never fires", func(t *testing.T) {
		got = nil
		w.recentARP = func(time.Time) bool { return false }
		w.Observe("192.168.1.50", "example.com", buildAResponse("example.com", net.ParseIP("93.184.216.34")), now)
		if len(got) != 0 {
			t.Errorf("a normal external answer must never fire, got %d events", len(got))
		}
	})

	t.Run("a LAN-range answer fires suspect without a recent ARP finding", func(t *testing.T) {
		got = nil
		w.recentARP = func(time.Time) bool { return false }
		w.Observe("192.168.1.51", "example.com", buildAResponse("example.com", net.ParseIP("192.168.1.99")), now)
		if len(got) != 1 || got[0].Kind != "dns_mitm_suspect" || got[0].Sev != sevAttention {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("the same thing, but with a recent ARP impersonation, is confirmed and alerts", func(t *testing.T) {
		got = nil
		w.recentARP = func(time.Time) bool { return true }
		w.Observe("192.168.1.52", "example.com", buildAResponse("example.com", net.ParseIP("192.168.1.98")), now)
		if len(got) != 1 || got[0].Kind != "dns_mitm_confirmed" || got[0].Sev != sevAlert {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("the same client is throttled for 10 minutes", func(t *testing.T) {
		got = nil
		w.recentARP = func(time.Time) bool { return false }
		w.Observe("192.168.1.51", "example.com", buildAResponse("example.com", net.ParseIP("192.168.1.99")), now.Add(time.Minute))
		if len(got) != 0 {
			t.Errorf("a repeat within 10 minutes from the same client must be throttled, got %d events", len(got))
		}
	})
}

func TestArpWatchRecentImpersonation(t *testing.T) {
	w := newARPWatch()
	now := time.Now()
	if w.RecentImpersonation(10*time.Minute, now) {
		t.Error("no findings yet: must be false")
	}
	w.finds = append(w.finds, arpFinding{T: now.Add(-2 * time.Minute).Unix(), Kind: "arp_flip"})
	if w.RecentImpersonation(10*time.Minute, now) {
		t.Error("arp_flip alone is not an impersonation finding")
	}
	w.finds = append(w.finds, arpFinding{T: now.Add(-1 * time.Minute).Unix(), Kind: "arp_gateway"})
	if !w.RecentImpersonation(10*time.Minute, now) {
		t.Error("a recent arp_gateway finding should count")
	}
	if w.RecentImpersonation(30*time.Second, now) {
		t.Error("a finding older than the asked window must not count")
	}
}
