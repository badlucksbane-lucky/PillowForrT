package main

import (
	"testing"
	"time"
)

// buildDHCPRequest assembles a minimal BOOTP/DHCP packet (the UDP payload only) for a given MAC with the given option-55 parameter request list.
func buildDHCPRequest(mac []byte, params []byte) []byte {
	b := make([]byte, bootpFixedLen+4)
	b[0] = 1 // BOOTREQUEST
	b[1] = 1 // Ethernet
	b[2] = 6 // hlen
	copy(b[28:34], mac)
	copy(b[bootpFixedLen:bootpFixedLen+4], []byte{0x63, 0x82, 0x53, 0x63}) // magic cookie
	if params != nil {
		b = append(b, 55, byte(len(params)))
		b = append(b, params...)
	}
	b = append(b, 0xff) // end option
	return b
}

func TestDHCPFingerprint(t *testing.T) {
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	t.Run("with option 55", func(t *testing.T) {
		m, fp, ok := dhcpFingerprint(buildDHCPRequest(mac, []byte{1, 3, 6, 15}))
		if !ok || m != "aa:bb:cc:dd:ee:ff" || fp != "0103060f" {
			t.Fatalf("mac=%q fp=%q ok=%v, want aa:bb:cc:dd:ee:ff 0103060f true", m, fp, ok)
		}
	})
	t.Run("no option 55", func(t *testing.T) {
		m, fp, ok := dhcpFingerprint(buildDHCPRequest(mac, nil))
		if !ok || m != "aa:bb:cc:dd:ee:ff" || fp != "" {
			t.Fatalf("mac=%q fp=%q ok=%v, want empty fp but ok", m, fp, ok)
		}
	})
	t.Run("a server reply (op 2) is never fingerprinted", func(t *testing.T) {
		b := buildDHCPRequest(mac, []byte{1, 3, 6})
		b[0] = 2
		if _, _, ok := dhcpFingerprint(b); ok {
			t.Fatal("a BOOTREPLY must not be read as a client fingerprint")
		}
	})
	t.Run("too short", func(t *testing.T) {
		if _, _, ok := dhcpFingerprint(make([]byte, 10)); ok {
			t.Fatal("a too-short payload must not parse")
		}
	})
}

func TestDHCPFPWatchObserve(t *testing.T) {
	var got []evt
	w := newDHCPFPWatch()
	w.emit = func(e evt) { got = append(got, e) }
	now := time.Unix(1000, 0)

	w.Observe("aa:bb:cc:dd:ee:ff", "0103060f", now) // first sighting: never a baseline
	w.Observe("aa:bb:cc:dd:ee:ff", "0103060f", now.Add(time.Minute))
	if len(got) != 0 {
		t.Fatalf("a first sighting and a repeat of the same fingerprint must not fire, got %d events", len(got))
	}

	w.Observe("aa:bb:cc:dd:ee:ff", "aabbccdd", now.Add(2*time.Minute)) // now it changes, after being stable twice
	if len(got) != 1 {
		t.Fatalf("a fingerprint change after a stable baseline should fire once, got %d", len(got))
	}

	w.Observe("aa:bb:cc:dd:ee:ff", "ffeeddcc", now.Add(3*time.Minute)) // changes again right away, inside the 24h throttle
	if len(got) != 1 {
		t.Fatalf("a second change within 24h of the last event must be throttled, got %d events", len(got))
	}

	w.Observe("aa:bb:cc:dd:ee:ff", "ffeeddcc", now.Add(25*time.Hour)) // stays the same past the throttle window: no new baseline violation
	if len(got) != 1 {
		t.Fatalf("holding steady must never fire on its own, got %d events", len(got))
	}
}
