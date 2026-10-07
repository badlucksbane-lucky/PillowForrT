package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEgressBlockListEmptyByDefault(t *testing.T) {
	l := newEgressBlockList(filepath.Join(t.TempDir(), "missing.txt"))
	if l.Available() {
		t.Fatal("expected an empty/missing blocklist file to leave the list unavailable")
	}
	if l.Contains("1.2.3.4") {
		t.Fatal("an empty list should never match")
	}
}

func TestEgressBlockListLoadsIPsAndCIDRs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	os.WriteFile(path, []byte("# comment\n203.0.113.5\n198.51.100.0/24\n\n"), 0o644)
	l := newEgressBlockList(path)
	if !l.Available() {
		t.Fatal("expected the list to be available")
	}
	if !l.Contains("203.0.113.5") {
		t.Fatal("expected the exact IP to match")
	}
	if !l.Contains("198.51.100.17") {
		t.Fatal("expected the CIDR to match an address inside it")
	}
	if l.Contains("8.8.8.8") {
		t.Fatal("expected an unlisted address not to match")
	}
}

func TestEgressBlockWatchFires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	os.WriteFile(path, []byte("203.0.113.5\n"), 0o644)
	w := newEgressBlockWatch(path)
	var events []evt
	w.emit = func(e evt) { events = append(events, e) }
	w.nameOf = func(string) string { return "" }
	now := time.Unix(1_700_000_000, 0)

	w.ObserveFlow("aa:bb:cc:dd:ee:ff", "192.168.1.50", "8.8.8.8", now)
	if len(events) != 0 {
		t.Fatalf("expected an unlisted destination not to fire, got %d events", len(events))
	}
	w.ObserveFlow("aa:bb:cc:dd:ee:ff", "192.168.1.50", "203.0.113.5", now)
	if len(events) != 1 {
		t.Fatalf("expected one event for a listed destination, got %d", len(events))
	}
	if events[0].Kind != "egress_ip_blocklist" {
		t.Fatalf("unexpected kind %q", events[0].Kind)
	}
	// throttled: the same device/destination pair does not fire again within 10 minutes
	w.ObserveFlow("aa:bb:cc:dd:ee:ff", "192.168.1.50", "203.0.113.5", now.Add(time.Minute))
	if len(events) != 1 {
		t.Fatalf("expected the finding to stay throttled, got %d events", len(events))
	}
}
