package main

import (
	"fmt"
	"testing"
	"time"
)

func staLines(macs ...string) string {
	out := ""
	for _, m := range macs {
		out += m + "\nflags=[AUTH][ASSOC][AUTHORIZED]\nconnected_time=60\n"
	}
	return out
}

func newDiscoHarness(stations func() int) (*wifiDiscoWatch, *[]evt) {
	n := 0
	w := newWifiDiscoWatch(func() string {
		macs := make([]string, stations())
		for i := range macs {
			macs[i] = fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i)
		}
		return staLines(macs...)
	})
	var events []evt
	w.emit = func(e evt) { events = append(events, e) }
	w.uptimeS = func() int { return 10000 }
	_ = n
	return w, &events
}

func TestWifiDiscoWatchMassDrop(t *testing.T) {
	count := 10
	w, events := newDiscoHarness(func() int { return count })
	now := time.Unix(1_700_000_000, 0)
	w.poll(now) // baseline: 10 connected, no comparison yet

	count = 3 // 7 dropped at once
	w.poll(now.Add(time.Second))
	if len(*events) != 1 {
		t.Fatalf("expected one mass-disconnect event, got %d", len(*events))
	}
	if (*events)[0].Kind != "wifi_mass_disconnect" {
		t.Fatalf("unexpected kind %q", (*events)[0].Kind)
	}
}

func TestWifiDiscoWatchIgnoresSmallDrop(t *testing.T) {
	count := 10
	w, events := newDiscoHarness(func() int { return count })
	now := time.Unix(1_700_000_000, 0)
	w.poll(now)

	count = 8 // only 2 dropped
	w.poll(now.Add(time.Second))
	if len(*events) != 0 {
		t.Fatalf("expected no event for a small drop, got %d", len(*events))
	}
}

func TestWifiDiscoWatchSkipsRecentBoot(t *testing.T) {
	count := 10
	w, events := newDiscoHarness(func() int { return count })
	w.uptimeS = func() int { return 5 } // the box itself just came up
	now := time.Unix(1_700_000_000, 0)
	w.poll(now)

	count = 0
	w.poll(now.Add(time.Second))
	if len(*events) != 0 {
		t.Fatalf("expected a fresh boot to suppress the finding, got %d events", len(*events))
	}
}
