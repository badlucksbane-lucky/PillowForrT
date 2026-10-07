package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The page runs .map/.length on these lists without checking for null first (egress_nulls_test.go found this failure mode once already): every list field on a freshly
// constructed watcher, with nothing observed yet, must still marshal as a real (possibly empty) array, never Go's nil-slice "null".
func TestNewDetectorViewsAreNeverNull(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]any{
		"dnscanary": newDNSCanaryWatch().View(),
		"macchurn":  newMACChurnWatch().View(),
		"torbypass": newTorBypassWatch(dir + "/exits.txt").View(),
		"beacon":    newBeaconWatch(dir + "/beacon.json").View(),
		"dga":       newDGAWatch().View(),
		"tlssni":    newTLSSNIWatch().View(),
		"dhcpfp":    newDHCPFPWatch().View(),
		"dnsmitm":   newDNSMITMWatch().View(),
	}
	for name, v := range cases {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for k, rv := range raw {
			s := strings.TrimSpace(string(rv))
			if s == "[]" || s[0] != '[' {
				continue
			}
			if s == "null" {
				t.Errorf("%s: field %q is null, the page cannot map over that", name, k)
			}
		}
	}
}

func TestBeaconStats(t *testing.T) {
	base := time.Unix(0, 0)
	var regular []time.Time
	for i := 0; i < 8; i++ {
		regular = append(regular, base.Add(time.Duration(i)*60*time.Second))
	}
	mean, cv, ok := beaconStats(regular)
	if !ok || mean != 60 || cv != 0 {
		t.Errorf("perfectly even 60s spacing: mean=%v cv=%v ok=%v, want 60 0 true", mean, cv, ok)
	}
	if !beaconLooksLikeOne(len(regular), mean, cv, ok) {
		t.Error("a tight, in-range run should look like a beacon")
	}

	var bursty []time.Time
	gaps := []int{1, 400, 2, 900, 1, 3, 600}
	t0 := base
	bursty = append(bursty, t0)
	for _, g := range gaps {
		t0 = t0.Add(time.Duration(g) * time.Second)
		bursty = append(bursty, t0)
	}
	mean, cv, ok = beaconStats(bursty)
	if beaconLooksLikeOne(len(bursty), mean, cv, ok) {
		t.Errorf("bursty, irregular traffic should not look like a beacon (mean=%v cv=%v)", mean, cv)
	}

	if _, _, ok := beaconStats([]time.Time{base}); ok {
		t.Error("a single sample has no interval and must not be ok")
	}
}

func TestExfilLabelShape(t *testing.T) {
	if exfilLabel("a1b2c3") {
		t.Error("a short label should not look like tunneling")
	}
	if !exfilLabel("deadbeefcafebabe0123456789abcdef") {
		t.Error("a long hex-looking label should look like tunneling")
	}
	if exfilLabel("this-is-a-very-ordinary-looking-cdn-hostname") {
		t.Error("an ordinary wordy hostname should not look like tunneling")
	}
}

func TestIsCanaryName(t *testing.T) {
	if !isCanaryName("heimdall-canary.invalid", nil) {
		t.Error("the exact decoy name should match")
	}
	if !isCanaryName("sub.heimdall-canary.invalid", nil) {
		t.Error("a subdomain of a decoy name should match")
	}
	if isCanaryName("notheimdall-canary.invalid", nil) {
		t.Error("a name that merely ends with the decoy string, without a dot boundary, must not match")
	}
	if !isCanaryName("example.com", []string{"example.com"}) {
		t.Error("an extra configured decoy should match too")
	}
}
