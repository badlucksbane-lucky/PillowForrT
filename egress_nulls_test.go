package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The page runs .map and .length on these lists. A Go nil slice or map marshals as null, which crashes the page's loader (its catch is silent, so the
// System card just stays on "loading"). On a unit with no outbound rules and nothing observed yet, every one of them must still be a real list or object.
func TestEgressViewListsAreNeverNull(t *testing.T) {
	m := newEgressMgr(t.TempDir() + "/e.json")
	for _, mac := range []string{"", "aa:bb:cc:dd:ee:01"} {
		b, err := json.Marshal(m.ViewFor(mac))
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		json.Unmarshal(b, &raw)
		for _, k := range []string{"allow", "devices", "observed", "services"} {
			v := strings.TrimSpace(string(raw[k]))
			if v == "null" || v == "" {
				t.Errorf("view for %q: %q is %q, the page cannot map over that", mac, k, v)
			}
		}
		if string(raw["allow"]) != "[]" || string(raw["observed"]) != "[]" || string(raw["devices"]) != "{}" {
			t.Errorf("view for %q: allow=%s observed=%s devices=%s (want [] [] {})", mac, raw["allow"], raw["observed"], raw["devices"])
		}
	}
}

func TestEgressViewKeepsRealRules(t *testing.T) {
	m := newEgressMgr(t.TempDir() + "/e.json")
	if err := m.Allow(egressRule{Proto: "tcp", Ports: "8443"}, ""); err != nil {
		t.Fatal(err)
	}
	if v := m.View(); len(v.Allow) != 1 || v.Allow[0].Ports != "8443" {
		t.Errorf("a real rule was lost: %+v", v.Allow)
	}
}

// The page must also cope if an older or odd server still sends null for a list.
func TestPageToleratesNullLists(t *testing.T) {
	for _, bad := range []string{"Eg.allow.map(", "Eg.observed.length", "Eg.observed.slice("} {
		if strings.Contains(string(uiHTML), bad) {
			t.Errorf("ui.html still uses %q on a value that can be null", bad)
		}
	}
}
