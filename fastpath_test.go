package main

import "testing"

func TestFastPathEligible(t *testing.T) {
	cases := []struct {
		name      string
		p         exitPlan
		torActive bool
		want      bool
	}{
		{"everyone on mullvad, tunnel up", exitPlan{DefaultVPN: true, TunnelUp: true}, false, true},
		{"tor device present", exitPlan{DefaultVPN: true, TunnelUp: true}, true, false},
		{"default exit is direct", exitPlan{DefaultVPN: false, TunnelUp: true}, false, false},
		{"one device exempted direct", exitPlan{DefaultVPN: true, TunnelUp: true, DirectMacs: []string{"aa:bb:cc:dd:ee:01"}}, false, false},
		{"tunnel not up yet", exitPlan{DefaultVPN: true, TunnelUp: false}, false, false},
	}
	for _, c := range cases {
		got, why := fastPathEligible(c.p, c.torActive)
		if got != c.want {
			t.Errorf("%s: got %v (%q), want %v", c.name, got, why, c.want)
		}
		if !got && why == "" {
			t.Errorf("%s: ineligible with no reason", c.name)
		}
	}
}
