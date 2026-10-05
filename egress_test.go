package main

import (
	"strings"
	"testing"
)

func TestEgressRules(t *testing.T) {
	c := egressCfg{Mode: "enforce", Allow: []egressRule{{"tcp", "80,443", "web"}}, Devices: map[string][]egressRule{"aa:bb:cc:dd:ee:ff": {{"udp", "5060", "sip"}}}}
	r := egressRules(c, false)
	for _, w := range []string{"-A HS_EGRESS -p icmp -j RETURN", "-p tcp -m multiport --dports 80,443 -j RETURN",
		"-m mac --mac-source aa:bb:cc:dd:ee:ff -p udp -m multiport --dports 5060 -j RETURN", "-p tcp -j REJECT --reject-with tcp-reset", "COMMIT"} {
		if !strings.Contains(r, w) {
			t.Errorf("missing %q in\n%s", w, r)
		}
	}
	c.Mode = "monitor"
	if m := egressRules(c, true); strings.Contains(m, "REJECT") || !strings.Contains(m, "--icmpv6-type 135") {
		t.Errorf("monitor must not reject and v6 must keep neighbour discovery:\n%s", m)
	}
}

func TestPortChunksAndListed(t *testing.T) {
	long := "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"
	if ch := portChunks(long); len(ch) != 2 || strings.Count(ch[0], ",") != 14 {
		t.Errorf("chunks %v", ch)
	}
	rs := []egressRule{{"tcp", "80,5228:5230", ""}}
	if !portListed(rs, "tcp", 5229) || portListed(rs, "udp", 80) || portListed(rs, "tcp", 8080) {
		t.Error("portListed wrong")
	}
	if validRule(egressRule{"tcp", "80;rm", ""}) == nil || validRule(egressRule{"icmp", "1", ""}) == nil || validRule(egressRule{"tcp", "70000", ""}) == nil || validRule(egressRule{"udp", "53,443", ""}) != nil {
		t.Error("validRule wrong")
	}
}

func TestParseConntrackAndSample(t *testing.T) {
	ct := "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.40 dst=17.0.0.1 sport=50000 dport=443 src=17.0.0.1 dst=100.65.1.1 sport=443 dport=50000 mark=0 use=2\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.40 dst=5.6.7.8 sport=50001 dport=6881 src=5.6.7.8 dst=100.65.1.1 sport=6881 dport=50001 mark=0 use=2\n" +
		"ipv4 2 udp 17 20 src=192.168.1.40 dst=5.6.7.8 sport=50002 dport=6881 src=5.6.7.8 dst=100.65.1.1 sport=6881 dport=50002 mark=0 use=2\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.2 dst=192.168.1.1 sport=44106 dport=3128 src=192.168.1.1 dst=192.168.1.2 sport=3128 dport=44106 mark=0 use=2\n"
	if n := len(parseConntrack(ct)); n != 3 {
		t.Fatalf("flows: %d", n)
	}
	m := newEgressMgr(t.TempDir() + "/e.json")
	m.conn = func() string { return ct }
	m.arp = func() map[string]string { return map[string]string{"aa:aa:aa:aa:aa:40": "192.168.1.40"} }
	m.Sample()
	m.Sample() // the same flows twice must not double count
	v := m.View()
	if len(v.Observed) != 2 || v.Observed[0].Port != 6881 && v.Observed[1].Port != 6881 {
		t.Fatalf("observed %+v", v.Observed)
	}
	for _, o := range v.Observed {
		if o.Flows != 1 || o.MAC != "aa:aa:aa:aa:aa:40" {
			t.Errorf("tally %+v", o)
		}
	}
	m.apply = func(a, b string, h bool) error { return nil }
	if err := m.Allow(egressRule{"tcp", "6881", "test"}, "aa:aa:aa:aa:aa:40"); err != nil {
		t.Fatal(err)
	}
	if len(m.View().Observed) != 1 {
		t.Error("allowing a port must drop its tally")
	}
}

func TestEgressServicesAndDeviceExtras(t *testing.T) {
	c := defaultEgress()
	if c.Mode != "enforce" {
		t.Errorf("the public build starts in enforce mode, got %s", c.Mode)
	}
	r := egressRules(c, false)
	for _, w := range []string{"--dports 80,443 -j RETURN", "-p udp -m multiport --dports 123", "--dports 5222,5223,5228:5230"} {
		if !strings.Contains(r, w) {
			t.Errorf("a starting service is missing %q:\n%s", w, r)
		}
	}
	if strings.Contains(r, "3074") || strings.Contains(r, "6881") {
		t.Error("off-by-default services must not be in the rules")
	}
	m := newEgressMgr(t.TempDir() + "/e.json")
	m.apply = func(a, b string, h bool) error { return nil }
	if err := m.SetService("consoles", true, "aa:bb:cc:dd:ee:01"); err != nil {
		t.Fatal(err)
	}
	e := egressRules(m.cfg, false)
	if !strings.Contains(e, "-m mac --mac-source aa:bb:cc:dd:ee:01 -p tcp -m multiport --dports 3074,3478:3480,1935") || strings.Count(e, "3074") != 2 {
		t.Errorf("a per-device service must appear only under that device's MAC:\n%s", e)
	}
	if err := m.SetService("torrent", true, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(egressRules(m.cfg, false), "-A HS_EGRESS -p tcp -m multiport --dports 6881:6889,51413 -j RETURN") {
		t.Error("a global service must apply to everyone")
	}
	if m.SetService("nonsense", true, "") == nil || m.SetService("web", true, "zz") == nil {
		t.Error("bad service or MAC accepted")
	}
	v := m.ViewFor("aa:bb:cc:dd:ee:01")
	var extra, glob int
	for _, s := range v.Services {
		if s.Extra {
			extra++
		}
		if s.On {
			glob++
		}
	}
	if extra != 1 || glob != 7 {
		t.Errorf("view: %d extra, %d global", extra, glob)
	}
}
