package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPUpgradeURL(t *testing.T) {
	ok := []struct{ host, uri, want string }{
		{"example.com", "/a?b=1", "https://example.com/a?b=1"},
		{"Example.com:80", "/", "https://Example.com/"},
		{"1.2.3.4", "", "https://1.2.3.4/"},
		{"[2001:db8::1]:80", "/x", "https://[2001:db8::1]/x"},
		{"a_b.example.com", "*", "https://a_b.example.com/"},
	}
	for _, c := range ok {
		if got, good := httpUpgradeURL(c.host, c.uri); !good || got != c.want {
			t.Errorf("%q %q: got %q %v want %q", c.host, c.uri, got, good, c.want)
		}
	}
	bad := [][2]string{
		{"", "/"}, {"evil.com\r\nSet-Cookie: x", "/"}, {"a b", "/"}, {"example.com:abc", "/"}, {"example.com:99999", "/"}, {"[::1", "/"}, {"[1.2.3.4]", "/"},
		{"example.com", "http://other/"}, {"example.com", "/a b"}, {"example.com", "/a\r\nx: y"}, {"example.com", "/\xff"}, {"-bad.com", "/"},
		{"example.com", "/" + strings.Repeat("a", httpUpMaxURI)},
	}
	for _, c := range bad {
		if got, good := httpUpgradeURL(c[0], c[1]); good {
			t.Errorf("accepted %q %q -> %q", c[0], c[1], got)
		}
	}
}

func newTestUpgrader() (*httpUpgrader, *time.Time, *[]evt, *[]httpExempt) {
	now := time.Unix(1_800_000_000, 0)
	var evs []evt
	var passes []httpExempt
	u := newHTTPUpgrader()
	u.now = func() time.Time { return now }
	u.emit = func(e evt) { evs = append(evs, e) }
	u.exempt = func(c, d string, until time.Time) error { passes = append(passes, httpExempt{c, d, until}); return nil }
	u.httpsUp = func(c, d string) bool { return false }
	return u, &now, &evs, &passes
}

func TestUpgradeThenFallBack(t *testing.T) {
	u, now, evs, passes := newTestUpgrader()
	st, loc, _ := u.decide("192.168.1.40", "93.184.216.34", "example.com", "/p")
	if st != 307 || loc != "https://example.com/p" || u.Redirected.Load() != 1 {
		t.Fatalf("first request: %d %q", st, loc)
	}
	*now = now.Add(20 * time.Second)
	st, loc, _ = u.decide("192.168.1.40", "93.184.216.34", "example.com", "/p")
	if st != 307 || loc != "http://example.com/p" || u.FellBack.Load() != 1 {
		t.Fatalf("repeat without TLS must fall back: %d %q", st, loc)
	}
	if len(*passes) != 1 || (*passes)[0].Client != "192.168.1.40" || (*passes)[0].Dst != "93.184.216.34" || !(*passes)[0].Until.Equal(now.Add(httpUpWindow)) {
		t.Errorf("pass: %+v", *passes)
	}
	if len(*evs) != 1 || (*evs)[0].Sev != sevInfo || strings.ContainsAny((*evs)[0].Text+(*evs)[0].Public, "0123456789") || strings.Contains((*evs)[0].Text, "example") {
		t.Errorf("the event must exist and name no device, host or address: %+v", *evs)
	}
	// after the pass the next plain request is upgraded again, and another fall-back inside ten minutes raises no second event
	*now = now.Add(time.Second)
	u.decide("192.168.1.40", "93.184.216.34", "example.com", "/p")
	u.decide("192.168.1.40", "93.184.216.34", "example.com", "/p")
	if len(*evs) != 1 || u.FellBack.Load() != 2 {
		t.Errorf("events %d, fell back %d", len(*evs), u.FellBack.Load())
	}
}

func TestRepeatAfterWorkingHTTPSIsNotAFallBack(t *testing.T) {
	u, now, evs, passes := newTestUpgrader()
	u.httpsUp = func(c, d string) bool { return c == "192.168.1.40" && d == "93.184.216.34" }
	u.decide("192.168.1.40", "93.184.216.34", "example.com", "/")
	*now = now.Add(5 * time.Second)
	if st, loc, _ := u.decide("192.168.1.40", "93.184.216.34", "example.com", "/"); st != 307 || loc != "https://example.com/" {
		t.Errorf("a working HTTPS connection means upgrade again: %d %q", st, loc)
	}
	if u.FellBack.Load() != 0 || len(*evs) != 0 || len(*passes) != 0 {
		t.Error("nothing should be noted or passed")
	}
}

func TestFallBackNeedsSameDeviceHostAndWindow(t *testing.T) {
	u, now, _, _ := newTestUpgrader()
	u.decide("192.168.1.40", "1.1.1.1", "a.example", "/")
	u.decide("192.168.1.41", "1.1.1.1", "a.example", "/") // another device
	u.decide("192.168.1.40", "1.1.1.1", "b.example", "/") // another host
	*now = now.Add(httpUpWindow + time.Second)
	u.decide("192.168.1.40", "1.1.1.1", "a.example", "/") // too late
	if u.FellBack.Load() != 0 || u.Redirected.Load() != 4 {
		t.Errorf("fell back %d redirected %d", u.FellBack.Load(), u.Redirected.Load())
	}
}

func TestFallBackWithoutPassFailsClosed(t *testing.T) {
	u, _, _, _ := newTestUpgrader()
	u.decide("192.168.1.40", "", "example.com", "/")
	if st, loc, _ := u.decide("192.168.1.40", "", "example.com", "/"); st != 503 || loc != "" {
		t.Errorf("with no original destination the repeat cannot be let through: %d %q", st, loc)
	}
	u2, _, _, _ := newTestUpgrader()
	u2.exempt = func(string, string, time.Time) error { return http.ErrAbortHandler }
	u2.decide("192.168.1.40", "1.1.1.1", "example.com", "/")
	if st, _, _ := u2.decide("192.168.1.40", "1.1.1.1", "example.com", "/"); st != 503 {
		t.Errorf("a failed pass must not look like success: %d", st)
	}
}

func TestUpgradeHandler(t *testing.T) {
	u, _, _, _ := newTestUpgrader()
	h := u.handler()
	do := func(method, target, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Host, r.RemoteAddr = host, "192.168.1.40:51000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do("GET", "/x?y=1", "example.com")
	if w.Code != 307 || w.Header().Get("Location") != "https://example.com/x?y=1" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("%d %v", w.Code, w.Header())
	}
	if w := do("HEAD", "/", "other.example"); w.Code != 307 || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d %q", w.Code, w.Body.String())
	}
	if w := do("POST", "/form", "post.example"); w.Code != 307 { // 307 keeps the method for a client that follows it
		t.Errorf("POST: %d", w.Code)
	}
	if w := do("GET", "/", "bad host"); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Errorf("bad host: %d %v", w.Code, w.Header())
	}
	if w := do("CONNECT", "example.com:443", "example.com:443"); w.Code != 400 {
		t.Errorf("CONNECT: %d", w.Code)
	}
}

func TestConntrackHasTLS(t *testing.T) {
	ct := "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.40 dst=93.184.216.34 sport=50000 dport=443 src=93.184.216.34 dst=100.65.1.1 sport=443 dport=50000 [ASSURED] mark=0 use=2\n" +
		"ipv4 2 tcp 6 59 SYN_SENT src=192.168.1.41 dst=93.184.216.34 sport=50001 dport=443 [UNREPLIED] src=93.184.216.34 dst=100.65.1.1 sport=443 dport=50001 mark=0 use=2\n" +
		"ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.42 dst=93.184.216.34 sport=50002 dport=80 src=93.184.216.34 dst=100.65.1.1 sport=80 dport=50002 [ASSURED] mark=0 use=2\n"
	if !conntrackHasTLS(ct, "192.168.1.40", "93.184.216.34") {
		t.Error("an established 443 flow must count")
	}
	if conntrackHasTLS(ct, "192.168.1.41", "93.184.216.34") || conntrackHasTLS(ct, "192.168.1.42", "93.184.216.34") || conntrackHasTLS(ct, "192.168.1.40", "93.184.216.3") {
		t.Error("an unanswered SYN, a port-80 flow or a different address must not count")
	}
}

func TestHTTPUpgradeNat(t *testing.T) {
	c := egressCfg{Mode: "monitor", HTTPSkip: []string{"aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01"},
		httpExempt: []httpExempt{{"192.168.1.40", "93.184.216.34", time.Now()}}}
	n := httpUpgradeNat(c)
	want := []string{"*nat\n:HS_HTTPUP - [0:0]\n", "-A HS_HTTPUP -d 192.168.1.0/24 -j RETURN\n", "--mac-source aa:bb:cc:dd:ee:01 -j RETURN\n", "--mac-source aa:bb:cc:dd:ee:02 -j RETURN\n",
		"-A HS_HTTPUP -s 192.168.1.40 -d 93.184.216.34 -j RETURN\n", "-A HS_HTTPUP -p tcp --dport 80 -j REDIRECT --to-ports 3130\nCOMMIT\n"}
	last := -1
	for _, w := range want {
		i := strings.Index(n, w)
		if i < 0 || i < last {
			t.Fatalf("missing or out of order %q in\n%s", w, n)
		}
		last = i
	}
	c.NoHTTPUpgrade = true
	if n := httpUpgradeNat(c); strings.Contains(n, "-A ") || !strings.Contains(n, ":HS_HTTPUP") {
		t.Errorf("off: the chain must be declared (so it is flushed) and empty:\n%s", n)
	}
	c.NoHTTPUpgrade, c.Mode = false, "off"
	if strings.Contains(httpUpgradeNat(c), "-A ") {
		t.Error("list off: no redirect")
	}
}

func TestEgressRulesCarryNatAndDNSRefusal(t *testing.T) {
	c := defaultEgress()
	v4, v6 := egressRules(c, false), egressRules(c, true)
	if !strings.Contains(v4, "*nat\n:HS_HTTPUP") || strings.Contains(v6, "*nat") {
		t.Error("the nat block goes in the IPv4 input only")
	}
	if !strings.Contains(v4, "-A HS_EGRESS -p tcp -m multiport --dports 80,443 -j RETURN") {
		t.Error("port 80 stays allowed")
	}
	i, j := strings.Index(v4, "--dports 53,853 -j REJECT"), strings.Index(v4, "--dports 80,443")
	if i < 0 || j < 0 || i > j || !strings.Contains(v6, "-p udp -m multiport --dports 53,853 -j REJECT --reject-with icmp6-port-unreachable") {
		t.Errorf("DNS and DoT must be refused ahead of the allow-list:\n%s", v4)
	}
	c.Allow = append(c.Allow, egressRule{"udp", "53", "oops"})
	if v := egressRules(c, false); strings.Index(v, "--dports 53,853 -j REJECT") > strings.Index(v, "-p udp -m multiport --dports 53 -j RETURN") {
		t.Error("an allow rule for 53 must not get ahead of the refusal")
	}
	c.Mode = "monitor"
	if strings.Contains(egressRules(c, false), "--dports 53,853") {
		t.Error("watch-only mode refuses nothing; the guard does that")
	}
}

func TestHTTPUpgradeManager(t *testing.T) {
	m := newEgressMgr(t.TempDir() + "/e.json")
	var last string
	m.apply = func(a, b string, h bool) error { last = a; return nil }
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	if err := m.AddHTTPExempt("192.168.1.40", "93.184.216.34", now.Add(httpUpWindow)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(last, "-s 192.168.1.40 -d 93.184.216.34 -j RETURN") {
		t.Errorf("the pass must be in the rules:\n%s", last)
	}
	for _, bad := range [][2]string{{"192.168.1.40", "192.168.1.9"}, {"192.168.1.40", "127.0.0.1"}, {"x", "1.1.1.1"}, {"192.168.1.40", "::1"}, {"192.168.1.40", "224.0.0.1"}} {
		if m.AddHTTPExempt(bad[0], bad[1], now.Add(time.Minute)) == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	now = now.Add(httpUpWindow + time.Second)
	m.Reconcile()
	if strings.Contains(last, "-s 192.168.1.40") {
		t.Error("an expired pass must go")
	}
	if err := m.SetHTTPUpgrade(false, "AA:BB:CC:DD:EE:01"); err != nil || !strings.Contains(last, "--mac-source aa:bb:cc:dd:ee:01 -j RETURN") {
		t.Errorf("skip a device: %v\n%s", err, last)
	}
	if err := m.SetHTTPUpgrade(true, "aa:bb:cc:dd:ee:01"); err != nil || strings.Contains(last, "aa:bb:cc:dd:ee:01") {
		t.Errorf("put it back: %v", err)
	}
	if m.SetHTTPUpgrade(false, "nope") == nil {
		t.Error("bad MAC accepted")
	}
	if err := m.SetHTTPUpgrade(false, ""); err != nil || strings.Contains(last, "REDIRECT") || m.View().HTTPUp {
		t.Errorf("global off: %v", err)
	}
	m.cfg.NoHTTPUpgrade, m.noUpgrade = false, true
	m.Reconcile()
	if strings.Contains(last, "REDIRECT") {
		t.Error("-http-upgrade=false must win over the saved config")
	}
}
