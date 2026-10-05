package main

import (
	"testing"
	"time"
)

func TestNormalizePattern(t *testing.T) {
	ok := map[string]string{
		"https://Ads.Example.com:8443/a/b?c=1#x": "ads.example.com", "||tracker.net^": "tracker.net", "*.zip": "*.zip", "user:pw@site.org/": "site.org",
		"ads*.example.com.": "ads*.example.com", "*track*": "*track*", "EXAMPLE.com": "example.com",
	}
	for in, want := range ok {
		if got, err := normalizePattern(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v (want %q)", in, got, err, want)
		}
	}
	for _, in := range []string{"", "*", "*.*", "a.b", "203.0.113.7", "exa mple.com", "bücher.de", "x..com", "ex$ample.com"} {
		if _, err := normalizePattern(in); err == nil {
			t.Errorf("%q must be refused", in)
		}
	}
}

func TestPatternMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"example.com", "example.com", true}, {"example.com", "a.b.example.com", true}, {"example.com", "notexample.com", false},
		{"*.example.com", "a.example.com", true}, {"*.example.com", "example.com", false}, {"*.example.com", "x.notexample.com", false},
		{"ads*.example.com", "ads1.example.com", true}, {"ads*.example.com", "ads.foo.example.com", true}, {"ads*.example.com", "bads.example.com", false},
		{"*track*", "a.tracker.net", true}, {"*track*", "example.com", false}, {"*.zip", "evil.zip", true}, {"*.zip", "zip", false},
	}
	for _, c := range cases {
		if got := patternMatch(c.pat, c.name); got != c.want {
			t.Errorf("patternMatch(%q,%q)=%v want %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestCustomRulesScopeAndExpiry(t *testing.T) {
	c := newCustomRules(t.TempDir())
	if n, err := c.Add("https://bad.example.com/x, *.zip\nbad2.net", "", "", 0); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if _, err := c.Add("kids-only.com", "192.168.1.40", "kids", 60); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if p, ok := c.Match("192.168.1.2", "sub.bad.example.com", now); !ok || p != "bad.example.com" {
		t.Errorf("match %v %v", p, ok)
	}
	if _, ok := c.Match("192.168.1.2", "kids-only.com", now); ok {
		t.Error("a device-scoped rule must not hit another device")
	}
	if _, ok := c.Match("192.168.1.40", "kids-only.com", now); !ok {
		t.Error("device rule must hit its device")
	}
	if _, ok := c.Match("192.168.1.40", "kids-only.com", now.Add(2*time.Hour)); ok {
		t.Error("an expired rule must not match")
	}
	if got := len(c.List(now.Add(2 * time.Hour))); got != 3 {
		t.Errorf("expired rule must be dropped from the list, have %d", got)
	}
	d := newCustomRules(c.path[:len(c.path)-len("custom.json")]) // reload from disk
	if len(d.rules) != 3 {
		t.Errorf("persisted %d", len(d.rules))
	}
}

func TestCnameTargets(t *testing.T) {
	// question: www.site.com A IN; answer 1: www.site.com CNAME a.tracker.net (name compressed to the question); answer 2: a.tracker.net A 1.2.3.4
	q := []byte{3, 'w', 'w', 'w', 4, 's', 'i', 't', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	m := append([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}, q...)
	rd := []byte{1, 'a', 7, 't', 'r', 'a', 'c', 'k', 'e', 'r', 3, 'n', 'e', 't', 0}
	m = append(m, 0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, byte(len(rd)))
	m = append(m, rd...)
	m = append(m, 0xC0, byte(12+len(q)+12), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
	got := cnameTargets(m)
	if len(got) != 1 || got[0] != "a.tracker.net" {
		t.Errorf("cname targets %v", got)
	}
	if cnameTargets(m[:30]) != nil && len(cnameTargets(m[:30])) > 1 {
		t.Error("truncated message must not panic or invent names")
	}
	cnameTargets(nil)
	cnameTargets([]byte{1, 2, 3})
}
