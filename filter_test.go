package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHosts(t *testing.T) {
	in := `# a header
127.0.0.1 localhost
127.0.0.1 localhost.localdomain
255.255.255.255 broadcasthost
::1 ip6-localhost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com
0.0.0.0 Tracker.Example.NET # tracking
0.0.0.0 a.example.org b.example.org  # two names on one line
0.0.0.0 not_a_host_with_no_dot
0.0.0.0 bad!char.example.com

garbage line without an ip
`
	names, err := parseList(strings.NewReader(in), "hosts")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]struct{}{}
	for _, n := range names {
		set[n] = struct{}{}
	}
	for _, want := range []string{"ads.example.com", "tracker.example.net", "a.example.org", "b.example.org"} {
		if _, ok := set[want]; !ok {
			t.Errorf("missing %q", want)
		}
	}
	for _, bad := range []string{"localhost", "broadcasthost", "0.0.0.0", "ip6-localhost", "not_a_host_with_no_dot", "bad!char.example.com"} {
		if _, ok := set[bad]; ok {
			t.Errorf("should have skipped %q", bad)
		}
	}
	if len(names) != 4 {
		t.Errorf("want 4 entries, got %d: %v", len(names), names)
	}
}

func TestParseDomains(t *testing.T) {
	in := "# Version: 1\n\n0-02.net\n*.wild.example.com\n||adblock.example.org^\nUPPER.Example.Com\nlocalhost\n1.2.3.4\nhas space.example.com\n"
	names, _ := parseList(strings.NewReader(in+"0-02.net\n"), "domains") // a repeated name counts once
	set := newHashSet(names)
	for _, want := range []string{"0-02.net", "wild.example.com", "adblock.example.org", "upper.example.com"} {
		if !set.has(want) {
			t.Errorf("missing %q in %v", want, names)
		}
	}
	if len(names) != 4 || len(set) != 4 {
		t.Errorf("want 4, got %d names and %d hashes: %v", len(names), len(set), names)
	}
}

func TestSuffixHit(t *testing.T) {
	set := newHashSet([]string{"example.com", "com"})
	for name, want := range map[string]bool{
		"example.com": true, "a.example.com": true, "x.y.example.com": true,
		"other.com":      false, // the bare TLD "com" in the set must never act as a wildcard
		"notexample.com": false, "com": true, "example.org": false,
	} {
		if got := suffixHit(set.has, name); got != want {
			t.Errorf("suffixHit(%q) = %v want %v", name, got, want)
		}
	}
}

func testFilter(t *testing.T) *Filter {
	f := NewFilter(t.TempDir())
	testSetList(f, defaultLists[0], []string{"wild.example.com", "ads.shared.net"}, "", "")
	testSetList(f, defaultLists[1], []string{"exact.example.org", "ads.shared.net"}, "", "")
	return f
}

func TestMatchModes(t *testing.T) {
	f := testFilter(t)
	now := time.Now()
	check := func(mode, name string, want bool, wantList string) {
		t.Helper()
		f.SetMode(mode)
		got, list := f.Match(name, now)
		if got != want || (want && list != wantList) {
			t.Errorf("mode %s: %s -> %v/%s, want %v/%s", mode, name, got, list, want, wantList)
		}
	}
	check("oisd", "wild.example.com", true, "oisd")
	check("oisd", "sub.wild.example.com", true, "oisd") // wildcard list covers subdomains
	check("oisd", "exact.example.org", false, "")
	check("stevenblack", "exact.example.org", true, "stevenblack")
	check("stevenblack", "sub.exact.example.org", false, "") // exact list does not
	check("stevenblack", "wild.example.com", false, "")
	check("both", "wild.example.com", true, "oisd")
	check("both", "exact.example.org", true, "stevenblack")
	check("both", "ads.shared.net", true, "oisd")
	check("off", "wild.example.com", false, "")
	check("both", "innocent.example.net", false, "")
	if err := f.SetMode("nonsense"); err == nil {
		t.Error("a bad mode was accepted")
	}
}

func TestAllowAndPause(t *testing.T) {
	f := testFilter(t)
	f.SetMode("both")
	now := time.Now()
	if err := f.AllowAdd("Wild.Example.com"); err != nil {
		t.Fatal(err)
	}
	if b, _ := f.Match("wild.example.com", now); b {
		t.Error("allow-listed name still blocked")
	}
	if b, _ := f.Match("deep.sub.wild.example.com", now); b {
		t.Error("allow-list must cover subdomains")
	}
	if b, _ := f.Match("exact.example.org", now); !b {
		t.Error("an unrelated block disappeared")
	}
	f.AllowRemove("wild.example.com")
	if b, _ := f.Match("wild.example.com", now); !b {
		t.Error("removal from the allow-list did not re-block")
	}
	if err := f.AllowAdd("not a domain"); err == nil {
		t.Error("garbage accepted into the allow-list")
	}
	f.Pause(5 * time.Minute)
	if b, _ := f.Match("wild.example.com", now); b || f.PausedUntil().IsZero() {
		t.Error("pause did not switch the filter off")
	}
	if b, _ := f.Match("wild.example.com", now.Add(6*time.Minute)); !b {
		t.Error("filter did not come back after the pause ended")
	}
	f.Resume()
	if b, _ := f.Match("wild.example.com", time.Now()); !b || !f.PausedUntil().IsZero() {
		t.Error("resume did not re-enable the filter")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	f := NewFilter(dir)
	names := []string{"other.example.com", "wild.example.com"}
	if err := writeList(filepath.Join(dir, "oisd.list"), names); err != nil {
		t.Fatal(err)
	}
	testSetList(f, defaultLists[0], names, `"etag1"`, "Mon, 01 Jan 2026")
	f.SetMode("oisd")
	f.AllowAdd("keep.example.com")

	g := NewFilter(dir) // a fresh process
	g.Load()
	if g.Mode() != "on" || len(g.EnabledLists()) != 1 || g.EnabledLists()[0] != "oisd" { // the legacy "oisd" mode is stored as on + one enabled list
		t.Errorf("mode not restored: %s %v", g.Mode(), g.EnabledLists())
	}
	if b, _ := g.Match("sub.wild.example.com", time.Now()); !b {
		t.Error("list not reloaded from disk")
	}
	if a := g.AllowList(); len(a) != 1 || a[0] != "keep.example.com" {
		t.Errorf("allow-list not restored: %v", a)
	}
	l := g.Lists()
	if jb, _ := json.Marshal(l[0]); l[0].Entries != 2 || strings.Contains(string(jb), "etag1") { // the etag must not leak into the public JSON
		t.Errorf("list view: %+v / %s", l[0], jb)
	}
	g.mu.RLock()
	etag := g.lists["oisd"].ETag
	g.mu.RUnlock()
	if etag != `"etag1"` {
		t.Errorf("etag not restored: %q", etag)
	}
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{broken"), 0o644) // a corrupt state file must not break startup
	h := NewFilter(dir)
	h.Load()
	if got := h.EnabledLists(); h.Mode() != "on" || len(got) != 2 { // a fresh install: on, with the two default lists
		t.Errorf("default after corrupt state: %s %v", h.Mode(), got)
	}
}

func TestPerDeviceMode(t *testing.T) {
	f := testFilter(t)
	f.SetMode("both")
	now := time.Now()
	if err := f.SetDeviceMode("192.168.1.40", "off"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetDeviceMode("192.168.1.20", "stevenblack"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		client, name string
		want         bool
	}{
		{"192.168.1.40", "wild.example.com", false}, // this device has the filter off
		{"192.168.1.20", "wild.example.com", false}, // stevenblack only: the OISD name passes
		{"192.168.1.20", "exact.example.org", true}, // and its own list still blocks
		{"192.168.1.99", "wild.example.com", true},  // everyone else: the default (both)
		{"", "wild.example.com", true},               // no attribution: the default
	} {
		if got, _ := f.MatchFor(c.client, c.name, now); got != c.want {
			t.Errorf("%s %s: blocked=%v want %v", c.client, c.name, got, c.want)
		}
	}
	f.Pause(time.Minute) // a global pause beats every override
	if b, _ := f.MatchFor("192.168.1.20", "exact.example.org", now); b {
		t.Error("pause did not switch an overridden device off")
	}
	f.Resume()
	if f.SetDeviceMode("not-an-ip", "off") == nil || f.SetDeviceMode("192.168.1.5", "bogus") == nil {
		t.Error("bad input accepted")
	}
	g := NewFilter(f.dir) // survives a restart
	g.Load()
	if m := g.DeviceModes(); m["192.168.1.40"] != "off" || m["192.168.1.20"] != "stevenblack" || len(m) != 2 {
		t.Errorf("not restored: %v", m)
	}
	f.SetDeviceMode("192.168.1.40", "default")
	if _, ok := f.DeviceModes()["192.168.1.40"]; ok {
		t.Error("default did not remove the override")
	}
}

func TestHashSet(t *testing.T) {
	var names []string
	for i := 0; i < 50000; i++ {
		names = append(names, fmt.Sprintf("host%d.tracker%d.example.com", i, i%97))
	}
	set := newHashSet(append(names, names[:1000]...)) // duplicates collapse
	if len(set) != 50000 {
		t.Fatalf("want 50000 hashes, got %d", len(set))
	}
	for _, n := range names {
		if !set.has(n) {
			t.Fatalf("lost %q", n)
		}
	}
	for i := 0; i < 50000; i++ {
		if n := fmt.Sprintf("absent%d.other.example.net", i); set.has(n) {
			t.Fatalf("false hit for %q", n)
		}
	}
	if (hashSet)(nil).has("example.com") || newHashSet(nil).has("example.com") {
		t.Error("an empty set must hold nothing")
	}
}

// testSetList publishes a list from names (the old setList, now over the streaming path's types).
func testSetList(f *Filter, sp listSpec, names []string, etag, lastmod string) {
	f.setListSet(sp, newHashSet(names), etag, lastmod)
}

func TestCatalogEnableExplainAndGlobAllow(t *testing.T) {
	f := testFilter(t)
	testSetList(f, defaultLists[2], []string{"pro-only.example.net"}, "", "") // hagezi-pro: downloaded but not enabled
	now := time.Now()
	if b, _ := f.MatchFor("192.168.1.2", "pro-only.example.net", now); b {
		t.Fatal("a list that is not enabled must not block")
	}
	f.SetDeviceMode("192.168.1.9", "strict") // strict = every downloaded list
	if b, by := f.MatchFor("192.168.1.9", "pro-only.example.net", now); !b || by != "hagezi-pro" {
		t.Errorf("strict: %v %q", b, by)
	}
	if err := f.SetListEnabled("hagezi-pro", true); err != nil {
		t.Fatal(err)
	}
	if b, by := f.MatchFor("192.168.1.2", "pro-only.example.net", now); !b || by != "hagezi-pro" {
		t.Errorf("enabled: %v %q", b, by)
	}
	if f.SetListEnabled("nonsense", true) == nil {
		t.Error("unknown list accepted")
	}
	if _, err := f.custom.Add("*.evil.test", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if d := f.Explain("192.168.1.2", "a.evil.test", now); d.Result != "blocked" || d.By != "custom" || d.Detail != "*.evil.test" {
		t.Errorf("explain custom: %+v", d)
	}
	if b, _ := f.MatchFor("127.0.0.1", "a.evil.test", now); b {
		t.Error("the router's own lookups are exempt from custom rules")
	}
	f.AllowAdd("*.good.evil.test")
	if d := f.Explain("192.168.1.2", "x.good.evil.test", now); d.Result != "allowed" {
		t.Errorf("a wildcard allow-list entry must win: %+v", d)
	}
	f.SetMode("off")
	if d := f.Explain("192.168.1.2", "a.evil.test", now); d.Result != "filter off" {
		t.Errorf("off: %+v", d)
	}
}

func TestCompileStream(t *testing.T) {
	dir := t.TempDir()
	in := "# c\n127.0.0.1 localhost\n0.0.0.0 ads.one.com\n0.0.0.0 ads.one.com two.com # dup\n"
	h, err := compileStream(strings.NewReader(in), "hosts", filepath.Join(dir, "x.list"), 10)
	if err != nil || len(h) != 2 {
		t.Fatalf("%d %v", len(h), err)
	}
	if !h.has("two.com") || h.has("localhost") {
		t.Error("membership wrong")
	}
	g, err := loadCompiled(filepath.Join(dir, "x.list"), 10)
	if err != nil || len(g) != 2 {
		t.Errorf("reload %d %v", len(g), err)
	}
	if _, err := compileStream(strings.NewReader(in), "hosts", filepath.Join(dir, "y.list"), 1); err == nil {
		t.Error("the per-list cap must stop a runaway download")
	}
}
