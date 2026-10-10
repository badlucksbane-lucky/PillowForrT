package main

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseDDG(t *testing.T) {
	r, err := parseDDG(fixture(t, "search_ddg.html"))
	if err != nil || len(r) < 5 {
		t.Fatalf("got %d results, err %v", len(r), err)
	}
	if r[0].URL != "https://www.wireguard.com/protocol/" || !strings.Contains(r[0].Title, "WireGuard") || !strings.Contains(r[0].Snippet, "ChaCha20") {
		t.Fatalf("first result wrong: %+v", r[0])
	}
	for _, x := range r {
		if strings.Contains(x.URL, "duckduckgo.com") || strings.Contains(x.Snippet, "<b>") {
			t.Fatalf("redirect or markup left in %+v", x)
		}
	}
	if _, err := parseDDG([]byte(`<div class="anomaly-modal__title">x</div>`)); err == nil {
		t.Fatal("a CAPTCHA page should be an error")
	}
}

func TestParseWiby(t *testing.T) {
	r, err := parseWiby(fixture(t, "search_wiby.html"))
	if err != nil || len(r) < 5 {
		t.Fatalf("got %d results, err %v", len(r), err)
	}
	if r[0].URL != "https://alextsang.net/articles/20191012-080947/" || r[0].Title != "WireGuard on Alpine Linux with nftables" || r[0].Snippet == "" || strings.Contains(r[0].Snippet, "https://") {
		t.Fatalf("first result wrong: %+v", r[0])
	}
}

func TestParseWikipedia(t *testing.T) {
	r, err := parseWikipedia(fixture(t, "search_wikipedia.json"))
	if err != nil || len(r) < 3 {
		t.Fatalf("got %d results, err %v", len(r), err)
	}
	if r[0].URL != "https://en.wikipedia.org/wiki/WireGuard" || strings.Contains(r[0].Snippet, "<span") || !strings.HasPrefix(r[0].Snippet, "WireGuard is a communication protocol") {
		t.Fatalf("first result wrong: %+v", r[0])
	}
	if _, err := parseWikipedia([]byte("<html>")); err == nil {
		t.Fatal("garbage should be an error")
	}
}

func TestSearchPathReady(t *testing.T) {
	down := ownState{}
	up := ownState{MullvadWanted: true, TunnelUp: true, TorEnabled: true, TorReady: true, TorOverVPN: true}
	for _, m := range searchModes {
		if err := searchPathReady(m, up); err != nil {
			t.Errorf("%s with everything up: %v", m, err)
		}
	}
	if searchPathReady(spDirect, down) != nil {
		t.Error("direct needs nothing")
	}
	for _, m := range []string{spMullvad, spTor, spTorMullvad} {
		if searchPathReady(m, down) == nil {
			t.Errorf("%s should be refused with nothing up", m)
		}
	}
	s := up
	s.TorOverVPN = false
	if searchPathReady(spTorMullvad, s) == nil || searchPathReady(spTor, s) != nil {
		t.Error("Tor over Mullvad needs the Tor-over-Mullvad switch; plain Tor does not")
	}
	s = up
	s.TunnelUp = false
	if searchPathReady(spTorMullvad, s) == nil || searchPathReady(spMullvad, s) == nil || searchPathReady(spTor, s) != nil {
		t.Error("a down tunnel stops Mullvad and Tor over Mullvad, not Tor")
	}
}

func TestSearchFailsClosed(t *testing.T) {
	m := newSearchMgr("")
	m.state = func() ownState { return ownState{} }
	m.cfg.Enabled = true
	m.cfg.Proxy, m.cfg.DNS = spTor, spDirect
	o := m.Search(context.Background(), "x")
	if !strings.Contains(o.Err, "Proxy Tor") || len(o.Results) != 0 {
		t.Fatalf("proxy down: %+v", o)
	}
	m.cfg.Proxy, m.cfg.DNS = spDirect, spMullvad
	if o = m.Search(context.Background(), "x"); !strings.Contains(o.Err, "DNS Mullvad") {
		t.Fatalf("dns down: %+v", o)
	}
	m.cfg.Enabled = false
	if o = m.Search(context.Background(), "x"); o.Err != "Search is off" {
		t.Fatalf("off: %+v", o)
	}
}

func TestSearchDNS(t *testing.T) {
	q := searchDNSQuery("html.duckduckgo.com")
	if len(q) < 12 || q[5] != 1 || q[len(q)-4] != 0 || q[len(q)-3] != 1 {
		t.Fatalf("bad query %v", q)
	}
	if searchDNSQuery("a..b") != nil || searchDNSQuery("") != nil || searchDNSQuery(strings.Repeat("a", 64)+".com") != nil {
		t.Fatal("bad names must not make a query")
	}
	resp := buildAResponse("example.com", net.ParseIP("93.184.216.34"))
	ips, err := searchAnswer(resp)
	if err != nil || len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("%v %v", ips, err)
	}
	if _, err := searchAnswer(buildAResponse("example.com", net.ParseIP("192.168.1.20"))); err == nil {
		t.Fatal("a private answer must be refused")
	}
}

func TestMergeResults(t *testing.T) {
	engs := []searchEngine{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}}
	per := [][]searchResult{
		{{Title: "One", URL: "https://www.example.com/x/?utm_source=z#frag", Snippet: "short"}, {Title: "Two", URL: "https://two.example/"}},
		{{Title: "Two", URL: "https://two.example"}, {Title: "One", URL: "http://example.com/x?fbclid=1", Snippet: "a longer snippet"}, {Title: "Bad", URL: "javascript:alert(1)"}},
	}
	m := mergeResults(per, engs)
	if len(m) != 2 {
		t.Fatalf("want 2 merged, got %+v", m)
	}
	if m[0].Title != "One" && m[0].Title != "Two" {
		t.Fatal(m)
	}
	for _, r := range m {
		if len(r.Engines) != 2 {
			t.Fatalf("both engines should be credited: %+v", r)
		}
		if strings.Contains(r.URL, "utm_") || strings.Contains(r.URL, "#") || strings.Contains(r.URL, "fbclid") {
			t.Fatalf("tracking left in %s", r.URL)
		}
	}
	if m[0].Title == "One" && m[0].Snippet != "a longer snippet" {
		t.Fatalf("longest snippet should win: %+v", m[0])
	}
}

func TestSearchSettings(t *testing.T) {
	p := filepath.Join(t.TempDir(), "search.json")
	m := newSearchMgr(p)
	on, tor, bad := true, spTor, "carrier-pigeon"
	if m.Set(searchSet{Proxy: &bad}) == nil || m.Set(searchSet{Engine: "nope", On: &on}) == nil {
		t.Fatal("bad values must be refused")
	}
	if err := m.Set(searchSet{Enabled: &on, Proxy: &tor, DNS: &tor}); err != nil {
		t.Fatal(err)
	}
	off := false
	m.Set(searchSet{Engine: "wikipedia", On: &off})
	m.Set(searchSet{Engine: "wiby", On: &on})
	c := newSearchMgr(p).Config()
	if !c.Enabled || c.Proxy != spTor || c.DNS != spTor || strings.Join(c.Engines, ",") != "duckduckgo,wiby" {
		t.Fatalf("not saved or reloaded: %+v", c)
	}
	if cleanQuery("  a\tb \n c ") != "a b c" || cleanQuery(strings.Repeat("é", 500)) == "" || len([]rune(cleanQuery(strings.Repeat("é", 500)))) != searchMaxQuery {
		t.Fatal("cleanQuery")
	}
}

func TestSearchPageEscapes(t *testing.T) {
	engs := []searchEngine{{ID: "a", Name: "A"}}
	v := searchView{Q: `"><script>alert(1)</script>`, Results: mergeResults([][]searchResult{{
		{Title: `<img src=x onerror=1>`, URL: "javascript:alert(1)", Snippet: "<b>x</b>"},
		{Title: `<i>ok</i>`, URL: "https://example.com/a?b=1&c=2", Snippet: "<b>x</b>"},
	}}, engs), Engines: []engineStatus{{Name: "A", N: 2}, {Name: "B", Err: "blocked (CAPTCHA)"}}}
	out := renderSearch(v)
	for _, bad := range []string{"<script>alert", "<img src=x", "<b>x</b>", "<i>ok", "javascript:"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped %q in page", bad)
		}
	}
	if !strings.Contains(out, `href="https://example.com/a?b=1&amp;c=2"`) || !strings.Contains(out, "blocked (CAPTCHA)") {
		t.Errorf("good result or engine status missing:\n%s", out)
	}
}

func TestSearchAPI(t *testing.T) {
	old := searchMgrG
	defer func() { searchMgrG = old }()
	searchMgrG = newSearchMgr("")
	searchMgrG.state = func() ownState { return ownState{} }
	w := httptest.NewRecorder()
	handleSearchAPI(w, httptest.NewRequest("POST", "/api/search/set", strings.NewReader(`{"proxy":"tor","enabled":true}`)), "search/set")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"proxy":"tor"`) || !strings.Contains(w.Body.String(), `"tor":"Tor is not switched on"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handleSearchAPI(w, httptest.NewRequest("POST", "/api/search/set", strings.NewReader(`{"dns":"x"}`)), "search/set")
	if w.Code != 400 {
		t.Fatalf("bad mode accepted: %d", w.Code)
	}
}

func TestParseNyaa(t *testing.T) {
	r, err := parseNyaa(fixture(t, "search_nyaa.xml"))
	if err != nil || len(r) != 6 || r[0].Seeds == 0 || !nyaaHashRe.MatchString(r[0].Hash) || !strings.HasPrefix(r[0].URL, "https://nyaa.si/view/") || !strings.Contains(r[0].Size, "iB") {
		t.Fatalf("nyaa: %d %v %+v", len(r), err, r)
	}
	if r, _ := parseNyaa([]byte(`<rss><channel><item><title>x</title></item></channel></rss>`)); len(r) != 0 {
		t.Fatal("an item without a hash must be dropped")
	}
}

func TestNyaaRelayFailsClosed(t *testing.T) {
	m := newSearchMgr("")
	m.state = func() ownState { return ownState{} }
	if _, err := m.Nyaa(context.Background(), "x"); err == nil || err.Error() != "Search is off" {
		t.Fatalf("off: %v", err)
	}
	m.cfg.Enabled, m.cfg.Proxy = true, spTor
	if _, err := m.Nyaa(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "Proxy Tor") {
		t.Fatalf("path down: %v", err)
	}
}

func TestBrowsePolicy(t *testing.T) {
	w := httptest.NewRecorder()
	writeBrowse(w)
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "connect-src 'self' https://v3-cinemeta.strem.io", "https://graphql.anilist.co", "https://torrentio.strem.fun", "https://kitsu.io", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy lacks %q", want)
		}
	}
	if strings.Contains(csp, " * ") || strings.Contains(csp, "http:") || strings.Contains(csp, "'unsafe-eval'") {
		t.Error("policy is wider than the named sources (only 'wasm-unsafe-eval' and blob: workers, for the audio decoder)")
	}
	if !strings.Contains(w.Body.String(), "id=\"sheet\"") || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("page or headers wrong")
	}
	if strings.Contains(browseHTML, ".innerHTML") || strings.Contains(browseHTML, "document.write") || strings.Contains(browseHTML, "eval(") {
		t.Error("the page must build everything from text nodes: no innerHTML, document.write or eval")
	}
}
