package main

import (
	"context"
	"net"
	"net/http"
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
	o := m.Search(context.Background(), "x", kindWeb)
	if !strings.Contains(o.Err, "Proxy Tor") || len(o.Results) != 0 {
		t.Fatalf("proxy down: %+v", o)
	}
	m.cfg.Proxy, m.cfg.DNS = spDirect, spMullvad
	if o = m.Search(context.Background(), "x", kindWeb); !strings.Contains(o.Err, "DNS Mullvad") {
		t.Fatalf("dns down: %+v", o)
	}
	m.cfg.Enabled = false
	if o = m.Search(context.Background(), "x", kindWeb); o.Err != "Search is off" {
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

func TestMagnetParsers(t *testing.T) {
	y, err := parseYTS(fixture(t, "search_yts.json"))
	if err != nil || len(y) < 3 || y[0].Hash == "" || !strings.HasPrefix(y[0].Magnet, "magnet:?xt=urn:btih:"+y[0].Hash) || y[0].Size == "" || !strings.HasPrefix(y[0].URL, "https://") {
		t.Fatalf("yts: %d %v %+v", len(y), err, y)
	}
	z, err := parseEZTV(fixture(t, "search_eztv.json"), 0, 0)
	if err != nil || len(z) < 3 || z[0].Seeds < 0 || !validHash(z[0].Hash) {
		t.Fatalf("eztv: %d %v", len(z), err)
	}
	one, _ := parseEZTV(fixture(t, "search_eztv.json"), 1, 10)
	if len(one) == 0 || len(one) >= len(z) || !strings.Contains(one[0].Title, "S01E10") {
		t.Fatalf("eztv season filter: %d of %d", len(one), len(z))
	}
	bay, err := parseBay(fixture(t, "search_bay.json"))
	if err != nil || len(bay) < 3 || bay[0].Title != "Ubuntu 22.04 LTS" || bay[0].Hash != "2c6b6858d61da9543d4231a71db4b1c9264b0685" || bay[0].Seeds != 31 || bay[0].Size != "3.4 GB" {
		t.Fatalf("bay: %d %v %+v", len(bay), err, bay)
	}
	if r, _ := parseBay([]byte(`[{"id":"0","name":"No results returned","info_hash":"0000000000000000000000000000000000000000"}]`)); len(r) != 0 {
		t.Fatalf("the no-results row should be dropped: %+v", r)
	}
	ny, err := parseNyaa(fixture(t, "search_nyaa.xml"))
	if err != nil || len(ny) != 6 || ny[0].Seeds == 0 || !validHash(ny[0].Hash) || !strings.HasPrefix(ny[0].URL, "https://nyaa.si/view/") || !strings.Contains(ny[0].Size, "iB") {
		t.Fatalf("nyaa: %d %v %+v", len(ny), err, ny)
	}
}

func TestParseTorznab(t *testing.T) {
	r, err := parseTorznab(fixture(t, "search_torznab.xml"))
	if err != nil || len(r) != 2 {
		t.Fatalf("want 2 with a hash, got %d %v", len(r), err)
	}
	if r[0].Hash != "2c6b6858d61da9543d4231a71db4b1c9264b0685" || r[0].Seeds != 321 || r[0].Size != "5.7 GB" || r[0].URL != "https://tracker.example/details/1" {
		t.Fatalf("first: %+v", r[0])
	}
	if r[1].Hash != "a017ac9bf02de9e36f1f9177bdb60612186b0b0d" || r[1].Size != "1.0 MB" || r[1].URL != "" {
		t.Fatalf("second: %+v", r[1])
	}
	if _, err := parseTorznab(fixture(t, "search_torznab_error.xml")); err == nil || !strings.Contains(err.Error(), "Incorrect user credentials") {
		t.Fatalf("an error answer should be an error: %v", err)
	}
}

func TestMagnetBuild(t *testing.T) {
	m := buildMagnet("2C6B6858D61DA9543D4231A71DB4B1C9264B0685", "A & B <x>")
	if !strings.HasPrefix(m, "magnet:?xt=urn:btih:2c6b6858d61da9543d4231a71db4b1c9264b0685&dn=A+%26+B+%3Cx%3E&tr=") || hashFromMagnet(m) != "2c6b6858d61da9543d4231a71db4b1c9264b0685" {
		t.Fatalf("%s", m)
	}
	for _, bad := range []string{"", "zz", "2c6b6858d61da9543d4231a71db4b1c9264b068", "2c6b6858d61da9543d4231a71db4b1c9264b0685&x=y"} {
		if buildMagnet(bad, "n") != "" {
			t.Errorf("hash %q should not make a link", bad)
		}
	}
}

func TestMagnetMerge(t *testing.T) {
	engs := []searchEngine{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}}
	h := "2c6b6858d61da9543d4231a71db4b1c9264b0685"
	per := [][]searchResult{
		{{Title: "Ubuntu", Hash: h, Magnet: buildMagnet(h, "Ubuntu"), Seeds: 5}},
		{{Title: "Ubuntu again", Hash: h, Magnet: buildMagnet(h, "Ubuntu again"), Seeds: 50, URL: "https://x.example/p"}, {Title: "bad", Hash: "nothex"}},
	}
	m := mergeResults(per, engs)
	if len(m) != 1 || m[0].Seeds != 50 || len(m[0].Engines) != 2 || m[0].Magnet == "" {
		t.Fatalf("%+v", m)
	}
	out := renderSearch(searchView{Kind: kindMagnet, Q: "ubuntu", Results: m})
	if !strings.Contains(out, `href="magnet:?xt=urn:btih:`) || !strings.Contains(out, "S 50") || !strings.Contains(out, `class="on">Magnets`) {
		t.Fatalf("page: %s", out)
	}
}

func TestCheckTz(t *testing.T) {
	ok := tzEndpoint{Name: "Jackett", URL: "http://192.168.1.50:9117/api/v2.0/indexers/all/results/torznab/api", Key: "k"}
	if e, err := checkTz(ok, nil); err != nil || !e.On {
		t.Fatalf("good server refused: %v", err)
	}
	for name, e := range map[string]tzEndpoint{
		"https":    {Name: "A", URL: "https://192.168.1.50/x"},
		"name":     {Name: "A", URL: "http://jackett.lan:9117/x"},
		"public":   {Name: "A", URL: "http://8.8.8.8/x"},
		"loopback": {Name: "A", URL: "http://127.0.0.1:9117/x"},
		"badname":  {Name: "<b>", URL: "http://192.168.1.50/x"},
		"dupe":     {Name: "jackett", URL: "http://192.168.1.51/x"},
	} {
		if _, err := checkTz(e, []tzEndpoint{ok}); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}
}

func TestFetchTorznab(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		w.Write(fixture(t, "search_torznab.xml"))
	}))
	defer srv.Close()
	r, err := fetchTorznab(context.Background(), srv.Client(), tzEndpoint{URL: srv.URL + "/api", Key: "sec ret"}, "ubuntu 24")
	if err != nil || len(r) != 2 {
		t.Fatalf("%d %v", len(r), err)
	}
	if !strings.Contains(got, "t=search") || !strings.Contains(got, "q=ubuntu+24") || !strings.Contains(got, "apikey=sec+ret") {
		t.Fatalf("query was %q", got)
	}
}
