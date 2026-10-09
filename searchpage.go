package main

// The search page (/search), the browser's search-engine descriptor (/opensearch.xml) and the settings API (/api/search). The page needs a login session like the rest. Every engine-supplied string is escaped by hand (renderSearch), and a link that is not http(s) never gets this far. The query is read from the URL and shown back; it is never logged or stored.

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const searchCSS = `<style>
:root{--bg:#f1e4c8;--fg:#3f2a18;--card:#f8f0dc;--mut:#7a5638;--ac:#7b502d;--onac:#fff;--bad:#a3322a;--warn:#a76a00;--ok:#2f7d3a;--ln:#d9c7a0}
@media(prefers-color-scheme:dark){:root{--bg:#1b130c;--fg:#ecd9b0;--card:#26190f;--mut:#b98b55;--ac:#d3a96e;--onac:#1b130c;--bad:#e8776a;--warn:#e0a84a;--ok:#7bc57f;--ln:#3a2a1a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:720px;margin:0 auto;padding:12px 16px 40px}
form{display:flex;gap:8px;align-items:center;margin:8px 0}
.mark{width:32px;height:32px;flex:none}
input{font:inherit;flex:1;min-width:0;min-height:44px;padding:0 12px;border:1px solid var(--ln);border-radius:22px;background:var(--card);color:var(--fg)}
button{font:inherit;min-height:44px;padding:0 18px;border:0;border-radius:22px;background:var(--ac);color:var(--onac);cursor:pointer}
.row{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.b{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border:1px solid var(--ln);border-radius:12px;font-size:12px;color:var(--mut)}
.b.bad{color:var(--bad);border-color:var(--bad)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok)}.dot.warn{background:var(--warn)}.dot.bad{background:var(--bad)}
.r{padding:12px 0;border-bottom:1px solid var(--ln)}.r:last-child{border:0}
.r a.t{color:var(--ac);font-size:17px;text-decoration:none;word-break:break-word}.r a.t:visited{color:var(--mut)}.r a.t:hover{text-decoration:underline}
.u{color:var(--mut);font-size:12px;word-break:break-all}.s{margin-top:2px}.e{color:var(--mut);font-size:11px;margin-top:2px}
.tabs{display:flex;gap:16px;margin:4px 0 0 44px}.tabs a{color:var(--mut);text-decoration:none;padding:4px 0}.tabs a.on{color:var(--fg);border-bottom:2px solid var(--ac)}
.err{color:var(--bad);margin:16px 0}a.home{color:var(--mut);text-decoration:none}
</style>`

// renderSearch writes the page. Every string that came from the URL or from an engine goes through html.EscapeString, and a result link has already passed normalizeResultURL
// (http or https only), so nothing here can open a tag or an attribute.
func tabOn(on bool) string {
	if on {
		return ` class="on"`
	}
	return ""
}

func hiddenKind(kind string) string {
	if kind == kindMagnet {
		return `<input type="hidden" name="t" value="m">`
	}
	return ""
}

func renderSearch(v searchView) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>`)
	if v.Q != "" {
		b.WriteString(e(v.Q) + " · ")
	}
	b.WriteString(`Search</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><link rel="search" type="application/opensearchdescription+xml" title="Heimdall search" href="/opensearch.xml">` + searchCSS + `</head><body><main>`)
	b.WriteString(`<div class="tabs"><a href="/search?q=` + url.QueryEscape(v.Q) + `"` + tabOn(v.Kind == kindWeb) + `>Web</a><a href="/search?t=m&q=` + url.QueryEscape(v.Q) + `"` + tabOn(v.Kind == kindMagnet) + `>Magnets</a></div><form action="/search" method="get" role="search">` + hiddenKind(v.Kind) + `<a href="/ui" class="home" title="Dashboard"><img class="mark" src="/favicon.svg" alt="Dashboard"></a><input name="q" value="` + e(v.Q) + `" aria-label="Search" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="200"`)
	if v.Q == "" {
		b.WriteString(" autofocus")
	}
	b.WriteString(`><button type="submit">Search</button></form><div class="row">`)
	b.WriteString(`<span class="b"><span class="dot ` + v.ProxyDot + `"></span>Proxy ` + e(v.ProxyLabel) + `</span><span class="b"><span class="dot ` + v.DNSDot + `"></span>DNS ` + e(v.DNSLabel) + `</span>`)
	for _, g := range v.Engines {
		if g.Err != "" {
			b.WriteString(`<span class="b bad" title="` + e(g.Err) + `">` + e(g.Name) + ` ✗ ` + e(g.Err) + `</span>`)
		} else {
			b.WriteString(`<span class="b">` + e(g.Name) + ` ` + strconv.Itoa(g.N) + `</span>`)
		}
	}
	b.WriteString(`</div>`)
	if v.Err != "" {
		b.WriteString(`<div class="err">` + e(v.Err))
		if v.Off {
			b.WriteString(` · <a href="/ui">Dashboard</a>`)
		}
		b.WriteString(`</div>`)
	} else if v.Q != "" && len(v.Results) == 0 {
		b.WriteString(`<div class="err">No results</div>`)
	}
	for _, r := range v.Results {
		if r.Magnet != "" { // built in buildMagnet from a checked hash, so it is a magnet: link and nothing else
			meta := "S " + strconv.Itoa(r.Seeds)
			if r.Size != "" {
				meta += " · " + r.Size
			}
			b.WriteString(`<div class="r"><a class="t" href="` + e(r.Magnet) + `">` + e(r.Title) + `</a><div class="u">` + e(meta))
			if r.URL != "" {
				b.WriteString(` · <a href="` + e(r.URL) + `" rel="noreferrer noopener">page</a>`)
			}
			b.WriteString(`</div><div class="e">` + e(strings.Join(r.Engines, " · ")) + `</div></div>`)
			continue
		}
		b.WriteString(`<div class="r"><a class="t" href="` + e(r.URL) + `" rel="noreferrer noopener">` + e(r.Title) + `</a><div class="u">` + e(r.URL) + `</div>`)
		if r.Snippet != "" {
			b.WriteString(`<div class="s">` + e(r.Snippet) + `</div>`)
		}
		b.WriteString(`<div class="e">` + e(strings.Join(r.Engines, " · ")) + `</div></div>`)
	}
	b.WriteString(`</main></body></html>`)
	return b.String()
}

type searchView struct {
	Kind                 string
	Q                    string
	Err                  string
	Off                  bool
	Results              []searchResult
	Engines              []engineStatus
	ProxyLabel, DNSLabel string
	ProxyDot, DNSDot     string
}

// pathDot colours a mode's dot: amber when a private path is used for the connection but the name is looked up directly (the name leaks), red when the path is down.
func (v *searchView) dots(cfg searchCfg, ready map[string]string) {
	v.ProxyLabel, v.DNSLabel = searchModeLabel(cfg.Proxy), searchModeLabel(cfg.DNS)
	if ready[cfg.Proxy] != "" {
		v.ProxyDot = "bad"
	}
	if ready[cfg.DNS] != "" {
		v.DNSDot = "bad"
	} else if cfg.DNS == spDirect && cfg.Proxy != spDirect {
		v.DNSDot = "warn"
	}
}

func (u *webUI) searchPage(w http.ResponseWriter, r *http.Request) {
	if u.auth.Session(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secureHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	m := searchMgrG
	if m == nil {
		http.NotFound(w, r)
		return
	}
	q := cleanQuery(r.URL.Query().Get("q"))
	kind := kindWeb
	if r.URL.Query().Get("t") == "m" {
		kind = kindMagnet
	}
	cfg := m.Config()
	v := searchView{Q: q, Kind: kind}
	v.dots(cfg, m.Ready())
	if !cfg.Enabled {
		v.Err, v.Off = "Search is off", true
	} else if q != "" {
		o := m.Search(r.Context(), q, kind)
		v.Err, v.Results, v.Engines = o.Err, o.Results, o.Engines
		if o.Busy {
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}
	io.WriteString(w, renderSearch(v))
}

func serveOpenSearch(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.ContainsAny(host, "<>&\"' ") {
		host = *uiHost
	}
	w.Header().Set("Content-Type", "application/opensearchdescription+xml")
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/"><ShortName>Heimdall search</ShortName>` +
		`<Description>Metasearch on the hotspot</Description><InputEncoding>UTF-8</InputEncoding><Image width="16" height="16" type="image/svg+xml">https://` + host + `/favicon.svg</Image>` +
		`<Url type="text/html" method="get" template="https://` + host + `/search?q={searchTerms}"/></OpenSearchDescription>`))
}

type searchAPIEngine struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	On   bool   `json:"on"`
	LAN  bool   `json:"lan,omitempty"`
	Host string `json:"host,omitempty"`
	Key  bool   `json:"key,omitempty"`
}

func searchAPIView(m *searchMgr) map[string]any {
	cfg := m.Config()
	var es []searchAPIEngine
	for _, e := range searchEngines {
		on := false
		for _, id := range cfg.Engines {
			if id == e.ID {
				on = true
			}
		}
		es = append(es, searchAPIEngine{ID: e.ID, Name: e.Name, Kind: e.Kind, On: on})
	}
	for _, t := range cfg.Torznab {
		host := ""
		if u, err := url.Parse(t.URL); err == nil {
			host = u.Host
		}
		es = append(es, searchAPIEngine{ID: "tz:" + t.Name, Name: t.Name, Kind: kindMagnet, On: t.On, LAN: true, Host: host, Key: t.Key != ""})
	}
	return map[string]any{"available": true, "enabled": cfg.Enabled, "proxy": cfg.Proxy, "dns": cfg.DNS, "engines": es, "ready": m.Ready()}
}

func handleSearchAPI(w http.ResponseWriter, r *http.Request, path string) {
	m := searchMgrG
	if m == nil {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	switch {
	case path == "search" && r.Method == http.MethodGet:
		writeJSON(w, 200, searchAPIView(m))
	case path == "search/set" && r.Method == http.MethodPost:
		var b searchSet
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b) != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := m.Set(b); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, searchAPIView(m))
	default:
		http.Error(w, "not found", 404)
	}
}
