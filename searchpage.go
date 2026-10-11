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
.err{color:var(--bad);margin:16px 0}a.home{color:var(--mut);text-decoration:none}
.tabs{display:flex;gap:4px;margin:4px 0 10px}.tabs a{padding:4px 12px;border-radius:14px;font-size:13px;text-decoration:none;color:var(--mut);border:1px solid var(--ln)}.tabs a.on{background:var(--ac);color:var(--onac);border-color:var(--ac)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px}.grid .c{display:block;text-decoration:none;color:var(--fg)}
.grid img{width:100%;height:110px;object-fit:cover;border-radius:8px;background:var(--card)}.grid .ct{font-size:12px;margin-top:4px;color:var(--mut);word-break:break-word}
.r img.th{width:96px;height:72px;object-fit:cover;border-radius:6px;float:left;margin-right:10px;background:var(--card)}.r::after{content:"";display:block;clear:both}
.b.pending{font-style:italic}
</style>`

// pfUpdateJS defines pfUpdate(o), called from a <script> chunk flushed after every engine answers (searchPage, below). It only ever uses textContent and element properties (.href,
// .src) on engine-supplied strings, never innerHTML, so there is nothing here for a hostile title or snippet to break out of; a result's .url has already passed normalizeResultURL
// (http or https only) before it ever reaches this JSON.
// pfStallMS is well above the server's own worst-case window for one search (15s direct/Mullvad, 40s Tor — circuits take time), so a dropped connection gets flagged as "stalled"
// without the normal slow-but-alive case of a search that is legitimately still running ever triggering it.
const pfStallMS = 55000

var pfUpdateJS = `<script>
var pfTimer=null;
function pfArm(){ clearTimeout(pfTimer); pfTimer=setTimeout(function(){
  var err=document.getElementById('err');
  if(!err.textContent) err.textContent='Connection stalled — try reloading';
}, ` + strconv.Itoa(pfStallMS) + `); }
pfArm();
function pfUpdate(o){
  if(o.done){ clearTimeout(pfTimer); } else { pfArm(); }
  document.getElementById('err').textContent = o.error || (o.done && (!o.results || !o.results.length) ? 'No results' : '');
  var eng=document.getElementById('engines');
  eng.textContent='';
  (o.engines||[]).forEach(function(g){
    var sp=document.createElement('span');
    sp.className='b'+(g.err?' bad':(!g.done?' pending':''));
    if(g.err){ sp.title=g.err; sp.textContent=g.name+' ✗ '+g.err; }
    else if(!g.done){ sp.textContent=g.name+' …'; }
    else { sp.textContent=g.name+' '+g.n; }
    eng.appendChild(sp);
  });
  var res=document.getElementById('results');
  res.textContent='';
  res.className=o.cat==='images'?'grid':'';
  (o.results||[]).forEach(function(r){
    if(o.cat==='images'){
      var a=document.createElement('a'); a.className='c'; a.href=r.url; a.rel='noreferrer noopener';
      if(r.thumb){ var im=document.createElement('img'); im.loading='lazy'; im.alt=''; im.src=r.thumb; a.appendChild(im); }
      var d=document.createElement('div'); d.className='ct'; d.textContent=r.title; a.appendChild(d);
      res.appendChild(a);
      return;
    }
    var row=document.createElement('div'); row.className='r';
    if(r.thumb){ var im=document.createElement('img'); im.className='th'; im.loading='lazy'; im.alt=''; im.src=r.thumb; row.appendChild(im); }
    var a=document.createElement('a'); a.className='t'; a.href=r.url; a.rel='noreferrer noopener'; a.textContent=r.title; row.appendChild(a);
    var u=document.createElement('div'); u.className='u'; u.textContent=r.url; row.appendChild(u);
    if(r.snippet){ var s=document.createElement('div'); s.className='s'; s.textContent=r.snippet; row.appendChild(s); }
    var en=document.createElement('div'); en.className='e'; en.textContent=(r.engines||[]).join(' · '); row.appendChild(en);
    res.appendChild(row);
  });
}
</script>`

// searchHead writes everything shared by renderSearch (one shot, used when there is nothing to search) and renderSearchShell (streamed live, below): the form, the status row and the
// category tabs. Every string that came from the URL goes through html.EscapeString, so nothing here can open a tag or an attribute.
func searchHead(v searchView) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>`)
	if v.Q != "" {
		b.WriteString(e(v.Q) + " · ")
	}
	b.WriteString(`Search</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><link rel="search" type="application/opensearchdescription+xml" title="PillowForrT search" href="/opensearch.xml">` + searchCSS + `</head><body><main>`)
	b.WriteString(`<form action="/search" method="get" role="search"><a href="/ui" class="home" title="Dashboard"><img class="mark" src="/favicon.svg" alt="Dashboard"></a><input name="q" value="` + e(v.Q) + `" aria-label="Search" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="200"`)
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
	b.WriteString(`<a class="b" href="/browse">Browse</a></div><div class="tabs">`)
	for _, c := range searchCategories {
		cls := ""
		if c == v.Cat {
			cls = ` class="on"`
		}
		b.WriteString(`<a href="/search?q=` + url.QueryEscape(v.Q) + `&cat=` + c + `"` + cls + `>` + catLabels[c] + `</a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// renderSearchShell writes the page with empty result/status placeholders: the live search itself streams in afterwards as a run of flushed <script>pfUpdate(...)</script> chunks
// (searchPage, below), so the browser shows the form and tabs at once and fills in engines/results as each one answers instead of waiting for the slowest.
func renderSearchShell(v searchView) string {
	var b strings.Builder
	b.WriteString(searchHead(v))
	b.WriteString(`<div id="err" class="err"></div><div id="engines" class="row"></div><div id="results"></div>`)
	b.WriteString(pfUpdateJS)
	b.WriteString(`</main></body></html>`)
	return b.String()
}

type liveResult struct {
	Title   string   `json:"title"`
	URL     string   `json:"url"`
	Snippet string   `json:"snippet"`
	Thumb   string   `json:"thumb,omitempty"`
	Engines []string `json:"engines"`
}

type liveSnapshot struct {
	Cat     string         `json:"cat"`
	Error   string         `json:"error"`
	Done    bool           `json:"done"`
	Engines []engineStatus `json:"engines"`
	Results []liveResult   `json:"results"`
}

// writeLiveSnapshot writes one <script>pfUpdate(...)</script> chunk for the browser to run as it arrives. json.Marshal escapes '<', '>' and '&' by default, so an engine's title or
// snippet containing a literal "</script>" cannot close the tag early — it comes out as </script> instead, inert as JSON text.
func writeLiveSnapshot(w io.Writer, o searchOutcome, final bool) {
	rs := make([]liveResult, 0, len(o.Results))
	for _, r := range o.Results {
		rs = append(rs, liveResult{r.Title, r.URL, r.Snippet, r.Thumb, r.Engines})
	}
	b, err := json.Marshal(liveSnapshot{Cat: o.Cat, Error: o.Err, Done: final, Engines: o.Engines, Results: rs})
	if err != nil {
		return
	}
	io.WriteString(w, "<script>pfUpdate(")
	w.Write(b)
	io.WriteString(w, ")</script>")
}

// renderSearch writes the whole page at once, including any results already known: used when there is nothing to search (search is off, or no query yet), so there is nothing to
// stream. Every string that came from the URL or from an engine goes through html.EscapeString, and a result link has already passed normalizeResultURL (http or https only), so
// nothing here can open a tag or an attribute.
func renderSearch(v searchView) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(searchHead(v))
	if v.Err != "" {
		b.WriteString(`<div class="err">` + e(v.Err))
		if v.Off {
			b.WriteString(` · <a href="/ui">Dashboard</a>`)
		}
		b.WriteString(`</div>`)
	} else if v.Q != "" && len(v.Results) == 0 {
		b.WriteString(`<div class="err">No results</div>`)
	}
	if v.Cat == catImages {
		b.WriteString(`<div class="grid">`)
		for _, r := range v.Results {
			b.WriteString(`<a class="c" href="` + e(r.URL) + `" rel="noreferrer noopener">`)
			if r.Thumb != "" {
				b.WriteString(`<img src="` + e(r.Thumb) + `" loading="lazy" alt="">`)
			}
			b.WriteString(`<div class="ct">` + e(r.Title) + `</div></a>`)
		}
		b.WriteString(`</div>`)
	} else {
		for _, r := range v.Results {
			b.WriteString(`<div class="r">`)
			if r.Thumb != "" {
				b.WriteString(`<img class="th" src="` + e(r.Thumb) + `" loading="lazy" alt="">`)
			}
			b.WriteString(`<a class="t" href="` + e(r.URL) + `" rel="noreferrer noopener">` + e(r.Title) + `</a><div class="u">` + e(r.URL) + `</div>`)
			if r.Snippet != "" {
				b.WriteString(`<div class="s">` + e(r.Snippet) + `</div>`)
			}
			b.WriteString(`<div class="e">` + e(strings.Join(r.Engines, " · ")) + `</div></div>`)
		}
	}
	b.WriteString(`</main></body></html>`)
	return b.String()
}

type searchView struct {
	Q                    string
	Cat                  string
	Err                  string
	Off                  bool
	Results              []searchResult
	Engines              []engineStatus
	ProxyLabel, DNSLabel string
	ProxyDot, DNSDot     string
}

var catLabels = map[string]string{catWeb: "Web", catImages: "Images", catVideo: "Video", catMaps: "Maps"}

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
		http.Redirect(w, r, loginURL(r.URL.Path), http.StatusSeeOther)
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
	cat := r.URL.Query().Get("cat")
	if !validSearchCategory(cat) {
		cat = catWeb
	}
	cfg := m.Config()
	v := searchView{Q: q, Cat: cat}
	v.dots(cfg, m.Ready())
	if !cfg.Enabled {
		v.Err, v.Off = "Search is off", true
		io.WriteString(w, renderSearch(v))
		return
	}
	if q == "" {
		io.WriteString(w, renderSearch(v))
		return
	}
	// A real query: show the form and tabs at once, then stream engines/results in as each one answers (SearchStream) instead of making the whole page wait for the slowest.
	// The status line this used to set for a busy rejection is gone — that case now just shows up as #err text like any other error, since the shell's 200 is already on the wire.
	io.WriteString(w, renderSearchShell(v))
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	m.SearchStream(r.Context(), q, cat, func(o searchOutcome, final bool) {
		writeLiveSnapshot(w, o, final)
		if fl != nil {
			fl.Flush()
		}
	})
}

func serveOpenSearch(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.ContainsAny(host, "<>&\"' ") {
		host = *uiHost
	}
	w.Header().Set("Content-Type", "application/opensearchdescription+xml")
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/"><ShortName>PillowForrT search</ShortName>` +
		`<Description>Metasearch on the hotspot</Description><InputEncoding>UTF-8</InputEncoding><Image width="16" height="16" type="image/svg+xml">https://` + host + `/favicon.svg</Image>` +
		`<Url type="text/html" method="get" template="https://` + host + `/search?q={searchTerms}"/></OpenSearchDescription>`))
}

type searchAPIEngine struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	On   bool   `json:"on"`
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
		es = append(es, searchAPIEngine{e.ID, e.Name, on})
	}
	v := map[string]any{"available": true, "enabled": cfg.Enabled, "proxy": cfg.Proxy, "dns": cfg.DNS, "engines": es, "ready": m.Ready()}
	if btMgrG != nil {
		v["bt"] = map[string]any{"enabled": btMgrG.Enabled(), "ready": btMgrG.Ready(), "upload": btMgrG.Upload()}
	}
	return v
}

func handleSearchAPI(w http.ResponseWriter, r *http.Request, path string) {
	if (path == "search/web" || path == "search/nyaa") && kidsNoSearch(w) {
		return
	}
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
	case path == "search/web" && r.Method == http.MethodGet:
		cat := r.URL.Query().Get("cat")
		if !validSearchCategory(cat) {
			cat = catWeb
		}
		o := m.Search(r.Context(), cleanQuery(r.URL.Query().Get("q")), cat)
		type res struct {
			Title   string   `json:"title"`
			URL     string   `json:"url"`
			Snippet string   `json:"snippet"`
			Thumb   string   `json:"thumb,omitempty"`
			Engines []string `json:"engines"`
		}
		rs := []res{}
		for _, x := range o.Results {
			rs = append(rs, res{x.Title, x.URL, x.Snippet, x.Thumb, x.Engines})
		}
		writeJSON(w, 200, map[string]any{"results": rs, "engines": o.Engines, "error": o.Err, "cat": cat})
	case path == "search/nyaa" && r.Method == http.MethodGet:
		items, err := m.Nyaa(r.Context(), cleanQuery(r.URL.Query().Get("q")))
		if err != nil {
			writeJSON(w, 200, map[string]any{"items": []nyaaItem{}, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	default:
		http.Error(w, "not found", 404)
	}
}
