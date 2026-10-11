package main

// The keyless engines for the search page (search.go). Each one fetches a single page and reads it with a real HTML parser, never regular expressions on markup. A parser returns what it
// found in the engine's own order; the merge ranks across engines. Engines that turn this box away (a CAPTCHA, a block) are reported as such on the page and the others carry on.
// Checked against live pages on 2026-10-11. Mojeek, Marginalia and Startpage were tried and refused that client (Startpage redirects straight to a CAPTCHA page), so they are not here;
// adding one is a searchEngine entry and a parser. Wolfram|Alpha has no keyless official API; fetchWolfram instead calls the same undocumented endpoint the wolframalpha.com site itself
// uses (SearXNG's wolframalpha_noapi approach) — it can stop working without notice, and on this network the token endpoint has timed out rather than answered.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	nethtml "golang.org/x/net/html"
)

// Category is "" (meaning catWeb) for a text-result engine, or one of the other searchCategories for images/video/maps; engineCategory reads it with the "" default applied.
type searchEngine struct {
	ID, Name, Category string
	fetch              func(ctx context.Context, c *http.Client, q string) ([]searchResult, error)
}

var searchEngines = []searchEngine{
	{ID: "wikipedia", Name: "Wikipedia", fetch: wikiFetch("en.wikipedia.org")},
	{ID: "duckduckgo", Name: "DuckDuckGo", fetch: fetchDDG},
	{ID: "wiby", Name: "Wiby", fetch: fetchWiby},
	{ID: "brave", Name: "Brave", fetch: fetchBrave},
	{ID: "hackernews", Name: "Hacker News", fetch: fetchHN},
	{ID: "stackexchange", Name: "Stack Overflow", fetch: fetchStackExchange},
	{ID: "github", Name: "GitHub", fetch: fetchGitHub},
	{ID: "wikidata", Name: "Wikidata", fetch: wikiFetch("www.wikidata.org")},
	{ID: "wiktionary", Name: "Wiktionary", fetch: wikiFetch("en.wiktionary.org")},
	{ID: "wikiquote", Name: "Wikiquote", fetch: wikiFetch("en.wikiquote.org")},
	{ID: "wikibooks", Name: "Wikibooks", fetch: wikiFetch("en.wikibooks.org")},
	{ID: "wikisource", Name: "Wikisource", fetch: wikiFetch("en.wikisource.org")},
	{ID: "wolfram", Name: "Wolfram|Alpha", fetch: fetchWolfram},
	{ID: "openverse", Name: "Openverse", Category: catImages, fetch: fetchOpenverse},
	{ID: "iavideo", Name: "Internet Archive video", Category: catVideo, fetch: fetchIAVideo},
	{ID: "osm", Name: "OpenStreetMap", Category: catMaps, fetch: fetchNominatim},
}

const (
	browserUA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
	wikiUA    = "PillowForrT-search/1 (self-hosted metasearch on a hotspot)"
	maxPerEng = 12
	maxSnip   = 260
)

// ---- HTML helpers ----

func hasClass(n *nethtml.Node, c string) bool {
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, t := range strings.Fields(a.Val) {
				if t == c {
					return true
				}
			}
		}
	}
	return false
}

func attrOf(n *nethtml.Node, k string) string {
	for _, a := range n.Attr {
		if a.Key == k {
			return a.Val
		}
	}
	return ""
}

// walkNodes visits n and its descendants in document order; returning false skips a node's children.
func walkNodes(n *nethtml.Node, fn func(*nethtml.Node) bool) {
	if !fn(n) {
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkNodes(c, fn)
	}
}

func textOf(n *nethtml.Node) string {
	var b strings.Builder
	walkNodes(n, func(x *nethtml.Node) bool {
		switch {
		case x.Type == nethtml.TextNode:
			b.WriteString(x.Data)
		case x.Type == nethtml.ElementNode && (x.Data == "script" || x.Data == "style"):
			return false
		case x.Type == nethtml.ElementNode && x.Data == "br":
			b.WriteByte(' ')
		}
		return true
	})
	return clip(strings.Join(strings.Fields(b.String()), " "), maxSnip)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

func firstDesc(n *nethtml.Node, match func(*nethtml.Node) bool) *nethtml.Node {
	var found *nethtml.Node
	walkNodes(n, func(x *nethtml.Node) bool {
		if found != nil {
			return false
		}
		if x.Type == nethtml.ElementNode && match(x) {
			found = x
			return false
		}
		return true
	})
	return found
}

// ---- The Wikimedia family (every wiki.org project shares this search API; wikidata's "titles" are Q-ids, which happen to round-trip through the same /wiki/<title> URL shape) ----

func wikiFetch(host string) func(context.Context, *http.Client, string) ([]searchResult, error) {
	return func(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
		u := "https://" + host + "/w/api.php?action=query&list=search&format=json&srlimit=8&srprop=snippet&srsearch=" + url.QueryEscape(q)
		b, err := searchGet(ctx, c, u, wikiUA, "application/json")
		if err != nil {
			return nil, err
		}
		return parseWikiSearch(b, host)
	}
}

func parseWikiSearch(b []byte, host string) ([]searchResult, error) {
	var d struct {
		Query struct {
			Search []struct {
				Title   string `json:"title"`
				Snippet string `json:"snippet"`
			} `json:"search"`
		} `json:"query"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, r := range d.Query.Search {
		doc, err := nethtml.Parse(strings.NewReader(r.Snippet))
		snip := r.Snippet
		if err == nil {
			snip = textOf(doc)
		}
		out = append(out, searchResult{Title: r.Title, URL: "https://" + host + "/wiki/" + url.PathEscape(strings.ReplaceAll(r.Title, " ", "_")), Snippet: snip})
	}
	return out, nil
}

// parseWikipedia is kept as a named entry point for the Wikipedia fixture test; every other wiki shares parseWikiSearch directly.
func parseWikipedia(b []byte) ([]searchResult, error) { return parseWikiSearch(b, "en.wikipedia.org") }

// ---- DuckDuckGo (the HTML page) ----

func fetchDDG(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://html.duckduckgo.com/html/?q="+url.QueryEscape(q), browserUA, "text/html")
	if err != nil {
		return nil, err
	}
	return parseDDG(b)
}

// ddgTarget unwraps DuckDuckGo's redirect link (//duckduckgo.com/l/?uddg=<target>) to the page it points at; "" for anything else of theirs (an ad's click tracker).
func ddgTarget(href string) string {
	if strings.HasPrefix(href, "//") {
		href = "https:" + href
	}
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	if strings.HasSuffix(u.Hostname(), "duckduckgo.com") {
		if u.Path == "/l/" {
			return u.Query().Get("uddg")
		}
		return ""
	}
	return href
}

func parseDDG(b []byte) ([]searchResult, error) {
	if strings.Contains(string(b), "anomaly-modal") {
		return nil, errors.New("blocked (CAPTCHA)")
	}
	doc, err := nethtml.Parse(strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	var out []searchResult
	walkNodes(doc, func(n *nethtml.Node) bool {
		if n.Type != nethtml.ElementNode || n.Data != "div" || !hasClass(n, "result") {
			return true
		}
		if hasClass(n, "result--ad") || len(out) >= maxPerEng {
			return false
		}
		a := firstDesc(n, func(x *nethtml.Node) bool { return x.Data == "a" && hasClass(x, "result__a") })
		if a == nil {
			return false
		}
		target := ddgTarget(attrOf(a, "href"))
		if target == "" {
			return false
		}
		r := searchResult{Title: textOf(a), URL: target}
		if s := firstDesc(n, func(x *nethtml.Node) bool { return hasClass(x, "result__snippet") }); s != nil {
			r.Snippet = textOf(s)
		}
		out = append(out, r)
		return false
	})
	return out, nil
}

// ---- Wiby (the small web) ----

func fetchWiby(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://wiby.me/?q="+url.QueryEscape(q), browserUA, "text/html")
	if err != nil {
		return nil, err
	}
	return parseWiby(b)
}

func parseWiby(b []byte) ([]searchResult, error) {
	doc, err := nethtml.Parse(strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	var out []searchResult
	walkNodes(doc, func(n *nethtml.Node) bool {
		if n.Type != nethtml.ElementNode || n.Data != "blockquote" {
			return true
		}
		if len(out) >= maxPerEng {
			return false
		}
		a := firstDesc(n, func(x *nethtml.Node) bool { return x.Data == "a" && hasClass(x, "tlink") })
		if a == nil {
			return false
		}
		r := searchResult{Title: textOf(a), URL: attrOf(a, "href")}
		if p := firstDesc(n, func(x *nethtml.Node) bool { return x.Data == "p" && !hasClass(x, "url") }); p != nil {
			r.Snippet = textOf(p)
		}
		out = append(out, r)
		return false
	})
	return out, nil
}

// ---- Brave Search (the server-rendered results page; it is a Svelte app, but the first response already carries the results) ----

func fetchBrave(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://search.brave.com/search?q="+url.QueryEscape(q), browserUA, "text/html")
	if err != nil {
		return nil, err
	}
	return parseBrave(b)
}

func parseBrave(b []byte) ([]searchResult, error) {
	s := string(b)
	if !strings.Contains(s, `id="mixed-main"`) {
		return nil, errors.New("blocked (no results container)")
	}
	doc, err := nethtml.Parse(strings.NewReader(s))
	if err != nil {
		return nil, err
	}
	var out []searchResult
	walkNodes(doc, func(n *nethtml.Node) bool {
		if n.Type != nethtml.ElementNode || n.Data != "div" || !hasClass(n, "snippet") {
			return true
		}
		if len(out) >= maxPerEng {
			return false
		}
		a := firstDesc(n, func(x *nethtml.Node) bool {
			href := attrOf(x, "href")
			return x.Data == "a" && strings.HasPrefix(href, "http") && !strings.Contains(href, "search.brave.com")
		})
		if a == nil {
			return false
		}
		titleNode := firstDesc(a, func(x *nethtml.Node) bool { return hasClass(x, "title") })
		if titleNode == nil {
			titleNode = a
		}
		r := searchResult{Title: textOf(titleNode), URL: attrOf(a, "href")}
		if d := firstDesc(n, func(x *nethtml.Node) bool {
			return x.Data == "div" && (hasClass(x, "description") || hasClass(x, "content"))
		}); d != nil {
			r.Snippet = textOf(d)
		}
		out = append(out, r)
		return false
	})
	return out, nil
}

// ---- Hacker News (Algolia's search API over HN) ----

func fetchHN(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://hn.algolia.com/api/v1/search?query="+url.QueryEscape(q), wikiUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseHN(b)
}

func parseHN(b []byte) ([]searchResult, error) {
	var d struct {
		Hits []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			StoryText   string `json:"story_text"`
			CommentText string `json:"comment_text"`
			ObjectID    string `json:"objectID"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, h := range d.Hits {
		if len(out) >= maxPerEng {
			break
		}
		if h.Title == "" {
			continue
		}
		link := h.URL
		if link == "" {
			link = "https://news.ycombinator.com/item?id=" + h.ObjectID
		}
		snip := h.StoryText
		if snip == "" {
			snip = h.CommentText
		}
		if doc, err := nethtml.Parse(strings.NewReader(snip)); err == nil {
			snip = textOf(doc)
		}
		out = append(out, searchResult{Title: h.Title, URL: link, Snippet: snip})
	}
	return out, nil
}

// ---- Stack Exchange (the public API; the free, keyless quota is shared by IP across all of Stack Exchange's anonymous callers) ----

func fetchStackExchange(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	u := "https://api.stackexchange.com/2.3/search/advanced?order=desc&sort=relevance&site=stackoverflow&q=" + url.QueryEscape(q)
	b, err := searchGet(ctx, c, u, wikiUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseStackExchange(b)
}

func parseStackExchange(b []byte) ([]searchResult, error) {
	var d struct {
		Items []struct {
			Title       string `json:"title"`
			Link        string `json:"link"`
			IsAnswered  bool   `json:"is_answered"`
			AnswerCount int    `json:"answer_count"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for i, it := range d.Items {
		if i >= maxPerEng {
			break
		}
		snip := strconv.Itoa(it.AnswerCount) + " answers"
		if it.IsAnswered {
			snip += " (answered)"
		}
		out = append(out, searchResult{Title: html.UnescapeString(it.Title), URL: it.Link, Snippet: snip})
	}
	return out, nil
}

// ---- GitHub (unauthenticated repository search; a low, shared-IP rate limit, so this one errors out the most often) ----

func fetchGitHub(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://api.github.com/search/repositories?q="+url.QueryEscape(q), wikiUA, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	return parseGitHub(b)
}

func parseGitHub(b []byte) ([]searchResult, error) {
	var d struct {
		Items []struct {
			FullName    string `json:"full_name"`
			HTMLURL     string `json:"html_url"`
			Description string `json:"description"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for i, it := range d.Items {
		if i >= maxPerEng {
			break
		}
		out = append(out, searchResult{Title: it.FullName, URL: it.HTMLURL, Snippet: it.Description})
	}
	return out, nil
}

// ---- Wolfram|Alpha (the site's own json.jsp endpoint, reverse-engineered the way SearXNG's wolframalpha_noapi does it: no official app id, but a short-lived "proxycode" token read
// off the site itself first). This is the most fragile engine here — the token endpoint can simply stop answering, which shows up as a timeout on the page like any other dead engine. ----

var (
	wolframTokMu sync.Mutex
	wolframTok   string
	wolframTokAt time.Time
)

func wolframToken(ctx context.Context, c *http.Client) (string, error) {
	wolframTokMu.Lock()
	defer wolframTokMu.Unlock()
	if wolframTok != "" && time.Since(wolframTokAt) < time.Hour {
		return wolframTok, nil
	}
	b, err := searchGet(ctx, c, "https://www.wolframalpha.com/input/api/v1/code?ts="+strconv.FormatInt(time.Now().UnixNano(), 10), browserUA, "application/json")
	if err != nil {
		return "", err
	}
	var d struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(b, &d) != nil || d.Code == "" {
		return "", errors.New("no token")
	}
	wolframTok, wolframTokAt = d.Code, time.Now()
	return wolframTok, nil
}

// fetchWolfram bounds itself to 6s rather than riding the full per-search budget: the token endpoint either answers fast or, on this reverse-engineered path, hangs or 502s for seconds on
// end, and letting it do that would make this one unreliable engine set the wait time for every web search.
func fetchWolfram(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	tok, err := wolframToken(ctx, c)
	if err != nil {
		return nil, err
	}
	v := url.Values{
		"async": {"false"}, "banners": {"raw"}, "debuggingdata": {"false"},
		"format": {"plaintext"}, "formattimeout": {"8"}, "parsetimeout": {"5"}, "scantimeout": {"3"},
		"input": {q}, "output": {"JSON"}, "proxycode": {tok},
		"sponsorcategories": {"true"}, "statemethod": {"deploybutton"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.wolframalpha.com/input/json.jsp?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Referer", "https://www.wolframalpha.com/input/?i="+url.QueryEscape(q))
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	res, err := parseWolfram(b)
	if err != nil || len(res) == 0 {
		return res, err
	}
	res[0].URL = "https://www.wolframalpha.com/input/?i=" + url.QueryEscape(q)
	return res, nil
}

func parseWolfram(b []byte) ([]searchResult, error) {
	var d struct {
		QueryResult struct {
			Success bool `json:"success"`
			Pods    []struct {
				ID      string `json:"id"`
				Primary bool   `json:"primary"`
				Subpods []struct {
					Plaintext string `json:"plaintext"`
				} `json:"subpods"`
			} `json:"pods"`
		} `json:"queryresult"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	if !d.QueryResult.Success {
		return nil, nil // not an error: Wolfram understood the query fine, it just has no answer
	}
	var title, summary string
	for _, p := range d.QueryResult.Pods {
		if len(p.Subpods) == 0 {
			continue
		}
		text := strings.TrimSpace(p.Subpods[0].Plaintext)
		if text == "" {
			continue
		}
		if p.ID == "Input" {
			title = text
			continue
		}
		if title == "" {
			title = text
		}
		if summary == "" || p.Primary {
			summary = text
		}
	}
	if summary == "" {
		return nil, nil
	}
	if title == "" {
		title = summary
	}
	return []searchResult{{Title: "Wolfram|Alpha: " + clip(title, 80), Snippet: clip(summary, maxSnip)}}, nil
}

// ---- Openverse (openly-licensed images only — nothing copyrighted and unlicensed makes it into this index) ----

func fetchOpenverse(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	u := "https://api.openverse.org/v1/images/?format=json&page_size=" + strconv.Itoa(maxPerEng) + "&q=" + url.QueryEscape(q)
	b, err := searchGet(ctx, c, u, wikiUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseOpenverse(b)
}

func parseOpenverse(b []byte) ([]searchResult, error) {
	var d struct {
		Results []struct {
			Title             string `json:"title"`
			ForeignLandingURL string `json:"foreign_landing_url"`
			Thumbnail         string `json:"thumbnail"`
			Creator           string `json:"creator"`
			License           string `json:"license"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, r := range d.Results {
		if r.ForeignLandingURL == "" {
			continue
		}
		title := r.Title
		if title == "" {
			title = "Image"
		}
		snip := strings.ToUpper(r.License)
		if r.Creator != "" {
			snip = "by " + r.Creator + " · " + snip
		}
		out = append(out, searchResult{Title: title, URL: r.ForeignLandingURL, Thumb: r.Thumbnail, Snippet: snip})
	}
	return out, nil
}

// ---- Internet Archive's "movies" collection (the closest thing to a keyless video index; result quality trails a real video search since it is matching full-text, not metadata alone) ----

func fetchIAVideo(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	u := "https://archive.org/advancedsearch.php?output=json&rows=" + strconv.Itoa(maxPerEng) +
		"&fl[]=identifier&fl[]=title&fl[]=description&q=" + url.QueryEscape(q+" AND mediatype:movies")
	b, err := searchGet(ctx, c, u, wikiUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseIAVideo(b)
}

func parseIAVideo(b []byte) ([]searchResult, error) {
	var d struct {
		Response struct {
			Docs []struct {
				Identifier  string `json:"identifier"`
				Title       string `json:"title"`
				Description string `json:"description"`
			} `json:"docs"`
		} `json:"response"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, r := range d.Response.Docs {
		if r.Identifier == "" || r.Title == "" {
			continue
		}
		snip := r.Description
		if doc, err := nethtml.Parse(strings.NewReader(snip)); err == nil {
			snip = textOf(doc)
		}
		id := url.PathEscape(r.Identifier)
		out = append(out, searchResult{Title: r.Title, URL: "https://archive.org/details/" + id, Thumb: "https://archive.org/services/img/" + id, Snippet: snip})
	}
	return out, nil
}

// ---- OpenStreetMap's Nominatim (geocoding search; a shared public instance, so this one is the most rate-limited of all of them) ----

func fetchNominatim(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	u := "https://nominatim.openstreetmap.org/search?format=json&limit=" + strconv.Itoa(maxPerEng) + "&q=" + url.QueryEscape(q)
	b, err := searchGet(ctx, c, u, wikiUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseNominatim(b)
}

func parseNominatim(b []byte) ([]searchResult, error) {
	var d []struct {
		DisplayName string `json:"display_name"`
		Name        string `json:"name"`
		Lat         string `json:"lat"`
		Lon         string `json:"lon"`
		OSMType     string `json:"osm_type"`
		OSMID       int64  `json:"osm_id"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, r := range d {
		if r.DisplayName == "" {
			continue
		}
		title := r.Name
		if title == "" {
			title = r.DisplayName
		}
		link := "https://www.openstreetmap.org/" + r.OSMType + "/" + strconv.FormatInt(r.OSMID, 10)
		if r.Lat != "" && r.Lon != "" {
			link = "https://www.openstreetmap.org/?mlat=" + r.Lat + "&mlon=" + r.Lon + "#map=16/" + r.Lat + "/" + r.Lon
		}
		out = append(out, searchResult{Title: title, URL: link, Snippet: r.DisplayName})
	}
	return out, nil
}
