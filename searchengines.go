package main

// The keyless engines for the search page (search.go). Each one fetches a single page and reads it with a real HTML parser, never regular expressions on markup. A parser returns what it
// found in the engine's own order; the merge ranks across engines. Engines that turn this box away (a CAPTCHA, a block) are reported as such on the page and the others carry on.
// Checked against live pages on 2026-10-08. Mojeek and Marginalia were tried and refused that client, so they are not here; adding one is a searchEngine entry and a parser.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	nethtml "golang.org/x/net/html"
)

type searchEngine struct {
	ID, Name string
	Kind     string // kindWeb or kindMagnet: which tab of the page runs it
	fetch    func(ctx context.Context, c *http.Client, q string) ([]searchResult, error)
}

var searchEngines = []searchEngine{
	{ID: "wikipedia", Name: "Wikipedia", Kind: kindWeb, fetch: fetchWikipedia},
	{ID: "duckduckgo", Name: "DuckDuckGo", Kind: kindWeb, fetch: fetchDDG},
	{ID: "wiby", Name: "Wiby", Kind: kindWeb, fetch: fetchWiby},
	{ID: "yts", Name: "YTS", Kind: kindMagnet, fetch: fetchYTS},
	{ID: "eztv", Name: "EZTV", Kind: kindMagnet, fetch: fetchEZTV},
	{ID: "piratebay", Name: "Pirate Bay", Kind: kindMagnet, fetch: fetchBay},
	{ID: "nyaa", Name: "Nyaa", Kind: kindMagnet, fetch: fetchNyaa},
}

const (
	browserUA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
	wikiUA    = "StoneOfHeimdall-search/1 (self-hosted metasearch on a hotspot)"
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

// ---- Wikipedia (JSON API) ----

func fetchWikipedia(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	u := "https://en.wikipedia.org/w/api.php?action=query&list=search&format=json&srlimit=8&srprop=snippet&srsearch=" + url.QueryEscape(q)
	b, err := searchGet(ctx, c, u, wikiUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseWikipedia(b)
}

func parseWikipedia(b []byte) ([]searchResult, error) {
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
		out = append(out, searchResult{Title: r.Title, URL: "https://en.wikipedia.org/wiki/" + url.PathEscape(strings.ReplaceAll(r.Title, " ", "_")), Snippet: snip})
	}
	return out, nil
}

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
