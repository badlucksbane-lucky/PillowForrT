package main

// Magnet engines for the Magnets tab of the search page (search.go): YTS, EZTV, the Pirate Bay's API and Nyaa over the chosen proxy and DNS, and Torznab servers on the LAN (Jackett,
// Prowlarr) over the plain LAN. Every result is reduced to an info hash and a title, and the magnet link is built here from those, so a link is never taken from an engine as given.
// Checked against live answers on 2026-10-08. YTS and EZTV change domains, so each tries a short list of mirrors. EZTV's API takes an IMDb id, not words, so the words are turned into an
// id first by IMDb's public suggestion lookup (that lookup goes by the same path, and IMDb sees the words). No cookies and no challenge solving: a site that wants either is left out.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	kindWeb    = "web"
	kindMagnet = "magnet"
	maxMagnets = 25
	tzMax      = 4
)

var magnetTrackers = []string{
	"udp://tracker.opentrackr.org:1337/announce", "udp://open.tracker.cl:1337/announce",
	"udp://tracker.torrent.eu.org:451/announce", "udp://exodus.desync.com:6969/announce",
}

var hashRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validHash(h string) bool { return hashRe.MatchString(h) }

// buildMagnet makes the link from a hash and a name; "" for a hash that is not 40 hex digits.
func buildMagnet(hash, name string) string {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !validHash(hash) {
		return ""
	}
	var b strings.Builder
	b.WriteString("magnet:?xt=urn:btih:" + hash + "&dn=" + url.QueryEscape(name))
	for _, t := range magnetTrackers {
		b.WriteString("&tr=" + url.QueryEscape(t))
	}
	return b.String()
}

// hashFromMagnet pulls the btih hash out of a magnet link, or "".
func hashFromMagnet(m string) string {
	u, err := url.Parse(m)
	if err != nil || u.Scheme != "magnet" {
		return ""
	}
	for _, xt := range u.Query()["xt"] {
		if h, ok := strings.CutPrefix(strings.ToLower(xt), "urn:btih:"); ok && validHash(h) {
			return h
		}
	}
	return ""
}

func torrentResult(name, hash string, seeds int, size string) (searchResult, bool) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	mg := buildMagnet(hash, name)
	if mg == "" || strings.TrimSpace(name) == "" {
		return searchResult{}, false
	}
	return searchResult{Title: name, Hash: hash, Magnet: mg, Seeds: seeds, Size: size}, true
}

func fmtSize(n int64) string {
	if n <= 0 {
		return ""
	}
	f, units := float64(n), []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

// firstMirror runs get against each mirror host in turn and returns the first answer.
func firstMirror(hosts []string, get func(host string) ([]byte, error)) ([]byte, error) {
	var last error
	for _, h := range hosts {
		b, err := get(h)
		if err == nil {
			return b, nil
		}
		last = err
	}
	return nil, last
}

// ---- YTS ----

var ytsHosts = []string{"yts.gg", "yts.bz", "yts.lt"}

func fetchYTS(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := firstMirror(ytsHosts, func(h string) ([]byte, error) {
		return searchGet(ctx, c, "https://"+h+"/api/v2/list_movies.json?limit=10&query_term="+url.QueryEscape(q), browserUA, "application/json")
	})
	if err != nil {
		return nil, err
	}
	return parseYTS(b)
}

func parseYTS(b []byte) ([]searchResult, error) {
	var d struct {
		Data struct {
			Movies []struct {
				TitleLong string `json:"title_long"`
				URL       string `json:"url"`
				Torrents  []struct {
					Hash      string `json:"hash"`
					Quality   string `json:"quality"`
					Type      string `json:"type"`
					Seeds     int    `json:"seeds"`
					SizeBytes int64  `json:"size_bytes"`
				} `json:"torrents"`
			} `json:"movies"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &d) != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, m := range d.Data.Movies {
		for _, t := range m.Torrents {
			r, ok := torrentResult(m.TitleLong+" ["+t.Quality+" "+t.Type+"]", t.Hash, t.Seeds, fmtSize(t.SizeBytes))
			if ok && len(out) < maxMagnets {
				r.URL = m.URL
				out = append(out, r)
			}
		}
	}
	return out, nil
}

// ---- EZTV ----

var eztvHosts = []string{"eztvx.to", "eztv.re", "eztv.wf"}
var seRe = regexp.MustCompile(`(?i)\bs(\d{1,2})\s*e(\d{1,3})\b`)

// imdbSeries finds the IMDb id (digits only) of the TV series that best matches words, through IMDb's keyless suggestion lookup.
func imdbSeries(ctx context.Context, c *http.Client, words string) (string, error) {
	w := strings.ToLower(strings.Join(strings.Fields(words), " "))
	if w == "" {
		return "", nil
	}
	first := "x"
	if w[0] >= 'a' && w[0] <= 'z' || w[0] >= '0' && w[0] <= '9' {
		first = w[:1]
	}
	b, err := searchGet(ctx, c, "https://v3.sg.media-imdb.com/suggestion/"+first+"/"+url.PathEscape(w)+".json", browserUA, "application/json")
	if err != nil {
		return "", err
	}
	var d struct {
		D []struct {
			ID  string `json:"id"`
			QID string `json:"qid"`
		} `json:"d"`
	}
	if json.Unmarshal(b, &d) != nil {
		return "", errors.New("unexpected answer from IMDb")
	}
	for _, x := range d.D {
		if (x.QID == "tvSeries" || x.QID == "tvMiniSeries") && strings.HasPrefix(x.ID, "tt") {
			return strings.TrimPrefix(x.ID, "tt"), nil
		}
	}
	return "", nil
}

func fetchEZTV(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	words, season, episode := strings.TrimSpace(seRe.ReplaceAllString(q, "")), 0, 0
	if m := seRe.FindStringSubmatch(q); m != nil {
		season, episode = atoi(m[1]), atoi(m[2])
	}
	id, err := imdbSeries(ctx, c, words)
	if err != nil || id == "" {
		return nil, err // no series by that name is no results, not a failure
	}
	b, err := firstMirror(eztvHosts, func(h string) ([]byte, error) {
		return searchGet(ctx, c, "https://"+h+"/api/get-torrents?limit=100&imdb_id="+id, browserUA, "application/json")
	})
	if err != nil {
		return nil, err
	}
	return parseEZTV(b, season, episode)
}

func parseEZTV(b []byte, season, episode int) ([]searchResult, error) {
	var d struct {
		Torrents []struct {
			Hash      string      `json:"hash"`
			Title     string      `json:"title"`
			Season    string      `json:"season"`
			Episode   string      `json:"episode"`
			Seeds     int         `json:"seeds"`
			SizeBytes json.Number `json:"size_bytes"`
		} `json:"torrents"`
	}
	if json.Unmarshal(b, &d) != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, t := range d.Torrents {
		if season > 0 && (atoi(t.Season) != season || atoi(t.Episode) != episode) {
			continue
		}
		n, _ := t.SizeBytes.Int64()
		if r, ok := torrentResult(t.Title, t.Hash, t.Seeds, fmtSize(n)); ok && len(out) < maxMagnets {
			out = append(out, r)
		}
	}
	return out, nil
}

// ---- The Pirate Bay (apibay) ----

func fetchBay(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://apibay.org/q.php?cat=0&q="+url.QueryEscape(q), browserUA, "application/json")
	if err != nil {
		return nil, err
	}
	return parseBay(b)
}

func parseBay(b []byte) ([]searchResult, error) {
	var raw []map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return nil, errors.New("unexpected answer")
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	var out []searchResult
	for _, m := range raw {
		if str(m, "id") == "0" { // "No results returned"
			continue
		}
		if r, ok := torrentResult(str(m, "name"), str(m, "info_hash"), atoi(str(m, "seeders")), fmtSize(int64(atoi(str(m, "size"))))); ok && len(out) < maxMagnets {
			out = append(out, r)
		}
	}
	return out, nil
}

// ---- Nyaa (RSS) ----

func fetchNyaa(ctx context.Context, c *http.Client, q string) ([]searchResult, error) {
	b, err := searchGet(ctx, c, "https://nyaa.si/?page=rss&q="+url.QueryEscape(q), browserUA, "application/rss+xml")
	if err != nil {
		return nil, err
	}
	return parseNyaa(b)
}

func parseNyaa(b []byte) ([]searchResult, error) {
	var d struct {
		Items []struct {
			Title    string `xml:"title"`
			GUID     string `xml:"guid"`
			Seeders  string `xml:"https://nyaa.si/xmlns/nyaa seeders"`
			InfoHash string `xml:"https://nyaa.si/xmlns/nyaa infoHash"`
			Size     string `xml:"https://nyaa.si/xmlns/nyaa size"`
		} `xml:"channel>item"`
	}
	if xml.Unmarshal(b, &d) != nil {
		return nil, errors.New("unexpected answer")
	}
	var out []searchResult
	for _, it := range d.Items {
		if r, ok := torrentResult(it.Title, it.InfoHash, atoi(it.Seeders), strings.TrimSpace(it.Size)); ok && len(out) < maxMagnets {
			r.URL = it.GUID
			out = append(out, r)
		}
	}
	return out, nil
}

// ---- Torznab servers on the LAN ----

type tzEndpoint struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Key  string `json:"key,omitempty"`
	On   bool   `json:"on"`
}

var tzNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,23}$`)

// checkTz validates a server to add: a short name, an http URL whose host is a LAN address written as numbers (so no name lookup is involved and it can only be on this network), and
// not this box. The key is kept in search.json (mode 0600) and never sent back to the page.
func checkTz(e tzEndpoint, have []tzEndpoint) (tzEndpoint, error) {
	e.Name, e.URL, e.Key = strings.TrimSpace(e.Name), strings.TrimSpace(e.URL), strings.TrimSpace(e.Key)
	if !tzNameRe.MatchString(e.Name) {
		return e, errors.New("the name is 1 to 24 letters, digits, spaces, dots, dashes")
	}
	if len(have) >= tzMax {
		return e, fmt.Errorf("%d servers is the limit", tzMax)
	}
	for _, h := range have {
		if strings.EqualFold(h.Name, e.Name) {
			return e, errors.New("that name is taken")
		}
	}
	u, err := url.Parse(e.URL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return e, errors.New("the address must start with http://")
	}
	ip := net.ParseIP(u.Hostname())
	switch {
	case ip == nil:
		return e, errors.New("use the server's LAN IP address, not a name")
	case !ip.IsPrivate() || !proxyDestOK(ip):
		return e, errors.New("that is not another machine on this LAN")
	case len(e.Key) > 128:
		return e, errors.New("the key is too long")
	}
	e.On = true
	return e, nil
}

// lanClient reaches the Torznab servers: plain dials, no proxy and no DNS choice (this traffic stays on the LAN), and the proxy guard still keeps it off this box's own addresses.
func (m *searchMgr) lanClient() *http.Client {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 20 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return guardedDial(ctx, "tcp", addr, true, lookupIP, dialUpstream)
		}}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func fetchTorznab(ctx context.Context, c *http.Client, e tzEndpoint, q string) ([]searchResult, error) {
	u := e.URL
	if strings.Contains(u, "?") {
		u += "&"
	} else {
		u += "?"
	}
	u += "t=search&extended=1&q=" + url.QueryEscape(q)
	if e.Key != "" {
		u += "&apikey=" + url.QueryEscape(e.Key)
	}
	b, err := searchGet(ctx, c, u, browserUA, "application/xml")
	if err != nil {
		return nil, err
	}
	return parseTorznab(b)
}

func parseTorznab(b []byte) ([]searchResult, error) {
	var d struct {
		XMLName xml.Name
		Code    string `xml:"code,attr"`
		Desc    string `xml:"description,attr"`
		Items   []struct {
			Title     string `xml:"title"`
			Link      string `xml:"link"`
			GUID      string `xml:"guid"`
			Size      int64  `xml:"size"`
			Enclosure struct {
				URL string `xml:"url,attr"`
			} `xml:"enclosure"`
			Attrs []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value,attr"`
			} `xml:"attr"`
		} `xml:"channel>item"`
	}
	if err := xml.Unmarshal(b, &d); err != nil {
		return nil, errors.New("unexpected answer")
	}
	if d.XMLName.Local == "error" {
		return nil, fmt.Errorf("server said: %s", clip(d.Desc, 80))
	}
	var out []searchResult
	for _, it := range d.Items {
		if len(out) >= maxMagnets {
			break
		}
		at := map[string]string{}
		for _, a := range it.Attrs {
			at[strings.ToLower(a.Name)] = a.Value
		}
		hash := strings.ToLower(at["infohash"])
		if !validHash(hash) {
			hash = hashFromMagnet(at["magneturl"])
		}
		if !validHash(hash) {
			hash = hashFromMagnet(it.Link)
		}
		size := it.Size
		if n, err := strconv.ParseInt(at["size"], 10, 64); err == nil && n > 0 {
			size = n
		}
		if r, ok := torrentResult(it.Title, hash, atoi(at["seeders"]), fmtSize(size)); ok {
			if strings.HasPrefix(it.GUID, "http") {
				r.URL = it.GUID
			}
			out = append(out, r)
		}
	}
	return out, nil
}
