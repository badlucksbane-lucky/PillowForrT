package main

// Age ratings for Kids mode. The Browse page fetches titles straight from Cinemeta and AniList, so the box never sees them; this is the box's lookup the page asks, and the one the server-side
// checks (kids.go, the torrent bridge) use. A title is allowed in Kids mode only when a rating was FOUND and is on the allowed list; everything else is hidden, which includes a title with no
// rating, a lookup that failed, and no TMDB key at all (it fails closed, and says why).
//
//   Movies and series (IMDb ids):  TMDB, https://api.themoviedb.org/3. /find/{imdb} gives the TMDB id and its adult flag, then the US certification: release_dates for a movie, content_ratings for a
//                                  series (one call each, with append_to_response). The key is in <tmdb-key-file>: a 32-character v3 key, or a long v4 read token (sent as a Bearer header). It is read
//                                  on every lookup, so dropping the file in needs no restart.
//   Anime (AniList ids):           AniList, https://graphql.anilist.co: hidden when isAdult, or when the genres include Hentai or Ecchi. AniList has no age rating, so anime is not "unrated".
// Requests leave through ownDial (the tunnel, Tor or the cellular link as the kill switch says; blocked when it says so), at most three at a time. Results are cached in memory and in <ratings-file>:
// a rating for 30 days, "no rating found" for 7, a failed lookup for 2 minutes only. The file is written at most every 10 minutes, and only when something changed.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ratingTTLFound   = 30 * 24 * time.Hour
	ratingTTLMissing = 7 * 24 * time.Hour
	ratingTTLFailed  = 2 * time.Minute
	ratingMaxEntries = 20000
	ratingMaxBatch   = 60
	ratingSlots      = 3
)

var (
	ratingIMDbRe  = regexp.MustCompile(`^tt[0-9]{5,10}$`)
	ratingAniRe   = regexp.MustCompile(`^[0-9]{1,9}$`)
	ratingAllowed = map[string]bool{"G": true, "PG": true, "PG-13": true, "TV-Y": true, "TV-Y7": true, "TV-Y7-FV": true, "TV-G": true, "TV-PG": true, "TV-14": true}
	// when a title has several US certifications the most restrictive one counts: a higher number is stricter
	ratingStrict = map[string]int{"G": 1, "TV-Y": 1, "TV-G": 1, "TV-Y7": 2, "TV-Y7-FV": 2, "PG": 3, "TV-PG": 3, "PG-13": 4, "TV-14": 4, "R": 5, "TV-MA": 6, "NC-17": 7, "X": 7}
)

// ratingInfo is what the page and the checks get for one title.
type ratingInfo struct {
	Cert    string `json:"cert"`              // the US certification found ("R", "PG-13", "TV-MA"), "" when there is none
	Adult   bool   `json:"adult"`             // TMDB's adult flag, or AniList's isAdult
	OK      bool   `json:"ok"`                // allowed in Kids mode
	Why     string `json:"why,omitempty"`     // when not OK: the certification, "adult", "sensitive", "no rating", "no key", "lookup failed", "bad id"
	Pending bool   `json:"pending,omitempty"` // not answered yet: ask again in a moment
	At      int64  `json:"at"`
}

// kidsAllows is the whole policy in one place: allowed only with a found certification on the allowed list and no adult flag.
func kidsAllows(cert string, adult bool) (bool, string) {
	c := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(cert), " ", ""))
	switch {
	case adult:
		return false, "adult"
	case c == "":
		return false, "no rating"
	case ratingAllowed[c]:
		return true, ""
	}
	return false, c
}

// strictest picks the most restrictive of several certifications; a certification it does not know counts as the strictest of all.
func strictest(certs []string) string {
	best, rank := "", -1
	for _, c := range certs {
		c = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(c), " ", ""))
		if c == "" {
			continue
		}
		r, ok := ratingStrict[c]
		if !ok {
			r = 99
		}
		if r > rank {
			best, rank = c, r
		}
	}
	return best
}

type ratingMgr struct {
	mu       sync.Mutex
	path     string
	keyFile  string
	cache    map[string]ratingInfo
	dirty    bool
	lastSave time.Time
	inflight map[string]chan struct{}
	slots    chan struct{}
	now      func() time.Time
	client   func() *http.Client
	tmdb     string
	anilist  string
}

var ratingMgrG *ratingMgr

func newRatingMgr(path, keyFile string) *ratingMgr {
	m := &ratingMgr{path: path, keyFile: keyFile, cache: map[string]ratingInfo{}, inflight: map[string]chan struct{}{}, slots: make(chan struct{}, ratingSlots), now: time.Now,
		tmdb: "https://api.themoviedb.org/3", anilist: "https://graphql.anilist.co", client: ratingClient}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &m.cache)
	}
	return m
}

// ratingClient goes out the way everything tinyfwd does for itself does (owndial.go).
func ratingClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return ownDial(ctx, network, addr) },
		TLSClientConfig: &tls.Config{RootCAs: rootPool(), MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, TLSHandshakeTimeout: 12 * time.Second, ResponseHeaderTimeout: 12 * time.Second, MaxResponseHeaderBytes: 16 << 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// key returns the TMDB credential from the key file (empty when there is none).
func (m *ratingMgr) key() string {
	if m == nil || m.keyFile == "" {
		return ""
	}
	b, err := os.ReadFile(m.keyFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Configured says whether a TMDB key is in place (anime does not need one).
func (m *ratingMgr) Configured() bool { return m.key() != "" }

func (m *ratingMgr) get(ctx context.Context, u string, bearer string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	return b, resp.StatusCode, err
}

// ---- the cache ----

func ratingKey(kind, id string) string {
	if kind == "anime" {
		return "a:" + id
	}
	return "i:" + id
}

func (m *ratingMgr) cachedLocked(key string) (ratingInfo, bool) {
	r, ok := m.cache[key]
	if !ok {
		return r, false
	}
	ttl := ratingTTLFound
	switch {
	case r.Why == "lookup failed" || r.Why == "no key":
		ttl = ratingTTLFailed
	case r.Cert == "" && !r.Adult:
		ttl = ratingTTLMissing
	}
	if m.now().Sub(time.Unix(r.At, 0)) > ttl {
		delete(m.cache, key)
		return r, false
	}
	return r, true
}

func (m *ratingMgr) putLocked(key string, r ratingInfo) {
	r.At = m.now().Unix()
	m.cache[key] = r
	m.dirty = true
	if len(m.cache) > ratingMaxEntries { // drop the oldest tenth
		type kv struct {
			k string
			t int64
		}
		all := make([]kv, 0, len(m.cache))
		for k, v := range m.cache {
			all = append(all, kv{k, v.At})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
		for _, x := range all[:len(all)/10] {
			delete(m.cache, x.k)
		}
	}
}

// Save writes the cache if it changed and the last write was long enough ago (force skips the wait). Failed lookups are not written.
func (m *ratingMgr) Save(force bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path == "" || !m.dirty || (!force && m.now().Sub(m.lastSave) < 10*time.Minute) {
		return
	}
	keep := map[string]ratingInfo{}
	for k, v := range m.cache {
		if v.Why != "lookup failed" && v.Why != "no key" {
			keep[k] = v
		}
	}
	b, _ := json.Marshal(keep)
	if writeFileAtomic(m.path, b, 0o600) == nil {
		m.dirty, m.lastSave = false, m.now()
	}
}

// Run saves the cache now and then; the daemon starts it once.
func (m *ratingMgr) Run() {
	for {
		time.Sleep(time.Minute)
		m.Save(false)
	}
}

// ---- looking one title up ----

func failed(why string) ratingInfo { return ratingInfo{Why: why} }

func (m *ratingMgr) fetchTMDB(ctx context.Context, imdb, kind string) ratingInfo {
	key := m.key()
	if key == "" {
		return failed("no key")
	}
	bearer, q := "", ""
	if len(key) > 40 { // a v4 read token (a JWT); a v3 key is 32 characters
		bearer = key
	} else {
		q = "&api_key=" + url.QueryEscape(key)
	}
	b, code, err := m.get(ctx, m.tmdb+"/find/"+imdb+"?external_source=imdb_id"+q, bearer)
	if err != nil || code != 200 {
		return failed("lookup failed")
	}
	var f struct {
		Movies []struct {
			ID    int  `json:"id"`
			Adult bool `json:"adult"`
		} `json:"movie_results"`
		TV []struct {
			ID    int  `json:"id"`
			Adult bool `json:"adult"`
		} `json:"tv_results"`
	}
	if json.Unmarshal(b, &f) != nil {
		return failed("lookup failed")
	}
	isTV, id, adult := false, 0, false
	switch {
	case kind == "series" && len(f.TV) > 0, kind != "series" && len(f.Movies) == 0 && len(f.TV) > 0:
		isTV, id, adult = true, f.TV[0].ID, f.TV[0].Adult
	case len(f.Movies) > 0:
		id, adult = f.Movies[0].ID, f.Movies[0].Adult
	default:
		return ratingInfo{Cert: "", OK: false, Why: "no rating"} // TMDB does not know the title
	}
	var certs []string
	if isTV {
		b, code, err = m.get(ctx, fmt.Sprintf("%s/tv/%d/content_ratings?language=en-US%s", m.tmdb, id, q), bearer)
	} else {
		b, code, err = m.get(ctx, fmt.Sprintf("%s/movie/%d/release_dates?language=en-US%s", m.tmdb, id, q), bearer)
	}
	if err != nil || code != 200 {
		return failed("lookup failed")
	}
	if isTV {
		var c struct {
			Results []struct {
				Country string `json:"iso_3166_1"`
				Rating  string `json:"rating"`
			} `json:"results"`
		}
		if json.Unmarshal(b, &c) != nil {
			return failed("lookup failed")
		}
		for _, r := range c.Results {
			if r.Country == "US" {
				certs = append(certs, r.Rating)
			}
		}
	} else {
		var c struct {
			Results []struct {
				Country string `json:"iso_3166_1"`
				Dates   []struct {
					Cert string `json:"certification"`
				} `json:"release_dates"`
			} `json:"results"`
		}
		if json.Unmarshal(b, &c) != nil {
			return failed("lookup failed")
		}
		for _, r := range c.Results {
			if r.Country == "US" {
				for _, d := range r.Dates {
					certs = append(certs, d.Cert)
				}
			}
		}
	}
	cert := strictest(certs)
	ok, why := kidsAllows(cert, adult)
	return ratingInfo{Cert: cert, Adult: adult, OK: ok, Why: why}
}

// fetchAniList asks about several anime at once (one request, aliased) and returns what it found by id.
func (m *ratingMgr) fetchAniList(ctx context.Context, ids []string) (map[string]ratingInfo, error) {
	var q strings.Builder
	q.WriteString("query{")
	for _, id := range ids {
		fmt.Fprintf(&q, "a%s:Media(id:%s,type:ANIME){isAdult genres} ", id, id)
	}
	q.WriteString("}")
	body, _ := json.Marshal(map[string]string{"query": q.String()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.anilist, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		Data map[string]*struct {
			IsAdult bool     `json:"isAdult"`
			Genres  []string `json:"genres"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &out) != nil || out.Data == nil {
		return nil, errors.New("bad answer")
	}
	res := map[string]ratingInfo{}
	for _, id := range ids {
		d := out.Data["a"+id]
		if d == nil { // AniList does not know it (or errored for this id): hidden
			res[id] = ratingInfo{Why: "no rating"}
			continue
		}
		r := ratingInfo{Adult: d.IsAdult, OK: true}
		for _, g := range d.Genres {
			if g == "Hentai" || g == "Ecchi" {
				r.OK, r.Why = false, "sensitive"
			}
		}
		if d.IsAdult {
			r.OK, r.Why = false, "adult"
		}
		res[id] = r
	}
	return res, nil
}

// Batch answers for up to ratingMaxBatch ids of one kind ("movie", "series" or "anime"). Whatever could not be answered in time comes back Pending, not wrong.
func (m *ratingMgr) Batch(ctx context.Context, kind string, ids []string) map[string]ratingInfo {
	out := map[string]ratingInfo{}
	if len(ids) > ratingMaxBatch {
		ids = ids[:ratingMaxBatch]
	}
	var todo []string
	m.mu.Lock()
	for _, id := range ids {
		if _, dup := out[id]; dup {
			continue
		}
		if (kind == "anime" && !ratingAniRe.MatchString(id)) || (kind != "anime" && !ratingIMDbRe.MatchString(id)) {
			out[id] = ratingInfo{Why: "bad id"}
			continue
		}
		if r, ok := m.cachedLocked(ratingKey(kind, id)); ok {
			out[id] = r
			continue
		}
		out[id] = ratingInfo{Why: "checking", Pending: true}
		todo = append(todo, id)
	}
	m.mu.Unlock()
	if len(todo) == 0 {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if kind == "anime" {
		select {
		case m.slots <- struct{}{}:
			defer func() { <-m.slots }()
		case <-ctx.Done():
			return out
		}
		res, err := m.fetchAniList(ctx, todo)
		m.mu.Lock()
		for _, id := range todo {
			if err != nil {
				out[id] = failed("lookup failed")
				m.cache[ratingKey(kind, id)] = ratingInfo{Why: "lookup failed", At: m.now().Unix()}
				continue
			}
			out[id] = res[id]
			m.putLocked(ratingKey(kind, id), res[id])
		}
		m.mu.Unlock()
		return out
	}
	var wg sync.WaitGroup
	var omu sync.Mutex
	for _, id := range todo {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			select {
			case m.slots <- struct{}{}:
				defer func() { <-m.slots }()
			case <-ctx.Done():
				return
			}
			k := ratingKey(kind, id)
			m.mu.Lock()
			if ch, busy := m.inflight[k]; busy { // another request is already asking about this title: wait for it
				m.mu.Unlock()
				select {
				case <-ch:
				case <-ctx.Done():
				}
				m.mu.Lock()
				if r, ok := m.cachedLocked(k); ok {
					omu.Lock()
					out[id] = r
					omu.Unlock()
				}
				m.mu.Unlock()
				return
			}
			ch := make(chan struct{})
			m.inflight[k] = ch
			m.mu.Unlock()
			r := m.fetchTMDB(ctx, id, kind)
			m.mu.Lock()
			m.putLocked(k, r)
			delete(m.inflight, k)
			close(ch)
			m.mu.Unlock()
			omu.Lock()
			out[id] = r
			omu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

// Allowed answers one title for the server-side checks: true only with a found, allowed rating.
func (m *ratingMgr) Allowed(ctx context.Context, kind, id string) (bool, string) {
	if m == nil {
		return false, "no ratings"
	}
	r := m.Batch(ctx, kind, []string{id})[id]
	return r.OK, r.Why
}

// ---- the API: /api/rating ----

func handleRatingAPI(w http.ResponseWriter, r *http.Request, path string) {
	m := ratingMgrG
	if m == nil || path != "rating" || r.Method != http.MethodGet {
		http.Error(w, "not found", 404)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "movie" && kind != "series" && kind != "anime" {
		writeJSON(w, 400, map[string]string{"error": "kind is movie, series or anime"})
		return
	}
	var ids []string
	for _, id := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 || len(ids) > ratingMaxBatch {
		writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("1 to %d ids", ratingMaxBatch)})
		return
	}
	writeJSON(w, 200, map[string]any{"ratings": m.Batch(r.Context(), kind, ids), "configured": kind == "anime" || m.Configured()})
}
