package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPIs stands in for TMDB and AniList. movies/shows map an IMDb id to what TMDB would say.
type fakeTitle struct {
	id    int
	adult bool
	certs []string // US certifications (movie: release dates; series: one content rating each)
	other string   // a non-US certification that must be ignored
	tv    bool
}

type fakeAPIs struct {
	srv    *httptest.Server
	titles map[string]fakeTitle
	anime  map[string]struct {
		adult  bool
		genres []string
	}
	hits     atomic.Int32
	anilists atomic.Int32
	wantKey  string
	bearer   string
	fail     atomic.Bool
}

func newFakeAPIs(t *testing.T) *fakeAPIs {
	f := &fakeAPIs{titles: map[string]fakeTitle{}, anime: map[string]struct {
		adult  bool
		genres []string
	}{}, wantKey: "0123456789abcdef0123456789abcdef"}
	mux := http.NewServeMux()
	mux.HandleFunc("/3/find/", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.fail.Load() {
			http.Error(w, "boom", 500)
			return
		}
		if r.URL.Query().Get("api_key") != f.wantKey && r.Header.Get("Authorization") != "Bearer "+f.bearer {
			http.Error(w, "bad key", 401)
			return
		}
		imdb := strings.TrimPrefix(r.URL.Path, "/3/find/")
		tt, ok := f.titles[imdb]
		out := map[string]any{"movie_results": []any{}, "tv_results": []any{}}
		if ok {
			key := "movie_results"
			if tt.tv {
				key = "tv_results"
			}
			out[key] = []any{map[string]any{"id": tt.id, "adult": tt.adult}}
		}
		json.NewEncoder(w).Encode(out)
	})
	byID := func(id string) (fakeTitle, bool) {
		for _, tt := range f.titles {
			if fmt.Sprint(tt.id) == id {
				return tt, true
			}
		}
		return fakeTitle{}, false
	}
	mux.HandleFunc("/3/movie/", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		id := strings.Split(strings.TrimPrefix(r.URL.Path, "/3/movie/"), "/")[0]
		tt, _ := byID(id)
		var dates []any
		for _, c := range tt.certs {
			dates = append(dates, map[string]any{"certification": c, "type": 3})
		}
		res := []any{map[string]any{"iso_3166_1": "US", "release_dates": dates}}
		if tt.other != "" {
			res = append(res, map[string]any{"iso_3166_1": "GB", "release_dates": []any{map[string]any{"certification": tt.other}}})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	})
	mux.HandleFunc("/3/tv/", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		id := strings.Split(strings.TrimPrefix(r.URL.Path, "/3/tv/"), "/")[0]
		tt, _ := byID(id)
		var res []any
		for _, c := range tt.certs {
			res = append(res, map[string]any{"iso_3166_1": "US", "rating": c})
		}
		if tt.other != "" {
			res = append(res, map[string]any{"iso_3166_1": "DE", "rating": tt.other})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	})
	mux.HandleFunc("/anilist", func(w http.ResponseWriter, r *http.Request) {
		f.anilists.Add(1)
		var b struct{ Query string }
		json.NewDecoder(r.Body).Decode(&b)
		data := map[string]any{}
		for id, a := range f.anime {
			if strings.Contains(b.Query, "a"+id+":Media(id:"+id+",") {
				data["a"+id] = map[string]any{"isAdult": a.adult, "genres": a.genres}
			}
		}
		for _, part := range strings.Split(b.Query, "Media(id:") {
			if i := strings.Index(part, ","); i > 0 && i < 10 {
				if _, ok := data["a"+part[:i]]; !ok && f.anime[part[:i]].genres == nil && !f.anime[part[:i]].adult {
					if _, known := f.anime[part[:i]]; !known {
						data["a"+part[:i]] = nil
					}
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func testRatings(t *testing.T) (*ratingMgr, *fakeAPIs, *time.Time) {
	t.Helper()
	f := newFakeAPIs(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "tmdb.key")
	os.WriteFile(key, []byte(f.wantKey+"\n"), 0o600)
	m := newRatingMgr(filepath.Join(dir, "ratings.json"), key)
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	m.client = func() *http.Client { return f.srv.Client() }
	m.tmdb = f.srv.URL + "/3"
	m.anilist = f.srv.URL + "/anilist"
	return m, f, &now
}

func TestKidsPolicy(t *testing.T) {
	for _, c := range []struct {
		cert  string
		adult bool
		ok    bool
		why   string
	}{
		{"G", false, true, ""}, {"PG", false, true, ""}, {"PG-13", false, true, ""}, {"TV-Y", false, true, ""}, {"TV-Y7", false, true, ""}, {"TV-G", false, true, ""}, {"TV-PG", false, true, ""}, {"TV-14", false, true, ""}, {"tv-14", false, true, ""}, {" PG 13 ", false, false, "PG13"},
		{"R", false, false, "R"}, {"NC-17", false, false, "NC-17"}, {"TV-MA", false, false, "TV-MA"}, {"X", false, false, "X"}, {"NR", false, false, "NR"}, {"Unrated", false, false, "UNRATED"}, {"18", false, false, "18"},
		{"", false, false, "no rating"}, {"PG", true, false, "adult"}, {"", true, false, "adult"}, {"made-up", false, false, "MADE-UP"},
	} {
		ok, why := kidsAllows(c.cert, c.adult)
		if ok != c.ok || why != c.why {
			t.Errorf("kidsAllows(%q, %v) = %v %q, want %v %q", c.cert, c.adult, ok, why, c.ok, c.why)
		}
	}
	if strictest([]string{"PG", "R", "PG-13", ""}) != "R" || strictest([]string{"PG-13", "TV-14"}) == "" || strictest([]string{"PG", "weird"}) != "WEIRD" || strictest(nil) != "" || strictest([]string{"", " "}) != "" {
		t.Error("the most restrictive certification counts, an unknown one counts as the strictest, none is none")
	}
}

func TestRatingMovieAndSeries(t *testing.T) {
	m, f, _ := testRatings(t)
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"PG-13"}}
	f.titles["tt0000002"] = fakeTitle{id: 12, certs: []string{"R"}, other: "12"}
	f.titles["tt0000003"] = fakeTitle{id: 13, certs: []string{"PG", "R", ""}}    // several US certifications: the strictest counts
	f.titles["tt0000004"] = fakeTitle{id: 14, certs: nil, other: "U"}            // only a UK rating: no US rating
	f.titles["tt0000005"] = fakeTitle{id: 15, certs: []string{"G"}, adult: true} // TMDB's adult flag beats a G
	f.titles["tt0000006"] = fakeTitle{id: 16, certs: []string{"TV-14"}, tv: true}
	f.titles["tt0000007"] = fakeTitle{id: 17, certs: []string{"TV-MA"}, tv: true}
	f.titles["tt0000008"] = fakeTitle{id: 18, certs: []string{"TV-Y7", "TV-MA"}, tv: true}
	ctx := context.Background()
	mv := m.Batch(ctx, "movie", []string{"tt0000001", "tt0000002", "tt0000003", "tt0000004", "tt0000005", "tt0000099"})
	want := map[string][3]any{ // ok, cert, why
		"tt0000001": {true, "PG-13", ""}, "tt0000002": {false, "R", "R"}, "tt0000003": {false, "R", "R"}, "tt0000004": {false, "", "no rating"}, "tt0000005": {false, "G", "adult"}, "tt0000099": {false, "", "no rating"},
	}
	for id, w := range want {
		r := mv[id]
		if r.OK != w[0].(bool) || r.Cert != w[1].(string) || r.Why != w[2].(string) || r.Pending {
			t.Errorf("movie %s: %+v, want %v", id, r, w)
		}
	}
	sv := m.Batch(ctx, "series", []string{"tt0000006", "tt0000007", "tt0000008"})
	if !sv["tt0000006"].OK || sv["tt0000006"].Cert != "TV-14" || sv["tt0000007"].OK || sv["tt0000007"].Why != "TV-MA" || sv["tt0000008"].OK || sv["tt0000008"].Cert != "TV-MA" {
		t.Errorf("series: %+v", sv)
	}
	if r := m.Batch(ctx, "series", []string{"tt0000006"})["tt0000006"]; !r.OK {
		t.Error("a series is looked up as a series")
	}
	f.titles["tt0000009"] = fakeTitle{id: 19, certs: []string{"TV-Y7"}, other: "FSK 18", tv: true}
	if r := m.Batch(ctx, "series", []string{"tt0000009"})["tt0000009"]; !r.OK || r.Cert != "TV-Y7" {
		t.Errorf("only the US rating counts for a series, another country's is ignored: %+v", r)
	}
	f.titles["tt0000010"] = fakeTitle{id: 20, certs: []string{"PG"}}
	h := f.hits.Load()
	m.Batch(ctx, "movie", []string{"tt0000010", "tt0000010", "tt0000010"})
	if f.hits.Load()-h != 2 {
		t.Errorf("one title asked three times at once costs one lookup (find + details): %d calls", f.hits.Load()-h)
	}
}

func TestRatingFailsClosed(t *testing.T) {
	m, f, now := testRatings(t)
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"G"}}
	ctx := context.Background()
	f.fail.Store(true)
	r := m.Batch(ctx, "movie", []string{"tt0000001"})["tt0000001"]
	if r.OK || r.Why != "lookup failed" {
		t.Errorf("TMDB down: hidden, not shown: %+v", r)
	}
	f.fail.Store(false)
	if r := m.Batch(ctx, "movie", []string{"tt0000001"})["tt0000001"]; r.OK {
		t.Error("a failed lookup is remembered for a moment, not retried on every request")
	}
	*now = now.Add(3 * time.Minute)
	if r := m.Batch(ctx, "movie", []string{"tt0000001"})["tt0000001"]; !r.OK || r.Cert != "G" {
		t.Errorf("after the short wait it asks again and finds it: %+v", r)
	}
	os.Remove(m.keyFile)
	m2, f2, _ := testRatings(t)
	_ = f2
	os.Remove(m2.keyFile)
	if m2.Configured() {
		t.Error("no key file means not configured")
	}
	r = m2.Batch(ctx, "movie", []string{"tt0000001"})["tt0000001"]
	if r.OK || r.Why != "no key" || f2.hits.Load() != 0 {
		t.Errorf("no key: everything hidden, and nothing sent: %+v hits=%d", r, f2.hits.Load())
	}
	os.WriteFile(m2.keyFile, []byte("   \n"), 0o600)
	if m2.Configured() {
		t.Error("an empty key file is not a key")
	}
	m3, f3, _ := testRatings(t)
	os.WriteFile(m3.keyFile, []byte("wrong-key-0123456789abcdef0123456"), 0o600)
	f3.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"G"}}
	if r := m3.Batch(ctx, "movie", []string{"tt0000001"})["tt0000001"]; r.OK || r.Why != "lookup failed" {
		t.Errorf("a rejected key hides everything: %+v", r)
	}
}

func TestRatingKeyKinds(t *testing.T) {
	m, f, _ := testRatings(t)
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"PG"}}
	f.bearer = strings.Repeat("e", 60) + ".payload.sig"
	os.WriteFile(m.keyFile, []byte(f.bearer), 0o600)
	if r := m.Batch(context.Background(), "movie", []string{"tt0000001"})["tt0000001"]; !r.OK {
		t.Errorf("a long v4 read token is sent as a Bearer header: %+v", r)
	}
}

func TestRatingCacheAndLimits(t *testing.T) {
	m, f, now := testRatings(t)
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"PG"}}
	ctx := context.Background()
	m.Batch(ctx, "movie", []string{"tt0000001"})
	h := f.hits.Load()
	m.Batch(ctx, "movie", []string{"tt0000001", "tt0000001"})
	if f.hits.Load() != h {
		t.Error("a title already known is not asked again")
	}
	*now = now.Add(31 * 24 * time.Hour)
	m.Batch(ctx, "movie", []string{"tt0000001"})
	if f.hits.Load() == h {
		t.Error("a rating expires after 30 days")
	}
	bad := m.Batch(ctx, "movie", []string{"../../etc/passwd", "tt1", "12345", "tt0000001; drop", ""})
	for id, r := range bad {
		if r.Why != "bad id" || r.OK {
			t.Errorf("%q must be refused as a bad id: %+v", id, r)
		}
	}
	if r := m.Batch(ctx, "anime", []string{"tt0000001", "12ab"}); r["tt0000001"].Why != "bad id" || r["12ab"].Why != "bad id" {
		t.Errorf("anime ids are numbers: %+v", r)
	}
	many := []string{}
	for i := 0; i < 100; i++ {
		many = append(many, fmt.Sprintf("tt%07d", i+1))
	}
	if got := m.Batch(ctx, "movie", many); len(got) != ratingMaxBatch {
		t.Errorf("at most %d ids are answered at once, got %d", ratingMaxBatch, len(got))
	}
}

func TestRatingPersistence(t *testing.T) {
	m, f, now := testRatings(t)
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"R"}}
	m.Batch(context.Background(), "movie", []string{"tt0000001", "tt0000404"})
	f.fail.Store(true)
	m.Batch(context.Background(), "movie", []string{"tt0000777"}) // a failed lookup
	m.Save(false)
	if _, err := os.Stat(m.path); err != nil {
		t.Fatal("the first save is not held back by an earlier one:", err)
	}
	raw, _ := os.ReadFile(m.path)
	if strings.Contains(string(raw), "lookup failed") || strings.Contains(string(raw), "tt0000777") || !strings.Contains(string(raw), "tt0000001") {
		t.Errorf("failed lookups are not written, real answers are: %s", raw)
	}
	if fi, _ := os.Stat(m.path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	os.Remove(m.path)
	m.Batch(context.Background(), "movie", []string{"tt0000002"})
	m.Save(false)
	if _, err := os.Stat(m.path); err == nil {
		t.Error("saves are at most every 10 minutes")
	}
	*now = now.Add(11 * time.Minute)
	m.Save(false)
	if _, err := os.Stat(m.path); err != nil {
		t.Error("and then it writes")
	}
	m2 := newRatingMgr(m.path, m.keyFile)
	m2.now = m.now
	if r, ok := m2.cachedLocked("i:tt0000001"); !ok || r.OK || r.Cert != "R" {
		t.Errorf("a restart keeps what was learned: %+v %v", r, ok)
	}
}

func TestRatingAnime(t *testing.T) {
	m, f, _ := testRatings(t)
	f.anime["1"] = struct {
		adult  bool
		genres []string
	}{false, []string{"Action", "Adventure"}}
	f.anime["2"] = struct {
		adult  bool
		genres []string
	}{true, []string{"Drama"}}
	f.anime["3"] = struct {
		adult  bool
		genres []string
	}{false, []string{"Comedy", "Ecchi"}}
	f.anime["4"] = struct {
		adult  bool
		genres []string
	}{false, []string{"Hentai"}}
	os.Remove(m.keyFile) // anime needs no TMDB key
	got := m.Batch(context.Background(), "anime", []string{"1", "2", "3", "4", "5"})
	if !got["1"].OK || got["2"].OK || got["2"].Why != "adult" || got["3"].OK || got["3"].Why != "sensitive" || got["4"].OK || got["5"].OK || got["5"].Why != "no rating" {
		t.Errorf("anime: %+v", got)
	}
	if f.anilists.Load() != 1 {
		t.Errorf("one request for the whole batch, got %d", f.anilists.Load())
	}
	m.Batch(context.Background(), "anime", []string{"1", "3"})
	if f.anilists.Load() != 1 {
		t.Error("answers are cached")
	}
}

func TestRatingAPI(t *testing.T) {
	m, f, _ := testRatings(t)
	f.titles["tt0000001"] = fakeTitle{id: 11, certs: []string{"PG"}}
	old := ratingMgrG
	ratingMgrG = m
	defer func() { ratingMgrG = old }()
	do := func(method, q string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		handleRatingAPI(rec, httptest.NewRequest(method, "/api/rating"+q, nil), "rating")
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, v := do("GET", "?kind=movie&ids=tt0000001,tt0000002")
	rs, _ := v["ratings"].(map[string]any)
	if code != 200 || v["configured"] != true || rs["tt0000001"].(map[string]any)["ok"] != true || rs["tt0000002"].(map[string]any)["ok"] != false {
		t.Errorf("%d %v", code, v)
	}
	for _, q := range []string{"", "?kind=movie", "?kind=bogus&ids=tt0000001", "?kind=movie&ids=" + strings.Repeat("tt0000001,", 61)} {
		if code, _ := do("GET", q); code != 400 {
			t.Errorf("%q must be a 400, got %d", q, code)
		}
	}
	if code, _ := do("POST", "?kind=movie&ids=tt0000001"); code != 404 {
		t.Errorf("GET only: %d", code)
	}
	os.Remove(m.keyFile)
	if _, v = do("GET", "?kind=movie&ids=tt0000001"); v["configured"] != false {
		t.Errorf("the page is told when no key is set: %v", v)
	}
	if _, v = do("GET", "?kind=anime&ids=1"); v["configured"] != true {
		t.Errorf("anime needs no key: %v", v)
	}
	raw := fmt.Sprint(v)
	if strings.Contains(raw, f.wantKey) {
		t.Error("the key must never be in an answer")
	}
}
