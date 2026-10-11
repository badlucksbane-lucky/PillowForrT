package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func retroFixture(t *testing.T) (*webUI, string, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"cores", "roms"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	w := func(rel, body string) { os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644) }
	w("cores/fceumm.js", "createCore=1")
	w("cores/fceumm.wasm", "\x00asm")
	w("cores/gambatte.js", "createCore=2") // no .wasm: not offered
	w("roms/Zelda Test.nes", "NES\x1a")
	w("roms/alpha.GB", "gb")
	w("roms/notes.txt", "no core plays this")
	w("roms/.hidden.nes", "x")
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("SECRET"), 0o644)
	os.Symlink(filepath.Join(dir, "secret.txt"), filepath.Join(dir, "roms", "link.nes"))
	old := *retroDir
	*retroDir = dir
	t.Cleanup(func() { *retroDir = old })
	a := testAuth(t)
	id, _ := a.NewSession("ben")
	return &webUI{auth: a}, dir, &http.Cookie{Name: sessionCookie, Value: id}
}

func retroGet(u *webUI, path string, c *http.Cookie) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	u.retroFiles(rec, req)
	return rec
}

// TestRetroIndex: only a core with both files is offered, ROMs are matched to a core by extension, and odd files (hidden, symlinks, no core) are left out.
func TestRetroIndex(t *testing.T) {
	u, _, c := retroFixture(t)
	rec := retroGet(u, "/retro/index.json", c)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("code %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	for _, want := range []string{`"id":"fceumm"`, `"file":"Zelda Test.nes"`, `"name":"Zelda Test"`, `"core":"fceumm"`} {
		if !strings.Contains(body, want) {
			t.Errorf("index lacks %s: %s", want, body)
		}
	}
	for _, not := range []string{"gambatte", "alpha.GB", "notes.txt", ".hidden", "link.nes"} {
		if strings.Contains(body, not) {
			t.Errorf("index should not list %s: %s", not, body)
		}
	}
}

// TestRetroServe: files come out with the right type, and nothing outside cores/ and roms/ is reachable, nor a symlink, a folder or a name of the wrong shape.
func TestRetroServe(t *testing.T) {
	u, _, c := retroFixture(t)
	if r := retroGet(u, "/retro/cores/fceumm.wasm", c); r.Code != 200 || r.Header().Get("Content-Type") != "application/wasm" || r.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("wasm: %d %q", r.Code, r.Header().Get("Content-Type"))
	}
	if r := retroGet(u, "/retro/cores/fceumm.js", c); r.Code != 200 || !strings.HasPrefix(r.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("js: %d %q", r.Code, r.Header().Get("Content-Type"))
	}
	if r := retroGet(u, "/retro/roms/Zelda%20Test.nes", c); r.Code != 200 || r.Body.String() != "NES\x1a" {
		t.Errorf("rom: %d %q", r.Code, r.Body.String())
	}
	for _, p := range []string{"/retro/", "/retro/roms/", "/retro/roms/nope.nes", "/retro/roms/../secret.txt", "/retro/roms/%2e%2e/secret.txt", "/retro/cores/..%2fsecret.txt", "/retro/roms/link.nes",
		"/retro/roms/.hidden.nes", "/retro/other/x.js", "/retro/roms/a/b.nes", "/retro/cores/fceumm.txt", "/retro/roms/Zelda%20Test.nes/", "/retro/roms/a%00.nes", "/retro/roms/ba%5Cd.nes"} {
		if r := retroGet(u, p, c); r.Code != http.StatusNotFound || strings.Contains(r.Body.String(), "SECRET") {
			t.Errorf("%s: code %d", p, r.Code)
		}
	}
}

// TestRetroNeedsSession: with no session (or the folder setting empty) the box does not even say whether a file exists.
func TestRetroNeedsSession(t *testing.T) {
	u, _, c := retroFixture(t)
	for _, p := range []string{"/retro/index.json", "/retro/cores/fceumm.js", "/retro/roms/Zelda%20Test.nes"} {
		if r := retroGet(u, p, nil); r.Code != http.StatusNotFound || strings.Contains(r.Body.String(), "Zelda") {
			t.Errorf("%s signed out: code %d", p, r.Code)
		}
	}
	*retroDir = ""
	if r := retroGet(u, "/retro/index.json", c); r.Code != http.StatusNotFound {
		t.Errorf("with the folder setting empty: code %d", r.Code)
	}
}

// TestPlayPageAllowsWasmOnly: the screen page may compile WebAssembly (the cores), the phone page may not.
func TestPlayPageAllowsWasmOnly(t *testing.T) {
	u, _, c := retroFixture(t)
	for p, want := range map[string]bool{"/play": true, "/pad": false} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", p, nil)
		req.AddCookie(c)
		u.gamePage(p, "PAGE")(rec, req)
		if got := strings.Contains(rec.Header().Get("Content-Security-Policy"), "'wasm-unsafe-eval'"); got != want || !strings.Contains(rec.Body.String(), "PAGE") {
			t.Errorf("%s: wasm allowed %v, want %v (code %d)", p, got, want, rec.Code)
		}
	}
}

// ---- the upstream read-through ----

type retroUp struct {
	srv       *httptest.Server
	hits      []string
	elsewhere int
}

// retroUpFixture starts a stand-in for scripts/retro/pi-serve.py and points <retro-dir>/upstream at it.
func retroUpFixture(t *testing.T, dir string, files map[string]string, list string) *retroUp {
	t.Helper()
	up := &retroUp{}
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // where a redirect would lead: it must never be asked
		up.elsewhere++
		w.Write([]byte("EVIL"))
	}))
	t.Cleanup(elsewhere.Close)
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.hits = append(up.hits, r.URL.Path)
		switch {
		case r.URL.Path == "/list.json":
			w.Write([]byte(list))
		case r.URL.Path == "/roms/redirect.nes":
			http.Redirect(w, r, elsewhere.URL+"/evil", http.StatusFound)
		case r.URL.Path == "/roms/huge.nes":
			w.Header().Set("Content-Length", "999999999")
		case r.URL.Path == "/roms/broken.nes":
			http.Error(w, "boom", 500)
		default:
			if b, ok := files[strings.TrimPrefix(r.URL.Path, "/")]; ok {
				w.Write([]byte(b))
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.srv.Close)
	os.WriteFile(filepath.Join(dir, "upstream"), []byte(up.srv.URL+"\n"), 0o644)
	retroUpTTL = 0
	t.Cleanup(func() { retroUpTTL = 10 * time.Second })
	return up
}

// TestRetroUpstreamIndex: what the upstream has joins what is local: a core with its .js here and its .wasm there is offered, ROMs from both are listed once, and bad names are dropped.
func TestRetroUpstreamIndex(t *testing.T) {
	u, dir, c := retroFixture(t)
	retroUpFixture(t, dir, nil, `{"cores":["gambatte.wasm","fceumm.wasm","../evil.js","a/b.js"],"roms":["Tetris Remix.gb","Zelda Test.nes","../x.nes","dir/y.gb",".hidden.gb","notes.txt"]}`)
	body := retroGet(u, "/retro/index.json", c).Body.String()
	for _, want := range []string{`"id":"gambatte"`, `"id":"fceumm"`, `"file":"Tetris Remix.gb"`, `"file":"Zelda Test.nes"`} { // gambatte.js is local, its .wasm is upstream
		if !strings.Contains(body, want) {
			t.Errorf("index lacks %s: %s", want, body)
		}
	}
	if strings.Count(body, "Zelda Test.nes") != 1 {
		t.Errorf("a ROM that is in both places must be listed once: %s", body)
	}
	for _, not := range []string{"evil", "a/b", "../", "dir/", ".hidden", "notes.txt"} {
		if strings.Contains(body, not) {
			t.Errorf("index should not mention %q: %s", not, body)
		}
	}
}

// TestRetroReadThrough: a file that is not here comes from the upstream with the right headers, a local file wins, and an upstream that is wrong or down gives a clean error.
func TestRetroReadThrough(t *testing.T) {
	u, dir, c := retroFixture(t)
	up := retroUpFixture(t, dir, map[string]string{"roms/Remote Only.gb": "GBDATA", "roms/Zelda Test.nes": "UPSTREAM-COPY", "cores/gambatte.wasm": "\x00asm-up"}, `{"cores":[],"roms":[]}`)
	if r := retroGet(u, "/retro/roms/Remote%20Only.gb", c); r.Code != 200 || r.Body.String() != "GBDATA" || r.Header().Get("Content-Type") != "application/octet-stream" || r.Header().Get("X-Content-Type-Options") != "nosniff" || r.Header().Get("Content-Length") != "6" {
		t.Errorf("remote rom: %d %q %v", r.Code, r.Body.String(), r.Header())
	}
	if r := retroGet(u, "/retro/cores/gambatte.wasm", c); r.Code != 200 || r.Header().Get("Content-Type") != "application/wasm" || r.Body.String() != "\x00asm-up" {
		t.Errorf("remote core: %d %q", r.Code, r.Header().Get("Content-Type"))
	}
	if r := retroGet(u, "/retro/roms/Zelda%20Test.nes", c); r.Body.String() != "NES\x1a" {
		t.Errorf("a local file must win over the upstream copy, got %q", r.Body.String())
	}
	if r := retroGet(u, "/retro/roms/Missing.gb", c); r.Code != 404 {
		t.Errorf("missing everywhere: %d", r.Code)
	}
	for _, p := range []string{"/retro/roms/redirect.nes", "/retro/roms/huge.nes", "/retro/roms/broken.nes"} {
		if r := retroGet(u, p, c); r.Code != http.StatusBadGateway {
			t.Errorf("%s: want 502 (redirect not followed, too big, upstream error), got %d", p, r.Code)
		}
	}
	if up.elsewhere != 0 {
		t.Errorf("a redirect from the upstream was followed (%d requests elsewhere)", up.elsewhere)
	}
	if r := retroGet(u, "/retro/roms/link.nes", c); r.Code != 404 || strings.Contains(r.Body.String(), "SECRET") {
		t.Errorf("a local symlink stays a 404 even with an upstream: %d", r.Code)
	}
	before := len(up.hits)
	for _, p := range []string{"/retro/roms/..%2fsecret.txt", "/retro/roms/a%2Fb.gb", "/retro/roms/.hidden.gb", "/retro/roms/x.gb/", "/retro/cores/x.txt", "/retro/other/x.gb"} {
		retroGet(u, p, c)
	}
	if len(up.hits) != before {
		t.Errorf("a bad name must never reach the upstream: %v", up.hits[before:])
	}
	if r := retroGet(u, "/retro/roms/Remote%20Only.gb", nil); r.Code != 404 || len(up.hits) != before {
		t.Errorf("signed out: %d, upstream contacted %v", r.Code, up.hits[before:])
	}
	up.srv.Close() // now it is dead
	if r := retroGet(u, "/retro/roms/Remote%20Only.gb", c); r.Code != http.StatusBadGateway {
		t.Errorf("dead upstream: %d", r.Code)
	}
	if r := retroGet(u, "/retro/roms/Zelda%20Test.nes", c); r.Code != 200 {
		t.Errorf("local files must work with the upstream dead: %d", r.Code)
	}
	if body := retroGet(u, "/retro/index.json", c).Body.String(); !strings.Contains(body, "Zelda Test") {
		t.Errorf("the index must still list local files: %s", body)
	}
}

// TestRetroUpstreamAddress: only an http(s) address of a private or loopback IP, with no login, query or fragment, counts; anything else is no upstream.
func TestRetroUpstreamAddress(t *testing.T) {
	dir := t.TempDir()
	set := func(s string) string {
		os.WriteFile(filepath.Join(dir, "upstream"), []byte(s), 0o644)
		return retroUpstream(dir)
	}
	for in, want := range map[string]string{
		"http://192.168.1.2:8080": "http://192.168.1.2:8080", "http://192.168.1.2:8080/retro/\n": "http://192.168.1.2:8080/retro", "http://127.0.0.1:9": "http://127.0.0.1:9",
		"https://10.0.0.5": "https://10.0.0.5", "http://172.16.3.4": "http://172.16.3.4",
	} {
		if got := set(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "http://example.com", "http://8.8.8.8", "http://192.168.1.2.evil.com", "ftp://192.168.1.2", "http://u:p@192.168.1.2", "http://192.168.1.2/?x=1", "http://192.168.1.2/#f", "192.168.1.2:8080", "http://[2001:db8::1]/", "file:///etc/passwd"} {
		if got := set(bad); got != "" {
			t.Errorf("%q must not count, got %q", bad, got)
		}
	}
	os.Remove(filepath.Join(dir, "upstream"))
	if retroUpstream(dir) != "" {
		t.Error("no file means no upstream")
	}
}
