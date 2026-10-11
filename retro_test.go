package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
