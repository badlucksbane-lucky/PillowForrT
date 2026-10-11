package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tinyfwd/internal/retrosmbconf"
)

func TestHandlerRejectsWrites(t *testing.T) {
	h := &handler{s: &smbServer{cfg: &retrosmbconf.Config{}}}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(m, "/list.json", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /list.json: got %d, want 405", m, w.Code)
		}
	}
}

func TestHandlerRejectsBadNames(t *testing.T) {
	h := &handler{s: &smbServer{cfg: &retrosmbconf.Config{}}}
	cases := []string{
		"/roms/../etc/passwd",
		"/roms/..",
		"/notasub/x.nes",
		"/roms",
		"/roms/",
		"/roms/x/y.nes",
		"/cores/.hidden",
	}
	for _, p := range cases {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: got %d, want 404", p, w.Code)
		}
	}
}

// TestListJSONReportsShareUnreachable guards against the bug a review
// caught: /list.json answering 200 with empty arrays when the SMB
// connection itself fails (wrong password, wrong server, share down) looks
// identical to an empty-but-connected share unless share_ok says otherwise.
func TestListJSONReportsShareUnreachable(t *testing.T) {
	cfg := &retrosmbconf.Config{Server: "127.0.0.1", SMBPort: 1, Share: "nope", User: "u", Password: "p"} // nothing listens on :1
	h := &handler{s: &smbServer{cfg: cfg}}
	req := httptest.NewRequest(http.MethodGet, "/list.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (an unreachable share is not itself an HTTP error)", w.Code)
	}
	var v struct {
		Cores, Roms []string
		ShareOK     bool `json:"share_ok"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.ShareOK {
		t.Error("share_ok = true for a connection that cannot possibly have succeeded")
	}
	if v.Cores != nil || v.Roms != nil {
		t.Errorf("expected nil lists, got cores=%v roms=%v", v.Cores, v.Roms)
	}
}

func TestRetroFileNameRegex(t *testing.T) {
	ok := []string{"Mario.nes", "fceumm.wasm", "a", "Pokemon Red (USA).gb", "core_v2.js"}
	bad := []string{"", ".hidden", "../x", "a/b", "x\\y", string(make([]byte, 200))}
	for _, n := range ok {
		if !retroFileName.MatchString(n) {
			t.Errorf("expected %q to match", n)
		}
	}
	for _, n := range bad {
		if retroFileName.MatchString(n) {
			t.Errorf("expected %q to NOT match", n)
		}
	}
}
