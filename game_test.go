package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestGameScript: the scripts under /game/ are served from the embedded folder, as JavaScript, and nothing else is reachable through that route.
func TestGameScript(t *testing.T) {
	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gameScript(rec, httptest.NewRequest("GET", p, nil))
		return rec
	}
	for _, f := range []string{"console.js", "pad.js", "padtest.js"} {
		rec := get("/game/" + f)
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Body.Len() < 200 {
			t.Errorf("%s: code %d, type %q, %d bytes", f, rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
		}
	}
	for _, p := range []string{"/game/", "/game/nope.js", "/game/console.html", "/game/../room.go", "/game/%2e%2e/room.go", "/game/sub/pad.js", "/game/..%2fgo.mod", "/game/pad.js/"} {
		if rec := get(p); rec.Code != http.StatusNotFound {
			t.Errorf("%s: code %d, want 404", p, rec.Code)
		}
	}
}

// TestGamePagesAreGuarded: /play and /pad are reached from a QR code or a shared link, so with no session they answer with the same-site bounce (and, once bounced, the login page), never the page.
func TestGamePagesAreGuarded(t *testing.T) {
	u := &webUI{auth: testAuth(t)}
	for _, p := range []string{"/play", "/pad"} {
		h := u.gamePage(p, "SECRET-PAGE")
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "SECRET-PAGE") || !strings.Contains(rec.Body.String(), `location.replace("`+p+`"+"?b=1"+location.hash)`) {
			t.Errorf("%s without a session: code %d, body %q", p, rec.Code, rec.Body.String())
		}
		rec = httptest.NewRecorder()
		h(rec, httptest.NewRequest("GET", p+"?b=1", nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?next="+url.QueryEscape(p) {
			t.Errorf("%s bounced and still signed out: code %d, location %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
}
