package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSafeNext: the only way to come back from sign-in is an exact match with one of our own pages. Everything that could point elsewhere is refused.
func TestSafeNext(t *testing.T) {
	for _, ok := range []string{"/ui", "/search", "/browse", "/room-test", "/play", "/pad"} {
		if safeNext(ok) != ok {
			t.Errorf("%q should be allowed", ok)
		}
	}
	for _, bad := range []string{"", "/", "//evil.example", "//evil.example/pad", "/\\evil.example", "\\\\evil.example", "https://evil.example/", "http://evil.example", "javascript:alert(1)", "data:text/html,x",
		"/pad?x=1", "/pad#x", "/PAD", "/pad/", "/pad/../ui", "/%2fevil.example", "/%2e%2e/pad", "/pad%00", "/pad\r\nSet-Cookie: a=b", " /pad", "/pad ", "/login", "/logout", "/api/dns", "/api/", "pad", "/game/pad.js", "/ui/../api/x", "/\t/evil.example"} {
		if got := safeNext(bad); got != "" {
			t.Errorf("%q was allowed as %q", bad, got)
		}
	}
	if loginURL("/pad") != "/login?next=%2Fpad" || loginURL("/play") != "/login?next=%2Fplay" || loginURL("/ui") != "/login" || loginURL("/nope") != "/login" || loginURL("//evil.example") != "/login" {
		t.Errorf("loginURL: %q %q %q %q", loginURL("/pad"), loginURL("/ui"), loginURL("/nope"), loginURL("//evil.example"))
	}
}

func getBody(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	r, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r, string(b)
}

// TestLoginReturn: the whole route a phone takes from a scanned link: the page it asked for sends it to sign in, and signing in brings it back to that page, and only to one of our own.
func TestLoginReturn(t *testing.T) {
	srv, c, _ := testWeb(t)
	// signed out, each page sends the person to the login page, telling it where they were going
	for path, want := range map[string]string{"/pad?b=1": "/login?next=%2Fpad", "/play?b=1": "/login?next=%2Fplay", "/room-test?b=1": "/login?next=%2Froom-test", "/browse": "/login?next=%2Fbrowse", "/search": "/login?next=%2Fsearch", "/ui": "/login"} {
		if r, _ := getBody(t, c, srv.URL+path); r.StatusCode != 303 || r.Header.Get("Location") != want {
			t.Errorf("%s signed out: %d %q, want %q", path, r.StatusCode, r.Header.Get("Location"), want)
		}
	}
	// the login page carries a good target in a hidden field and refuses a bad one
	_, page := getBody(t, c, srv.URL+"/login?next=%2Fpad")
	if !strings.Contains(page, `<input type="hidden" name="next" value="/pad">`) || !strings.Contains(page, "location.hash") {
		t.Error("login page lacks the hidden next field or the fragment script")
	}
	for _, bad := range []string{"//evil.example", "https://evil.example", `/pad"><script>alert(1)</script>`, "/api/dns", ""} {
		if _, p := getBody(t, c, srv.URL+"/login?next="+url.QueryEscape(bad)); strings.Contains(p, `name="next"`) || strings.Contains(p, "evil.example") && strings.Contains(p, "value=") {
			t.Errorf("login page kept next=%q", bad)
		}
	}
	post := func(user, pass, next string) *http.Response {
		v := url.Values{"user": {user}, "password": {pass}}
		if next != "" {
			v.Set("next", next)
		}
		r, err := c.PostForm(srv.URL+"/login", v)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r
	}
	// a wrong password keeps the target on the page that comes back
	r, err := c.PostForm(srv.URL+"/login", url.Values{"user": {"ben"}, "password": {"wrong"}, "next": {"/pad"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 401 || !strings.Contains(string(b), `name="next" value="/pad"`) {
		t.Errorf("wrong password: %d, next kept: %v", r.StatusCode, strings.Contains(string(b), `name="next" value="/pad"`))
	}
	// success goes to the target, or to /ui when there is none or it is not ours
	cases := []struct{ next, want string }{{"/pad", "/pad"}, {"/play", "/play"}, {"/browse", "/browse"}, {"", "/ui"}, {"//evil.example", "/ui"}, {"https://evil.example/", "/ui"}, {"/api/dns", "/ui"}, {"/pad?x=1", "/ui"}, {"/pad\r\nX: y", "/ui"}, {"/login", "/ui"}}
	for _, tc := range cases {
		if r := post("ben", "correct horse battery", tc.next); r.StatusCode != 303 || r.Header.Get("Location") != tc.want {
			t.Errorf("sign in with next=%q: %d %q, want %q", tc.next, r.StatusCode, r.Header.Get("Location"), tc.want)
		}
	}
	// already signed in: the login page just forwards, by the same rule
	for next, want := range map[string]string{"/pad": "/pad", "//evil.example": "/ui", "": "/ui"} {
		if r, _ := getBody(t, c, srv.URL+"/login?next="+url.QueryEscape(next)); r.StatusCode != 303 || r.Header.Get("Location") != want {
			t.Errorf("signed in, /login?next=%q: %d %q, want %q", next, r.StatusCode, r.Header.Get("Location"), want)
		}
	}
}

// TestLoginServeForJS serves the real web UI (login, bounce, game pages) over plain HTTP on loopback for scripts/dev/login-return-test.mjs. The login is ben / correct horse battery.
func TestLoginServeForJS(t *testing.T) {
	if os.Getenv("LOGIN_SERVE") == "" {
		t.Skip("serves the web UI for scripts/dev/login-return-test.mjs; set LOGIN_SERVE=1")
	}
	allowNets = nil
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	allowNets = append(allowNets, n)
	defer func() { allowNets = nil }()
	ui := &webUI{auth: testAuth(t), fp: "AA:BB"}
	webAuth = ui.auth
	defer func() { webAuth = nil }()
	quit := make(chan struct{})
	h := ui.handler()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/quit" {
			close(quit)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer plain.Close()
	fmt.Printf("{\"url\":%q}\n", plain.URL)
	select {
	case <-quit:
	case <-time.After(2 * time.Minute):
	}
}
