package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAuth(t *testing.T) *Auth {
	a := NewAuth(filepath.Join(t.TempDir(), "secure", "auth.json"))
	if err := a.SetLogin("ben", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAuthStore(t *testing.T) {
	a := testAuth(t)
	if a.SetLogin("", "correct horse battery") == nil || a.SetLogin("ben", "short") == nil || a.SetLogin("ben", strings.Repeat("x", 73)) == nil {
		t.Error("a bad username or password was accepted")
	}
	raw, _ := os.ReadFile(a.path)
	if strings.Contains(string(raw), "correct horse") || !strings.Contains(string(raw), "$2a$") {
		t.Error("the password is in the file, or the hash is not bcrypt")
	}
	if fi, _ := os.Stat(a.path); fi.Mode().Perm() != 0o600 {
		t.Errorf("auth file mode %v", fi.Mode().Perm())
	}
	if !a.Check("ben", "correct horse battery") || a.Check("ben", "wrong password!!") || a.Check("bob", "correct horse battery") || a.Check("ben", strings.Repeat("x", 200)) {
		t.Error("Check gave a wrong answer")
	}
	b := NewAuth(a.path)
	if b.Configured() {
		t.Error("configured before loading")
	}
	b.Load()
	if !b.Configured() || !b.Check("ben", "correct horse battery") {
		t.Error("the login did not survive a restart")
	}
	id, _ := a.NewSession("ben")
	a.SetLogin("ben", "another long password")
	if a.sessions[id] != nil {
		t.Error("changing the password kept old sessions")
	}
}

func TestThrottle(t *testing.T) {
	a := testAuth(t)
	now := time.Now()
	a.now = func() time.Time { return now }
	for i := 0; i < failsPerIP; i++ {
		if a.Throttled("1.2.3.4") {
			t.Fatal("throttled too early")
		}
		a.RecordFail("1.2.3.4")
	}
	if !a.Throttled("1.2.3.4") || a.Throttled("1.2.3.5") {
		t.Error("per-address throttle wrong")
	}
	now = now.Add(failWindow + time.Second)
	if a.Throttled("1.2.3.4") {
		t.Error("the throttle never lifts")
	}
	for i := 0; i < failsGlobal; i++ { // many addresses: the global limit
		a.RecordFail(net.IPv4(10, 0, 0, byte(i)).String())
	}
	if !a.Throttled("9.9.9.9") {
		t.Error("the global limit did not apply")
	}
}

func TestSessionExpiryAndCap(t *testing.T) {
	a := testAuth(t)
	now := time.Now()
	a.now = func() time.Time { return now }
	id, _ := a.NewSession("ben")
	req := func(id string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		return r
	}
	if a.Session(req(id)) == nil || a.Session(req("nope")) != nil || a.Session(req(strings.Repeat("a", 64))) != nil {
		t.Error("session lookup")
	}
	now = now.Add(sessionLife + time.Minute)
	if a.Session(req(id)) != nil {
		t.Error("an expired session still works")
	}
	for i := 0; i < maxSessions+5; i++ {
		a.NewSession("ben")
	}
	if len(a.sessions) > maxSessions {
		t.Errorf("%d sessions", len(a.sessions))
	}
}

// the whole web server over TLS with a cookie jar, as a browser would use it
func testWeb(t *testing.T) (*httptest.Server, *http.Client, *webUI) {
	allowNets = nil
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	allowNets = append(allowNets, n)
	t.Cleanup(func() { allowNets = nil; uiTokenFile = "" })
	ui := &webUI{auth: testAuth(t), fp: "AA:BB"}
	webAuth = ui.auth
	t.Cleanup(func() { webAuth = nil })
	srv := httptest.NewTLSServer(ui.handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, c, ui
}

func login(t *testing.T, srv *httptest.Server, c *http.Client, user, pass string) *http.Response {
	r, err := c.PostForm(srv.URL+"/login", url.Values{"user": {user}, "password": {pass}})
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	return r
}

func TestLoginFlow(t *testing.T) {
	srv, c, ui := testWeb(t)
	if r, _ := c.Get(srv.URL + "/ui"); r.StatusCode != 303 || r.Header.Get("Location") != "/login" {
		t.Errorf("/ui without a login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r, _ := c.Get(srv.URL + "/api/dns"); r.StatusCode != 401 {
		t.Errorf("/api/dns without a login: %d", r.StatusCode)
	}
	r, _ := c.Get(srv.URL + "/login")
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(string(b), "AA:BB") || r.Header.Get("Content-Security-Policy") == "" || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("login page or its security headers")
	}
	if r := login(t, srv, c, "ben", "not the password"); r.StatusCode != 401 {
		t.Errorf("wrong password: %d", r.StatusCode)
	}
	r = login(t, srv, c, "ben", "correct horse battery")
	if r.StatusCode != 303 || r.Header.Get("Location") != "/ui" {
		t.Fatalf("login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	var ck *http.Cookie
	for _, x := range r.Cookies() {
		if x.Name == sessionCookie {
			ck = x
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || len(ck.Value) != 64 {
		t.Errorf("session cookie: %+v", ck)
	}
	if r, _ := c.Get(srv.URL + "/ui"); r.StatusCode != 200 {
		t.Errorf("/ui logged in: %d", r.StatusCode)
	}
	if r, _ := c.Get(srv.URL + "/api/vpn"); r.StatusCode != 200 {
		t.Errorf("GET /api/vpn logged in: %d", r.StatusCode)
	}
	// a POST needs the session's CSRF token
	post := func(csrf string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/api/vpn/panic", strings.NewReader("{}"))
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if post("") != 403 || post("wrong") != 403 {
		t.Error("a POST without the CSRF token was accepted")
	}
	var sess struct{ User, CSRF string }
	r, _ = c.Get(srv.URL + "/api/session")
	json.NewDecoder(r.Body).Decode(&sess)
	r.Body.Close()
	if sess.User != "ben" || len(sess.CSRF) != 32 {
		t.Fatalf("session: %+v", sess)
	}
	if code := post(sess.CSRF); code == 403 || code == 401 { // vpn is nil in tests: any answer but an auth failure is fine
		t.Errorf("POST with the CSRF token: %d", code)
	}
	// change the password: wrong old, short new, then good; the old sessions end
	pw := func(old, nw string) int {
		b, _ := json.Marshal(map[string]string{"old": old, "new": nw})
		req, _ := http.NewRequest("POST", srv.URL+"/api/account/password", strings.NewReader(string(b)))
		req.Header.Set("X-CSRF-Token", sess.CSRF)
		r, _ := c.Do(req)
		r.Body.Close()
		return r.StatusCode
	}
	if pw("wrong", "a brand new password") != 400 || pw("correct horse battery", "short") != 400 {
		t.Error("a bad password change was accepted")
	}
	if pw("correct horse battery", "a brand new password") != 200 {
		t.Error("the password change failed")
	}
	if r, _ := c.Get(srv.URL + "/ui"); r.StatusCode != 303 {
		t.Error("the old session survived a password change")
	}
	if !ui.auth.Check("ben", "a brand new password") || ui.auth.Check("ben", "correct horse battery") {
		t.Error("the new password is not in effect")
	}
	// logout
	login(t, srv, c, "ben", "a brand new password")
	if r, _ := c.PostForm(srv.URL+"/logout", nil); r.StatusCode != 303 {
		t.Error("logout")
	}
	if r, _ := c.Get(srv.URL + "/api/dns"); r.StatusCode != 401 {
		t.Error("still logged in after logout")
	}
	if r, _ := c.Get(srv.URL + "/logout"); r.StatusCode != 405 {
		t.Error("logout by GET (a link) must not work")
	}
}

func TestLoginThrottleAndToken(t *testing.T) {
	srv, c, _ := testWeb(t)
	for i := 0; i < failsPerIP; i++ {
		login(t, srv, c, "ben", "wrong password "+string(rune('a'+i)))
	}
	if r := login(t, srv, c, "ben", "correct horse battery"); r.StatusCode != 429 {
		t.Errorf("after %d failures the right password still got %d (want 429)", failsPerIP, r.StatusCode)
	}
	// scripts: the API-key token header works over HTTPS without a session, a wrong one does not
	tf := filepath.Join(t.TempDir(), "ui.token")
	os.WriteFile(tf, []byte("s3cret-token\n"), 0o600)
	uiTokenFile = tf
	req, _ := http.NewRequest("GET", srv.URL+"/api/session", nil)
	req.Header.Set("X-UI-Token", "s3cret-token")
	if r, _ := c.Do(req); r.StatusCode != 200 {
		t.Errorf("token auth: %d", r.StatusCode)
	}
	req.Header.Set("X-UI-Token", "wrong")
	if r, _ := c.Do(req); r.StatusCode != 401 {
		t.Errorf("wrong token: %d", r.StatusCode)
	}
}

func TestNoLoginConfigured(t *testing.T) {
	allowNets = nil
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	allowNets = append(allowNets, n)
	t.Cleanup(func() { allowNets = nil })
	ui := &webUI{auth: NewAuth(filepath.Join(t.TempDir(), "auth.json")), fp: "x"}
	srv := httptest.NewTLSServer(ui.handler())
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ := c.Get(srv.URL + "/login")
	b, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(b), "set-login.sh") {
		t.Error("the login page does not say how to set a login up")
	}
	r, _ = c.PostForm(srv.URL+"/login", url.Values{"user": {""}, "password": {""}})
	if r.StatusCode != 401 {
		t.Errorf("empty credentials with no login set: %d", r.StatusCode)
	}
}

func TestOffLANRefused(t *testing.T) {
	allowNets = nil
	t.Cleanup(func() { allowNets = nil })
	ui := &webUI{auth: testAuth(t)}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	ui.handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("a non-LAN address got %d", rec.Code)
	}
}

func TestHTTPStaysOrRedirects(t *testing.T) {
	cases := []struct {
		method, target, accept string
		stays                  bool
	}{
		{"GET", "/wpad.dat", "", true}, {"GET", "/proxy.pac", "", true}, {"GET", "/", "", true}, {"GET", "/wpad", "*/*", true},
		{"GET", "/", "text/html,application/xhtml+xml", false},
		{"GET", "/status.json", "", true}, {"POST", "/beat", "", true},
		{"GET", "/ui", "", false}, {"GET", "/login", "", false}, {"POST", "/login", "", false},
		{"GET", "/api/dns", "", false}, {"POST", "/api/vpn/enable", "", false}, {"GET", "/anything", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.target, nil)
		if c.accept != "" {
			r.Header.Set("Accept", c.accept)
		}
		if got := httpStays(r); got != c.stays {
			t.Errorf("%s %s (Accept %q): stays=%v want %v", c.method, c.target, c.accept, got, c.stays)
		}
	}
	h := "orbic"
	uiHost = &h
	rec := httptest.NewRecorder()
	redirectHTTPS(rec, httptest.NewRequest("GET", "/ui?x=1", nil))
	if rec.Code != 308 || rec.Header().Get("Location") != "https://orbic/ui?x=1" {
		t.Errorf("redirect: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestStatusDetailNeedsAuth(t *testing.T) {
	webAuth = testAuth(t)
	t.Cleanup(func() { webAuth = nil; uiTokenFile = "" })
	tf := filepath.Join(t.TempDir(), "ui.token")
	os.WriteFile(tf, []byte("tok"), 0o600)
	uiTokenFile = tf
	plain := httptest.NewRequest("GET", "/status.json", nil)
	if statusDetailOK(plain) {
		t.Error("an anonymous caller gets the detail")
	}
	withTok := httptest.NewRequest("GET", "/status.json", nil)
	withTok.Header.Set("X-UI-Token", "tok")
	if !statusDetailOK(withTok) {
		t.Error("the API token does not unlock the detail")
	}
	id, _ := webAuth.NewSession("ben")
	withSess := httptest.NewRequest("GET", "/status.json", nil)
	withSess.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	if !statusDetailOK(withSess) {
		t.Error("a session does not unlock the detail")
	}
}

func TestCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	names := []string{"orbic", "orbic.lan", "wpad"}
	ips := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.254")}
	now := time.Now()
	c1, fp1, created, err := loadOrCreateCert(dir, names, ips, now)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	for _, h := range []string{"orbic", "wpad", "192.168.1.1", "192.168.1.254"} {
		if c1.Leaf.VerifyHostname(h) != nil {
			t.Errorf("the certificate does not cover %s", h)
		}
	}
	if c1.Leaf.VerifyHostname("example.com") == nil {
		t.Error("covers a name it should not")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "key.pem")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", fi.Mode().Perm())
	}
	if d := c1.Leaf.NotAfter.Sub(now); d < 799*24*time.Hour || d > 801*24*time.Hour {
		t.Errorf("validity %v", d)
	}
	_, fp2, created2, err := loadOrCreateCert(dir, names, ips, now.Add(24*time.Hour))
	if err != nil || created2 || fp2 != fp1 {
		t.Error("a still-good certificate was not reused")
	}
	if _, fp3, c3, _ := loadOrCreateCert(dir, append(names, "new-name"), ips, now); !c3 || fp3 == fp1 {
		t.Error("a certificate that lacks a needed name was kept")
	}
	if _, _, c4, _ := loadOrCreateCert(dir, append(names, "new-name"), ips, now.Add(760*24*time.Hour)); !c4 {
		t.Error("a certificate close to expiry was kept")
	}
	if len(fp1) != 95 || strings.Count(fp1, ":") != 31 {
		t.Errorf("fingerprint %q", fp1)
	}
	// and it really serves TLS
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hi")) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{c1}}
	srv.StartTLS()
	defer srv.Close()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if r, err := cl.Get(srv.URL); err != nil || r.StatusCode != 200 {
		t.Errorf("TLS handshake: %v", err)
	}
}
