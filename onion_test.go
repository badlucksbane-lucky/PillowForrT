package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// a real x25519 public key in the form Tor wants: 52 base32 characters, no padding
func newTestPub(t *testing.T) string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return onionB32.EncodeToString(k.PublicKey().Bytes())
}

func TestOnionPubOK(t *testing.T) {
	good := newTestPub(t)
	if len(good) != 52 || !onionPubOK(good) {
		t.Fatalf("a real key must pass: %q", good)
	}
	for name, bad := range map[string]string{
		"empty":                "",
		"too short":            good[:51],
		"too long":             good + "A",
		"lower case":           strings.ToLower(good),
		"padding":              good[:51] + "=",
		"not base32":           good[:51] + "1",
		"all zero":             strings.Repeat("A", 52),
		"nonzero padding bits": good[:51] + "B", // 52 chars carry 260 bits for 256: the last 4 must be zero
		"a private-key file":   "abc:descriptor:x25519:" + good,
		"whitespace":           good + "\n",
	} {
		if onionPubOK(bad) {
			t.Errorf("%s must be refused: %q", name, bad)
		}
	}
}

func TestOnionTorrcFailsClosed(t *testing.T) {
	pub := newTestPub(t)
	one := []onionClient{{Name: "laptop", Pub: pub}}
	for name, d := range map[string]onionDoor{
		"off":                {Enabled: false, Clients: one},
		"no clients":         {Enabled: true},
		"nothing configured": {},
	} {
		if l := onionTorrcLines(d, "/x/onion/admin"); l != nil {
			t.Errorf("%s: nothing may be rendered (an unrestricted service would be open to anyone with the address): %v", name, l)
		}
	}
	on := onionTorrcLines(onionDoor{Enabled: true, Clients: one}, "/x/onion/admin")
	text := strings.Join(on, "\n")
	for _, want := range []string{"HiddenServiceDir /x/onion/admin", "HiddenServiceVersion 3", "HiddenServicePort 80 127.0.0.1:3130", "HiddenServiceEnableIntroDoSDefense 1", "HiddenServiceMaxStreams 20"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	// the web page is the ONLY service: no SSH (or any other port) through the door, whatever the settings ()
	ports := 0
	for _, l := range on {
		if strings.HasPrefix(l, "HiddenServicePort") {
			ports++
			if l != "HiddenServicePort 80 127.0.0.1:3130" {
				t.Errorf("unexpected service port line: %s", l)
			}
		}
	}
	if ports != 1 || strings.Contains(text, " 22 ") || strings.Contains(text, "2222") {
		t.Errorf("exactly one service port (80 to the loopback web listener), got %d:\n%s", ports, text)
	}
	// the whole torrc keeps being a client's
	m, _, _, _ := testTor(t)
	m.cfg.Door = onionDoor{Enabled: true, Clients: one}
	rc := m.renderTorrc()
	if !strings.Contains(rc, "ClientOnly 1") || !strings.Contains(rc, "HiddenServiceDir "+m.onionDir()) || strings.Contains(rc, "ORPort") {
		t.Errorf("torrc: %s", rc)
	}
}

func TestOnionClients(t *testing.T) {
	a, b := newTestPub(t), newTestPub(t)
	cs, err := withClient(nil, "  Laptop ", strings.ToLower(a)) // name and key are normalized
	if err != nil || len(cs) != 1 || cs[0].Name != "laptop" || cs[0].Pub != a {
		t.Fatalf("add: %v %v", cs, err)
	}
	if _, err := withClient(cs, "laptop", b); err == nil {
		t.Error("a duplicate name is refused")
	}
	if _, err := withClient(cs, "phone", a); err == nil {
		t.Error("a duplicate key is refused")
	}
	for _, bad := range []string{"", "-x", "has space", "UPPER_CASE", strings.Repeat("a", 25), "../etc"} {
		if _, err := withClient(cs, bad, b); err == nil {
			t.Errorf("name %q must be refused", bad)
		}
	}
	if _, err := withClient(cs, "phone", "descriptor:x25519:"+b); err == nil {
		t.Error("a pasted file line is not a key")
	}
	var full []onionClient
	for i := 0; i < onionMaxClients; i++ {
		var err error
		full, err = withClient(full, "d"+string(rune('a'+i)), newTestPub(t))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := withClient(full, "one-more", newTestPub(t)); err == nil {
		t.Error("the limit holds")
	}
	if out, ok := withoutClient(full, "DA"); !ok || len(out) != onionMaxClients-1 {
		t.Errorf("remove: %v %v", len(out), ok)
	}
	if _, ok := withoutClient(full, "nobody"); ok {
		t.Error("removing an unknown name reports it")
	}
	if f := onionFingerprint(a); len(f) != 8 || f != onionFingerprint(a) || f == onionFingerprint(b) {
		t.Errorf("fingerprint %q", f)
	}
}

func TestSyncOnionDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "onion", "admin")
	a, b := newTestPub(t), newTestPub(t)
	d := onionDoor{Enabled: true, Clients: []onionClient{{"laptop", a}, {"phone", b}}}
	if err := syncOnionDir(dir, d, -1); err != nil {
		t.Fatal(err)
	}
	// the identity key must survive every sync, and a stray file in authorized_clients must go
	key := filepath.Join(dir, "hs_ed25519_secret_key")
	os.WriteFile(key, []byte("identity"), 0o600)
	os.WriteFile(filepath.Join(dir, "authorized_clients", "old.auth"), []byte("descriptor:x25519:"+newTestPub(t)+"\n"), 0o600)
	d.Clients = d.Clients[:1]
	if err := syncOnionDir(dir, d, -1); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(key); string(b) != "identity" {
		t.Error("the identity key was touched")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "authorized_clients"))
	if len(entries) != 1 || entries[0].Name() != "laptop.auth" {
		t.Errorf("authorized_clients: %v", entries)
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "authorized_clients", "laptop.auth")); string(body) != "descriptor:x25519:"+a+"\n" {
		t.Errorf("file body: %q", body)
	}
	for _, p := range []string{filepath.Join(root, "onion"), dir, filepath.Join(dir, "authorized_clients")} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s is %v, want 0700", p, fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "authorized_clients", "laptop.auth")); fi.Mode().Perm() != 0o600 {
		t.Errorf("auth file mode %v", fi.Mode().Perm())
	}
	if readOnionAddress(dir) != "" {
		t.Error("no hostname yet")
	}
	os.WriteFile(filepath.Join(dir, "hostname"), []byte(strings.Repeat("a", 56)+".onion\n"), 0o600)
	if readOnionAddress(dir) != strings.Repeat("a", 56) {
		t.Error("the address is read")
	}
	os.WriteFile(filepath.Join(dir, "hostname"), []byte("garbage\n"), 0o600)
	if readOnionAddress(dir) != "" {
		t.Error("a bad hostname file is ignored")
	}
}

func TestDoorSettings(t *testing.T) {
	m, _, _, _ := testTor(t)
	pub := newTestPub(t)

	if err := m.DoorSet(true, false); err == nil {
		t.Error("switching on with no authorized device is refused")
	}
	if err := m.DoorAddClient("laptop", pub); err != nil {
		t.Fatal(err)
	}
	if err := m.DoorSet(true, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(m.onionDir(), "authorized_clients", "laptop.auth")); string(b) != "descriptor:x25519:"+pub+"\n" {
		t.Errorf("authorized_clients file: %q", b)
	}
	if err := m.DoorSet(true, true); err != nil || !m.RemoteWrite() {
		t.Fatalf("remote writes can be switched on (and are off by default): %v", err)
	}
	if err := m.DoorSet(true, false); err != nil || m.RemoteWrite() {
		t.Fatal("and off again")
	}
	// saved: a fresh manager on the same file sees the same door
	var saved torConfig
	b, _ := os.ReadFile(m.path)
	if json.Unmarshal(b, &saved) != nil || !saved.Door.Enabled || len(saved.Door.Clients) != 1 || saved.Door.Clients[0].Pub != pub {
		t.Errorf("saved: %s", b)
	}
	// the view: fingerprints, never keys, and no address until Tor has made one
	v := m.DoorView()
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), pub) || strings.Contains(strings.ToLower(string(raw)), "priv") || !v.Active || v.Address != "" || v.Clients[0].Fingerprint != onionFingerprint(pub) {
		t.Errorf("view: %s", raw)
	}
	os.WriteFile(filepath.Join(m.onionDir(), "hostname"), []byte(strings.Repeat("b", 56)+".onion\n"), 0o600)
	if m.DoorView().Address != strings.Repeat("b", 56) {
		t.Error("the address shows once Tor made it")
	}
	// removing the last device switches the door off: it never runs open
	if err := m.DoorRemoveClient("laptop"); err != nil {
		t.Fatal(err)
	}
	if v := m.DoorView(); v.Enabled || v.Active || v.Address != "" || len(v.Clients) != 0 {
		t.Errorf("after removing the last device: %+v", v)
	}
	if strings.Contains(m.renderTorrc(), "HiddenService") {
		t.Error("no service in the torrc without a device")
	}
	if err := m.DoorRemoveClient("laptop"); err == nil {
		t.Error("removing an unknown device is an error")
	}
	if m.RemoteWrite() {
		t.Error("remote writes default to off")
	}
	if (*torMgr)(nil).RemoteWrite() {
		t.Error("a nil manager never allows remote writes")
	}
}

func TestDoorReloadsRunningTor(t *testing.T) {
	m, _, _, _ := testTor(t)
	got := filepath.Join(t.TempDir(), "hup")
	cmd := exec.Command("sh", "-c", `trap 'echo hup > `+got+`' HUP; while :; do sleep 0.1; done`)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	go cmd.Wait()
	time.Sleep(200 * time.Millisecond) // let the shell install its trap
	m.cmd = cmd
	if err := m.DoorAddClient("laptop", newTestPub(t)); err != nil {
		t.Fatal(err)
	}
	if err := m.DoorSet(true, false); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(got); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(got); err != nil {
		t.Error("a running Tor is sent SIGHUP so it re-reads the torrc and the authorized clients")
	}
	if rc, _ := os.ReadFile(m.torrc); !strings.Contains(string(rc), "HiddenServicePort 80 127.0.0.1:3130") {
		t.Errorf("the torrc was rewritten: %s", rc)
	}
}

// ---- the web gate ----

type onionWeb struct {
	srv   *httptest.Server
	c     *http.Client
	write *bool
}

func testOnionWeb(t *testing.T) *onionWeb {
	allowNets = nil
	_, n, _ := net.ParseCIDR("127.0.0.0/8")
	allowNets = append(allowNets, n)
	t.Cleanup(func() { allowNets = nil; uiTokenFile = "" })
	ui := &webUI{auth: testAuth(t), fp: "AA:BB"}
	webAuth = ui.auth
	t.Cleanup(func() { webAuth = nil })
	write := false
	srv := httptest.NewServer(ui.onionHandler(func() bool { return write })) // plain HTTP, as the real listener is
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	return &onionWeb{srv, c, &write}
}

func (w *onionWeb) do(t *testing.T, method, path string, csrf string) (int, string) {
	req, _ := http.NewRequest(method, w.srv.URL+path, strings.NewReader("{}"))
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	r, err := w.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r.StatusCode, string(b)
}

func TestOnionWebIsReadOnlyAndNarrow(t *testing.T) {
	w := testOnionWeb(t)
	// only the page, the login and the API are reachable; the machine endpoints are not
	for _, p := range []string{"/status.json", "/metrics", "/beat", "/wpad.dat", "/proxy.pac", "/dhcp-hook", "/secure", "/anything"} {
		if code, _ := w.do(t, "GET", p, ""); code != 404 {
			t.Errorf("%s over the onion: %d, want 404", p, code)
		}
	}
	if code, _ := w.do(t, "GET", "/login", ""); code != 200 {
		t.Errorf("login page: %d", code)
	}
	// logging in works over plain HTTP: the cookie is not Secure (a browser would not send it back), but is HttpOnly and SameSite=Strict
	r, err := w.c.PostForm(w.srv.URL+"/login", url.Values{"user": {"ben"}, "password": {"correct horse battery"}})
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	var ck *http.Cookie
	for _, x := range r.Cookies() {
		if x.Name == sessionCookie {
			ck = x
		}
	}
	if r.StatusCode != 303 || ck == nil || ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("onion login: %d %+v", r.StatusCode, ck)
	}
	s := webAuth.Session(&http.Request{Header: http.Header{"Cookie": {sessionCookie + "=" + ck.Value}}})
	if s == nil {
		t.Fatal("no session")
	}
	if code, _ := w.do(t, "GET", "/ui", ""); code != 200 {
		t.Errorf("the page after login: %d", code)
	}
	if code, _ := w.do(t, "GET", "/api/tor/onion", ""); code != 200 {
		t.Errorf("reading is allowed: %d", code)
	}
	// every change is refused while remote writes are off, with the CSRF token or without
	for _, p := range []string{"/api/tor/set", "/api/system/reboot", "/api/wifi", "/api/devices/note", "/api/fw/pause"} {
		code, body := w.do(t, "POST", p, s.CSRF)
		if code != 403 || !strings.Contains(body, "read-only") {
			t.Errorf("POST %s: %d %s", p, code, body)
		}
	}
	// remote writes on: ordinary changes reach the handlers (anything but the read-only refusal)...
	*w.write = true
	if _, body := w.do(t, "POST", "/api/tor/set", s.CSRF); strings.Contains(body, "read-only") {
		t.Errorf("with remote writes on, an ordinary change is not refused as read-only: %s", body)
	}
	// ...but the door's own settings, SSH keys, the account and backup restore never go through the onion
	for _, p := range []string{"/api/tor/onion/set", "/api/tor/onion/client", "/api/tor/onion/client/remove", "/api/ssh/add", "/api/ssh/delete", "/api/account/password", "/api/backup/restore"} {
		code, body := w.do(t, "POST", p, s.CSRF)
		if code != 403 || !strings.Contains(body, "read-only") {
			t.Errorf("POST %s with remote writes on: %d %s (must stay LAN-only)", p, code, body)
		}
	}
}

func TestOnionWebOnlyForLoopbackPeers(t *testing.T) {
	ui := &webUI{auth: testAuth(t), fp: "AA:BB"}
	h := ui.onionHandler(func() bool { return true })
	for addr, want := range map[string]int{"127.0.0.1:5000": 200, "[::1]:5000": 200, "192.168.1.50:5000": 403, "198.51.100.7:5000": 403, "garbage": 403} {
		allowNets = nil
		for _, c := range []string{"0.0.0.0/0", "::/0"} {
			_, n, _ := net.ParseCIDR(c)
			allowNets = append(allowNets, n)
		}
		req := httptest.NewRequest("GET", "/login", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		allowNets = nil
		if rec.Code != want {
			t.Errorf("peer %s: %d, want %d", addr, rec.Code, want)
		}
	}
}

func TestLANPageStillSecureCookieAndManagesTheDoor(t *testing.T) {
	// the TLS listener keeps the Secure cookie (the existing login test), and the door can be managed from it
	srv, c, _ := testWeb(t)
	login(t, srv, c, "ben", "correct horse battery")
	var csrf string
	u, _ := url.Parse(srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			s := webAuth.Session(&http.Request{Header: http.Header{"Cookie": {sessionCookie + "=" + ck.Value}}})
			csrf = s.CSRF
		}
	}
	prev := torMgrG
	t.Cleanup(func() { torMgrG = prev })
	m, _, _, _ := testTor(t)
	torMgrG = m
	req, _ := http.NewRequest("POST", srv.URL+"/api/tor/onion/set", strings.NewReader(`{"enabled":true}`))
	req.Header.Set("X-CSRF-Token", csrf)
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 400 || !strings.Contains(string(b), "authorize at least one device") {
		t.Errorf("from the LAN page, switching on with no device is refused with the reason: %d %s", r.StatusCode, b)
	}
	pub := newTestPub(t)
	req, _ = http.NewRequest("POST", srv.URL+"/api/tor/onion/client", strings.NewReader(`{"name":"laptop","pub":"`+pub+`"}`))
	req.Header.Set("X-CSRF-Token", csrf)
	r, _ = c.Do(req)
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || strings.Contains(string(b), pub) || !strings.Contains(string(b), onionFingerprint(pub)) {
		t.Errorf("adding a device: %d %s (the response shows the fingerprint, not the key)", r.StatusCode, b)
	}
}
