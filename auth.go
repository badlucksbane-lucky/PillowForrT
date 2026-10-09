package main

// Login for the web page: a username and password (stored as a bcrypt hash, never the password), a session cookie, and a per-session CSRF token. The browser only gets
// this over HTTPS (tlsgen.go). The old change token stays valid as an API key for scripts (X-UI-Token), over HTTPS only.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie  = "pillowforrt_session"
	sessionLife    = 12 * time.Hour
	maxSessions    = 20
	minPasswordLen = 10
	maxPasswordLen = 72 // bcrypt ignores everything past 72 bytes: refuse it instead of silently truncating
	failWindow     = 10 * time.Minute
	failsPerIP     = 5
	failsGlobal    = 30
	bcryptCost     = 10
)

type authFile struct {
	User string `json:"user"`
	Hash string `json:"hash"`
}

type session struct {
	User string
	CSRF string
	Exp  time.Time
}

type Auth struct {
	mu       sync.Mutex
	path     string
	user     string
	hash     []byte
	sessions map[string]*session
	fails    map[string][]time.Time // client address -> recent failed logins
	allFails []time.Time
	now      func() time.Time
}

func NewAuth(path string) *Auth {
	return &Auth{path: path, sessions: map[string]*session{}, fails: map[string][]time.Time{}, now: time.Now}
}

func (a *Auth) Load() {
	b, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	var f authFile
	if json.Unmarshal(b, &f) != nil || f.User == "" || f.Hash == "" {
		return
	}
	a.mu.Lock()
	a.user, a.hash = f.User, []byte(f.Hash)
	a.mu.Unlock()
}

func (a *Auth) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.user != ""
}

func (a *Auth) User() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.user
}

func checkPasswordPolicy(p string) error {
	if len(p) < minPasswordLen {
		return errors.New("the password must be at least 10 characters")
	}
	if len(p) > maxPasswordLen {
		return errors.New("the password can be at most 72 bytes")
	}
	return nil
}

// SetLogin stores the username and the bcrypt hash of the password (file mode 0600, written atomically). All sessions are dropped.
func (a *Auth) SetLogin(user, pass string) error {
	if user == "" || len(user) > 64 {
		return errors.New("the username must be 1 to 64 characters")
	}
	if err := checkPasswordPolicy(pass); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcryptCost)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(authFile{User: user, Hash: string(h)})
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return err
	}
	a.mu.Lock()
	a.user, a.hash = user, h
	a.sessions = map[string]*session{}
	a.mu.Unlock()
	return nil
}

// a hash that never matches, so a wrong username costs the same time as a wrong password
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not the password"), bcryptCost)

func (a *Auth) Check(user, pass string) bool {
	a.mu.Lock()
	u, h := a.user, a.hash
	a.mu.Unlock()
	if len(pass) > maxPasswordLen || u == "" {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(pass[:min(len(pass), maxPasswordLen)]))
		return false
	}
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(u)) == 1
	if !okUser {
		h = dummyHash
	}
	return bcrypt.CompareHashAndPassword(h, []byte(pass)) == nil && okUser
}

func clientAddr(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func prune(ts []time.Time, now time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < failWindow {
			out = append(out, t)
		}
	}
	return out
}

// Throttled: too many recent failures from this address (or from everywhere): refuse before even checking the password.
func (a *Auth) Throttled(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.fails[ip] = prune(a.fails[ip], now)
	a.allFails = prune(a.allFails, now)
	return len(a.fails[ip]) >= failsPerIP || len(a.allFails) >= failsGlobal
}

func (a *Auth) RecordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.fails[ip] = append(prune(a.fails[ip], now), now)
	a.allFails = append(prune(a.allFails, now), now)
	if len(a.fails) > 256 {
		a.fails = map[string][]time.Time{ip: a.fails[ip]}
	}
}

func (a *Auth) ClearFails(ip string) {
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *Auth) NewSession(user string) (id, csrf string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, s := range a.sessions {
		if now.After(s.Exp) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= maxSessions { // drop the oldest
		var oldest string
		var ot time.Time
		for k, s := range a.sessions {
			if oldest == "" || s.Exp.Before(ot) {
				oldest, ot = k, s.Exp
			}
		}
		delete(a.sessions, oldest)
	}
	id, csrf = randHex(32), randHex(16)
	a.sessions[id] = &session{User: user, CSRF: csrf, Exp: now.Add(sessionLife)}
	return
}

// Session returns the logged-in session for this request (and extends it), or nil.
func (a *Auth) Session(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || len(c.Value) != 64 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[c.Value]
	if s == nil {
		return nil
	}
	now := a.now()
	if now.After(s.Exp) {
		delete(a.sessions, c.Value)
		return nil
	}
	s.Exp = now.Add(sessionLife)
	cp := *s
	return &cp
}

func (a *Auth) EndSession(r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
}

// setSessionCookie: Secure whenever the request came over TLS (always, on the LAN page). The onion door's loopback listener is plain HTTP on purpose (the onion hop is end-to-end encrypted and a
// self-signed certificate for a .onion would only teach people to click through warnings), and a browser would refuse to send a Secure cookie back over it.
func setSessionCookie(w http.ResponseWriter, r *http.Request, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}
