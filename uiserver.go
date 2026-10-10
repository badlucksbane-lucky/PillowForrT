package main

// The web page's HTTPS server (login, session, CSRF) and the rules for what stays on plain HTTP. HTTP keeps only what machines need: the PAC file, /status.json (without the
// per-device detail), /beat for a companion computer's heartbeat, and the proxy itself. Everything else on HTTP is redirected to https://pillowforrt.lan/ .

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"html"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed login.html
var loginHTML string

type ctxKey int

const sessionKey ctxKey = 1

var webAuth *Auth

type webUI struct {
	auth *Auth
	fp   string        // the certificate's SHA-256 fingerprint, shown on the login page
	fpFn func() string // when set, asked each time (the certificate can be renewed while running)
}

func (u *webUI) fingerprint() string {
	if u.fpFn != nil {
		return u.fpFn()
	}
	return u.fp
}

func secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'")
}

func (u *webUI) loginPage(w http.ResponseWriter, code int, errMsg string) {
	secureHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	note := ""
	if !u.auth.Configured() {
		note = `<p class="err">No login has been set up yet. From a computer on the LAN run <code>scripts/set-login.sh</code>.</p>`
	}
	p := strings.NewReplacer("{{NOTE}}", note, "{{ERR}}", html.EscapeString(errMsg), "{{FP}}", html.EscapeString(u.fingerprint())).Replace(loginHTML)
	w.Write([]byte(p))
}

func (u *webUI) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if u.auth.Session(r) != nil {
			http.Redirect(w, r, "/ui", http.StatusSeeOther)
			return
		}
		u.loginPage(w, 200, "")
	case http.MethodPost:
		ip := clientAddr(r)
		if u.auth.Throttled(ip) {
			u.loginPage(w, http.StatusTooManyRequests, "Too many failed attempts. Wait ten minutes.")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			u.loginPage(w, 400, "Bad request.")
			return
		}
		user, pass := r.PostForm.Get("user"), r.PostForm.Get("password")
		if !u.auth.Configured() || !u.auth.Check(user, pass) {
			u.auth.RecordFail(ip)
			time.Sleep(500 * time.Millisecond)
			u.loginPage(w, http.StatusUnauthorized, "Wrong username or password.")
			return
		}
		u.auth.ClearFails(ip)
		id, _ := u.auth.NewSession(user)
		setSessionCookie(w, r, id, int(sessionLife.Seconds()))
		http.Redirect(w, r, "/ui", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (u *webUI) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u.auth.EndSession(r)
	setSessionCookie(w, r, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// apiAuthed lets a request through if it carries a valid session (POSTs also need that session's CSRF token) or, for scripts, the API-key token header.
func (u *webUI) apiAuthed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secureHeaders(w)
		if r.Header.Get("X-UI-Token") != "" && uiTokenOK(r) {
			next(w, r)
			return
		}
		s := u.auth.Session(r)
		if s == nil {
			writeJSON(w, 401, map[string]string{"error": "not logged in"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
				writeJSON(w, 403, map[string]string{"error": "missing or wrong CSRF token (reload the page)"})
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, s)))
	}
}

func (u *webUI) page(w http.ResponseWriter, r *http.Request) {
	if u.auth.Session(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secureHeaders(w)
	handleUI(w, r)
}

func (u *webUI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", u.login)
	mux.HandleFunc("/favicon.svg", serveFavicon)
	mux.HandleFunc("/logout", u.logout)
	mux.HandleFunc("/ui", u.page)
	mux.HandleFunc("/search", u.searchPage)
	mux.HandleFunc("/browse", u.browsePage)
	mux.HandleFunc("/room-test", u.roomTestPage)
	mux.HandleFunc("/room/room.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, roomClientJS) })
	mux.HandleFunc("/room/qr.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, roomQRJS) })
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, btSWJS) })
	mux.HandleFunc("/bt/btclient.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, btClientJS) })
	mux.HandleFunc("/bt/audio.js", func(w http.ResponseWriter, r *http.Request) { serveBTAsset(w, btAudioJS) })
	mux.HandleFunc("/opensearch.xml", serveOpenSearch)
	mux.HandleFunc("/api/", u.apiAuthed(handleAPI))
	mux.HandleFunc("/status.json", func(w http.ResponseWriter, r *http.Request) { secureHeaders(w); serveStatus(w, r) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { secureHeaders(w); serveMetrics(w, r) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui", http.StatusSeeOther)
			return
		}
		http.NotFound(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// ---- the onion door's web listener (127.0.0.1 only; Tor is its only client). See ONION-SERVICE.md. ----

type onionCtxKey struct{}

// viaOnion says whether the request came in through the onion listener (a context value set there, so a client cannot fake it).
func viaOnion(r *http.Request) bool { v, _ := r.Context().Value(onionCtxKey{}).(bool); return v }

func isLoopbackAddr(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// onionPathOK: the only paths an onion visitor can reach. Not /status.json, /metrics, /beat, the PAC file or the proxy: fail closed.
func onionPathOK(p string) bool {
	switch p {
	case "/", "/login", "/logout", "/ui":
		return true
	}
	return strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/api/bt") && !strings.HasPrefix(p, "/api/room") // the torrent bridge and the room channel are for the LAN only
}

// onionLANOnly: changes that are refused through the onion door even when remote writes are switched on: the door's own settings (a remote session must never authorize more keys or loosen its
// own limits), SSH keys, the login itself and restoring a backup.
func onionLANOnly(p string) bool {
	return strings.HasPrefix(p, "/api/ssh") || strings.HasPrefix(p, "/api/account/") || strings.HasPrefix(p, "/api/backup/restore") || strings.HasPrefix(p, "/api/export") || p == "/api/tap" || strings.HasPrefix(p, "/api/towers")
}

// onionHandler is the web page for a visitor who came through the onion service: same login, same pages, but read-only (any change is refused) unless remote writes are on, and the
// door's own management never goes through it.
func (u *webUI) onionHandler(remoteWrite func() bool) http.Handler {
	inner := u.handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackAddr(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !onionPathOK(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != "/login" && r.URL.Path != "/logout" {
			if onionLANOnly(r.URL.Path) || !remoteWrite() {
				secureHeaders(w)
				writeJSON(w, 403, map[string]string{"error": "this page is read-only when opened through the onion door: make changes from the LAN page"})
				return
			}
		}
		inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), onionCtxKey{}, true)))
	})
}

// httpStays: does this plain-HTTP request keep being served over HTTP? Only what machines need.
func httpStays(r *http.Request) bool {
	switch r.URL.Path {
	case "/status.json", "/metrics", "/beat", "/dhcp-hook":
		return true
	}
	if r.Method == http.MethodGet && isPACPath(r.URL.Path) {
		// a browser opening http://pillowforrt.lan/ is sent to the login; PAC fetchers send no Accept: text/html
		return !(r.URL.Path == "/" && strings.Contains(r.Header.Get("Accept"), "text/html"))
	}
	return false
}

func redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	host := *uiHost
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

// statusDetailOK: may this /status.json request see per-device and browsing detail? Only with a session or a token header.
func statusDetailOK(r *http.Request) bool {
	if r.Header.Get("X-UI-Token") != "" && uiTokenOK(r) {
		return true
	}
	if r.Header.Get("X-Beat-Token") != "" && tokenOK(r) {
		return true
	}
	return webAuth != nil && webAuth.Session(r) != nil
}
