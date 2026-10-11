package main

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

// The browser game system (docs/GAMES.md). The screen page (/play) is the console, the controller page (/pad) is a phone; both sit on the room channel (room.go) and the box only
// introduces them. /game/<file>.js serves the scripts in gameclient/, so a new game is one new file there plus a script tag in play.html.

//go:embed play.html
var gamePlayHTML string

//go:embed pad.html
var gamePadHTML string

//go:embed gameclient/*.js
var gameScripts embed.FS

// gameScript serves one of the scripts in gameclient/ (the name must be a plain file name, which fs.ValidPath and the prefix check enforce).
func gameScript(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/game/")
	if name == "" || strings.Contains(name, "/") || !strings.HasSuffix(name, ".js") {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(gameScripts, "gameclient/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	serveBTAsset(w, b)
}

// gamePage serves a viewer page that people reach from a QR code or a shared link: with no session it bounces through the same-site redirect (see roomBounce).
func (u *webUI) gamePage(path, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u.auth.Session(r) == nil {
			roomBounce(w, r, path)
			return
		}
		secureHeaders(w)
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, body)
	}
}
