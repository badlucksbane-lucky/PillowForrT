package main

// The browse page (/browse): movies, series and anime from public catalogs, drawn entirely in the browser (browse.html). The page talks to those sources itself, so this box only serves
// the file, relays Nyaa (searchnyaa.go) and runs the web tab's search (search.go). That means the page's security policy must name the sources it may contact: the list below is the whole
// of it, and everything else stays blocked as on every other page. It sits behind the same login and the same on/off switch as the web search.

import (
	_ "embed"
	"io"
	"net/http"
)

//go:embed browse.html
var browseHTML string

const browseCSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; " +
	"img-src 'self' data: https://*.metahub.space https://image.tmdb.org https://*.anilist.co; " +
	"connect-src 'self' https://v3-cinemeta.strem.io https://cinemeta-catalogs.strem.io https://yts.gg https://movies-api.accel.li https://yts.bz " +
	"https://eztvx.to https://eztv.re https://eztv.wf https://torrentio.strem.fun https://graphql.anilist.co; worker-src 'self' blob:; media-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"

func writeBrowse(w http.ResponseWriter) {
	secureHeaders(w)
	w.Header().Set("Content-Security-Policy", browseCSP)
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, browseHTML)
}

func (u *webUI) browsePage(w http.ResponseWriter, r *http.Request) {
	if u.auth.Session(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	m := searchMgrG
	if m == nil {
		http.NotFound(w, r)
		return
	}
	if !m.Config().Enabled {
		secureHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		v := searchView{Err: "Search is off", Off: true}
		v.dots(m.Config(), m.Ready())
		io.WriteString(w, renderSearch(v))
		return
	}
	writeBrowse(w)
}
