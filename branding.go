package main

// The product is PillowForrT. The mark (assets/mark.svg, the sepia Bifrost bridge with its watching stone) is embedded once and served at /favicon.svg:
// it is the browser tab icon and the picture in the page headers. It needs no sign-in (the sign-in page shows it too); it is a static, cacheable file.

import (
	_ "embed"
	"net/http"
)

//go:embed assets/mark.svg
var markSVG []byte

func serveFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "image/svg+xml")
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Write(markSVG)
}
