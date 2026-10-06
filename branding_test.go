package main

import (
	"io"
	"strings"
	"testing"
)

// The product is called Stone of Heimdall: the pages, the sign-in page and the browser tab say so, and the mark is the sepia Bifrost.

func TestBrandingOnTheSignInPage(t *testing.T) {
	srv, c, _ := testWeb(t)
	r, _ := c.Get(srv.URL + "/login")
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	page := string(b)
	for _, want := range []string{"<title>Stone of Heimdall", "<h1>Stone of Heimdall</h1>", "a watchman for your hotspot", `rel="icon"`, "/favicon.svg", `class="mark"`, "#f1e4c8", "#1b130c"} {
		if !strings.Contains(page, want) {
			t.Errorf("sign-in page lacks %q", want)
		}
	}
	if strings.Contains(page, "<h1>Orbic</h1>") || strings.Contains(page, "<title>Orbic") {
		t.Error("the sign-in page still carries the old name")
	}
	if !strings.Contains(page, "AA:BB") {
		t.Error("the certificate fingerprint went missing from the sign-in page")
	}
}

func TestBrandingOnTheMainPage(t *testing.T) {
	srv, c, _ := testWeb(t)
	login(t, srv, c, "ben", "correct horse battery")
	r, _ := c.Get(srv.URL + "/ui")
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	page := string(b)
	if r.StatusCode != 200 {
		t.Fatalf("/ui: %d", r.StatusCode)
	}
	for _, want := range []string{"<title>Stone of Heimdall</title>", `id="ver"`, `rel="icon"`, "/favicon.svg", `class="mark"`, "#f1e4c8", "#1b130c", "Collapse all"} {
		if !strings.Contains(page, want) {
			t.Errorf("main page lacks %q", want)
		}
	}
	if strings.Contains(page, "<title>Orbic</title>") || strings.Contains(page, "<h1>Orbic ") {
		t.Error("the main page still carries the old name")
	}
}

func TestFaviconIsServedWithoutALoginAndIsTheMark(t *testing.T) {
	srv, c, _ := testWeb(t)
	r, err := c.Get(srv.URL + "/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("favicon: %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(b), "<svg") || !strings.Contains(string(b), "#5b3a21") || !strings.Contains(string(b), "#f3dba5") {
		t.Error("the favicon is not the sepia mark")
	}
	if cc := r.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("a static favicon should be cacheable, Cache-Control %q", cc)
	}
	if r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("favicon lacks nosniff")
	}
	// only GET and HEAD
	r2, _ := c.Post(srv.URL+"/favicon.svg", "text/plain", strings.NewReader("x"))
	r2.Body.Close()
	if r2.StatusCode != 405 {
		t.Errorf("POST to the favicon: %d (want 405)", r2.StatusCode)
	}
}
