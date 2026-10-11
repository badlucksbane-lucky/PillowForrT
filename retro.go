package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Retro game (gameclient/retro.js) runs libretro cores built by scripts/retro/build-core.sh. The cores and the ROMs are files on the box, not part of the binary and not in git:
//
//	<retro-dir>/cores/<id>.js and <id>.wasm   a built core (both files, or it is not offered)
//	<retro-dir>/roms/<file>                    games; the extension picks the core
//
// /retro/index.json lists what is there, /retro/cores/<file> and /retro/roms/<file> serve it. Everything is behind the session; file names are a fixed shape and are never joined from the URL unchecked.
//
// The box has little room, so the same folders can live on another computer on the LAN (the Pi): put its address in the one-line file <retro-dir>/upstream, for example
// "http://192.168.1.2:8765", and anything not found here is read through from there (scripts/retro/pi-serve.py serves such a folder). Local files win; the address must be a private or
// loopback IP literal, redirects are not followed, and a dead upstream only means its files are missing.
var retroDir = flag.String("retro-dir", "/data/proxy/retro", "folder with cores/ (built libretro cores) and roms/ for the Retro game (empty = off)")

// retroSystems names each core and the ROM extensions it plays. A core not listed here is still served, but offers no games.
var retroSystems = map[string]struct {
	Name string
	Exts []string
}{
	"fceumm":   {"NES", []string{"nes", "fds", "unf", "unif"}},
	"gambatte": {"Game Boy", []string{"gb", "gbc"}},
}

var retroFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()'+,&-]{0,120}$`)

type retroCore struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Exts []string `json:"exts"`
}
type retroROM struct {
	File string `json:"file"`
	Core string `json:"core"`
	Name string `json:"name"`
}

// retroIndex lists the cores that have both files and the ROMs one of them can play.
func retroIndex(dir string, upCores, upRoms []string) (cores []retroCore, roms []retroROM) {
	cores, roms = []retroCore{}, []retroROM{}
	ents, _ := os.ReadDir(filepath.Join(dir, "cores"))
	have := map[string]bool{}
	for _, e := range ents {
		have[e.Name()] = e.Type().IsRegular()
	}
	for _, n := range upCores {
		have[n] = true
	}
	for id, sys := range retroSystems {
		if have[id+".js"] && have[id+".wasm"] {
			cores = append(cores, retroCore{ID: id, Name: sys.Name, Exts: sys.Exts})
		}
	}
	sort.Slice(cores, func(i, j int) bool { return cores[i].Name < cores[j].Name })
	ents, _ = os.ReadDir(filepath.Join(dir, "roms"))
	var names []string
	seen := map[string]bool{}
	for _, e := range ents {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
			seen[e.Name()] = true
		}
	}
	for _, n := range upRoms {
		if !seen[n] {
			names = append(names, n)
			seen[n] = true
		}
	}
	for _, n := range names {
		if !retroNameOK(n) {
			continue
		}
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(n), "."))
		for _, c := range cores {
			for _, x := range c.Exts {
				if x == ext {
					roms = append(roms, retroROM{File: n, Core: c.ID, Name: strings.TrimSuffix(n, filepath.Ext(n))})
					goto next
				}
			}
		}
	next:
	}
	sort.Slice(roms, func(i, j int) bool { return strings.ToLower(roms[i].Name) < strings.ToLower(roms[j].Name) })
	return
}

func retroNameOK(n string) bool { return retroFileName.MatchString(n) && !strings.Contains(n, "..") }

// ---- the upstream (another computer's copy of the folders) ----

var (
	retroUpTTL    = 10 * time.Second // how long a listing, or the news that there is none, is kept
	retroMaxBytes = int64(64 << 20)  // the most one file read through may be
	retroUpClient = &http.Client{
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // an upstream must not be able to send us elsewhere
	}
	retroUpState struct {
		mu          sync.Mutex
		url         string
		at          time.Time
		cores, roms []string
	}
)

// retroUpstream reads <dir>/upstream: an http(s) address on this network (a private or loopback IP literal), no login, query or fragment. Anything else counts as no upstream.
func retroUpstream(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "upstream"))
	if err != nil {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(string(b)))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return ""
	}
	return strings.TrimRight(u.String(), "/")
}

// retroUpList asks the upstream what it has ({"cores": [...], "roms": [...]} file names). Names of the wrong shape are dropped. Kept for retroUpTTL, failures too, so a dead upstream costs one wait, not one per page.
func retroUpList(base string) (cores, roms []string) {
	st := &retroUpState
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.url == base && time.Since(st.at) < retroUpTTL {
		return st.cores, st.roms
	}
	st.url, st.at, st.cores, st.roms = base, time.Now(), nil, nil
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/list.json", nil)
	resp, err := retroUpClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	var l struct{ Cores, Roms []string }
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&l) != nil {
		return nil, nil
	}
	keep := func(in []string) (out []string) {
		for _, n := range in {
			if retroNameOK(n) {
				out = append(out, n)
			}
		}
		return
	}
	st.cores, st.roms = keep(l.Cores), keep(l.Roms)
	return st.cores, st.roms
}

// retroReadThrough streams one file from the upstream.
func retroReadThrough(w http.ResponseWriter, r *http.Request, base, sub, name, ctype string) {
	req, _ := http.NewRequestWithContext(r.Context(), "GET", base+"/"+sub+"/"+url.PathEscape(name), nil)
	resp, err := retroUpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		http.NotFound(w, r)
		return
	case resp.StatusCode != 200 || resp.ContentLength > retroMaxBytes:
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-cache")
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	io.Copy(w, io.LimitReader(resp.Body, retroMaxBytes))
}

func (u *webUI) retroFiles(w http.ResponseWriter, r *http.Request) {
	if *retroDir == "" || u.auth.Session(r) == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	secureHeaders(w)
	rest := strings.TrimPrefix(r.URL.Path, "/retro/")
	if rest == "index.json" {
		var uc, ur []string
		if base := retroUpstream(*retroDir); base != "" {
			uc, ur = retroUpList(base)
		}
		cores, roms := retroIndex(*retroDir, uc, ur)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"cores": cores, "roms": roms})
		return
	}
	sub, name, ok := strings.Cut(rest, "/")
	if !ok || (sub != "cores" && sub != "roms") || !retroFileName.MatchString(name) || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	ctype := "application/octet-stream"
	if sub == "cores" {
		switch filepath.Ext(name) {
		case ".js":
			ctype = "text/javascript; charset=utf-8"
		case ".wasm":
			ctype = "application/wasm"
		default:
			http.NotFound(w, r)
			return
		}
	}
	p := filepath.Join(*retroDir, sub, name)
	fi0, err := os.Lstat(p)
	if os.IsNotExist(err) {
		if base := retroUpstream(*retroDir); base != "" {
			retroReadThrough(w, r, base, sub, name, ctype)
			return
		}
	}
	if err != nil || !fi0.Mode().IsRegular() { // no symlinks, no folders
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}
