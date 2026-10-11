package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The Retro game (gameclient/retro.js) runs libretro cores built by scripts/retro/build-core.sh. The cores and the ROMs are files on the box, not part of the binary and not in git:
//
//	<retro-dir>/cores/<id>.js and <id>.wasm   a built core (both files, or it is not offered)
//	<retro-dir>/roms/<file>                    games; the extension picks the core
//
// /retro/index.json lists what is there, /retro/cores/<file> and /retro/roms/<file> serve it. Everything is behind the session; file names are a fixed shape and are never joined from the URL unchecked.
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
func retroIndex(dir string) (cores []retroCore, roms []retroROM) {
	cores, roms = []retroCore{}, []retroROM{}
	ents, _ := os.ReadDir(filepath.Join(dir, "cores"))
	have := map[string]bool{}
	for _, e := range ents {
		have[e.Name()] = e.Type().IsRegular()
	}
	for id, sys := range retroSystems {
		if have[id+".js"] && have[id+".wasm"] {
			cores = append(cores, retroCore{ID: id, Name: sys.Name, Exts: sys.Exts})
		}
	}
	sort.Slice(cores, func(i, j int) bool { return cores[i].Name < cores[j].Name })
	ents, _ = os.ReadDir(filepath.Join(dir, "roms"))
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || !retroFileName.MatchString(n) || strings.Contains(n, "..") {
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

func (u *webUI) retroFiles(w http.ResponseWriter, r *http.Request) {
	if *retroDir == "" || u.auth.Session(r) == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	secureHeaders(w)
	rest := strings.TrimPrefix(r.URL.Path, "/retro/")
	if rest == "index.json" {
		cores, roms := retroIndex(*retroDir)
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
	if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() { // no symlinks, no folders
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
