// retro-smb-serve is a small, self-contained helper for the Orbic box: it
// speaks SMB2/3 directly to a ROMs/cores share on the local network (pure Go,
// no cgo, no libsmbclient) and re-serves it over loopback HTTP in the exact
// shape scripts/retro/pi-serve.py already serves (/list.json, /cores/<file>,
// /roms/<file>). Point <retro-dir>/upstream at http://127.0.0.1:<port> (see
// retro.go) and retro.go's existing, tested read-through does the rest -
// nothing about retro.go changes.
//
// It exists because tinyfwd (and the Orbic generally) has no kernel CIFS/FUSE
// and is built with CGO_ENABLED=0 (a static binary, so LD_PRELOAD tricks like
// ~/smb-proxy's have nothing to hook): this binary is cross-built the same
// way (see build.sh) and talks SMB itself instead.
//
// Config is a flat key=value file (see internal/retrosmbconf), not
// flags/env, so the password never shows up in `ps`. It is also the format
// the box's own admin API (retro_smb_admin.go) writes when it saves this
// from the admin page - the two never need to agree with each other by hand.
//
// The share's root must contain cores/ and roms/ subfolders, same as
// pi-serve.py's --dir. Read only: no method but GET/HEAD is accepted.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"

	"tinyfwd/internal/retrosmbconf"
)

// retroFileName is the same shape retro.go and pi-serve.py accept.
var retroFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()'+,&-]{0,120}$`)

// smbServer holds one lazily-(re)connected SMB session. A connection is
// opened on first use and kept until a request fails, at which point it is
// dropped and the next request reconnects - the box has no business retrying
// forever in the background for a share that may be off for hours.
type smbServer struct {
	cfg *retrosmbconf.Config

	mu    sync.Mutex
	conn  net.Conn
	sess  *smb2.Session
	share *smb2.Share
}

func (s *smbServer) connectLocked() error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(s.cfg.Server, strconv.Itoa(s.cfg.SMBPort)), 5*time.Second)
	if err != nil {
		return err
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.cfg.User,
			Password: s.cfg.Password,
			Domain:   s.cfg.Workgroup,
		},
	}
	sess, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return err
	}
	share, err := sess.Mount(s.cfg.Share)
	if err != nil {
		sess.Logoff()
		conn.Close()
		return err
	}
	s.conn, s.sess, s.share = conn, sess, share
	return nil
}

func (s *smbServer) dropLocked() {
	if s.share != nil {
		s.share.Umount()
	}
	if s.sess != nil {
		s.sess.Logoff()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	s.conn, s.sess, s.share = nil, nil, nil
}

// withShare runs fn against a connected share, reconnecting once if the
// share was not yet open or a previous call left it broken.
func (s *smbServer) withShare(fn func(*smb2.Share) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.share == nil {
		if err := s.connectLocked(); err != nil {
			return err
		}
	}
	err := fn(s.share)
	if err != nil {
		s.dropLocked()
	}
	return err
}

// listFiles lists the plain files directly under sub, plus (one level only,
// not recursive) the plain files in any subfolder of sub - so ROMs can be
// dropped into organizing folders like roms/NES/ and still show up to
// retro.go as flat names, same as a file placed directly in roms/. The bool
// says whether the SMB connection itself worked, independent of whether any
// matching files were found - an empty result from a share with the wrong
// password looks the same as an empty result from a share with no ROMs yet
// unless the caller can tell "connected" apart from "couldn't connect".
func (s *smbServer) listFiles(sub string) ([]string, bool) {
	var out []string
	err := s.withShare(func(sh *smb2.Share) error {
		ents, err := sh.ReadDir(sub)
		if err != nil {
			return err
		}
		var dirs []string
		for _, e := range ents {
			n := e.Name()
			if strings.Contains(n, "..") {
				continue
			}
			if e.IsDir() {
				dirs = append(dirs, n)
				continue
			}
			if retroFileName.MatchString(n) {
				out = append(out, n)
			}
		}
		for _, d := range dirs {
			subEnts, err := sh.ReadDir(sub + `\` + d)
			if err != nil {
				continue // one unreadable subfolder shouldn't hide the rest
			}
			for _, e := range subEnts {
				n := e.Name()
				if !e.IsDir() && retroFileName.MatchString(n) && !strings.Contains(n, "..") {
					out = append(out, n)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("list %s: %v", sub, err)
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

// listSubdirs returns the immediate subfolder names of sub (organizing
// folders like roms/NES/), used by openFile to search one level down.
func (s *smbServer) listSubdirs(sh *smb2.Share, sub string) []string {
	ents, err := sh.ReadDir(sub)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range ents {
		if e.IsDir() && !strings.Contains(e.Name(), "..") {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs
}

// openStat opens path on the share, stats it, and reports its size - or
// os.ErrNotExist if there's nothing there or it is a directory.
func openStat(sh *smb2.Share, path string) (*smb2.File, int64, error) {
	f, err := sh.Open(path)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if fi.IsDir() {
		f.Close()
		return nil, 0, os.ErrNotExist
	}
	return f, fi.Size(), nil
}

// openFile opens sub\name on the share, falling back to one level of
// subfolders under sub (see listFiles), and reports its size. The error is
// either os.ErrNotExist or a connection problem (the caller tells those
// apart with errors.Is).
func (s *smbServer) openFile(sub, name string) (*smb2.File, int64, error) {
	var (
		f    *smb2.File
		size int64
	)
	err := s.withShare(func(sh *smb2.Share) error {
		var err error
		f, size, err = openStat(sh, sub+`\`+name)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err // a connection problem, not "just not at top level"
		}
		for _, d := range s.listSubdirs(sh, sub) {
			if f, size, err = openStat(sh, sub+`\`+d+`\`+name); err == nil {
				return nil
			}
		}
		return os.ErrNotExist
	})
	return f, size, err
}

type handler struct {
	s *smbServer
}

func send(w http.ResponseWriter, code int, body []byte, ctype string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(body)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		send(w, http.StatusMethodNotAllowed, []byte("read only\n"), "text/plain")
		return
	}

	if r.URL.Path == "/list.json" {
		cores, coresOK := h.s.listFiles("cores")
		roms, romsOK := h.s.listFiles("roms")
		// share_ok is extra for retro.go (which only reads cores/roms and
		// ignores unknown fields) and load-bearing for the admin page's
		// status check (see retroSmbRunning in retro_smb_admin.go): an
		// empty list here is otherwise indistinguishable from "share
		// unreachable" (wrong password, wrong server, share down).
		body, _ := json.Marshal(map[string]any{
			"cores":    cores,
			"roms":     roms,
			"share_ok": coresOK && romsOK,
		})
		send(w, http.StatusOK, body, "application/json")
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	var sub, name string
	if len(parts) == 3 && parts[0] == "" {
		sub, name = parts[1], parts[2]
	}
	valid := (sub == "cores" || sub == "roms") && retroFileName.MatchString(name) && !strings.Contains(name, "..")
	if !valid {
		send(w, http.StatusNotFound, []byte("not found\n"), "text/plain")
		return
	}

	f, size, err := h.s.openFile(sub, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			send(w, http.StatusNotFound, []byte("not found\n"), "text/plain")
		} else {
			log.Printf("open %s/%s: %v", sub, name, err)
			send(w, http.StatusBadGateway, []byte("share unavailable\n"), "text/plain")
		}
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("stream %s/%s: %v", sub, name, err)
	}
}

func main() {
	cfgPath := flag.String("config", "/data/proxy/retro-smb.conf", "key=value config file (server=, share=, user=, password=, workgroup=, bind=, port=)")
	flag.Parse()

	cfg, err := retrosmbconf.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	s := &smbServer{cfg: cfg}
	addr := net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port))
	log.Printf("retro-smb-serve: %s/%s on http://%s (user %s)", cfg.Server, cfg.Share, addr, cfg.User)
	srv := &http.Server{
		Addr:              addr,
		Handler:           &handler{s: s},
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
