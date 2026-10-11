package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	if err := os.WriteFile(path, []byte(`
# comment
server = 192.168.1.5
share=roms
user=retroshare
password = hunter2

workgroup=HOME
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := config{server: "192.168.1.5", share: "roms", user: "retroshare", password: "hunter2", workgroup: "HOME", bind: "127.0.0.1", port: 8765, smbPort: 445}
	if *cfg != want {
		t.Fatalf("got %+v, want %+v", *cfg, want)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	os.WriteFile(path, []byte("server=1.2.3.4\nshare=roms\nuser=u\nport=9000\nsmb_port=1445\nbind=0.0.0.0\n"), 0o600)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.workgroup != "WORKGROUP" {
		t.Errorf("workgroup default = %q, want WORKGROUP", cfg.workgroup)
	}
	if cfg.port != 9000 || cfg.smbPort != 1445 || cfg.bind != "0.0.0.0" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadConfigMissingRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	os.WriteFile(path, []byte("server=1.2.3.4\n"), 0o600)
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for missing share/user")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig("/does/not/exist"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHandlerRejectsWrites(t *testing.T) {
	h := &handler{s: &smbServer{cfg: &config{}}}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(m, "/list.json", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /list.json: got %d, want 405", m, w.Code)
		}
	}
}

func TestHandlerRejectsBadNames(t *testing.T) {
	h := &handler{s: &smbServer{cfg: &config{}}}
	cases := []string{
		"/roms/../etc/passwd",
		"/roms/..",
		"/notasub/x.nes",
		"/roms",
		"/roms/",
		"/roms/x/y.nes",
		"/cores/.hidden",
	}
	for _, p := range cases {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: got %d, want 404", p, w.Code)
		}
	}
}

func TestRetroFileNameRegex(t *testing.T) {
	ok := []string{"Mario.nes", "fceumm.wasm", "a", "Pokemon Red (USA).gb", "core_v2.js"}
	bad := []string{"", ".hidden", "../x", "a/b", "x\\y", string(make([]byte, 200))}
	for _, n := range ok {
		if !retroFileName.MatchString(n) {
			t.Errorf("expected %q to match", n)
		}
	}
	for _, n := range bad {
		if retroFileName.MatchString(n) {
			t.Errorf("expected %q to NOT match", n)
		}
	}
}
