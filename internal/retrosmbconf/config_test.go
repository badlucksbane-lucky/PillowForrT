package retrosmbconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
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
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{Server: "192.168.1.5", Share: "roms", User: "retroshare", Password: "hunter2", Workgroup: "HOME", Bind: "127.0.0.1", Port: 8765, SMBPort: 445}
	if *cfg != want {
		t.Fatalf("got %+v, want %+v", *cfg, want)
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	os.WriteFile(path, []byte("server=1.2.3.4\nshare=roms\nuser=u\nport=9000\nsmb_port=1445\nbind=0.0.0.0\n"), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workgroup != "WORKGROUP" {
		t.Errorf("workgroup default = %q, want WORKGROUP", cfg.Workgroup)
	}
	if cfg.Port != 9000 || cfg.SMBPort != 1445 || cfg.Bind != "0.0.0.0" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	os.WriteFile(path, []byte("server=1.2.3.4\n"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing share/user")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/does/not/exist"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	want := Config{Server: "192.168.1.2", Share: "roms", User: "retroshare", Password: "Atari800", Workgroup: "WORKGROUP", Bind: "127.0.0.1", Port: 8765, SMBPort: 445}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if *got != want {
		t.Fatalf("round trip: got %+v, want %+v", *got, want)
	}
}

func TestSaveOverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	first := Config{Server: "1.1.1.1", Share: "a", User: "u1", Password: "p1", Workgroup: "WORKGROUP", Bind: "127.0.0.1", Port: 8765, SMBPort: 445}
	second := Config{Server: "2.2.2.2", Share: "b", User: "u2", Password: "p2", Workgroup: "WORKGROUP", Bind: "127.0.0.1", Port: 8765, SMBPort: 445}
	if err := Save(path, first); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".part"); !os.IsNotExist(err) {
		t.Errorf("leftover .part file: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if *got != second {
		t.Fatalf("got %+v, want %+v", *got, second)
	}
}
