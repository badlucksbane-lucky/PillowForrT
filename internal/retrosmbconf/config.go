// Package retrosmbconf is the key=value config file format shared by
// cmd/retro-smb-serve (which reads it) and the box's admin API (which
// writes it) - see retro_smb_admin.go. Keeping it in one place means the
// two sides can't drift apart on what a field is called or what its
// default is.
package retrosmbconf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is one retro-smb-serve instance's settings. Server, Share and
// User are required; everything else has a default.
type Config struct {
	Server, Share, User, Password, Workgroup string
	Bind                                     string
	Port, SMBPort                             int
}

// Defaults returns a Config with every optional field set, server/share/user
// empty.
func Defaults() Config {
	return Config{Workgroup: "WORKGROUP", Bind: "127.0.0.1", Port: 8765, SMBPort: 445}
}

// Load reads and parses a config file written by Save (or by hand, in the
// same key=value shape; see cmd/retro-smb-serve's doc comment).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Defaults()
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "server":
			cfg.Server = val
		case "share":
			cfg.Share = val
		case "user":
			cfg.User = val
		case "password":
			cfg.Password = val
		case "workgroup":
			cfg.Workgroup = val
		case "bind":
			cfg.Bind = val
		case "port":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.Port = n
			}
		case "smb_port":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.SMBPort = n
			}
		}
	}
	if cfg.Server == "" || cfg.Share == "" || cfg.User == "" {
		return nil, fmt.Errorf("%s: need at least server=, share= and user=", path)
	}
	return &cfg, nil
}

// Save writes cfg to path in the key=value shape Load reads, mode 600
// (it holds a password), replacing the file atomically.
func Save(path string, cfg Config) error {
	var b strings.Builder
	fmt.Fprintf(&b, "server=%s\n", cfg.Server)
	fmt.Fprintf(&b, "share=%s\n", cfg.Share)
	fmt.Fprintf(&b, "user=%s\n", cfg.User)
	fmt.Fprintf(&b, "password=%s\n", cfg.Password)
	fmt.Fprintf(&b, "workgroup=%s\n", cfg.Workgroup)
	fmt.Fprintf(&b, "bind=%s\n", cfg.Bind)
	fmt.Fprintf(&b, "port=%d\n", cfg.Port)
	fmt.Fprintf(&b, "smb_port=%d\n", cfg.SMBPort)
	tmp := path + ".part"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
