package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"tinyfwd/internal/retrosmbconf"
)

// retroSmbConfPath and retroSmbInitScript name the two fixed locations the
// Orbic deploy uses (see docs/GAMES.md and /etc/init.d/retro_smb_serve).
// They are plain vars, not flags, so tests can point them at a temp dir;
// nothing on the box has a reason to run them anywhere else.
var (
	retroSmbConfPath   = "/data/proxy/retro-smb.conf"
	retroSmbInitScript = "/etc/init.d/retro_smb_serve"
)

// retroSmbPingTimeout bounds how long the admin page waits to learn whether
// the bridge is actually answering, not just configured.
const retroSmbPingTimeout = 2 * time.Second

// retroSmbStatus asks the bridge's own /list.json. running is just "the
// process answered HTTP" - the bridge deliberately answers 200 with an
// empty list even when it cannot reach the SMB share at all (so a
// temporarily offline share never breaks the game), so running alone would
// read as healthy for a wrong password or server too. shareOK is the
// bridge's own report (its "share_ok" field) of whether its last SMB
// connection actually worked; only that field means the share itself, not
// just the process, is reachable with the saved credentials.
func retroSmbStatus(cfg *retrosmbconf.Config) (running, shareOK bool) {
	client := http.Client{Timeout: retroSmbPingTimeout}
	resp, err := client.Get("http://" + net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)) + "/list.json")
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	var v struct {
		ShareOK bool `json:"share_ok"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v)
	return true, v.ShareOK
}

// retroSmbView never includes the password.
func retroSmbView() map[string]any {
	cfg, err := retrosmbconf.Load(retroSmbConfPath)
	if err != nil {
		return map[string]any{"available": true, "configured": false}
	}
	running, shareOK := retroSmbStatus(cfg)
	return map[string]any{
		"available":  true,
		"configured": true,
		"server":     cfg.Server,
		"share":      cfg.Share,
		"user":       cfg.User,
		"workgroup":  cfg.Workgroup,
		"running":    running,
		"share_ok":   shareOK,
	}
}

// retroSmbRestart restarts the bridge process so a saved config takes
// effect without a reboot. Off the box (retroSmbInitScript cleared, or the
// script missing - e.g. in dev) it is simply a no-op: the config file is
// still saved either way.
func retroSmbRestart(ctx context.Context) bool {
	if retroSmbInitScript == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, retroSmbInitScript, "restart").Run() == nil
}

type retroSmbSetBody struct {
	Server, Share, User, Password, Workgroup string
}

func handleRetroAPI(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "retro" && r.Method == http.MethodGet:
		writeJSON(w, 200, retroSmbView())
	case path == "retro/set" && r.Method == http.MethodPost:
		handleRetroSet(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func handleRetroSet(w http.ResponseWriter, r *http.Request) {
	var b retroSmbSetBody
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b) != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	b.Server, b.Share, b.User = strings.TrimSpace(b.Server), strings.TrimSpace(b.Share), strings.TrimSpace(b.User)
	if b.Server == "" || b.Share == "" || b.User == "" {
		writeJSON(w, 400, map[string]string{"error": "server, share and user are required"})
		return
	}

	cfg := retrosmbconf.Defaults()
	cfg.Server, cfg.Share, cfg.User, cfg.Password = b.Server, b.Share, b.User, b.Password
	if wg := strings.TrimSpace(b.Workgroup); wg != "" {
		cfg.Workgroup = wg
	}
	if cfg.Password == "" {
		// Blank means "keep the current password" so the admin page never
		// has to show (or re-send) a saved secret just to change the server.
		if existing, err := retrosmbconf.Load(retroSmbConfPath); err == nil {
			cfg.Password = existing.Password
		}
	}
	if cfg.Password == "" {
		writeJSON(w, 400, map[string]string{"error": "password required (first time setup)"})
		return
	}

	if err := retrosmbconf.Save(retroSmbConfPath, cfg); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	restarted := retroSmbRestart(r.Context())
	resp := retroSmbView()
	resp["restarted"] = restarted
	writeJSON(w, 200, resp)
}
