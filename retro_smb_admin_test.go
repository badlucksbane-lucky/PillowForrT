package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"tinyfwd/internal/retrosmbconf"
)

func retroSmbFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "retro-smb.conf")
	oldConf, oldInit := retroSmbConfPath, retroSmbInitScript
	retroSmbConfPath, retroSmbInitScript = path, "" // no init.d on a dev machine
	t.Cleanup(func() { retroSmbConfPath, retroSmbInitScript = oldConf, oldInit })
	return path
}

func retroSmbPost(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/retro/set", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	handleRetroAPI(rec, req, "retro/set")
	return rec
}

func TestRetroSmbViewUnconfigured(t *testing.T) {
	retroSmbFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/retro", nil)
	rec := httptest.NewRecorder()
	handleRetroAPI(rec, req, "retro")
	var v map[string]any
	json.NewDecoder(rec.Body).Decode(&v)
	if v["configured"] != false {
		t.Fatalf("expected configured=false, got %+v", v)
	}
}

func TestRetroSmbSetRequiresFields(t *testing.T) {
	retroSmbFixture(t)
	rec := retroSmbPost(t, map[string]any{"server": "", "share": "roms", "user": "u", "password": "p"})
	if rec.Code != 400 {
		t.Fatalf("empty server: got %d, want 400", rec.Code)
	}
}

func TestRetroSmbSetRequiresPasswordFirstTime(t *testing.T) {
	retroSmbFixture(t)
	rec := retroSmbPost(t, map[string]any{"server": "1.2.3.4", "share": "roms", "user": "u"})
	if rec.Code != 400 {
		t.Fatalf("no password, no existing config: got %d, want 400", rec.Code)
	}
}

func TestRetroSmbSetAndView(t *testing.T) {
	path := retroSmbFixture(t)
	rec := retroSmbPost(t, map[string]any{"server": "192.168.1.2", "share": "roms", "user": "retroshare", "password": "Atari800", "workgroup": "HOME"})
	if rec.Code != 200 {
		t.Fatalf("set: got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)
	if _, has := resp["password"]; has {
		t.Fatal("response must never include the password")
	}
	if resp["server"] != "192.168.1.2" || resp["workgroup"] != "HOME" {
		t.Fatalf("unexpected view after set: %+v", resp)
	}
	// Nothing is actually listening on 127.0.0.1:8765 in this test process,
	// so both must honestly report false - this is the distinction the
	// earlier design got wrong (see TestListJSONReportsShareUnreachable).
	if resp["running"] != false || resp["share_ok"] != false {
		t.Errorf("expected running=false, share_ok=false with no bridge listening, got %+v", resp)
	}

	cfg, err := retrosmbconf.Load(path)
	if err != nil {
		t.Fatalf("saved config did not load: %v", err)
	}
	if cfg.Password != "Atari800" {
		t.Errorf("password not saved correctly")
	}
}

func TestRetroSmbSetBlankPasswordKeepsExisting(t *testing.T) {
	retroSmbFixture(t)
	retroSmbPost(t, map[string]any{"server": "1.1.1.1", "share": "roms", "user": "u1", "password": "secret1"})

	rec := retroSmbPost(t, map[string]any{"server": "2.2.2.2", "share": "roms", "user": "u1"}) // no password field
	if rec.Code != 200 {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	cfg, err := retrosmbconf.Load(retroSmbConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "secret1" || cfg.Server != "2.2.2.2" {
		t.Fatalf("blank password should keep old secret and still apply other changes: %+v", cfg)
	}
}

func TestRetroSmbSetBadJSON(t *testing.T) {
	retroSmbFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/retro/set", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	handleRetroAPI(rec, req, "retro/set")
	if rec.Code != 400 {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestRetroSmbAPIMethodNotFound(t *testing.T) {
	retroSmbFixture(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/retro", nil)
	rec := httptest.NewRecorder()
	handleRetroAPI(rec, req, "retro")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE /api/retro: got %d, want 404", rec.Code)
	}
}
