package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The heartbeat is a hidden feature: with no -beat-token-file the endpoint does not exist, and /status.json does not mention it.
func TestHeartbeatOffByDefault(t *testing.T) {
	old := *beatTokenFile
	defer func() { *beatTokenFile = old }()
	*beatTokenFile = ""
	rec := httptest.NewRecorder()
	handleBeat(rec, httptest.NewRequest("POST", "/beat?from=x", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("heartbeat must be off (404) without a token file, got %d", rec.Code)
	}
	tf := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tf, []byte("s3cret\n"), 0o600)
	*beatTokenFile = tf
	req := httptest.NewRequest("POST", "/beat", nil)
	req.Header.Set("X-Beat-Token", "s3cret")
	rec = httptest.NewRecorder()
	handleBeat(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("an operator who sets a token file gets the endpoint, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handleBeat(rec, httptest.NewRequest("POST", "/beat", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong token must be refused, got %d", rec.Code)
	}
}
