package main

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVitalsLine(t *testing.T) {
	m := &runtime.MemStats{HeapAlloc: 53 << 20, HeapInuse: 60 << 20, Sys: 70 << 20}
	got := vitalsLine(2.5, 41.6, m, 97, 54000, 3, 12*time.Millisecond, 0.376)
	for _, want := range []string{"load=2.50", "cpu=42%", "heap=54272KB", "inuse=61440KB", "sys=71680KB", "gcs=3", "gcpause=12ms", "goroutines=97", "avail=54000KB", "busy=38%"} {
		if !strings.Contains(got, want) {
			t.Errorf("vitals line %q lacks %q", got, want)
		}
	}
}

func TestSelfCPUTicksReads(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	x := 0
	for i := 0; i < 50_000_000; i++ {
		x += i
	}
	_ = x
	if selfCPUTicks() == 0 {
		t.Error("no CPU time read from /proc/self/stat")
	}
}

func TestDebugEndpoints(t *testing.T) {
	for path, ctype := range map[string]string{"debug/heap": "application/octet-stream", "debug/goroutines": "text/plain"} {
		rec := httptest.NewRecorder()
		handleDebug(rec, httptest.NewRequest("GET", "/api/"+path, nil), path)
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), ctype) || rec.Body.Len() == 0 {
			t.Errorf("%s: code %d type %q body %d bytes", path, rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
		}
	}
	rec := httptest.NewRecorder()
	handleDebug(rec, httptest.NewRequest("POST", "/api/debug/heap", nil), "debug/heap")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST gave %d, want 405", rec.Code)
	}
	rec = httptest.NewRecorder()
	handleDebug(rec, httptest.NewRequest("GET", "/api/debug/nope", nil), "debug/nope")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown debug path gave %d, want 404", rec.Code)
	}
}
