package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogGateSaysItOnceAndCountsTheRest(t *testing.T) {
	g := &logGate{}
	t0 := time.Now()
	if ok, n := g.allow("a", time.Minute, t0); !ok || n != 0 {
		t.Fatal("the first one is logged")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := g.allow("a", time.Minute, t0.Add(time.Duration(i)*time.Second)); ok {
			t.Fatal("repeats inside the interval are held back")
		}
	}
	if ok, _ := g.allow("b", time.Minute, t0); !ok {
		t.Error("another message is independent")
	}
	if ok, n := g.allow("a", time.Minute, t0.Add(2*time.Minute)); !ok || n != 5 {
		t.Errorf("after the interval: ok=%v, held back %d (want 5)", ok, n)
	}
}

func TestLogGateIsBounded(t *testing.T) {
	g := &logGate{}
	for i := 0; i < 5*logGateLimit; i++ {
		g.allow(string(rune('a'+i%26))+strings.Repeat("x", i), time.Minute, time.Now())
	}
	if len(g.m) > logGateLimit {
		t.Errorf("%d messages remembered", len(g.m))
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	var b bytes.Buffer
	log.SetOutput(&b)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(os.Stderr); log.SetFlags(log.LstdFlags) })
	logRate = &logGate{}
	return &b
}

func TestProxyErrorsAreQuietAndOnce(t *testing.T) {
	b := captureLog(t)
	logProxyError("CONNECT dial error", "a.example:443", context.Canceled)
	logProxyError("CONNECT dial error", "a.example:443", errors.New("wrapped: "+context.Canceled.Error()))
	if strings.Count(b.String(), "\n") != 1 {
		t.Errorf("a client that gave up is not logged (a plain error is): %q", b.String())
	}
	b.Reset()
	for i := 0; i < 50; i++ {
		logProxyError("CONNECT dial error", "blocked.example:443", errProxyDest)
	}
	logProxyError("CONNECT dial error", "other.example:443", errProxyDest)
	if got := strings.Count(b.String(), "\n"); got != 2 {
		t.Errorf("50 identical refusals and one other: %d lines\n%s", got, b.String())
	}
}

func TestHTTPErrorLogCollapsesHandshakeErrors(t *testing.T) {
	b := captureLog(t)
	l := httpErrorLog()
	for i := 0; i < 40; i++ {
		l.Printf("http: TLS handshake error from 192.168.1.10:%d: EOF", 30000+i)
	}
	l.Printf("http: Accept error: too many open files; retrying in 5ms")
	if got := strings.Count(b.String(), "\n"); got != 2 {
		t.Errorf("%d lines for 40 handshake errors and one accept error:\n%s", got, b.String())
	}
}

func TestRotatingLogMovesAsideAtTheLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tinyfwd.log")
	os.WriteFile(path, bytes.Repeat([]byte("old line\n"), 120), 0o644)
	r, err := newRotatingLog(path, false, 1000)
	if err != nil {
		t.Fatal(err)
	}
	r.Write([]byte("first new line\n")) // the file is already past the limit: moved aside before this is written
	if b, _ := os.ReadFile(path + ".1"); !bytes.HasPrefix(b, []byte("old line")) || len(b) != 1080 {
		t.Errorf("the old log is not in .1: %d bytes", len(b))
	}
	if b, _ := os.ReadFile(path); string(b) != "first new line\n" {
		t.Errorf("new log: %q", b)
	}
	for i := 0; i < 200; i++ {
		r.Write([]byte("0123456789 0123456789 0123456789\n"))
	}
	fi, _ := os.Stat(path)
	fi1, _ := os.Stat(path + ".1")
	if fi.Size() > 1000 || fi1.Size() > 1000 || fi1.Size() == 0 {
		t.Errorf("sizes %d and %d: neither may pass the limit, and the old copy must hold the last full log", fi.Size(), fi1.Size())
	}
}
