package main

// The daemon's log: kept to a size (the box's flash is small and the file is rewritten block by block), and the lines that repeat by the thousand said once in a while instead.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	logMax       = 512 << 10 // the log is moved to <name>.1 at this size; one old copy is kept, so at most about twice this
	logSayEvery  = 10 * time.Minute
	logGateLimit = 256 // distinct messages remembered
)

// ---- rotation ----

// rotatingLog is the log's destination when the daemon's stderr is a file (as the init script makes it: `>> tinyfwd.log 2>&1`). The daemon opens that same file itself, so that
// it can rename it at the size limit and start a new one, and points its own stderr at the new file so that whatever else writes there (a panic, a plain Fprintf) lands in it too.
type rotatingLog struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	dup    bool // point file descriptor 2 at each new file (off in tests)
	maxLen int64
}

func newRotatingLog(path string, dup bool, max int64) (*rotatingLog, error) {
	r := &rotatingLog{path: path, dup: dup, maxLen: max}
	return r, r.open()
}

func (r *rotatingLog) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if r.dup {
		unix.Dup3(int(f.Fd()), 2, 0)
	}
	r.f = f
	return nil
}

func (r *rotatingLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fi, err := r.f.Stat(); err == nil && fi.Size()+int64(len(p)) > r.maxLen {
		r.rotate()
	}
	return r.f.Write(p)
}

// rotate moves the log aside and starts a new one. If the new file cannot be made the old one stays in use: a log that keeps growing beats one that stops.
func (r *rotatingLog) rotate() {
	if os.Rename(r.path, r.path+".1") != nil {
		return
	}
	old := r.f
	if err := r.open(); err != nil {
		r.f = old
		os.Rename(r.path+".1", r.path)
		return
	}
	old.Close()
}

// startLogRotation takes over the log if stderr is a regular file; otherwise (a terminal, a pipe) it leaves things as they are.
func startLogRotation() {
	fi, err := os.Stderr.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	path, err := os.Readlink("/proc/self/fd/2")
	if err != nil || strings.HasSuffix(path, " (deleted)") {
		return
	}
	if r, err := newRotatingLog(path, true, logMax); err == nil {
		log.SetOutput(r)
	}
}

// ---- saying a repeated thing once in a while ----

type logGate struct {
	mu sync.Mutex
	m  map[string]*gateEntry
}

type gateEntry struct {
	last       time.Time
	suppressed int
}

var logRate = &logGate{}

// allow says whether the message for key may be logged now, and how many like it were held back since the last time it was.
func (g *logGate) allow(key string, every time.Duration, now time.Time) (bool, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil || len(g.m) >= logGateLimit {
		g.m = map[string]*gateEntry{}
	}
	e := g.m[key]
	if e == nil {
		g.m[key] = &gateEntry{last: now}
		return true, 0
	}
	if now.Sub(e.last) < every {
		e.suppressed++
		return false, 0
	}
	n := e.suppressed
	e.last, e.suppressed = now, 0
	return true, n
}

// logEvery logs the message at most once per interval for the key, adding how many identical ones were left out.
func logEvery(key string, every time.Duration, format string, args ...any) {
	ok, n := logRate.allow(key, every, time.Now())
	if !ok {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if n > 0 {
		msg += fmt.Sprintf(" (and %d more like it since)", n)
	}
	log.Print(msg)
}

// logProxyError records a failed proxied request. A client that gave up (the request's context was cancelled) is not an error of ours and is not logged; the rest are said once per
// destination and reason every ten minutes, since one app retrying a blocked name can produce them by the hundred.
func logProxyError(kind, dest string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	logEvery(kind+"|"+dest+"|"+err.Error(), logSayEvery, "%s for %s: %v", kind, dest, err)
}

// httpErrorLog is the ErrorLog of the daemon's HTTP servers: the standard library reports every failed TLS handshake (a phone that dropped off Wi-Fi mid-connection, a browser
// that tries a name and closes) as a line of its own, and they are not worth a line each.
func httpErrorLog() *log.Logger {
	return log.New(httpErrWriter{}, "", 0)
}

type httpErrWriter struct{}

func (httpErrWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	key := msg
	every := logSayEvery
	if strings.Contains(msg, "TLS handshake error") {
		key, every = "tls handshake", time.Minute
	}
	logEvery("http|"+key, every, "%s", msg)
	return len(p), nil
}
