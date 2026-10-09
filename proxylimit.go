package main

// Limits and plumbing for the forward proxy (:3128). Every CONNECT and every plain request costs a goroutine and, for a tunnel, two sockets, and the box has 4096 file descriptors
// shared with DNS, the web page and the packet watchers; a phone with a runaway app, or a dial that hangs for its 30 s timeout, must not be able to use them all up.

import (
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	proxyMaxConns     = 256 // proxied requests and tunnels open at once, all devices together
	proxyMaxPerClient = 128 // and for one device (a browser opens a few dozen at most)
)

type connLimiter struct {
	mu       sync.Mutex
	total    int
	per      map[string]int
	warnedAt time.Time
}

var proxyLimit = &connLimiter{per: map[string]int{}}

// acquire takes a slot for client. It reports false (and the reason) when the proxy is full; the caller must call release when it did get one.
func (l *connLimiter) acquire(client string) (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.total >= proxyMaxConns:
		return false, "the proxy is full"
	case l.per[client] >= proxyMaxPerClient:
		return false, "this device has too many connections open"
	}
	l.total++
	l.per[client]++
	return true, ""
}

func (l *connLimiter) release(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.per[client]--; l.per[client] <= 0 {
		delete(l.per, client)
	}
}

// admit takes a slot for the request or answers 503 itself. A refusal is logged at most once every 30 s, so a flood of them cannot flood the log as well.
func (l *connLimiter) admit(w http.ResponseWriter, client string) bool {
	ok, why := l.acquire(client)
	if ok {
		return true
	}
	l.mu.Lock()
	warn := time.Since(l.warnedAt) > 30*time.Second
	if warn {
		l.warnedAt = time.Now()
	}
	l.mu.Unlock()
	if warn {
		log.Printf("proxy: refusing %s: %s", client, why)
	}
	w.Header().Set("Retry-After", "5")
	http.Error(w, why, http.StatusServiceUnavailable)
	return false
}

// halfCloseGrace is how long the other direction of a tunnel may go on after the first one ended, when the connection cannot say "I am done sending" (CloseWrite).
const halfCloseGrace = 10 * time.Second

func closeWrite(c net.Conn) bool {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite() == nil
	}
	return false
}

// spliceTunnel copies both ways between the client and the server until both directions are finished, and closes both. When one side has no more to send it passes that on with CloseWrite
// and the other direction keeps going: a client that has sent its whole request and shut down its sending side still gets the answer. A reset (an error) ends both at once. It returns the bytes
// sent upstream and downstream. io.Copy between two TCP connections is a splice in the kernel, which is why the copy stays io.Copy.
func spliceTunnel(client, server net.Conn) (up, down uint64) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var grace *time.Timer
	closeBoth := func() { client.Close(); server.Close() }
	half := func(to, from net.Conn, n *uint64) {
		defer wg.Done()
		c, err := io.Copy(to, from)
		*n = uint64(c)
		if err == nil && closeWrite(to) {
			return
		}
		if err != nil {
			closeBoth()
			return
		}
		mu.Lock() // the end of the stream, but this connection cannot half-close: give the other direction a little longer, then stop it
		if grace == nil {
			grace = time.AfterFunc(halfCloseGrace, closeBoth)
		}
		mu.Unlock()
	}
	wg.Add(2)
	go half(server, client, &up)
	go half(client, server, &down)
	wg.Wait()
	mu.Lock()
	if grace != nil {
		grace.Stop()
	}
	mu.Unlock()
	closeBoth()
	return up, down
}

// keepAlive makes the kernel notice a client that has vanished (a phone that left the Wi-Fi), so its tunnel does not hold a slot for good.
func keepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
}
