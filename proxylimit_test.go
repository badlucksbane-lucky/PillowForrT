package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (a, b *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.Accept(); ch <- c.(*net.TCPConn) }()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn), <-ch
}

func TestConnLimiterTotalAndPerClient(t *testing.T) {
	oldT, oldC := proxyMaxConns, proxyMaxPerClient
	proxyMaxConns, proxyMaxPerClient = 3, 2
	defer func() { proxyMaxConns, proxyMaxPerClient = oldT, oldC }()
	l := &connLimiter{per: map[string]int{}}
	if ok, _ := l.acquire("a"); !ok {
		t.Fatal("first")
	}
	if ok, _ := l.acquire("a"); !ok {
		t.Fatal("second")
	}
	if ok, why := l.acquire("a"); ok || !strings.Contains(why, "this device") {
		t.Errorf("a third for one device: %v %q", ok, why)
	}
	if ok, _ := l.acquire("b"); !ok {
		t.Fatal("another device still gets one")
	}
	if ok, why := l.acquire("c"); ok || !strings.Contains(why, "full") {
		t.Errorf("past the total: %v %q", ok, why)
	}
	l.release("a")
	if ok, _ := l.acquire("c"); !ok {
		t.Error("a released slot is free again")
	}
	l.release("a")
	l.release("b")
	l.release("c")
	if l.total != 0 || len(l.per) != 0 {
		t.Errorf("slots leaked: %d %v", l.total, l.per)
	}
}

func TestAdmitAnswers503WithRetryAfter(t *testing.T) {
	oldT := proxyMaxConns
	proxyMaxConns = 0
	defer func() { proxyMaxConns = oldT }()
	l := &connLimiter{per: map[string]int{}}
	rec := httptest.NewRecorder()
	if l.admit(rec, "x") || rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("refusal: %d %v", rec.Code, rec.Header())
	}
}

// The client sends its whole request, then shuts down its sending side and waits for the answer. The old tunnel closed the server connection the moment the client's side ended.
func TestSpliceTunnelKeepsTheAnswerAfterTheClientHalfCloses(t *testing.T) {
	cliEnd, proxyCli := tcpPair(t) // client <-> proxy
	proxySrv, srvEnd := tcpPair(t) // proxy <-> server
	done := make(chan [2]uint64, 1)
	go func() { u, d := spliceTunnel(proxyCli, proxySrv); done <- [2]uint64{u, d} }()
	go func() { // a server that answers only after the request has ended
		req, _ := io.ReadAll(srvEnd)
		time.Sleep(100 * time.Millisecond)
		srvEnd.Write([]byte("answer to " + string(req)))
		srvEnd.CloseWrite()
	}()
	cliEnd.Write([]byte("the request"))
	cliEnd.CloseWrite()
	cliEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(cliEnd)
	if err != nil || string(got) != "answer to the request" {
		t.Fatalf("got %q, %v", got, err)
	}
	select {
	case n := <-done:
		if n[0] != uint64(len("the request")) || n[1] != uint64(len("answer to the request")) {
			t.Errorf("byte counts %v", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not finish")
	}
}

func TestSpliceTunnelEndsBothOnAReset(t *testing.T) {
	cliEnd, proxyCli := tcpPair(t)
	proxySrv, srvEnd := tcpPair(t)
	done := make(chan struct{})
	go func() { spliceTunnel(proxyCli, proxySrv); close(done) }()
	srvEnd.SetLinger(0)
	srvEnd.Close() // the server resets
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel still open after the server went away")
	}
	cliEnd.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(cliEnd).ReadByte(); err == nil {
		t.Error("the client side must be closed too")
	}
}
