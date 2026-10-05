package main

import (
	"net"
	"strings"
	"testing"
)

func TestPublicAddr(t *testing.T) {
	for ip, want := range map[string]bool{
		"2600:100a:b03d:7537::1": true, "8.8.8.8": true,
		"192.168.1.1": false, "192.168.1.254": false, "127.0.0.1": false, "fe80::1": false, "::1": false, "10.1.2.3": false, "fd00::5": false,
	} {
		if got := publicAddr(net.ParseIP(ip)); got != want {
			t.Errorf("publicAddr(%s) = %v want %v", ip, got, want)
		}
	}
	if publicAddr(net.ParseIP("::ffff:192.168.1.1")) { // a LAN client arriving over the dual-stack socket
		t.Error("v4-mapped LAN address counted as public")
	}
}

func TestProxyLine(t *testing.T) {
	s := proxyLine(&net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 5555}, &net.TCPAddr{IP: net.ParseIP("2600:1::1"), Port: 443})
	if s != "PROXY TCP6 2001:db8::7 2600:1::1 5555 443\r\n" {
		t.Errorf("got %q", s)
	}
	if !strings.HasPrefix(proxyLine(&net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1}, &net.TCPAddr{IP: net.ParseIP("5.6.7.8"), Port: 80}), "PROXY TCP4 ") {
		t.Error("v4 pair should be TCP4")
	}
}

func TestRelayCaps(t *testing.T) {
	p := newPorchRelay()
	p.maxAll, p.maxSrc = 3, 2
	if !p.admit("a") || !p.admit("a") || p.admit("a") {
		t.Fatal("per-source cap not enforced")
	}
	if !p.admit("b") || p.admit("c") {
		t.Fatal("total cap not enforced")
	}
	p.release("a")
	if !p.admit("c") {
		t.Fatal("release did not free a slot")
	}
}

func TestRelayClosedWithoutFlag(t *testing.T) {
	p := newPorchRelay()
	p.flag = func() bool { return false }
	a, b := net.Pipe()
	_ = b
	// a public-side connection with the flag absent is dropped before any dial: handle must return promptly
	done := make(chan struct{})
	go func() { p.handleForTest(a, "2600::1", "2001:db8::9"); close(done) }()
	<-done
	if p.Refused != 1 || p.Relayed != 0 {
		t.Errorf("refused=%d relayed=%d", p.Refused, p.Relayed)
	}
}
