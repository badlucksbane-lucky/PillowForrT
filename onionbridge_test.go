package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const ddg = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

func TestValidOnion(t *testing.T) {
	for _, ok := range []string{ddg, "www." + ddg, "A." + strings.ToUpper(ddg), "a-b.c." + ddg} {
		if !validOnion(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "onion", ".onion", "abcdefghij.onion", "expyuzz4wqqyqhjn.onion", ddg[:55] + ".onion", ddg + "x.onion", strings.Replace(ddg, "d", "1", 1), "example.com", ddg + ".com", "-" + ddg, "a b." + ddg, strings.Repeat("a.", 130) + ddg} {
		if validOnion(bad) {
			t.Errorf("%q must not be valid", bad)
		}
	}
}

func TestOnionMap(t *testing.T) {
	m := newOnionMap()
	a := m.ipFor(ddg)
	if a[0] != 198 || a[1] != 18 || a[3] == 0 {
		t.Errorf("an address in 198.18/16 not ending in .0: %v", a)
	}
	if b := m.ipFor(strings.ToUpper(ddg)); !a.Equal(b) {
		t.Error("the same name (any case) keeps its address")
	}
	if n, ok := m.nameFor(a); !ok || n != ddg {
		t.Errorf("round trip: %q %v", n, ok)
	}
	if _, ok := m.nameFor(net.ParseIP("198.18.15.200")); ok {
		t.Error("an address never handed out has no name")
	}
	for _, bad := range []string{"192.168.1.5", "198.17.0.1", "198.18.0.0", "198.18.255.255"} {
		if _, ok := m.nameFor(net.ParseIP(bad)); ok {
			t.Errorf("%s must have no name", bad)
		}
	}
	// 4000 slots, the oldest recycled; every address is distinct among the live ones and never ends in .0
	seen := map[string]string{}
	for i := 0; i < onionMapSize*2; i++ {
		name := "n" + strings.Repeat("a", 3) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + "." + ddg
		ip := m.ipFor(name)
		if ip[3] == 0 {
			t.Fatal("ends in .0")
		}
		seen[ip.String()] = name
		if n, ok := m.nameFor(ip); !ok || n != strings.ToLower(name) {
			t.Fatalf("freshly allocated %v must map back: %q", ip, n)
		}
	}
	live := 0
	for i := 1; i <= onionMapSize; i++ {
		if m.slots[i] != "" {
			live++
		}
	}
	if live > onionMapSize || len(m.byName) != live {
		t.Errorf("the table stays within its size and consistent: %d live, %d names", live, len(m.byName))
	}
}

func TestBuildA(t *testing.T) {
	q := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	dq, err := parseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	r := buildA(q, dq, net.ParseIP("198.18.0.7"), 30)
	if r[0] != 0xab || r[1] != 0xcd || r[2]&0x80 == 0 || r[3]&0x0f != 0 || binary.BigEndian.Uint16(r[6:8]) != 1 {
		t.Errorf("header: %x", r[:12])
	}
	if got := net.IP(r[len(r)-4:]).String(); got != "198.18.0.7" {
		t.Errorf("address %s", got)
	}
	if binary.BigEndian.Uint32(r[len(r)-10:len(r)-6]) != 30 {
		t.Error("ttl")
	}
}

func TestSocksRequest(t *testing.T) {
	r := socksRequest("ab.onion", 443)
	if r[0] != 5 || r[1] != 1 || r[3] != 3 || int(r[4]) != 8 || string(r[5:13]) != "ab.onion" || binary.BigEndian.Uint16(r[13:]) != 443 {
		t.Errorf("%x", r)
	}
}

// fakeSocks answers one SOCKS5 CONNECT, then echoes with a prefix. It records what host and port were asked for.
func fakeSocks(t *testing.T, replyCode byte) (addr string, asked chan string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	asked = make(chan string, 1)
	go func() {
		defer l.Close()
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		hs := make([]byte, 3)
		io.ReadFull(c, hs)
		c.Write([]byte{5, 0})
		h := make([]byte, 5)
		io.ReadFull(c, h)
		host := make([]byte, int(h[4]))
		io.ReadFull(c, host)
		p := make([]byte, 2)
		io.ReadFull(c, p)
		asked <- string(host) + ":" + string(rune('0'+binary.BigEndian.Uint16(p)%10))
		c.Write([]byte{5, replyCode, 0, 1, 0, 0, 0, 0, 0, 0})
		if replyCode != 0 {
			return
		}
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		c.Write(append([]byte("echo:"), buf[:n]...))
	}()
	return l.Addr().String(), asked
}

func TestSocksConnect(t *testing.T) {
	addr, asked := fakeSocks(t, 0)
	c, err := socksConnect(addr, ddg, 80, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := <-asked; got != ddg+":0" {
		t.Errorf("the NAME goes to Tor, not an address: %q", got)
	}
	c.Write([]byte("hi"))
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := c.Read(buf)
	if string(buf[:n]) != "echo:hi" {
		t.Errorf("data flows after the handshake: %q", buf[:n])
	}
	addr2, _ := fakeSocks(t, 4) // host unreachable
	if _, err := socksConnect(addr2, ddg, 80, 5*time.Second); err == nil || !strings.Contains(err.Error(), "SOCKS reply 4") {
		t.Errorf("a refused connect is an error: %v", err)
	}
	if _, err := socksConnect("127.0.0.1:1", ddg, 80, time.Second); err == nil {
		t.Error("no proxy is an error")
	}
	if _, err := socksConnect(addr, "", 80, time.Second); err == nil {
		t.Error("an empty host is refused")
	}
}

func TestOnionBridgeHandle(t *testing.T) {
	m := newOnionMap()
	ip := m.ipFor(ddg)
	b := newOnionBridge(m)
	var gotName string
	var gotPort int
	b.dial = func(name string, port int) (net.Conn, error) {
		gotName, gotPort = name, port
		x, y := net.Pipe()
		go func() { // the "onion service": echoes upper-case
			buf := make([]byte, 32)
			n, _ := y.Read(buf)
			y.Write([]byte(strings.ToUpper(string(buf[:n]))))
			y.Close()
		}()
		return x, nil
	}
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() { b.handle(srv, ip, 80); close(done) }()
	cli.Write([]byte("hello"))
	buf := make([]byte, 16)
	cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := cli.Read(buf)
	cli.Close()
	<-done
	if string(buf[:n]) != "HELLO" || gotName != ddg || gotPort != 80 {
		t.Errorf("relayed through Tor by name: %q %q %d", buf[:n], gotName, gotPort)
	}
	// an address with no name behind it is just closed, nothing is dialled
	dialled := false
	b.dial = func(string, int) (net.Conn, error) { dialled = true; return nil, io.EOF }
	s2, c2 := net.Pipe()
	d2 := make(chan struct{})
	go func() { b.handle(s2, net.ParseIP("198.18.9.9"), 80); close(d2) }()
	<-d2
	c2.Close()
	if dialled {
		t.Error("an unmapped address must not cause a connection")
	}
	// too many at once: the newcomer is refused
	for i := 0; i < onionMaxConns; i++ {
		b.active <- struct{}{}
	}
	s3, c3 := net.Pipe()
	d3 := make(chan struct{})
	go func() { b.handle(s3, ip, 80); close(d3) }()
	select {
	case <-d3:
	case <-time.After(2 * time.Second):
		t.Error("at the limit a new connection is refused at once")
	}
	c3.Close()
	if dialled {
		t.Error("nothing is dialled when the limit is reached")
	}
}
