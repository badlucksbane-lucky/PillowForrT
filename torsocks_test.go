package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const testHost = "example.test" // the NAME goes to Tor, never an address

func TestSocksRequest(t *testing.T) {
	r := socksRequest("example.test", 443)
	if r[0] != 5 || r[1] != 1 || r[3] != 3 || int(r[4]) != 12 || string(r[5:17]) != "example.test" || binary.BigEndian.Uint16(r[17:]) != 443 {
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
	c, err := socksConnect(addr, testHost, 80, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := <-asked; got != testHost+":0" {
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
	if _, err := socksConnect(addr2, testHost, 80, 5*time.Second); err == nil || !strings.Contains(err.Error(), "SOCKS reply 4") {
		t.Errorf("a refused connect is an error: %v", err)
	}
	if _, err := socksConnect("127.0.0.1:1", testHost, 80, time.Second); err == nil {
		t.Error("no proxy is an error")
	}
	if _, err := socksConnect(addr, "", 80, time.Second); err == nil {
		t.Error("an empty host is refused")
	}
}
