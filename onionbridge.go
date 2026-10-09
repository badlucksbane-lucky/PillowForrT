package main

// The onion bridge. The range is 198.18.0.0/16 (RFC 2544 benchmarking space), NOT a private range: the router's dnsmasq runs with DNS-rebind protection and silently drops any answer
// that points into 10/8, 172.16/12 or 192.168/16 (found 2026-10-02: the answer vanished and clients saw an empty NOERROR); nothing else in the house uses 198.18/16. Tor's own DNS port can only hand a .onion name an IPv6 "virtual" address (this Tor version copies no IPv4 preference into a DNS request), and the box has no IPv6
// redirect, so tinyfwd does the mapping itself:
//   DNS      the stub answers an A query for a valid v3 .onion name with a benchmarking-range address from 198.18.0.0/16 (onionMap below, in memory, 4000 names, oldest recycled)
//   firewall TCP aimed at that range is REDIRECTed to this bridge (nat HS_TOR), which reads the address the client really dialled (SO_ORIGINAL_DST)
//   bridge   finds the name behind it and connects to it through Tor's SOCKS port with the NAME (so Tor, not this router, resolves and meets the onion service), then relays the bytes
// It listens on the LAN address only. Nothing here sees the content beyond relaying bytes, and an address with no name behind it is simply closed.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	torBridgePort  = 9041
	onionMapSize   = 4000
	onionMaxConns  = 48
	onionIdle      = 15 * time.Minute
	onionSocksAddr = "127.0.0.1:9050"
)

var onionRe = regexp.MustCompile(`^([a-z0-9-]{1,63}\.)*[a-z2-7]{56}\.onion$`)

// validOnion accepts a version 3 onion service name (56 base32 characters) with optional subdomains. Anything else (old 16-character v2 names, junk) does not exist.
func validOnion(name string) bool {
	return len(name) <= 253 && onionRe.MatchString(strings.ToLower(name))
}

// onionMap hands out private addresses for names and takes them back. 4000 slots; when full, the oldest name's slot is reused.
type onionMap struct {
	mu     sync.Mutex
	byName map[string]int
	slots  [onionMapSize + 1]string // 1..onionMapSize
	next   int
}

func newOnionMap() *onionMap { return &onionMap{byName: map[string]int{}} }

func slotIP(i int) net.IP { return net.IPv4(198, 18, byte(i>>8), byte(i)).To4() }

func (o *onionMap) ipFor(name string) net.IP {
	name = strings.ToLower(name)
	o.mu.Lock()
	defer o.mu.Unlock()
	if i, ok := o.byName[name]; ok {
		return slotIP(i)
	}
	i := o.next%onionMapSize + 1
	o.next++
	if (i & 0xff) == 0 { // never hand out an address ending in .0
		i = o.next%onionMapSize + 1
		o.next++
	}
	if old := o.slots[i]; old != "" {
		delete(o.byName, old)
	}
	o.slots[i], o.byName[name] = name, i
	return slotIP(i)
}

func (o *onionMap) nameFor(ip net.IP) (string, bool) {
	ip = ip.To4()
	if ip == nil || ip[0] != 198 || ip[1] != 18 {
		return "", false
	}
	i := int(ip[2])<<8 | int(ip[3])
	if i < 1 || i > onionMapSize {
		return "", false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	n := o.slots[i]
	return n, n != ""
}

// buildA answers an A query with one address.
func buildA(query []byte, q dnsQuery, ip net.IP, ttl uint32) []byte {
	out := append(respHeader(q, 0, 1), query[12:q.QEnd]...)
	rr := make([]byte, 16)
	rr[0], rr[1] = 0xC0, 0x0C
	binary.BigEndian.PutUint16(rr[2:4], qtA)
	binary.BigEndian.PutUint16(rr[4:6], qclassI)
	binary.BigEndian.PutUint32(rr[6:10], ttl)
	binary.BigEndian.PutUint16(rr[10:12], 4)
	copy(rr[12:], ip.To4())
	return append(out, rr...)
}

// socksRequest builds the SOCKS5 CONNECT request for a host name.
func socksRequest(host string, port int) []byte {
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	return binary.BigEndian.AppendUint16(req, uint16(port))
}

// socksConnect opens a connection to host:port through a SOCKS5 proxy, letting the proxy resolve the name.
func socksConnect(proxy, host string, port int, timeout time.Duration) (net.Conn, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("bad host name")
	}
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 5 || r[1] != 0 {
		c.Close()
		return nil, errors.New("SOCKS handshake refused")
	}
	if _, err := c.Write(socksRequest(host, port)); err != nil {
		c.Close()
		return nil, err
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 5 {
		c.Close()
		return nil, errors.New("SOCKS reply malformed")
	}
	if rep[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("Tor could not connect (SOCKS reply %d)", rep[1])
	}
	skip := 0
	switch rep[3] { // the bound address that follows: skip it
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			c.Close()
			return nil, err
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// origDst reads the address a REDIRECTed connection was really aimed at.
func origDst(c *net.TCPConn) (net.IP, int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, 0, err
	}
	var ip net.IP
	var port int
	var gerr error
	raw.Control(func(fd uintptr) {
		m, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, 80) // SO_ORIGINAL_DST: a sockaddr_in in the first 8 bytes
		if err != nil {
			gerr = err
			return
		}
		port = int(m.Multiaddr[2])<<8 | int(m.Multiaddr[3])
		ip = net.IPv4(m.Multiaddr[4], m.Multiaddr[5], m.Multiaddr[6], m.Multiaddr[7])
	})
	return ip, port, gerr
}

// idleConn extends a connection's deadline whenever bytes move, so a relay ends after a quiet spell and not before.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}
func (c idleConn) Write(p []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(c.idle))
	return c.Conn.Write(p)
}

func relay(a, b net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(idleConn{dst, idle}, idleConn{src, idle})
		if t, ok := dst.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

type onionBridge struct {
	m      *onionMap
	active chan struct{}
	dial   func(name string, port int) (net.Conn, error)
}

func newOnionBridge(m *onionMap) *onionBridge {
	return &onionBridge{m: m, active: make(chan struct{}, onionMaxConns), dial: func(name string, port int) (net.Conn, error) {
		return socksConnect(onionSocksAddr, name, port, 90*time.Second)
	}}
}

// handle serves one redirected connection (src has already been accepted).
func (b *onionBridge) handle(src net.Conn, ip net.IP, port int) {
	defer src.Close()
	name, ok := b.m.nameFor(ip)
	if !ok {
		return // an address we never handed out: close
	}
	select {
	case b.active <- struct{}{}:
		defer func() { <-b.active }()
	default:
		return // too many at once on a small router: refuse the newcomer
	}
	dst, err := b.dial(name, port)
	if err != nil {
		return
	}
	relay(src, dst, onionIdle)
}

func (b *onionBridge) Serve(addr string) {
	for {
		l, err := net.Listen("tcp4", addr)
		if err != nil {
			log.Printf("onion bridge: %v (retrying in a minute)", err)
			time.Sleep(time.Minute)
			continue
		}
		for {
			c, err := l.Accept()
			if err != nil {
				l.Close()
				break
			}
			tc, ok := c.(*net.TCPConn)
			if !ok {
				c.Close()
				continue
			}
			ip, port, err := origDst(tc)
			if err != nil {
				c.Close()
				continue
			}
			go b.handle(c, ip, port)
		}
	}
}
