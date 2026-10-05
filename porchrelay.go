package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// The porch relay: the Orbic's outside ports 80, 443, 8080 and 8443 over IPv6 lead to a service you run on the LAN (the porchMap targets; there are none in this build). The Orbic has no IPv6 NAT and the phone cannot
// bind below 1024, so this is a plain TCP relay that tells the trap who is really calling with a PROXY protocol v1 line. Ports 80 and 443 are shared with the stock admin, which is moved to
// 81 and 444 (see PORCH.md): a connection that arrives on a LAN address is passed through to it unchanged, and one that arrives on a public address goes to the trap, and only while the
// flag file exists. The firewall (wpad-guard.sh) opens the public ports under the same flag, so this is a second lock, not the only one.

const porchFlag = "/data/proxy/porch.enabled"

var porchMap = map[int]string{} // no relay targets in the public build (the -porch-relay flag is inert)
var stockMap = map[int]string{80: "127.0.0.1:81", 443: "127.0.0.1:444"}

// ourMap is where a LAN client at the Orbic's own address goes once the stock admin is switched off: the PAC/redirect server (3128) and the web page (3129).
var ourMap = map[int]string{80: "127.0.0.1:3128", 443: "127.0.0.1:3129"}

// stockAdminOff reports whether the stock admin is switched off (set at start; nil means it never is).
var stockAdminOff func() bool

// publicAddr: reachable from the internet rather than from the LAN, loopback or link-local.
func publicAddr(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

type porchRelay struct {
	mu     sync.Mutex
	total  int
	perSrc map[string]int
	maxAll int
	maxSrc int
	flag   func() bool
	// counters shown by the status page
	Relayed, Refused, Stock uint64
}

func newPorchRelay() *porchRelay {
	return &porchRelay{perSrc: map[string]int{}, maxAll: 60, maxSrc: 8, flag: func() bool { _, err := os.Stat(porchFlag); return err == nil }}
}

func (p *porchRelay) admit(src string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total >= p.maxAll || p.perSrc[src] >= p.maxSrc {
		return false
	}
	p.total++
	p.perSrc[src]++
	return true
}
func (p *porchRelay) release(src string) {
	p.mu.Lock()
	p.total--
	if p.perSrc[src]--; p.perSrc[src] <= 0 {
		delete(p.perSrc, src)
	}
	p.mu.Unlock()
}

func hostIP(a net.Addr) net.IP {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP
	}
	h, _, _ := net.SplitHostPort(a.String())
	return net.ParseIP(h)
}

func proxyLine(src, dst *net.TCPAddr) string {
	fam := "TCP6"
	if src.IP.To4() != nil && dst.IP.To4() != nil {
		fam = "TCP4"
	}
	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, src.IP, dst.IP, src.Port, dst.Port)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		io.CopyBuffer(dst, src, buf)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	t := time.NewTimer(10 * time.Minute) // a hard ceiling; the trap's own drip limits are far shorter
	defer t.Stop()
	select {
	case <-done:
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
	case <-t.C:
	}
	a.Close()
	b.Close()
}

func (p *porchRelay) handle(c net.Conn, port int) {
	defer c.Close()
	p.route(c, c.LocalAddr().(*net.TCPAddr), c.RemoteAddr().(*net.TCPAddr), port)
}

// handleForTest runs the routing with chosen addresses (a net.Pipe has none).
func (p *porchRelay) handleForTest(c net.Conn, local, remote string) {
	defer c.Close()
	p.route(c, &net.TCPAddr{IP: net.ParseIP(local), Port: 443}, &net.TCPAddr{IP: net.ParseIP(remote), Port: 5555}, 443)
}

func (p *porchRelay) route(c net.Conn, local, remote *net.TCPAddr, port int) {
	if !publicAddr(local.IP) { // a LAN client at the Orbic's own address: the stock admin, untouched
		m := stockMap
		if stockAdminOff != nil && stockAdminOff() {
			m = ourMap
		}
		if target, ok := m[port]; ok {
			if u, err := net.DialTimeout("tcp", target, 3*time.Second); err == nil {
				p.mu.Lock()
				p.Stock++
				p.mu.Unlock()
				pipe(c, u)
			}
		}
		return
	}
	src := remote.IP.String()
	if !p.flag() || !p.admit(src) {
		p.mu.Lock()
		p.Refused++
		p.mu.Unlock()
		return
	}
	defer p.release(src)
	u, err := net.DialTimeout("tcp", porchMap[port], 3*time.Second)
	if err != nil {
		return
	}
	if _, err := io.WriteString(u, proxyLine(remote, local)); err != nil {
		u.Close()
		return
	}
	p.mu.Lock()
	p.Relayed++
	p.mu.Unlock()
	pipe(c, u)
}

func (p *porchRelay) serve(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("[::]:%d", port))
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			go p.handle(c, port)
		}
	}()
	return nil
}

// startPorchRelay binds the four ports; any that is still taken (the stock admin has not moved yet) is skipped with a log line, never fatal.
func startPorchRelay() *porchRelay {
	p := newPorchRelay()
	for _, port := range []int{80, 443, 8080, 8443} {
		if err := p.serve(port); err != nil {
			log.Printf("porch relay: port %d not bound: %v", port, err)
		} else {
			log.Printf("porch relay: port %d open (public side only while %s exists)", port, porchFlag)
		}
	}
	return p
}
