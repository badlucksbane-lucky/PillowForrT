package main

// The forward proxy's destination guard. A LAN client may use the proxy to reach the internet, never the hotspot itself: not loopback (the onion door's
// listener, Tor's SocksPort, dnsmasq), not link-local, and not the unit's own interface addresses. The guard resolves the name itself and dials only the
// vetted addresses, so a name that points at 127.0.0.1 cannot slip past a check made on the name.

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

var errProxyDest = errors.New("the proxy does not connect to the hotspot's own addresses")

// ownAddrs lists the unit's own interface addresses, refreshed at most every few seconds (interfaces come and go: bridge0, mullvad0, rmnet).
var ownAddrs = func() func() []net.IP {
	var mu sync.Mutex
	var at time.Time
	var ips []net.IP
	return func() []net.IP {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(at) < 5*time.Second {
			return ips
		}
		ips = ips[:0]
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ips = append(ips, n.IP)
			}
		}
		at = time.Now()
		return ips
	}
}()

// proxyDestOK: may the proxy connect to this address?
func proxyDestOK(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, own := range ownAddrs() {
		if own.Equal(ip) {
			return false
		}
	}
	return true
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// guardedDial resolves addr, drops every address the proxy must not reach, and dials the rest (in order) with dial. With v4Only, IPv6 answers are dropped
// too, as the plain dialers do.
func guardedDial(ctx context.Context, network, addr string, v4Only bool, lookup func(context.Context, string) ([]net.IPAddr, error), dial dialFunc) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var cands []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		cands = []net.IPAddr{{IP: ip}}
	} else if cands, err = lookup(ctx, host); err != nil {
		return nil, err
	}
	var last error = errProxyDest
	for _, c := range cands {
		if v4Only && c.IP.To4() == nil {
			continue
		}
		if !proxyDestOK(c.IP) {
			continue
		}
		conn, err := dial(ctx, network, net.JoinHostPort(c.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func lookupIP(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// proxyDialDirect and proxyDialMarked are the forward proxy's two dialers: the plain upstream one and the VPN-marked one, each behind the guard.
func proxyDialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	return guardedDial(ctx, network, addr, *ipv4Only, lookupIP, dialUpstream)
}

func proxyDialMarked(ctx context.Context, network, addr string) (net.Conn, error) {
	return guardedDial(ctx, network, addr, true, lookupIP, dialMarked)
}
