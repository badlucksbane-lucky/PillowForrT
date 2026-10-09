package main

import (
	"context"
	"errors"
	"net"
	"testing"
)

// A LAN client must not be able to use the proxy to reach the hotspot's own listeners (the onion door on 127.0.0.1:3130, Tor's SocksPort, dnsmasq):
// the onion handler trusts a loopback source as "came through Tor", and a direct-exit device could route through Tor's socks port.
func TestGuardedDialRefusesOwnAddresses(t *testing.T) {
	saved := ownAddrs
	ownAddrs = func() []net.IP { return []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.64.0.2")} }
	defer func() { ownAddrs = saved }()
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "localhost":
			return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.1")}}, nil
		case "rebind.example":
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("93.184.216.34")}}, nil
		case "pillowforrt":
			return []net.IPAddr{{IP: net.ParseIP("192.168.1.1")}}, nil
		}
		return nil, errors.New("no such host")
	}
	var dialed []string
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	for _, addr := range []string{"127.0.0.1:3130", "127.0.0.2:9050", "[::1]:3130", "localhost:3130", "0.0.0.0:80", "169.254.1.1:80", "192.168.1.1:443", "10.64.0.2:80", "pillowforrt:443", "224.0.0.1:80"} {
		dialed = nil
		if _, err := guardedDial(context.Background(), "tcp", addr, false, lookup, dial); err == nil {
			t.Errorf("%s: dialed %v, want refused", addr, dialed)
		} else if len(dialed) != 0 {
			t.Errorf("%s: the raw dialer was called with %v", addr, dialed)
		}
	}
	// a name whose answers mix a loopback and a public address: only the public one is dialed
	dialed = nil
	if _, err := guardedDial(context.Background(), "tcp", "rebind.example:443", true, lookup, dial); err != nil {
		t.Fatalf("rebind.example: %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "93.184.216.34:443" {
		t.Errorf("rebind.example dialed %v, want only the public address", dialed)
	}
	// a public literal passes straight through; with v4Only an IPv6 literal does not
	dialed = nil
	if _, err := guardedDial(context.Background(), "tcp", "1.1.1.1:443", true, lookup, dial); err != nil || len(dialed) != 1 {
		t.Errorf("1.1.1.1: err=%v dialed=%v", err, dialed)
	}
	if _, err := guardedDial(context.Background(), "tcp", "[2606:4700::1111]:443", true, lookup, dial); err == nil {
		t.Error("an IPv6 literal was dialed with v4Only set")
	}
	if _, err := guardedDial(context.Background(), "tcp", "no-port", false, lookup, dial); err == nil {
		t.Error("an address without a port was accepted")
	}
}

func TestProxyTransportsUseTheGuard(t *testing.T) {
	// the two proxy transports must dial through the guard, not the raw dialers (a regression here reopens the hole silently)
	for name, tr := range map[string]func(context.Context, string, string) (net.Conn, error){"direct": transport.DialContext, "vpn": vpnTransport.DialContext} {
		if _, err := tr(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
			t.Errorf("%s transport connected to loopback", name)
		}
	}
	var v *VPN
	if _, err := v.DialFor(context.Background(), "192.168.1.40", "tcp", "127.0.0.1:3130"); err == nil {
		t.Error("CONNECT to the onion door's listener was allowed")
	}
}
