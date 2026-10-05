package main

// Using the tunnel from inside tinyfwd: proxy connections and DNS for devices whose exit is Mullvad. A socket marked with SO_MARK 0x4d is routed by table 77 (out mullvad0).

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

func markControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 0x4d) }); err != nil {
		return err
	}
	return serr
}

func dialMarked(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: markControl}
	switch network {
	case "tcp", "tcp6":
		network = "tcp4"
	case "udp", "udp6":
		network = "udp4"
	}
	return d.DialContext(ctx, network, addr)
}

var errKillSwitch = errors.New("the VPN exit is down and the kill switch is on")

// DialFor dials from tinyfwd the way this client's exit says: through the tunnel, or directly.
func (v *VPN) DialFor(ctx context.Context, client, network, addr string) (net.Conn, error) {
	if v == nil || v.ExitFor(client) != "mullvad" {
		return dialUpstream(ctx, network, addr)
	}
	if !v.tun.isUp() {
		v.mu.Lock()
		ks := v.cfg.KillSwitch
		v.mu.Unlock()
		if ks {
			return nil, errKillSwitch
		}
		return dialUpstream(ctx, network, addr)
	}
	return dialMarked(ctx, network, addr)
}

var vpnTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           dialMarked,
	MaxIdleConns:          20,
	MaxIdleConnsPerHost:   4,
	IdleConnTimeout:       60 * time.Second,
	TLSHandshakeTimeout:   20 * time.Second,
	ExpectContinueTimeout: time.Second,
}

// TransportFor picks the HTTP transport (and so the connection pool) for a client, so a direct connection is never reused for a VPN client.
func (v *VPN) TransportFor(client string) (*http.Transport, error) {
	if v == nil || v.ExitFor(client) != "mullvad" {
		return transport, nil
	}
	if !v.tun.isUp() {
		v.mu.Lock()
		ks := v.cfg.KillSwitch
		v.mu.Unlock()
		if ks {
			return nil, errKillSwitch
		}
		return transport, nil
	}
	return vpnTransport, nil
}

// UseVPNDNS: should this client's DNS go to Mullvad's resolver through the tunnel?
func (v *VPN) UseVPNDNS(client string) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	on := v.cfg.DNSViaVPN
	v.mu.Unlock()
	return on && v.ExitFor(client) == "mullvad"
}

var vpnDNSOnce sync.Once

// ResolveDNS asks Mullvad's resolver (10.64.0.1, reachable only inside the tunnel). With the tunnel down it fails rather than leaking the lookup (unless the kill switch is off).
func (v *VPN) ResolveDNS(q []byte) ([]byte, error) {
	if !v.tun.isUp() {
		return nil, errKillSwitch
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := dialMarked(ctx, "udp", "10.64.0.1:53")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
