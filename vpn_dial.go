package main

// Using the tunnel from inside tinyfwd: proxy connections and DNS for devices whose exit is Mullvad. A socket marked with SO_MARK 0x4d is routed by table 77 (out mullvad0).
// DNS for a Mullvad device is encrypted only: DoH to Mullvad's resolver through the tunnel, or (when "Use Mullvad DNS" is off) the house's DoH endpoints with the plain fallback disabled
// for that device. A failure is a refused lookup and a dns_hardblock event, never plain DNS and never the cellular link.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
		return proxyDialDirect(ctx, network, addr)
	}
	if !v.tun.isUp() {
		v.mu.Lock()
		ks := v.cfg.KillSwitch
		v.mu.Unlock()
		if ks {
			return nil, errKillSwitch
		}
		return proxyDialDirect(ctx, network, addr)
	}
	return proxyDialMarked(ctx, network, addr)
}

var vpnTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           proxyDialMarked,
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

// UseVPNDNS: is this a Mullvad device whose lookups may go to Mullvad's resolver through the tunnel (the setting is on and the tunnel is up)? Whether they do is decided by the ladder
// (owndial.go, used in DNSProxy.Handle): Mullvad's resolver is rung 2, so Tor through Mullvad goes first when it is up, and when no allowed rung is up the lookup takes the house's
// encrypted-DNS path, which blocks or goes direct as the kill-switch tier says. Nothing is ever answered in the clear.
func (v *VPN) UseVPNDNS(client string) bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	on := v.cfg.DNSViaVPN
	v.mu.Unlock()
	return on && v.ExitFor(client) == "mullvad" && v.tunnelUp()
}

// tunnelUp is the tunnel's state (a test can stand in for it).
func (v *VPN) tunnelUp() bool {
	if v.upFn != nil {
		return v.upFn()
	}
	return v.tun.isUp()
}

// Mullvad's public encrypted DNS (https://mullvad.net/en/help/dns-over-https-and-dns-over-tls): an IP literal, so there is no lookup to bootstrap it, and the certificate is checked
// against its name. Reached through the tunnel. The tunnel's own plain resolver (10.64.0.1) is no longer used: the rule is encrypted DNS only.
const (
	mullvadDoHURL  = "https://194.242.2.2/dns-query"
	mullvadDoHName = "dns.mullvad.net"
)

var (
	vpnDoHOnce   sync.Once
	vpnDoHClient *http.Client
)

func vpnDoH() *http.Client {
	vpnDoHOnce.Do(func() {
		vpnDoHClient = &http.Client{Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialMarked,
			TLSClientConfig:       &tls.Config{ServerName: mullvadDoHName, RootCAs: rootPool(), MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          2,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 4 * time.Second,
		}}
	})
	return vpnDoHClient
}

// ResolveDNS asks Mullvad's encrypted resolver through the tunnel. With the tunnel down it fails (and the caller refuses the lookup) rather than going out by the cellular link.
func (v *VPN) ResolveDNS(q []byte) ([]byte, error) {
	if v.dohHook != nil { // tests
		return v.dohHook(q)
	}
	if !v.tunnelUp() {
		return nil, errKillSwitch
	}
	body := append([]byte(nil), q...)
	if len(body) >= 2 {
		body[0], body[1] = 0, 0 // RFC 8484: id 0; the caller restores the client's id
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, mullvadDoHURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := vpnDoH().Do(req)
	if err != nil {
		vpnDoH().CloseIdleConnections() // a tunnel that restarted leaves dead connections behind
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	switch {
	case err != nil:
		return nil, err
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("Mullvad DNS answered HTTP %d", resp.StatusCode)
	case len(b) < 12 || b[2]&0x80 == 0:
		return nil, errors.New("Mullvad DNS sent a bad DNS message")
	}
	return b, nil
}
