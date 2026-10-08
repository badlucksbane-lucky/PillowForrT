package main

// Tor over Mullvad. The Orbic's kernel has no iptables owner match (CONFIG_NETFILTER_XT_MATCH_OWNER is not set; found 2026-10-07 when the first attempt, a firewall mark on Tor's user id,
// failed to load) and its `ip` has no uidrange rules, so Tor's own packets cannot be picked out in the firewall. Instead Tor is told to make EVERY connection through tinyfwd's CONNECT proxy
// (torrc HTTPSProxy, with a secret that only this run of Tor knows), and the proxy dials those connections through the tunnel and nowhere else:
//   - the socket is marked (routed by table 77) AND bound to mullvad0 (SO_BINDTODEVICE), so with the tunnel gone the connection fails instead of finding another route;
//   - with the tunnel down, or the setting off, the proxy refuses (503) without dialling;
//   - only a request from loopback that presents the secret is treated this way; anyone else's CONNECT goes the normal way (the device's own exit).
// Tor has no other way out: with HTTPSProxy set it opens no direct connection. That is checked on the device after every change to this file (netstat for Tor's pid shows only loopback).
// Tor is also held back while the tunnel is down (torMgr.vpnGateLocked), so it does not sit retrying.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

const torProxyUser = "tor"

func newTorProxyKey() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err) // no randomness, no secret: better to stop than to run Tor with a guessable one
	}
	return hex.EncodeToString(b)
}

// torProxyPort is the port tinyfwd's proxy listens on (the -listen flag).
func torProxyPort() string {
	if _, p, err := net.SplitHostPort(*listenAddr); err == nil && p != "" {
		return p
	}
	return "3128"
}

// torVPNTorrcLines are the torrc lines that send all of Tor's connections through tinyfwd's proxy (none when the setting is off).
func torVPNTorrcLines(on bool, key string) []string {
	if !on || key == "" {
		return nil
	}
	return []string{
		"HTTPSProxy 127.0.0.1:" + torProxyPort(),
		"HTTPSProxyAuthenticator " + torProxyUser + ":" + key,
	}
}

// torProxyAllowed says whether a CONNECT request is Tor's (loopback, with this run's secret) and, if so, whether it may go through the tunnel now. isTor false: not Tor's, handle it as
// any other request. isTor true with an error: Tor's, and refused.
func (m *torMgr) torProxyAllowed(r *http.Request) (isTor bool, err error) {
	if m == nil {
		return false, nil
	}
	user, pass, ok := parseProxyBasic(r.Header.Get("Proxy-Authorization"))
	if !ok || user != torProxyUser {
		return false, nil
	}
	host, _, herr := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); herr != nil || ip == nil || !ip.IsLoopback() {
		return false, nil
	}
	m.mu.Lock()
	key, on := m.proxyKey, m.cfg.OverVPN
	up := m.vpnUp != nil && m.vpnUp()
	m.mu.Unlock()
	if key == "" || subtle.ConstantTimeCompare([]byte(pass), []byte(key)) != 1 {
		return true, errors.New("not Tor's secret")
	}
	if !on {
		return true, errors.New("Tor over Mullvad is off")
	}
	if !up {
		return true, errors.New("the Mullvad tunnel is down")
	}
	return true, nil
}

func parseProxyBasic(h string) (user, pass string, ok bool) {
	f := strings.Fields(h)
	if len(f) != 2 || !strings.EqualFold(f[0], "Basic") {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(b), ":")
	return u, p, found
}

// tunnelOnlyControl marks the socket for table 77 and binds it to the tunnel interface: a connection that cannot leave by mullvad0 does not leave at all.
func tunnelOnlyControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 0x4d); serr != nil {
			return
		}
		serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vpnIface)
	}); err != nil {
		return err
	}
	return serr
}

func dialTunnelOnly(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: tunnelOnlyControl}
	return d.DialContext(ctx, "tcp4", addr)
}

// dialTor dials a relay for Tor, through the tunnel only (and through the proxy guard, which keeps it off this box's own addresses).
func dialTor(ctx context.Context, addr string) (net.Conn, error) {
	return guardedDial(ctx, "tcp", addr, true, lookupIP, dialTunnelOnly)
}

// removeLegacyTorOut deletes the chains the first version of Tor over Mullvad hooked into OUTPUT (they were empty, and are not used any more). Harmless when they are not there.
func removeLegacyTorOut() {
	for _, c := range [][]string{
		{"iptables", "-t", "mangle", "OUTPUT", "HS_TOROUT"},
		{"iptables", "-t", "filter", "OUTPUT", "HS_TORKILL"},
		{"ip6tables", "-t", "filter", "OUTPUT", "HS_TORKILL6"},
	} {
		for i := 0; i < 4; i++ { // a hook may have been added more than once
			if _, err := run(c[0], c[1], c[2], "-D", c[3], "-j", c[4]); err != nil {
				break
			}
		}
		run(c[0], c[1], c[2], "-F", c[4])
		run(c[0], c[1], c[2], "-X", c[4])
	}
}
