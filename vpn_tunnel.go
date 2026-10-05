package main

// The WireGuard tunnel, in this process (wireguard-go as a library): no kernel module needed, just /dev/net/tun. The pure-Go crypto on this one Cortex-A7 core will
// not do gigabit; measure before trusting a number.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type tunnel struct {
	mu     sync.Mutex
	dev    *device.Device
	up     bool
	relay  vpnRelay
	since  time.Time
	failed time.Time
}

// run executes a helper (ip, iptables...) with a timeout and returns its combined output.
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

const lanCIDR = "192.168.1.0/24"

// createPlainTUN makes the tun device WITHOUT IFF_VNET_HDR. wireguard-go's default asks the kernel for TCP segmentation/checksum offload on the tun; on this 3.18 kernel
// (with the bridge, the Qualcomm fast path and the Wi-Fi driver downstream) forwarded TCP data from the tunnel never reached the device (ICMP and TCP handshakes did,
// found 2026-10-02), while the Orbic's own local sockets were fine. Plain packets, one per read/write, cost a little speed and work.
func createPlainTUN(name string, mtu int) (tun.Device, error) {
	nfd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		unix.Close(nfd)
		return nil, err
	}
	return tun.CreateTUNFromFile(os.NewFile(uintptr(nfd), "/dev/net/tun"), mtu)
}

func hexKey(b64key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil || len(raw) != 32 {
		return "", errors.New("bad WireGuard key")
	}
	return hex.EncodeToString(raw), nil
}

// start brings the tunnel up on the given relay and waits (up to 15 s) for a handshake. It replaces any running tunnel.
func (t *tunnel) start(cfg vpnConfig, r vpnRelay) error {
	t.stop()
	priv, err := hexKey(cfg.PrivKey)
	if err != nil {
		return err
	}
	peer, err := hexKey(r.PubKey)
	if err != nil {
		return fmt.Errorf("relay %s has a bad key", r.Hostname)
	}
	tdev, err := createPlainTUN(vpnIface, vpnMTU)
	if err != nil {
		return fmt.Errorf("could not create the tunnel interface: %v", err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
	conf := "private_key=" + priv + "\nreplace_peers=true\npublic_key=" + peer + "\nendpoint=" + r.IPv4 + ":51820\n" +
		"persistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"
	if err := dev.IpcSet(conf); err != nil {
		dev.Close()
		return fmt.Errorf("could not configure the tunnel: %v", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("could not start the tunnel: %v", err)
	}
	cmds := [][]string{
		{"ip", "addr", "flush", "dev", vpnIface},
		{"ip", "addr", "add", cfg.IPv4, "dev", vpnIface},
		{"ip", "link", "set", "dev", vpnIface, "up", "mtu", strconv.Itoa(vpnMTU)},
		{"ip", "route", "replace", "default", "dev", vpnIface, "table", vpnTable},
		// traffic from a VPN device to the LAN itself must stay on the LAN (bridged frames are routed by this table too when bridge netfilter is on)
		{"ip", "route", "replace", lanCIDR, "dev", "bridge0", "table", vpnTable},
	}
	for _, c := range cmds {
		if out, err := run(c[0], c[1:]...); err != nil {
			dev.Close()
			return fmt.Errorf("%s: %v %s", strings.Join(c, " "), err, out)
		}
	}
	if run("ip", "rule", "show"); true {
		if out, _ := run("ip", "rule", "show"); !strings.Contains(out, "fwmark "+vpnMark) {
			run("ip", "rule", "add", "fwmark", vpnMark, "lookup", vpnTable, "pref", "100")
		}
	}
	t.mu.Lock()
	t.dev, t.relay = dev, r
	t.mu.Unlock()
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		if hs, _, _ := t.counters(); hs > 0 {
			t.mu.Lock()
			t.up, t.since = true, time.Now()
			t.mu.Unlock()
			log.Printf("vpn: up via %s", r.Hostname)
			return nil
		}
	}
	t.stop()
	return fmt.Errorf("no handshake with %s in 15 s (UDP 51820 blocked, or the relay is down)", r.Hostname)
}

func (t *tunnel) stop() {
	t.mu.Lock()
	dev := t.dev
	t.dev, t.up = nil, false
	t.mu.Unlock()
	if dev != nil {
		dev.Close()
		run("ip", "link", "del", "dev", vpnIface) // CreateTUN makes a fresh one each time
	}
}

// counters reads the handshake age (seconds, 0 = never) and the byte counters from the device.
func (t *tunnel) counters() (hsAge int64, rx, tx uint64) {
	t.mu.Lock()
	dev := t.dev
	t.mu.Unlock()
	if dev == nil {
		return 0, 0, 0
	}
	s, err := dev.IpcGet()
	if err != nil {
		return 0, 0, 0
	}
	var hs int64
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			hs, _ = strconv.ParseInt(val, 10, 64)
		case "rx_bytes":
			rx, _ = strconv.ParseUint(val, 10, 64)
		case "tx_bytes":
			tx, _ = strconv.ParseUint(val, 10, 64)
		}
	}
	if hs > 0 {
		hsAge = time.Now().Unix() - hs
		if hsAge < 1 {
			hsAge = 1
		}
	}
	return hsAge, rx, tx
}

func (t *tunnel) isUp() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up
}

func (t *tunnel) snapshot() (up bool, relay string, since time.Time, hsAge int64, rx, tx uint64) {
	t.mu.Lock()
	up, relay, since = t.up, t.relay.Hostname, t.since
	t.mu.Unlock()
	if up {
		hsAge, rx, tx = t.counters()
	}
	return
}
