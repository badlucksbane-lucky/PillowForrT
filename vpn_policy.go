package main

// Who goes through the tunnel, enforced in the kernel. Devices are matched by MAC address (the web page keys devices by IPv4 address; this maps them through the ARP table).
//   mangle  HS_EXIT : packets from VPN devices get MARK 0x4d, and `ip rule fwmark 0x4d lookup 77` sends them out mullvad0 (vpn_tunnel.go)
//   filter  HS_KILL : the kill switch: a VPN device's packets that would leave by the cellular interface are DROPPED (so a dead tunnel blocks instead of leaking)
//   ip6     HS_V6   : a VPN device's IPv6 forwarding is refused (IPv6 would bypass the tunnel); apps fall back to IPv4
// Each chain is rewritten in ONE atomic iptables-restore commit (--noflush), so there is never a moment with the rules half-built.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type exitPlan struct {
	DefaultVPN bool     // every device not listed as direct goes through the tunnel
	VPNMacs    []string // devices forced through the tunnel (used when !DefaultVPN)
	DirectMacs []string // devices forced direct (used when DefaultVPN)
	KillSwitch bool
	TunnelUp   bool
	Active     bool // any device uses the tunnel at all
}

func macRule(m string) string { return "-m mac --mac-source " + m }

// planRules renders the three restore blocks. Pure function: unit-tested.
func planRules(p exitPlan) (mangle, filter, v6 string) {
	var m, f, s6 strings.Builder
	m.WriteString("*mangle\n:HS_EXIT - [0:0]\n")
	f.WriteString("*filter\n:HS_KILL - [0:0]\n")
	s6.WriteString("*filter\n:HS_V6 - [0:0]\n")
	if p.Active {
		direct := append([]string(nil), p.DirectMacs...)
		vpn := append([]string(nil), p.VPNMacs...)
		sort.Strings(direct)
		sort.Strings(vpn)
		if p.DefaultVPN {
			for _, d := range direct { // exempt first
				fmt.Fprintf(&m, "-A HS_EXIT %s -j RETURN\n", macRule(d))
				fmt.Fprintf(&f, "-A HS_KILL %s -j RETURN\n", macRule(d))
				fmt.Fprintf(&s6, "-A HS_V6 %s -j RETURN\n", macRule(d))
			}
			if p.TunnelUp || !p.KillSwitch {
				if p.TunnelUp {
					m.WriteString("-A HS_EXIT -j MARK --set-mark " + vpnMark + "\n")
				}
			}
			if p.KillSwitch {
				f.WriteString("-A HS_KILL -i bridge0 -o rmnet_data+ -j DROP\n")
			}
			s6.WriteString("-A HS_V6 -i bridge0 -j REJECT --reject-with icmp6-port-unreachable\n")
		} else {
			for _, d := range vpn {
				if p.TunnelUp {
					fmt.Fprintf(&m, "-A HS_EXIT %s -j MARK --set-mark %s\n", macRule(d), vpnMark)
				}
				if p.KillSwitch {
					fmt.Fprintf(&f, "-A HS_KILL -i bridge0 -o rmnet_data+ %s -j DROP\n", macRule(d))
				}
				fmt.Fprintf(&s6, "-A HS_V6 -i bridge0 %s -j REJECT --reject-with icmp6-port-unreachable\n", macRule(d))
			}
		}
	}
	m.WriteString("COMMIT\n")
	f.WriteString("COMMIT\n")
	s6.WriteString("COMMIT\n")
	return m.String(), f.String(), s6.String()
}

// restore feeds a ruleset to iptables-restore --noflush (declared chains are replaced, everything else is left alone).
func restore(cmd, rules string) error {
	f, err := os.CreateTemp("", "heimdallstone-rules")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.WriteString(rules)
	f.Close()
	out, err := run("sh", "-c", cmd+" --noflush < "+f.Name())
	if err != nil {
		return fmt.Errorf("%s: %v %s", cmd, err, out)
	}
	return nil
}

// hooks makes sure the chains are called (the stock firmware can rebuild its tables) and the NAT/MSS rules for the tunnel exist.
func ensureHooks() {
	type h struct{ cmd, table, chain, spec string }
	for _, x := range []h{
		{"iptables", "mangle", "PREROUTING", "-i bridge0 -j HS_EXIT"},
		{"iptables", "filter", "FORWARD", "-j HS_KILL"},
		{"ip6tables", "filter", "FORWARD", "-j HS_V6"},
	} {
		if _, err := run("sh", "-c", fmt.Sprintf("%s -t %s -C %s %s 2>/dev/null || %s -t %s -I %s 1 %s", x.cmd, x.table, x.chain, x.spec, x.cmd, x.table, x.chain, x.spec)); err != nil {
			fmt.Fprintf(os.Stderr, "vpn: hook %s %s: %v\n", x.cmd, x.chain, err)
		}
	}
	for _, spec := range []string{
		"-t nat -C POSTROUTING -o " + vpnIface + " -j MASQUERADE",
		"-t mangle -C FORWARD -o " + vpnIface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
	} {
		add := strings.Replace(spec, " -C ", " -A ", 1)
		run("sh", "-c", "iptables "+spec+" 2>/dev/null || iptables "+add)
	}
}

// macMap resolves device IPv4 addresses to MACs from the ARP table (and the lease file for devices that are asleep).
func macMapFromARP(arp, leases string) map[string]string {
	out := map[string]string{}
	for mac, ip := range parseARP(arp) {
		out[ip] = mac
	}
	for _, l := range strings.Split(leases, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && strings.Count(f[1], ":") == 5 {
			if _, ok := out[f[2]]; !ok {
				out[f[2]] = strings.ToLower(f[1])
			}
		}
	}
	return out
}

func (v *VPN) macs() map[string]string {
	if v.macOf != nil { // tests
		return nil
	}
	arp, _ := os.ReadFile("/proc/net/arp")
	lease, _ := os.ReadFile(*leasesFile)
	return macMapFromARP(string(arp), string(lease))
}

// buildPlan turns the configuration into the sets of MACs.
func (v *VPN) buildPlan() exitPlan {
	up := v.tun.isUp()
	v.mu.Lock()
	cfg := v.cfg
	v.mu.Unlock()
	p := exitPlan{DefaultVPN: cfg.DefaultExit == "mullvad", KillSwitch: cfg.KillSwitch, TunnelUp: up}
	if !cfg.Registered {
		return p
	}
	mac := v.macs()
	resolve := func(ip string) string {
		if v.macOf != nil {
			return v.macOf(ip)
		}
		return mac[ip]
	}
	for ip, e := range cfg.DeviceExit {
		m := resolve(ip)
		if m == "" {
			continue
		}
		if e == "mullvad" {
			p.VPNMacs = append(p.VPNMacs, m)
		} else {
			p.DirectMacs = append(p.DirectMacs, m)
		}
	}
	p.Active = p.DefaultVPN || len(p.VPNMacs) > 0
	return p
}

// The Qualcomm fast path (shortcut_fe_cm) takes over a forwarded flow once it is established and picks the outgoing interface with a plain route lookup that ignores
// firewall marks: a VPN device's TCP handshake went through the tunnel and then its first data packet left by the cellular interface with the tunnel's private address
// (captured 2026-10-02). ICMP, which it does not accelerate, worked. So while any device exits via the tunnel the connection manager is unloaded (everything is then
// forwarded by the normal stack, a little slower), and it is loaded back when nobody uses the tunnel.
const sfeModule = "shortcut_fe_cm"
const sfeModulePath = "/usr/lib/modules/3.18.48/extra/shortcut-fe-cm.ko"

func moduleLoaded(name string) bool {
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, name+" ") {
			return true
		}
	}
	return false
}

func manageSFE(active bool) {
	loaded := moduleLoaded(sfeModule)
	switch {
	case active && loaded:
		if out, err := run("rmmod", sfeModule); err != nil {
			fmt.Fprintf(os.Stderr, "vpn: could not unload the fast path: %v %s\n", err, out)
		}
	case !active && !loaded:
		if _, err := os.Stat(sfeModulePath); err == nil {
			run("insmod", sfeModulePath)
		}
	}
}

// Reconcile applies the current plan to the kernel. Safe to call often.
func (v *VPN) Reconcile() {
	p := v.buildPlan()
	if v.applyFn != nil {
		v.applyFn(p)
		return
	}
	manageSFE(p.Active || torMgrG.Active())
	ensureHooks()
	m, f, s6 := planRules(p)
	for _, r := range []struct{ cmd, rules string }{{"iptables-restore", m}, {"iptables-restore", f}, {"ip6tables-restore", s6}} {
		if err := restore(r.cmd, r.rules); err != nil {
			v.fail(err)
			return
		}
	}
}

// Run is the background loop: it keeps the tunnel up while it should be (trying the next relay on failure), watches the handshake, and re-applies the rules.
func (v *VPN) Run() {
	time.Sleep(25 * time.Second) // let the uplink come up after a boot
	backoff := 20 * time.Second
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	attempt := 0
	next := time.Now()
	for range tick.C {
		v.mu.Lock()
		want := v.cfg.Registered && v.cfg.Enabled
		v.mu.Unlock()
		switch {
		case want && v.tun.isUp():
			if age, _, _ := v.tun.counters(); age > 180 || age == 0 {
				v.fail(fmt.Errorf("handshake went stale: reconnecting"))
				v.tun.stop()
				next = time.Now()
			} else {
				backoff, attempt = 20*time.Second, 0
			}
		case want && time.Now().After(next):
			if err := v.connect(attempt); err != nil {
				v.fail(err)
				attempt++
				next = time.Now().Add(backoff)
				if backoff < 5*time.Minute {
					backoff *= 2
				}
			} else {
				v.mu.Lock()
				v.lastErr = ""
				v.mu.Unlock()
				backoff, attempt = 20*time.Second, 0
			}
		case !want && v.tun.isUp():
			v.tun.stop()
		}
		v.Reconcile()
	}
}
