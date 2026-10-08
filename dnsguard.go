package main

// The DNS guard: the one place that says how DNS may move on the box. It replaces the DNS lines that wpad-guard.sh added one by one (check, then insert, every 60 s) and the copy of them in
// egress.go. tinyfwd renders the chains, applies each table in ONE atomic iptables-restore (the way HS_TOR and HS_EXIT already work), and remembers a hash of the rules as the kernel reports
// them back. The watcher then needs one cheap look (three table dumps) to know whether anything was rebuilt, removed or edited, instead of three spot checks.
//
//   nat    HS_DNSNAT   devices' DNS (udp/tcp 53), unless it is for this box, is redirected to the box's own port 53 (dnsmasq, then the filtering stub);
//   filter HS_DNSOUT   the box itself sends no DNS or DoT out of the cellular interface;
//   filter HS_DNSFWD   a device's DNS to the cellular side or the tunnel, and DoT/DoQ (853) anywhere, is refused: the net under the redirect;
//   ip6    HS_DNSOUT6 / HS_DNSFWD6   the same for IPv6 (there is no ip6 nat table, so there DNS is refused, and the device falls back to the box's own resolver).
// Encrypted DNS (DoH) is carried by tinyfwd itself, over the tunnel, Tor or the cellular link as ownDial says (owndial.go), and is not DNS as far as these rules are concerned.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dnsChainNAT  = "HS_DNSNAT"
	dnsChainOut  = "HS_DNSOUT"
	dnsChainFwd  = "HS_DNSFWD"
	dnsChainOut6 = "HS_DNSOUT6"
	dnsChainFwd6 = "HS_DNSFWD6"
	dnsCell      = "rmnet_data+"
	dnsBridge    = "bridge0"
)

type dnsGuardPlan struct {
	Local []string // this box's own addresses: DNS sent to them is for the box and is not redirected
}

var defaultDNSLocal = []string{"192.168.1.254", "192.168.1.1"} // the services address, then the router address

func rej(proto string, v6 bool) string {
	switch {
	case proto == "tcp":
		return "tcp-reset"
	case v6:
		return "icmp6-port-unreachable"
	}
	return "icmp-port-unreachable"
}

// planDNSGuard renders the three restore blocks. Pure function: unit-tested.
func planDNSGuard(p dnsGuardPlan) (nat, filter, v6 string) {
	var n, f, s strings.Builder
	n.WriteString("*nat\n:" + dnsChainNAT + " - [0:0]\n")
	f.WriteString("*filter\n:" + dnsChainOut + " - [0:0]\n:" + dnsChainFwd + " - [0:0]\n")
	s.WriteString("*filter\n:" + dnsChainOut6 + " - [0:0]\n:" + dnsChainFwd6 + " - [0:0]\n")
	for _, proto := range []string{"udp", "tcp"} {
		for _, l := range p.Local { // the exemptions come first: the first match wins
			fmt.Fprintf(&n, "-A %s -p %s --dport 53 -d %s -j RETURN\n", dnsChainNAT, proto, l)
		}
	}
	for _, proto := range []string{"udp", "tcp"} {
		fmt.Fprintf(&n, "-A %s -p %s --dport 53 -j REDIRECT --to-ports 53\n", dnsChainNAT, proto)
	}
	for _, proto := range []string{"udp", "tcp"} {
		for _, port := range []string{"53", "853"} {
			fmt.Fprintf(&f, "-A %s -o %s -p %s --dport %s -j REJECT --reject-with %s\n", dnsChainOut, dnsCell, proto, port, rej(proto, false))
			fmt.Fprintf(&s, "-A %s -o %s -p %s --dport %s -j REJECT --reject-with %s\n", dnsChainOut6, dnsCell, proto, port, rej(proto, true))
		}
		fmt.Fprintf(&f, "-A %s -i %s -o %s -p %s --dport 53 -j REJECT --reject-with %s\n", dnsChainFwd, dnsBridge, dnsCell, proto, rej(proto, false))
		fmt.Fprintf(&f, "-A %s -i %s -o %s -p %s --dport 53 -j REJECT --reject-with %s\n", dnsChainFwd, dnsBridge, vpnIface, proto, rej(proto, false))
		fmt.Fprintf(&f, "-A %s -i %s -p %s --dport 853 -j REJECT --reject-with %s\n", dnsChainFwd, dnsBridge, proto, rej(proto, false))
		fmt.Fprintf(&s, "-A %s -i %s -p %s --dport 53 -j REJECT --reject-with %s\n", dnsChainFwd6, dnsBridge, proto, rej(proto, true))
		fmt.Fprintf(&s, "-A %s -i %s -p %s --dport 853 -j REJECT --reject-with %s\n", dnsChainFwd6, dnsBridge, proto, rej(proto, true))
	}
	n.WriteString("COMMIT\n")
	f.WriteString("COMMIT\n")
	s.WriteString("COMMIT\n")
	return n.String(), f.String(), s.String()
}

type dnsHook struct{ cmd, table, parent, spec string }

// dnsHooks are the jumps into the chains. They go in first in their parent chain.
var dnsHooks = []dnsHook{
	{"iptables", "nat", "PREROUTING", "-i " + dnsBridge + " -j " + dnsChainNAT},
	{"iptables", "filter", "OUTPUT", "-j " + dnsChainOut},
	{"iptables", "filter", "FORWARD", "-j " + dnsChainFwd},
	{"ip6tables", "filter", "OUTPUT", "-j " + dnsChainOut6},
	{"ip6tables", "filter", "FORWARD", "-j " + dnsChainFwd6},
}

type dnsGuard struct {
	mu       sync.Mutex
	plan     dnsGuardPlan
	baseline string // hash of the guard's rules as the kernel reported them right after the last apply
	want     int    // how many guard rules (and hooks) there should be
	// replaceable for tests
	restore func(cmd, rules string) error
	sh      func(cmd string) (string, error)
	save    func(cmd, table string) (string, error)
	sleep   func(time.Duration)
	marker  string // a file whose presence tells wpad-guard.sh that tinyfwd owns the DNS rules (empty: do not write one)
}

const dnsGuardMarker = "/var/volatile/dnsguard.on"

func newDNSGuard() *dnsGuard {
	return &dnsGuard{plan: dnsGuardPlan{Local: defaultDNSLocal}, restore: restore,
		sh:    func(c string) (string, error) { return run("sh", "-c", c) },
		save:  func(cmd, table string) (string, error) { return run(cmd, "-t", table) },
		sleep: time.Sleep, marker: dnsGuardMarker}
}

func (g *dnsGuard) saveCmd(h dnsHook) (string, string) {
	return map[string]string{"iptables": "iptables-save", "ip6tables": "ip6tables-save"}[h.cmd], h.table
}

// Apply installs the chains and hooks (make-before-break: the old shell-installed rules are removed only after these are in place) and records the baseline. Safe to call at any time.
func (g *dnsGuard) Apply() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	nat, f, s := planDNSGuard(g.plan)
	for _, r := range []struct{ cmd, rules string }{{"iptables-restore", nat}, {"iptables-restore", f}, {"ip6tables-restore", s}} {
		var err error
		for try := 0; try < 4; try++ { // other code touches iptables too, and the old userspace has no lock to wait on
			if err = g.restore(r.cmd, r.rules); err == nil {
				break
			}
			g.sleep(250 * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("dns guard: %v", err)
		}
	}
	for _, h := range dnsHooks {
		cmd := fmt.Sprintf("%s -t %s -C %s %s 2>/dev/null || %s -t %s -I %s 1 %s", h.cmd, h.table, h.parent, h.spec, h.cmd, h.table, h.parent, h.spec)
		if out, err := g.sh(cmd); err != nil {
			return fmt.Errorf("dns guard: hook %s %s: %v %s", h.cmd, h.parent, err, out)
		}
	}
	g.want = countRules(nat) + countRules(f) + countRules(s) + len(dnsHooks)
	snap, n, err := g.snapshot()
	if err != nil {
		return fmt.Errorf("dns guard: read back: %v", err)
	}
	if n != g.want {
		return fmt.Errorf("dns guard: %d rules applied, %d expected", n, g.want) // the old rules stay until the new ones are known to be in
	}
	g.baseline = snap
	g.removeLegacy()
	if g.marker != "" {
		os.WriteFile(g.marker, []byte("tinyfwd owns the DNS rules\n"), 0o644) // wpad-guard.sh stops adding its own copy
	}
	return nil
}

func countRules(block string) int {
	n := 0
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "-A ") {
			n++
		}
	}
	return n
}

// snapshot hashes the guard's rules and hooks as the kernel reports them (three table dumps), and counts them.
func (g *dnsGuard) snapshot() (hash string, n int, err error) {
	h := sha256.New()
	for _, t := range [][2]string{{"iptables-save", "nat"}, {"iptables-save", "filter"}, {"ip6tables-save", "filter"}} {
		out, err := g.save(t[0], t[1])
		if err != nil {
			return "", 0, err
		}
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "-A ") && strings.Contains(l, "HS_DNS") { // counters live on the ':' lines and are left out
				h.Write([]byte(l + "\n"))
				n++
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Verify says whether the guard is exactly as it was applied: same rules, same order, hooks present.
func (g *dnsGuard) Verify() bool {
	g.mu.Lock()
	base, want := g.baseline, g.want
	g.mu.Unlock()
	if base == "" {
		return false
	}
	snap, n, err := g.snapshot()
	return err == nil && n == want && snap == base
}

// legacyDNSRules are the rules wpad-guard.sh used to add one at a time; they are deleted once the guard's chains are in, so the same refusal is not made in two places.
func legacyDNSRules() [][3]string {
	var out [][3]string
	for _, p := range []string{"udp", "tcp"} {
		out = append(out,
			[3]string{"iptables", "nat", "PREROUTING -i bridge0 -p " + p + " --dport 53 -j REDIRECT --to-ports 53"},
			[3]string{"iptables", "nat", "PREROUTING -i bridge0 -p " + p + " --dport 53 -d 192.168.1.254 -j RETURN"},
			[3]string{"iptables", "nat", "PREROUTING -i bridge0 -p " + p + " --dport 53 -d 192.168.1.1 -j RETURN"},
			[3]string{"ip6tables", "filter", "FORWARD -i bridge0 -p " + p + " --dport 53 -j REJECT --reject-with " + map[string]string{"udp": "icmp6-port-unreachable", "tcp": "tcp-reset"}[p]},
		)
		for _, d := range []string{"53", "853"} {
			for _, c := range []string{"iptables", "ip6tables"} {
				out = append(out,
					[3]string{c, "filter", "OUTPUT -o rmnet_data+ -p " + p + " --dport " + d + " -j REJECT"},
					[3]string{c, "filter", "FORWARD -i bridge0 -o rmnet_data+ -p " + p + " --dport " + d + " -j REJECT"})
			}
		}
	}
	out = append(out,
		[3]string{"iptables", "filter", "FORWARD -i bridge0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset"},
		[3]string{"ip6tables", "filter", "FORWARD -i bridge0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset"})
	return out
}

func (g *dnsGuard) removeLegacy() {
	for _, r := range legacyDNSRules() {
		g.sh(fmt.Sprintf("while %s -t %s -D %s 2>/dev/null; do :; done", r[0], r[1], r[2]))
	}
}

// ---- the process-wide guard ----

var dnsGuardG *dnsGuard

func startDNSGuard() {
	g := newDNSGuard()
	if err := g.Apply(); err != nil {
		log.Printf("%v", err)
	}
	dnsGuardG = g
}
