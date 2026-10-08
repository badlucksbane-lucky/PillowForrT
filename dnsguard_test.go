package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPlanDNSGuard(t *testing.T) {
	nat, f, v6 := planDNSGuard(dnsGuardPlan{Local: defaultDNSLocal})
	for _, want := range []string{
		"-A HS_DNSNAT -p udp --dport 53 -d 192.168.1.254 -j RETURN",
		"-A HS_DNSNAT -p tcp --dport 53 -d 192.168.1.1 -j RETURN",
		"-A HS_DNSNAT -p udp --dport 53 -j REDIRECT --to-ports 53",
		"-A HS_DNSNAT -p tcp --dport 53 -j REDIRECT --to-ports 53",
	} {
		if !strings.Contains(nat, want+"\n") {
			t.Errorf("nat is missing %q:\n%s", want, nat)
		}
	}
	if strings.Index(nat, "-j RETURN") > strings.Index(nat, "-j REDIRECT") || strings.LastIndex(nat, "-j RETURN") > strings.Index(nat, "-j REDIRECT") {
		t.Error("the exemptions for the box's own addresses must come before the redirect")
	}
	for _, want := range []string{
		"-A HS_DNSOUT -o rmnet_data+ -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable",
		"-A HS_DNSOUT -o rmnet_data+ -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A HS_DNSFWD -i bridge0 -o rmnet_data+ -p udp --dport 53 -j REJECT --reject-with icmp-port-unreachable",
		"-A HS_DNSFWD -i bridge0 -o mullvad0 -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
		"-A HS_DNSFWD -i bridge0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A HS_DNSFWD -i bridge0 -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable",
	} {
		if !strings.Contains(f, want+"\n") {
			t.Errorf("filter is missing %q:\n%s", want, f)
		}
	}
	for _, want := range []string{
		"-A HS_DNSFWD6 -i bridge0 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable",
		"-A HS_DNSFWD6 -i bridge0 -p tcp --dport 853 -j REJECT --reject-with tcp-reset",
		"-A HS_DNSOUT6 -o rmnet_data+ -p udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable",
	} {
		if !strings.Contains(v6, want+"\n") {
			t.Errorf("ip6 is missing %q:\n%s", want, v6)
		}
	}
	for _, blk := range []string{nat, f, v6} {
		if !strings.HasSuffix(blk, "COMMIT\n") || strings.Contains(blk, "ACCEPT") {
			t.Errorf("each block is one atomic restore and the guard never accepts:\n%s", blk)
		}
	}
}

// fakeKernel stands in for iptables: it keeps the rules the guard asked for and reports them back the way iptables-save does.
type fakeKernel struct {
	rules   map[string][]string // table key -> "-A ..." lines
	sh      []string
	failN   int
	applied int
}

func newFakeGuard() (*dnsGuard, *fakeKernel) {
	k := &fakeKernel{rules: map[string][]string{}}
	g := newDNSGuard()
	g.sleep = func(time.Duration) {}
	g.marker = "" // the tests never touch /var/volatile
	g.restore = func(cmd, rules string) error {
		if k.failN > 0 {
			k.failN--
			return errors.New("iptables-restore: Resource temporarily unavailable")
		}
		k.applied++
		key := map[string]string{"iptables-restore": "v4", "ip6tables-restore": "v6"}[cmd] + ":" + strings.SplitN(strings.TrimPrefix(strings.SplitN(rules, "\n", 2)[0], "*"), "\n", 2)[0]
		var keep []string
		for _, l := range k.rules[key] {
			if !strings.Contains(l, "HS_DNS") || strings.Contains(l, " -j HS_DNS") { // hooks stay; chain contents are replaced
				keep = append(keep, l)
			}
		}
		for _, l := range strings.Split(rules, "\n") {
			if strings.HasPrefix(l, "-A ") {
				keep = append(keep, l)
			}
		}
		k.rules[key] = keep
		return nil
	}
	g.sh = func(c string) (string, error) {
		k.sh = append(k.sh, c)
		for _, h := range dnsHooks {
			if strings.HasPrefix(c, fmt.Sprintf("%s -t %s -C %s %s", h.cmd, h.table, h.parent, h.spec)) {
				key := map[string]string{"iptables": "v4", "ip6tables": "v6"}[h.cmd] + ":" + h.table
				line := "-A " + h.parent + " " + h.spec
				for _, l := range k.rules[key] {
					if l == line {
						return "", nil
					}
				}
				k.rules[key] = append(k.rules[key], line)
			}
		}
		return "", nil
	}
	g.save = func(cmd, table string) (string, error) {
		key := map[string]string{"iptables": "v4", "ip6tables": "v6"}[strings.TrimSuffix(cmd, "-save")] + ":" + table
		return "# Generated\n*" + table + "\n:HS_DNSOUT - [12:34]\n" + strings.Join(k.rules[key], "\n") + "\nCOMMIT\n", nil
	}
	return g, k
}

func TestDNSGuardApplyVerifyDrift(t *testing.T) {
	g, k := newFakeGuard()
	if g.Verify() {
		t.Error("before the first apply nothing is verified")
	}
	if err := g.Apply(); err != nil {
		t.Fatal(err)
	}
	if !g.Verify() {
		t.Fatal("right after an apply the guard verifies")
	}
	if len(k.rules["v4:nat"]) == 0 || len(k.rules["v6:filter"]) == 0 {
		t.Errorf("rules went into every table: %v", k.rules)
	}
	// the firmware rebuilds the nat table: the redirect is gone
	k.rules["v4:nat"] = nil
	if g.Verify() {
		t.Error("a rebuilt table must fail the check")
	}
	if err := g.Apply(); err != nil || !g.Verify() {
		t.Errorf("re-applying restores it: %v", err)
	}
	// one rule edited out of the middle of a chain, count dropping by one
	f := k.rules["v4:filter"]
	for i, l := range f {
		if strings.HasPrefix(l, "-A HS_DNSFWD ") {
			k.rules["v4:filter"] = append(append([]string(nil), f[:i]...), f[i+1:]...)
			break
		}
	}
	if g.Verify() {
		t.Error("a missing rule must fail the check")
	}
	g.Apply()
	// the same rules in another order are not "as applied"
	f = k.rules["v6:filter"]
	f[0], f[len(f)-1] = f[len(f)-1], f[0]
	if g.Verify() {
		t.Error("a reordered chain must fail the check")
	}
}

func TestDNSGuardRetriesBusyTablesAndGivesUp(t *testing.T) {
	g, k := newFakeGuard()
	k.failN = 2
	if err := g.Apply(); err != nil {
		t.Errorf("two busy answers are retried: %v", err)
	}
	g2, k2 := newFakeGuard()
	k2.failN = 100
	if err := g2.Apply(); err == nil || g2.Verify() {
		t.Error("a table that never takes the rules is an error, and not verified")
	}
	if len(k2.sh) != 0 {
		t.Errorf("nothing is hooked or removed when the chains did not go in: %v", k2.sh)
	}
}

// The old shell-installed rules are removed only after the new ones are confirmed in place, never before.
func TestDNSGuardRemovesLegacyRulesLast(t *testing.T) {
	g, k := newFakeGuard()
	if err := g.Apply(); err != nil {
		t.Fatal(err)
	}
	firstDel := -1
	lastHook := -1
	for i, c := range k.sh {
		if strings.Contains(c, " -D ") && firstDel < 0 {
			firstDel = i
		}
		if strings.Contains(c, " -C ") {
			lastHook = i
		}
	}
	if firstDel < 0 || firstDel < lastHook {
		t.Errorf("the legacy rules must be deleted after every hook is in place: del=%d hook=%d\n%v", firstDel, lastHook, k.sh)
	}
	seen := map[string]bool{}
	for _, c := range k.sh {
		seen[c] = true
	}
	want := "while iptables -t nat -D PREROUTING -i bridge0 -p udp --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do :; done"
	if !seen[want] {
		t.Errorf("the old redirect must be among the deletions:\n%v", k.sh)
	}
	// and a failed apply leaves the old rules alone (checked above with sh empty); a guard that applied but reads back wrong keeps them too
	g3, k3 := newFakeGuard()
	g3.save = func(cmd, table string) (string, error) { return "", nil }
	if err := g3.Apply(); err == nil {
		t.Error("a read-back that finds no rules is an error")
	}
	for _, c := range k3.sh {
		if strings.Contains(c, " -D ") {
			t.Errorf("legacy rules deleted although the new ones could not be confirmed: %s", c)
		}
	}
}

func TestDNSGuardWritesMarkerOnlyWhenOwning(t *testing.T) {
	g, _ := newFakeGuard()
	g.marker = t.TempDir() + "/dnsguard.on"
	g2, k2 := newFakeGuard()
	g2.marker = t.TempDir() + "/never"
	k2.failN = 100
	g2.Apply()
	if _, err := os.Stat(g2.marker); err == nil {
		t.Error("no marker when the rules did not go in: the script must keep protecting")
	}
	if err := g.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(g.marker); err != nil {
		t.Error("marker written once the guard is confirmed")
	}
}
