package main

// Phase 2: the stock admin (`goahead`) switched off for the network, reversibly. Phase 1 rebuilt everything it did on this page, so it can be shut out. "Off" means:
//   - nothing on the network can reach its ports 81 and 444 (it listens on every interface): INPUT rules in our chain HS_ADMIN reject them, IPv4 and IPv6, except from
//     loopback (the box itself keeps access, and so does our relay);
//   - a LAN client that opens 192.168.1.1 on port 80 or 443, which used to be passed through to it, lands on THIS page instead (80 to the PAC/redirect server, 443 to the
//     web page: our certificate covers that address).
// The daemon itself is left running, NOT suspended: it holds the System V message queue the other stock daemons talk to, and stopping it could stall them. The switch is the
// flag file /data/proxy/stockadmin.off (present = off); undo it from the page, or over ssh: `rm /data/proxy/stockadmin.off` (the rules go within 20 seconds). One thing the stock
// admin is still needed for: entering a SIM PIN, if the carrier ever asks for one (the box has not so far). Its password files are untouched.

import (
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const adminRules = "-p tcp -m multiport --dports 81,444 ! -i lo -j REJECT --reject-with tcp-reset"

type stockAdmin struct {
	mu      sync.Mutex
	flag    string
	apply   func(off bool) error // make the firewall match (idempotent)
	checked time.Time
	off     bool
	now     func() time.Time
}

func defaultStockAdmin() *stockAdmin {
	return &stockAdmin{flag: *stockAdminFlag, now: time.Now, apply: applyAdminRules}
}

// Off is asked on every relayed LAN connection: a cached stat of the flag file (1 s).
func (s *stockAdmin) Off() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.checked) > time.Second {
		_, err := os.Stat(s.flag)
		s.off, s.checked = err == nil, s.now()
	}
	return s.off
}

func (s *stockAdmin) Set(off bool) error {
	s.mu.Lock()
	var err error
	if off {
		err = os.WriteFile(s.flag, []byte("the stock admin is switched off: remove this file to switch it back on\n"), 0o644)
	} else if e := os.Remove(s.flag); e != nil && !os.IsNotExist(e) {
		err = e
	}
	s.off, s.checked = off, s.now()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if e := s.apply(off); e != nil {
		return errors.New("saved, but " + e.Error() + " (it is re-applied within 20 seconds)")
	}
	return nil
}

func (s *stockAdmin) Reconcile() {
	if err := s.apply(s.Off()); err != nil {
		log.Printf("stock admin switch: %v", err)
	}
}

func (s *stockAdmin) Run() {
	for {
		s.Reconcile()
		time.Sleep(20 * time.Second)
	}
}

// applyAdminRules makes our chain hold the reject rule (off) or nothing and be unhooked (on), for IPv4 and IPv6.
func applyAdminRules(off bool) error {
	if out, err := run("sh", "-c", adminScript(off)); err != nil {
		return errors.New("firewall: " + strings.TrimSpace(out))
	}
	return nil
}

func adminScript(off bool) string {
	var b strings.Builder
	for _, t := range []string{"iptables", "ip6tables"} {
		b.WriteString(t + " -N HS_ADMIN 2>/dev/null\n")
		if off {
			b.WriteString(t + " -C HS_ADMIN " + adminRules + " 2>/dev/null || { " + t + " -F HS_ADMIN && " + t + " -A HS_ADMIN " + adminRules + "; }\n")
			b.WriteString(t + " -C INPUT -j HS_ADMIN 2>/dev/null || " + t + " -I INPUT 1 -j HS_ADMIN\n")
		} else {
			b.WriteString("while " + t + " -D INPUT -j HS_ADMIN 2>/dev/null; do :; done\n" + t + " -F HS_ADMIN\n")
		}
	}
	return b.String()
}

type stockAdminView struct {
	Off       bool `json:"off"`
	RulesIn   bool `json:"rules_in_place"`
	Listening bool `json:"listening"` // the daemon itself is still running (it is never stopped)
}

func (s *stockAdmin) View() stockAdminView {
	v := stockAdminView{Off: s.Off()}
	out, _ := run("iptables", "-S", "INPUT")
	out6, _ := run("ip6tables", "-S", "INPUT")
	v.RulesIn = strings.Contains(out, "-j HS_ADMIN") && strings.Contains(out6, "-j HS_ADMIN")
	ps, _ := run("sh", "-c", "pidof goahead")
	v.Listening = strings.TrimSpace(ps) != ""
	return v
}
