package main

// Re-asserting the guard when the cellular link changes. wpad-guard.sh keeps the DNS redirect and the "no DNS or DoT leaves by the cellular side" rejects in place, but only
// re-checks every 60 seconds, and the stock firmware (qcmap) rebuilds its NAT and filter tables on network events. For up to a minute after such an event a device's hard-coded
// resolver would have gone out in the clear. This watcher closes that window two ways:
//   - the cellular interface's state and addresses, and the carrier resolver file, are compared every 2 seconds; a change runs the guard at once, and again 5 and 20 seconds later
//     (the firmware rebuilds a moment after the link settles, not always at the instant the address changes);
//   - three of the guard's rules (the port-53 redirect, the IPv4 and IPv6 DNS rejects) are checked every 10 seconds, so a rebuild that is not a link change is caught as well. A run that
//     finds a rule missing is recorded as an event, because the rules really were absent for a while.
// The guard is run with `once` (one pass, no loop); it is idempotent. Runs are at least 3 seconds apart.

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

var guardScript = flag.String("guard-script", "/data/proxy/wpad-guard.sh", "the standing guard, run with `once` when the cellular link changes or its rules go missing (empty = off)")

const (
	guardCellIface   = "rmnet_data0"
	guardMinGap      = 3 * time.Second
	guardCanaryEvery = 10 * time.Second
	guardEventEvery  = 10 * time.Minute
)

var guardFollowUps = []time.Duration{0, 5 * time.Second, 20 * time.Second}

type guardWatch struct {
	sig      func() string           // a signature of the cellular link
	canaryOK func() bool             // are the guard's rules still in place
	runGuard func()                  // one pass of the guard
	emit     func(kind, text string) // an event for the owner
	now      func() time.Time

	last       string
	pending    []time.Time // follow-up runs still to do
	lastRun    time.Time
	lastCanary time.Time
	lastEvent  time.Time
	every      time.Duration // the canary interval: doubled (to 5 minutes) while a run does not bring the rules back, so a rule the kernel cannot hold does not make a busy loop
	Runs       int
}

// step is one look. It is called every couple of seconds.
func (w *guardWatch) step() {
	now := w.now()
	sig := w.sig()
	reason := ""
	if w.last != "" && sig != w.last {
		for _, d := range guardFollowUps {
			w.pending = append(w.pending, now.Add(d))
		}
		log.Printf("guard: cellular link changed, re-asserting the guard rules")
	}
	w.last = sig
	due := false
	rest := w.pending[:0]
	for _, t := range w.pending {
		if !t.After(now) {
			due = true
		} else {
			rest = append(rest, t)
		}
	}
	w.pending = rest
	if due {
		reason = "link"
	}
	if w.every == 0 {
		w.every = guardCanaryEvery
	}
	if reason == "" && now.Sub(w.lastCanary) >= w.every {
		w.lastCanary = now
		if !w.canaryOK() {
			reason = "missing"
		}
	}
	if reason == "" || now.Sub(w.lastRun) < guardMinGap {
		if reason == "link" { // too soon after the last run: do it on the next look
			w.pending = append(w.pending, now.Add(guardMinGap))
		}
		return
	}
	w.lastRun = now
	w.Runs++
	w.runGuard()
	if reason == "missing" {
		if w.canaryOK() {
			w.every = guardCanaryEvery
		} else if w.every *= 2; w.every > 5*time.Minute {
			w.every = 5 * time.Minute
		}
	}
	if reason == "missing" && now.Sub(w.lastEvent) >= guardEventEvery {
		w.lastEvent = now
		w.emit("guard_rules_missing", "The DNS guard rules (the port-53 redirect and the rejects of plain DNS on the cellular side) were missing and have been put back. The firmware rebuilds its firewall tables on some network events.")
	}
}

func (w *guardWatch) Run() {
	for {
		w.step()
		time.Sleep(2 * time.Second)
	}
}

// linkSignature changes when the cellular interface goes up or down, gets another address, or the modem rewrites the carrier resolver file.
func linkSignature(iface, resolvPath string) string {
	var b strings.Builder
	if ifc, err := net.InterfaceByName(iface); err == nil {
		b.WriteString(strconv.FormatUint(uint64(ifc.Flags&net.FlagUp), 10))
		addrs, _ := ifc.Addrs()
		var as []string
		for _, a := range addrs {
			as = append(as, a.String())
		}
		sort.Strings(as)
		b.WriteString("|" + strings.Join(as, ","))
	} else {
		b.WriteString("absent")
	}
	if resolvPath != "" {
		if st, err := os.Stat(resolvPath); err == nil {
			b.WriteString("|" + strconv.FormatInt(st.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(st.Size(), 10))
		}
	}
	return b.String()
}

// guardCanaries are three rules the guard installs; if any is gone the rest probably went with it.
var guardCanaries = [][]string{
	{"iptables", "-t", "nat", "-C", "PREROUTING", "-i", "bridge0", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"},
	{"iptables", "-C", "OUTPUT", "-o", "rmnet_data+", "-p", "udp", "--dport", "53", "-j", "REJECT"},
	{"ip6tables", "-C", "FORWARD", "-i", "bridge0", "-p", "udp", "--dport", "53", "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"},
}

func liveGuardWatch() *guardWatch {
	return &guardWatch{
		now: time.Now,
		sig: func() string { return linkSignature(guardCellIface, *dnsResolv) },
		canaryOK: func() bool {
			for _, c := range guardCanaries {
				if _, err := run(c[0], c[1:]...); err != nil {
					return false
				}
			}
			return true
		},
		runGuard: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, *guardScript, "once").CombinedOutput(); err != nil {
				log.Printf("guard: %s once: %v %s", *guardScript, err, strings.TrimSpace(string(out)))
			}
		},
		emit: func(kind, text string) {
			if events != nil {
				events.Add([]evt{{T: time.Now().Unix(), Kind: kind, Sev: sevAttention, Text: text, Public: "Firewall rules that keep DNS encrypted were missing and were restored"}})
			}
		},
	}
}

func startGuardWatch() {
	if *guardScript == "" {
		return
	}
	if _, err := os.Stat(*guardScript); err != nil {
		log.Printf("guard watch off: %v", err)
		return
	}
	go liveGuardWatch().Run()
}
