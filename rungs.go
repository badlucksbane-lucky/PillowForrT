package main

// Rung viability. The ladder in owndial.go says which rungs the tier allows; this decides when a rung may be used, from evidence that it works, not from the state of its process:
//   - stepping DOWN is immediate: a rung that is not up (tunnel down, Tor not ready) is gone at once, and a rung that is "up" but failing (two probes or two real dials through it in a row)
//     is given up and not tried again for a hold-down period;
//   - stepping UP waits: the rung must have been up for a while, answered enough probes, and the box must not be busy (load), while a lower rung is serving. The wait is dropped when nothing
//     lower is serving (the house would otherwise sit blocked or raw longer than it has to), and then one good probe is enough.
// Probes go through the rung itself (for Tor: a TLS handshake to a resolver, through Tor's SOCKS port), so a Tor that has "bootstrapped" but cannot carry traffic is not stepped up to.

import (
	"crypto/tls"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type rungGate struct {
	stableFor    time.Duration // how long the rung must have been up before it is stepped up to
	holdDown     time.Duration // after a failure, how long before it is tried again
	probesNeeded int           // consecutive good probes before stepping up (0: the rung has no probe)
	up           bool
	since        time.Time // when the rung last came up (zero while it is not)
	okRun        int
	failRun      int
	holdUntil    time.Time
}

// step returns whether the rung is usable now. raw is whether it is up at all; needed is whether nothing lower is serving; loadOK is whether the box can take it.
func (g *rungGate) step(now time.Time, raw, needed, loadOK bool) bool {
	if !raw { // down is immediate
		g.up, g.since, g.okRun, g.failRun = false, time.Time{}, 0, 0
		return false
	}
	if g.since.IsZero() {
		g.since = now
	}
	if g.up {
		if g.failRun >= 2 { // up on paper, failing in practice: give it up and wait before trying again
			g.up, g.okRun = false, 0
			g.holdUntil = now.Add(g.holdDown)
		}
		return g.up
	}
	need := g.probesNeeded
	if needed && need > 1 {
		need = 1
	}
	stable := needed || now.Sub(g.since) >= g.stableFor
	held := !needed && now.Before(g.holdUntil)
	if stable && !held && g.okRun >= need && (loadOK || needed) {
		g.up, g.failRun = true, 0
	}
	return g.up
}

// report records the result of one probe (or one real dial) through the rung.
func (g *rungGate) report(ok bool) {
	if ok {
		g.okRun++
		g.failRun = 0
	} else {
		g.failRun++
		g.okRun = 0
	}
}

const (
	torStepUpAfter  = 45 * time.Second
	torHoldDown     = 5 * time.Minute
	tunnelStepUp    = 10 * time.Second
	stepUpLoadLimit = 2.0 // one-minute load average above which no rung is stepped up to (stepping down never waits for it)
)

func newRungGates() (tor, tunnel *rungGate) {
	return &rungGate{stableFor: torStepUpAfter, holdDown: torHoldDown, probesNeeded: 2},
		&rungGate{stableFor: tunnelStepUp, holdDown: 30 * time.Second}
}

func loadAvg1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// probeTorViable asks whether Tor can carry a real connection: a TLS handshake with a public resolver, through Tor's SOCKS port.
func probeTorViable() bool {
	c, err := socksConnect(onionSocksAddr, "1.1.1.1", 443, 10*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(c, &tls.Config{ServerName: "1.1.1.1", RootCAs: rootPool(), MinVersion: tls.VersionTLS12})
	return tc.Handshake() == nil
}

// startRungProber probes Tor through its SOCKS port while it says it is ready: often while stepping up is being decided, rarely once it is carrying traffic.
func startRungProber() {
	go func() {
		for {
			wait := 30 * time.Second
			if s := liveOwnState(); s.TorEnabled && s.TorReady {
				ok := probeTorViable()
				ownR.reportTor(ok)
				if !ok {
					log.Printf("own traffic: Tor answered no probe connection")
				}
				if !ownR.torUp() {
					wait = 12 * time.Second
				}
			}
			time.Sleep(wait)
		}
	}()
}
