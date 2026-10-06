package main

// Tor / proxy-bypass detection: catches a device reaching Tor on its own, outside the Orbic's own Tor path (tor.go), which egress.go and the per-device firewall rules cannot
// see because Tor traffic to a public relay looks like an ordinary HTTPS connection to the service allow-list. Two signals, both passive:
//   tor_bypass_exit    a device that is NOT one of the MACs assigned to tor.go's forced-Tor path has opened a connection to a known Tor relay or bridge address. That device is
//                       running its own Tor client (or a proxy that chains through one), unseen by and unaffected by the house's own Tor controls.
//   tor_bypass_onion   a device asked the DNS stub for a .onion name while house-wide .onion is off and the device itself is not assigned to Tor. tor.go already answers this
//                       NXDOMAIN (never resolved, nothing leaked); this only notes that the attempt happened, since trying is itself a signal even though it was refused.
// The relay/bridge address list is the hard part: Tor's own consensus lists thousands of relays that change by the hour, so this ships with the list EMPTY and off by default
// (Available()==false) until something populates torExitFile (one dotted IP or CIDR per line, '#' comments) -- a cron action (actions.go) refreshing it from a trusted list is the
// natural source, deliberately left out here so nothing is fetched from the network without the owner choosing a feed. With no list loaded, tor_bypass_exit never fires: silence,
// not a false "nothing is wrong". At most one event per device per 10 minutes. Nothing is ever sent outward; the public text never names a device or address.

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type torExitList struct {
	mu   sync.Mutex
	path string
	nets []*net.IPNet
	ips  map[string]bool
	at   time.Time
}

func newTorExitList(path string) *torExitList {
	l := &torExitList{path: path, ips: map[string]bool{}}
	l.Reload()
	return l
}

// Reload re-reads the exit/bridge list from disk. Safe to call on a timer (actions.go) after a feed refreshes the file; a missing or empty file just means the list stays empty.
func (l *torExitList) Reload() {
	f, err := os.Open(l.path)
	if err != nil {
		return
	}
	defer f.Close()
	var nets []*net.IPNet
	ips := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.Contains(ln, "/") {
			if _, n, err := net.ParseCIDR(ln); err == nil {
				nets = append(nets, n)
			}
			continue
		}
		if ip := net.ParseIP(ln); ip != nil {
			ips[ip.String()] = true
		}
	}
	l.mu.Lock()
	l.nets, l.ips, l.at = nets, ips, time.Now()
	l.mu.Unlock()
}

func (l *torExitList) Available() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.ips) > 0 || len(l.nets) > 0
}

func (l *torExitList) Contains(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ips[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range l.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

type torBypassFinding struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"` // tor_bypass_exit | tor_bypass_onion
	MAC  string `json:"mac,omitempty"`
	IP   string `json:"ip,omitempty"`
	Dst  string `json:"dst,omitempty"`
	Name string `json:"name,omitempty"` // the .onion name attempted (tor_bypass_onion only)
}

type torBypassWatch struct {
	mu       sync.Mutex
	exits    *torExitList
	isDevice func(mac string) bool // true for a MAC already assigned to tor.go's forced-Tor path: expected to touch exit addresses, not news
	nameOf   func(mac string) string
	lastEv   map[string]time.Time
	finds    []torBypassFinding
	now      func() time.Time
	emit     func(evt)
}

func newTorBypassWatch(exitFile string) *torBypassWatch {
	return &torBypassWatch{exits: newTorExitList(exitFile), lastEv: map[string]time.Time{}, now: time.Now,
		isDevice: func(mac string) bool { return torMgrG != nil && torMgrG.Active() && torMgrHasDevice(mac) },
		nameOf: func(mac string) string {
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					if r.MAC == mac {
						return r.Name
					}
				}
			}
			return ""
		},
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		}}
}

func torMgrHasDevice(mac string) bool {
	if torMgrG == nil {
		return false
	}
	torMgrG.mu.Lock()
	defer torMgrG.mu.Unlock()
	for _, d := range torMgrG.cfg.Devices {
		if d == mac {
			return true
		}
	}
	return false
}

func (w *torBypassWatch) label(mac string) string {
	if n := w.nameOf(mac); n != "" {
		return n + " (" + mac + ")"
	}
	return mac
}

func (w *torBypassWatch) throttled(key string, now time.Time) bool {
	if t, ok := w.lastEv[key]; ok && now.Sub(t) < 10*time.Minute {
		return true
	}
	w.lastEv[key] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	return false
}

func (w *torBypassWatch) record(f torBypassFinding) {
	w.finds = append(w.finds, f)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
}

// ObserveFlow is meant to be called from egress.go's Sample (alongside its own conntrack read) for every LAN->outside flow: dst is the remote address of a flow already known to be
// forwarded. mac may be "" when the ARP table has nothing for that source yet.
func (w *torBypassWatch) ObserveFlow(mac, src, dst string, now time.Time) {
	if !w.exits.Available() || !w.exits.Contains(dst) || w.isDevice(mac) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	key := "exit|" + src
	if w.throttled(key, now) {
		return
	}
	w.record(torBypassFinding{T: now.Unix(), Kind: "tor_bypass_exit", MAC: mac, IP: src, Dst: dst})
	who := src
	if mac != "" {
		who = w.label(mac)
	}
	w.emit(evt{T: now.Unix(), Kind: "tor_bypass_exit", Sev: sevAttention, Text: fmt.Sprintf("%s connected directly to a known Tor relay address (%s) but is not one of the devices assigned to the Orbic's own Tor path: it is likely running its own Tor client or a proxy that chains through one, unseen by the house's Tor controls.", who, dst), Public: "A device reached the Tor network outside the router's own Tor controls"})
}

// ObserveOnionAttempt is called from tor.go's DNS when a non-Tor device's .onion lookup is refused because house-wide .onion is off: the refusal already stops anything from
// resolving, this only notes that the attempt happened.
func (w *torBypassWatch) ObserveOnionAttempt(mac, client, name string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := "onion|" + client
	if w.throttled(key, now) {
		return
	}
	w.record(torBypassFinding{T: now.Unix(), Kind: "tor_bypass_onion", MAC: mac, IP: client, Name: name})
	who := client
	if mac != "" {
		who = w.label(mac)
	}
	w.emit(evt{T: now.Unix(), Kind: "tor_bypass_onion", Sev: sevAttention, Text: fmt.Sprintf("%s asked for the .onion name %s while house-wide .onion is off and it is not assigned to Tor; the lookup was refused (never resolved), but the attempt is worth a look.", who, name), Public: "A device attempted a .onion lookup that the router refused"})
}

type torBypassView struct {
	Available bool               `json:"available"` // an exit/bridge list is loaded
	Findings  []torBypassFinding `json:"findings"`  // newest first
}

func (w *torBypassWatch) View() torBypassView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := torBypassView{Available: w.exits.Available(), Findings: []torBypassFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var torBypassMgr *torBypassWatch
