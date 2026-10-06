package main

// MAC churn detection: a companion to arpwatch.go's arp_flip, looking at the same stream of ARP claims but over a wider window and from both directions. arp_flip only remembers the
// one previous owner of an address; this keeps a short history per address and per MAC so it can also see the shapes arp_flip misses:
//   mac_churn_ip   one IP has been claimed by three or more distinct MACs within 10 minutes: classic ARP-spoof back-and-forth, or a NAT/relay box doing something it shouldn't.
//   mac_churn_mac  one MAC has claimed four or more distinct IPs within 10 minutes: a device impersonating several addresses in turn, or a rogue bridge.
// Both are "to look at", not proof: a phone that rejoins with Wi-Fi MAC randomization picks a new random address and then a new random MAC each join, which can resemble churn over
// a long day, but a handful of distinct values inside ten minutes from one real join is unusual. At most one event per IP and per MAC every 10 minutes. Nothing is ever sent.

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	churnWindow = 10 * time.Minute
	churnIPMACs = 3 // distinct MACs for one IP within the window before mac_churn_ip fires
	churnMACIPs = 4 // distinct IPs for one MAC within the window before mac_churn_mac fires
)

type churnSeen struct {
	val string
	at  time.Time
}

type churnTrack struct {
	seen []churnSeen // distinct values claimed for this key, oldest first, pruned to the window
	last time.Time
}

// distinct returns the values still inside the window, after dropping anything older.
func (t *churnTrack) distinct(now time.Time) []string {
	i := 0
	for i < len(t.seen) && now.Sub(t.seen[i].at) > churnWindow {
		i++
	}
	t.seen = t.seen[i:]
	out := make([]string, 0, len(t.seen))
	seen := map[string]bool{}
	for _, s := range t.seen {
		if !seen[s.val] {
			seen[s.val] = true
			out = append(out, s.val)
		}
	}
	return out
}

func (t *churnTrack) add(val string, now time.Time) {
	for _, s := range t.seen {
		if s.val == val {
			return // already counted within the current (unpruned) history
		}
	}
	t.seen = append(t.seen, churnSeen{val, now})
	t.last = now
}

type churnFinding struct {
	T     int64    `json:"t"`
	Kind  string   `json:"kind"` // mac_churn_ip | mac_churn_mac
	Key   string   `json:"key"`  // the IP (mac_churn_ip) or MAC (mac_churn_mac)
	Other []string `json:"others"`
}

type macChurnWatch struct {
	mu     sync.Mutex
	byIP   map[string]*churnTrack // IP -> the MACs that have claimed it
	byMAC  map[string]*churnTrack // MAC -> the IPs it has claimed
	lastEv map[string]time.Time
	finds  []churnFinding
	now    func() time.Time
	emit   func(evt)
	nameOf func(mac string) string
}

func newMACChurnWatch() *macChurnWatch {
	return &macChurnWatch{byIP: map[string]*churnTrack{}, byMAC: map[string]*churnTrack{}, lastEv: map[string]time.Time{}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		nameOf: func(mac string) string {
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					if r.MAC == mac {
						return r.Name
					}
				}
			}
			return ""
		}}
}

func (w *macChurnWatch) label(mac string) string {
	if n := w.nameOf(mac); n != "" {
		return n + " (" + mac + ")"
	}
	return mac
}

// Observe takes the same arpClaim arpwatch.go already parses off the wire; call it alongside arpWatch.observe (see the hook in arpwatch.go's observe) so no second capture is needed.
func (w *macChurnWatch) Observe(c arpClaim, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, t := range w.byIP {
		if now.Sub(t.last) > time.Hour {
			delete(w.byIP, k)
		}
	}
	for k, t := range w.byMAC {
		if now.Sub(t.last) > time.Hour {
			delete(w.byMAC, k)
		}
	}
	ipT := w.byIP[c.IP]
	if ipT == nil {
		ipT = &churnTrack{}
		w.byIP[c.IP] = ipT
	}
	ipT.add(c.MAC, now)
	if macs := ipT.distinct(now); len(macs) >= churnIPMACs {
		w.fire("mac_churn_ip", c.IP, macs, now)
	}
	macT := w.byMAC[c.MAC]
	if macT == nil {
		macT = &churnTrack{}
		w.byMAC[c.MAC] = macT
	}
	macT.add(c.IP, now)
	if ips := macT.distinct(now); len(ips) >= churnMACIPs {
		w.fire("mac_churn_mac", c.MAC, ips, now)
	}
}

func (w *macChurnWatch) fire(kind, key string, others []string, now time.Time) {
	evKey := kind + "|" + key
	if t, ok := w.lastEv[evKey]; ok && now.Sub(t) < churnWindow {
		return
	}
	w.lastEv[evKey] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	w.finds = append(w.finds, churnFinding{T: now.Unix(), Kind: kind, Key: key, Other: append([]string{}, others...)})
	if len(w.finds) > 50 {
		w.finds = w.finds[len(w.finds)-50:]
	}
	var e evt
	switch kind {
	case "mac_churn_ip":
		var who []string
		for _, m := range others {
			who = append(who, w.label(m))
		}
		e = evt{Kind: kind, Sev: sevAttention, Text: fmt.Sprintf("The address %s has changed hands %d times in the last %d minutes: %s. A device that rejoined with a new random MAC can look the same, so this is one to look at.", key, len(others), int(churnWindow.Minutes()), joinLabels(who)), Public: "An address on the network changed owner several times in a short period"}
	default:
		e = evt{Kind: kind, Sev: sevAttention, Text: fmt.Sprintf("%s has claimed %d different addresses in the last %d minutes: %v. That can be a rejoining device with address randomization, or something impersonating several hosts in turn.", w.label(key), len(others), int(churnWindow.Minutes()), others), Public: "A device on the network claimed several different addresses in a short period"}
	}
	e.T = now.Unix()
	w.emit(e)
}

func joinLabels(l []string) string {
	s := ""
	for i, x := range l {
		if i > 0 {
			s += ", "
		}
		s += x
	}
	return s
}

type macChurnView struct {
	Findings []churnFinding `json:"findings"` // newest first, last hour
}

func (w *macChurnWatch) View() macChurnView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := macChurnView{Findings: []churnFinding{}}
	cut := w.now().Add(-time.Hour).Unix()
	for i := len(w.finds) - 1; i >= 0; i-- {
		if w.finds[i].T >= cut {
			v.Findings = append(v.Findings, w.finds[i])
		}
	}
	sort.SliceStable(v.Findings, func(i, j int) bool { return v.Findings[i].T > v.Findings[j].T })
	return v
}

var macChurnMgr *macChurnWatch
