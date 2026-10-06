package main

// DGA / NXDOMAIN-flood detection: malware that generates its C2 domains algorithmically (a "domain generation algorithm") burns through dozens of names a real server never
// registered before it lands on the live one; from inside the DNS stub that looks like one client racking up NXDOMAIN answers fast, to many DIFFERENT names, which an honest
// device essentially never does (a typo or an uninstalled app's one dead callback is one NXDOMAIN, not twenty in a few minutes). This is deliberately a different shape from
// dnscanary.go's dns_exfil check, which wants many distinct SUBDOMAINS of the SAME base domain succeeding or erroring; this one wants many distinct BASE names, most of them
// failing, which is the DGA signature rather than the tunneling one.
// One finding per client per 10 minutes. Nothing is sent outward or kept beyond the small ring below; the public text never names a device or a domain.

import (
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	dgaWindow    = 5 * time.Minute
	dgaThreshold = 20 // distinct NXDOMAIN names within the window before it fires
)

type dgaSource struct {
	names     map[string]time.Time // name -> first seen this window
	windowAt  time.Time
	lastEvent time.Time
}

type dgaFinding struct {
	T      int64  `json:"t"`
	Client string `json:"client"`
	MAC    string `json:"mac,omitempty"`
	Count  int    `json:"count"`
}

type dgaWatch struct {
	mu      sync.Mutex
	sources map[string]*dgaSource
	finds   []dgaFinding
	now     func() time.Time
	emit    func(evt)
	macOf   func(client string) string
	nameOf  func(mac string) string
}

func newDGAWatch() *dgaWatch {
	return &dgaWatch{sources: map[string]*dgaSource{}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		macOf: func(client string) string {
			b, err := os.ReadFile("/proc/net/arp")
			if err != nil {
				return ""
			}
			for mac, ip := range parseARP(string(b)) {
				if ip == client {
					return mac
				}
			}
			return ""
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

// Observe is called from DNSProxy.Handle whenever an upstream answer comes back NXDOMAIN (rcodeOf(resp) == 3) for a class-Internet query; name is the query name, lower-cased by
// the caller is not required here.
func (w *dgaWatch) Observe(client, name string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if client == "" || name == "" {
		return
	}
	for k, s := range w.sources {
		if now.Sub(s.windowAt) > time.Hour {
			delete(w.sources, k)
		}
	}
	s := w.sources[client]
	if s == nil {
		s = &dgaSource{names: map[string]time.Time{}, windowAt: now}
		w.sources[client] = s
	}
	if now.Sub(s.windowAt) > dgaWindow {
		s.names, s.windowAt = map[string]time.Time{}, now
	}
	s.names[name] = now
	if len(s.names) < dgaThreshold || now.Sub(s.lastEvent) < 10*time.Minute {
		return
	}
	s.lastEvent = now
	mac := w.macOf(client)
	w.finds = append(w.finds, dgaFinding{T: now.Unix(), Client: client, MAC: mac, Count: len(s.names)})
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := client
	if n := w.nameOf(mac); n != "" {
		who = fmt.Sprintf("%s (%s)", n, client)
	} else if mac != "" {
		who = fmt.Sprintf("%s (%s)", client, mac)
	}
	w.emit(evt{T: now.Unix(), Kind: "dns_nxdomain_flood", Sev: sevAttention, Text: fmt.Sprintf("%s has had %d different DNS lookups fail (NXDOMAIN) in %d minutes: a real server list does not usually miss that often, and a malware domain-generation algorithm burning through candidate names looks exactly like this.", who, len(s.names), int(dgaWindow.Minutes())), Public: "A device has had an unusually large number of DNS lookups fail in a short time"})
}

type dgaView struct {
	Findings []dgaFinding `json:"findings"`
}

func (w *dgaWatch) View() dgaView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := dgaView{Findings: []dgaFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var dgaMgr *dgaWatch
