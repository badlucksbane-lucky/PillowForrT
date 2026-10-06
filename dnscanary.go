package main

// DNS exfiltration canary: a lookup that should never happen on an honest LAN is itself the signal, the same idea as canary.go but on the name a device asks for instead of the
// address it touches. Three things are watched, all from inside the DNS stub (dnsproxy.go) where every query already passes through, so nothing new is opened on the wire:
//   dns_canary       a device asked for one of a small set of decoy names (house-internal-looking names nobody configured, and a few names shaped like common C2/beacon domains).
//                     Reuses a device's own reservation name where DHCP has one, exactly like the canary and ARP watch.
//   dns_plain_fallback a device's query left as plain UDP/TCP port 53 while the stub's own upstream is still doing DoH: that only happens when something routes around the stub
//                     (a device with its own resolver settings, or malware carrying one), since every normal query already arrives here over the LAN side.
//   dns_exfil        a run of queries to the same base domain whose labels look like encoded data (long, high-entropy, many unique subdomains in a short time): the classic shape of
//                     DNS tunneling and beaconing. This one is heuristic and noisier, so it asks for a higher bar (distinct-label count) before it fires, and at most once per 10 min
//                     per (client, base domain).
// Nothing is ever sent outward, no name is logged beyond the ring buffers already in dnsproxy.go, and this never blocks or alters an answer: it only watches and emits an event.
// Honest limits: a device that ignores the stub entirely (hard-coded DoH/DoT elsewhere) is invisible here, the same gap egress.go's service list cannot close either.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// dnsCanaryDomains are decoy or suspicious names: anyone asking for one is looking around, not browsing. Lower-case, no trailing dot.
var dnsCanaryDomains = []string{
	"heimdall-canary.invalid",
	"internal-admin.local",
	"c2-checkin.invalid",
}

type dnsCanaryHit struct {
	T      int64  `json:"t"`
	Client string `json:"client"`
	MAC    string `json:"mac,omitempty"`
	Name   string `json:"name"`
	Kind   string `json:"kind"` // canary | plain_fallback | exfil
}

type dnsCanarySource struct {
	First, Last    time.Time
	MAC            string
	LastEvent      map[string]time.Time       // kind -> last emitted
	labels         map[string]map[string]bool // base domain -> distinct labels seen recently
	labelsAt       map[string]time.Time       // base domain -> when that window started
	LastExfilEvent map[string]time.Time       // base domain -> last emitted
}

type dnsCanaryState struct {
	Enabled bool     `json:"enabled"`
	Decoys  []string `json:"decoys,omitempty"` // extra decoy names, beyond the built-in set
	Ignore  []string `json:"ignore,omitempty"` // MACs that may do any of this without an event (e.g. a known DNS research tool)
}

type dnsCanaryWatch struct {
	mu      sync.Mutex
	path    string
	st      dnsCanaryState
	hits    []dnsCanaryHit
	sources map[string]*dnsCanarySource
	now     func() time.Time
	emit    func(evt)
	nameOf  func(mac string) string
	macOf   func(client string) string
	doh     func() bool // true while the upstream is using DoH (not already in plain fallback): a plain-53 query is only news then
}

func newDNSCanaryWatch() *dnsCanaryWatch {
	w := &dnsCanaryWatch{path: "/data/proxy/dnscanary.json", sources: map[string]*dnsCanarySource{}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		macOf: func(client string) string {
			b, _ := os.ReadFile("/proc/net/arp")
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
		},
		doh: func() bool {
			return dnsProxy != nil && dnsProxy.Up != nil && !dnsProxy.Up.inFallback()
		},
	}
	w.st.Enabled = true
	if b, err := os.ReadFile(w.path); err == nil {
		json.Unmarshal(b, &w.st)
	}
	return w
}

func (w *dnsCanaryWatch) save() {
	b, _ := json.Marshal(w.st)
	writeFileAtomic(w.path, b, 0o600)
}

func (w *dnsCanaryWatch) ignored(mac string) bool {
	for _, m := range w.st.Ignore {
		if m == mac && m != "" {
			return true
		}
	}
	return false
}

// isCanaryName reports whether name (already lower-cased, no trailing dot) is one of the decoy domains or a subdomain of one.
func isCanaryName(name string, extra []string) bool {
	for _, list := range [][]string{dnsCanaryDomains, extra} {
		for _, d := range list {
			if name == d || strings.HasSuffix(name, "."+d) {
				return true
			}
		}
	}
	return false
}

// exfilLabel is a rough shape test for a DNS-tunneling label: long, and mostly hex/base32-looking characters.
func exfilLabel(label string) bool {
	if len(label) < 24 {
		return false
	}
	hexish := 0
	for _, c := range label {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			hexish++
		}
	}
	return hexish*100/len(label) > 80
}

// baseDomain keeps the last two labels ("example.com" out of "a.b.c.example.com"), a reasonable stand-in for "the domain actually being tunneled through".
func baseDomain(name string) string {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(parts) <= 2 {
		return name
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// Observe is called from DNSProxy.Handle for every query, after the name is known. viaPlain says the query is about to go out (or came back) over plain port-53 DNS rather than DoH/VPN/Tor.
func (w *dnsCanaryWatch) Observe(client, name string, viaPlain bool, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.st.Enabled || client == "" || name == "" {
		return
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	mac := w.macOf(client)
	if w.ignored(mac) {
		return
	}
	for k, s := range w.sources {
		if now.Sub(s.Last) > time.Hour {
			delete(w.sources, k)
		}
	}
	s := w.sources[client]
	if s == nil {
		s = &dnsCanarySource{First: now, LastEvent: map[string]time.Time{}, labels: map[string]map[string]bool{}, labelsAt: map[string]time.Time{}, LastExfilEvent: map[string]time.Time{}}
		w.sources[client] = s
	}
	s.Last, s.MAC = now, mac

	switch {
	case isCanaryName(name, w.st.Decoys):
		w.fire(s, client, mac, name, "canary", now)
	case viaPlain && w.doh():
		w.fire(s, client, mac, name, "plain_fallback", now)
	}

	base := baseDomain(name)
	first := strings.SplitN(name, ".", 2)[0]
	if exfilLabel(first) {
		if now.Sub(s.labelsAt[base]) > 10*time.Minute {
			s.labels[base] = map[string]bool{}
			s.labelsAt[base] = now
		}
		s.labels[base][first] = true
		if len(s.labels[base]) >= 20 && now.Sub(s.LastExfilEvent[base]) > 10*time.Minute {
			s.LastExfilEvent[base] = now
			w.recordHit(client, mac, base, "exfil", now)
			who := label(client, w.nameOf(mac), mac)
			w.emit(evt{T: now.Unix(), Kind: "dns_exfil", Sev: sevAttention, Text: fmt.Sprintf("%s has made %d odd-looking DNS lookups under %s in 10 minutes: this is the shape of DNS tunneling, though some legitimate CDNs and trackers look similar", who, len(s.labels[base]), base), Public: "A device is making DNS lookups shaped like data tunneling"})
		}
	}
}

// label mirrors canary.go/arpwatch.go's "address (name)" convention.
func label(addr, name, mac string) string {
	who := addr
	if name != "" {
		who += " (" + name + ")"
	} else if mac != "" {
		who += " (" + mac + ")"
	}
	return who
}

func (w *dnsCanaryWatch) fire(s *dnsCanarySource, client, mac, name, kind string, now time.Time) {
	if now.Sub(s.LastEvent[kind]) < 10*time.Minute {
		return
	}
	s.LastEvent[kind] = now
	w.recordHit(client, mac, name, kind, now)
	who := label(client, w.nameOf(mac), mac)
	switch kind {
	case "canary":
		w.emit(evt{T: now.Unix(), Kind: "dns_canary", Sev: sevAttention, Text: fmt.Sprintf("%s looked up a DNS canary name: %s", who, name), Public: "A device queried a decoy DNS name"})
	case "plain_fallback":
		w.emit(evt{T: now.Unix(), Kind: "dns_plain_fallback", Sev: sevAttention, Text: fmt.Sprintf("%s's query for %s left as plain DNS while the Orbic's own upstream is still using DoH: something on that device may be bypassing the resolver policy", who, name), Public: "A device sent a plain DNS query while encrypted DNS is in use"})
	}
}

func (w *dnsCanaryWatch) recordHit(client, mac, name, kind string, now time.Time) {
	w.hits = append(w.hits, dnsCanaryHit{T: now.Unix(), Client: client, MAC: mac, Name: name, Kind: kind})
	if len(w.hits) > 200 {
		w.hits = w.hits[len(w.hits)-200:]
	}
}

type dnsCanaryView struct {
	Enabled bool           `json:"enabled"`
	Decoys  []string       `json:"decoys"`
	Ignore  []string       `json:"ignore"`
	Hits    []dnsCanaryHit `json:"hits"`
}

func (w *dnsCanaryWatch) View() dnsCanaryView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := dnsCanaryView{Enabled: w.st.Enabled, Decoys: append([]string{}, w.st.Decoys...), Ignore: append([]string{}, w.st.Ignore...), Hits: []dnsCanaryHit{}}
	for i := len(w.hits) - 1; i >= 0 && len(v.Hits) < 40; i-- {
		v.Hits = append(v.Hits, w.hits[i])
	}
	sort.Slice(v.Hits, func(i, j int) bool { return v.Hits[i].T > v.Hits[j].T })
	return v
}

func (w *dnsCanaryWatch) SetEnabled(on bool) {
	w.mu.Lock()
	w.st.Enabled = on
	w.save()
	w.mu.Unlock()
}

var dnsCanaryMgr *dnsCanaryWatch
