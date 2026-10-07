package main

// Resolver cross-check: the stub asks two independent DoH resolvers (Quad9 and Cloudflare by default) but, until now, only ever the first one that answers. Each is trusted
// on its own word. This samples a small share of the A answers that came back over DoH (one in dnsXSampleEvery, never more than one check in flight and never more than
// one every few seconds, so the stub's in-flight cap is untouched) and asks the OTHER resolver the same question, then compares. Two honest resolvers disagree all the time
// about which address a CDN name maps to, so a plain difference between two public address sets is counted on the card and never an event. What IS worth a look is a
// disagreement about the shape of the answer: one resolver says the name exists and the other says it does not (NXDOMAIN), or one hands back a private, loopback, link-local
// or otherwise unroutable address where the other hands back a public one. Those are what a poisoned or hijacked resolver, or an interception box answering for one, look like,
// and they are raised as "to look at" (one per name per hour). An alert would need a third opinion this box deliberately does not fetch.
// Honest limits: it only sees names that went out over DoH (a VPN device's queries go through the tunnel, a Tor device's through Tor, neither is checked); a sample is a
// sample, so a one-off poisoned answer can slip between checks; and when the two resolvers disagree it cannot say which one is wrong, only that they do. Nothing is sent that
// was not already being sent: the second query names the same hostname the first did, to a resolver this box already trusts with every other query. The client's address never
// leaves the box, same as every other query (the add-subnet is stripped before any upstream sees it).

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	dnsXSampleEvery = 50
	dnsXMinGap      = 3 * time.Second
	dnsXNamesTTL    = time.Hour
)

type dnsXFinding struct {
	T       int64    `json:"t"`
	Kind    string   `json:"kind"`
	MAC     string   `json:"mac,omitempty"`
	Client  string   `json:"client"`
	Name    string   `json:"name"`
	First   string   `json:"first"`  // the resolver that answered the device
	Second  string   `json:"second"` // the one asked to cross-check
	Answer1 []string `json:"answer1"`
	Answer2 []string `json:"answer2"`
}

type dnsXWatch struct {
	mu       sync.Mutex
	ask      func(url string, q []byte) ([]byte, error)
	urls     func() []string
	now      func() time.Time
	emit     func(evt)
	macOf    func(ip string) string
	nameOf   func(mac string) string
	seen     uint64
	inFlight bool
	lastRun  time.Time
	lastName map[string]time.Time // names flagged, for the per-name rate limit
	checked  map[string]time.Time // names checked recently, so a busy name does not use every sample
	finds    []dnsXFinding
	Agree    uint64 `json:"agree"`
	Differ   uint64 `json:"differ"` // both public, no overlap: the CDN case
	Flagged  uint64 `json:"flagged"`
	Failed   uint64 `json:"failed"` // the second resolver did not answer
	wg       sync.WaitGroup
}

func newDNSXWatch(up *Upstream) *dnsXWatch {
	w := &dnsXWatch{now: time.Now, lastName: map[string]time.Time{}, checked: map[string]time.Time{},
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		macOf: func(ip string) string {
			b, _ := os.ReadFile("/proc/net/arp")
			for mac, a := range parseARP(string(b)) {
				if a == ip {
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
	if up != nil {
		w.ask = up.dohOne
		w.urls = func() []string { return up.cfg.DoHURLs }
	}
	return w
}

func (w *dnsXWatch) label(ip, mac string) string {
	if n := w.nameOf(mac); n != "" {
		return fmt.Sprintf("%s (%s)", n, ip)
	}
	if mac != "" {
		return fmt.Sprintf("%s (%s)", ip, mac)
	}
	return ip
}

// unroutable reports whether an address is one no public name should resolve to: private, loopback, link-local, CGNAT, the benchmark range this box uses for .onion, or unspecified.
func unroutable(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	for _, c := range []string{"100.64.0.0/10", "198.18.0.0/15", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Observe is called from DNSProxy.Handle for every A answer that came back over DoH. It decides whether this one is sampled; the check itself runs in the background.
func (w *dnsXWatch) Observe(client, name, fromURL string, q, resp []byte, now time.Time) {
	if w.ask == nil || w.urls == nil {
		return
	}
	w.mu.Lock()
	w.seen++
	sample := w.seen%dnsXSampleEvery == 1
	if !sample || w.inFlight || now.Sub(w.lastRun) < dnsXMinGap {
		w.mu.Unlock()
		return
	}
	if t, had := w.checked[name]; had && now.Sub(t) < dnsXNamesTTL {
		w.mu.Unlock()
		return
	}
	var other string
	for _, u := range w.urls() {
		if u != fromURL {
			other = u
			break
		}
	}
	if other == "" {
		w.mu.Unlock()
		return // only one resolver configured: nothing to compare against
	}
	w.inFlight = true
	w.lastRun = now
	w.checked[name] = now
	for k, t := range w.checked {
		if now.Sub(t) > dnsXNamesTTL {
			delete(w.checked, k)
		}
	}
	w.mu.Unlock()
	qCopy := append([]byte(nil), q...)
	respCopy := append([]byte(nil), resp...)
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		second, err := w.ask(other, qCopy)
		w.mu.Lock()
		defer w.mu.Unlock()
		w.inFlight = false
		if err != nil {
			w.Failed++
			return
		}
		w.compare(client, name, fromURL, other, respCopy, second, w.now())
	}()
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

// compare is the pure decision: given the two answers, what, if anything, is worth saying. Called with the lock held.
func (w *dnsXWatch) compare(client, name, first, second string, a, b []byte, now time.Time) {
	ra, rb := rcodeOf(a), rcodeOf(b)
	ipa, ipb := aRecordIPs(a), aRecordIPs(b)
	var kind string
	switch {
	case (ra == 0 && len(ipa) > 0) != (rb == 0 && len(ipb) > 0):
		if ra == 3 || rb == 3 {
			kind = "dns_xcheck_exists" // one says the name exists, the other says it does not
		} else {
			w.Failed++ // SERVFAIL or an empty NOERROR on one side: a resolver hiccup, nothing to say
			return
		}
	case len(ipa) == 0 && len(ipb) == 0:
		w.Agree++
		return
	default:
		ua, ub := false, false
		for _, ip := range ipa {
			ua = ua || unroutable(ip)
		}
		for _, ip := range ipb {
			ub = ub || unroutable(ip)
		}
		if ua != ub {
			kind = "dns_xcheck_bogon" // one of them hands back an address nothing public should resolve to
			break
		}
		overlap := false
		for _, x := range ipa {
			for _, y := range ipb {
				if x.Equal(y) {
					overlap = true
				}
			}
		}
		if overlap {
			w.Agree++
		} else {
			w.Differ++
		}
		return
	}
	w.Flagged++
	if t, had := w.lastName[name]; had && now.Sub(t) < time.Hour {
		return
	}
	w.lastName[name] = now
	for k, t := range w.lastName {
		if now.Sub(t) > 2*time.Hour {
			delete(w.lastName, k)
		}
	}
	mac := w.macOf(client)
	f := dnsXFinding{T: now.Unix(), Kind: kind, MAC: mac, Client: client, Name: name, First: hostOf(first), Second: hostOf(second), Answer1: ipStrings(ipa), Answer2: ipStrings(ipb)}
	if ra == 3 {
		f.Answer1 = []string{"NXDOMAIN"}
	}
	if rb == 3 {
		f.Answer2 = []string{"NXDOMAIN"}
	}
	w.finds = append(w.finds, f)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := w.label(client, mac)
	switch kind {
	case "dns_xcheck_exists":
		w.emit(evt{T: f.T, Kind: kind, Sev: sevAttention, Text: fmt.Sprintf("%s was answered for %s by %s, but %s says that name does not exist: a resolver returning an answer for a name that does not exist is what poisoning looks like, though a name mid-registration or mid-takedown also does this.", who, name, f.First, f.Second),
			Public: "Two DNS resolvers disagreed about whether a name exists"})
	case "dns_xcheck_bogon":
		w.emit(evt{T: f.T, Kind: kind, Sev: sevAttention, Text: fmt.Sprintf("%s was answered for %s with a private or unroutable address by one resolver (%s: %s) and a public one by the other (%s: %s): no public name should resolve to an address like that.", who, name, f.First, strings.Join(f.Answer1, " "), f.Second, strings.Join(f.Answer2, " ")),
			Public: "Two DNS resolvers disagreed about a name's address in a suspicious way"})
	}
}

// hostOf shortens a DoH URL to its host for the page.
func hostOf(url string) string {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

type dnsXView struct {
	Agree    uint64        `json:"agree"`
	Differ   uint64        `json:"differ"`
	Flagged  uint64        `json:"flagged"`
	Failed   uint64        `json:"failed"`
	Sampled  uint64        `json:"sampled"`
	Findings []dnsXFinding `json:"findings"`
}

func (w *dnsXWatch) View() dnsXView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := dnsXView{Agree: w.Agree, Differ: w.Differ, Flagged: w.Flagged, Failed: w.Failed, Sampled: w.Agree + w.Differ + w.Flagged + w.Failed, Findings: []dnsXFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var dnsXMgr *dnsXWatch
