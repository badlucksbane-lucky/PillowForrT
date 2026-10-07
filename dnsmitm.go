package main

// ARP/DNS correlation: on its own, arpwatch.go's arp_gateway finding says a MAC is impersonating the router, and that alone is already an alert. What it cannot show is
// whether the impersonation is actually being USED for anything, as opposed to a one-off glitch or a security researcher's probe. The other half of a real man-in-the-middle
// is DNS: dnsmasq answers every local and DHCP name before a query ever reaches this stub (see dnsproxy.go's own pipeline comment), so a name that DOES reach here and comes
// back from the real upstream pointing at an address INSIDE the LAN is not a coincidence -- there is no feature on this box that ever rewrites a public name to a LAN address.
// That alone (dns_mitm_suspect) is worth attention. If it happens within a short window of arpwatch.go recording a gateway or reserved-address impersonation, the two together
// (dns_mitm_confirmed, sevAlert) are a far stronger signal than either alone: something is both claiming to be the router AND handing back LAN addresses for the internet.
// Nothing is ever sent outward or decrypted; this only reads the plaintext answer already in hand at the end of DNSProxy.Handle.

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// aRecordIPs returns the IPv4 addresses in a DNS response's A records (type 1), walking answers the same bounded way cnameTargets does. A malformed message yields what was
// read rather than nothing, since a partial answer is still worth checking.
func aRecordIPs(m []byte) []net.IP {
	if len(m) < 12 {
		return nil
	}
	qd, an := int(m[4])<<8|int(m[5]), int(m[6])<<8|int(m[7])
	off := 12
	skipName := func(at int) int { // returns the offset just after the (possibly compressed) name, or -1
		for hops := 0; hops < 40 && at < len(m); hops++ {
			l := int(m[at])
			switch {
			case l == 0:
				return at + 1
			case l&0xC0 == 0xC0:
				if at+1 >= len(m) {
					return -1
				}
				return at + 2
			default:
				if at+1+l > len(m) {
					return -1
				}
				at += 1 + l
			}
		}
		return -1
	}
	for i := 0; i < qd; i++ {
		n := skipName(off)
		if n < 0 || n+4 > len(m) {
			return nil
		}
		off = n + 4
	}
	var out []net.IP
	for i := 0; i < an && i < 30; i++ {
		n := skipName(off)
		if n < 0 || n+10 > len(m) {
			return out
		}
		typ, rdlen := int(m[n])<<8|int(m[n+1]), int(m[n+8])<<8|int(m[n+9])
		rd := n + 10
		if rd+rdlen > len(m) {
			return out
		}
		if typ == 1 && rdlen == 4 {
			out = append(out, net.IP(m[rd:rd+4]))
		}
		off = rd + rdlen
	}
	return out
}

type dnsMITMFinding struct {
	T            int64  `json:"t"`
	Client       string `json:"client"`
	MAC          string `json:"mac,omitempty"`
	Name         string `json:"name"`
	LANIP        string `json:"lan_ip"`
	Corroborated bool   `json:"corroborated"` // a recent ARP impersonation finding coincided with this one
}

type dnsMITMWatch struct {
	mu        sync.Mutex
	lastEv    map[string]time.Time
	finds     []dnsMITMFinding
	now       func() time.Time
	emit      func(evt)
	macOf     func(client string) string
	nameOf    func(mac string) string
	recentARP func(now time.Time) bool
}

func newDNSMITMWatch() *dnsMITMWatch {
	return &dnsMITMWatch{lastEv: map[string]time.Time{}, now: time.Now,
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
		},
		recentARP: func(now time.Time) bool {
			return arpMgr != nil && arpMgr.RecentImpersonation(10*time.Minute, now)
		}}
}

// Observe is called from DNSProxy.Handle with a resolved (never Tor, never cached-from-Tor) answer: name is the query name, resp the raw DNS message that came back.
func (w *dnsMITMWatch) Observe(client, name string, resp []byte, now time.Time) {
	if client == "" {
		return
	}
	_, lan, _ := net.ParseCIDR(lanCIDR)
	var hit net.IP
	for _, ip := range aRecordIPs(resp) {
		if lan.Contains(ip) {
			hit = ip
			break
		}
	}
	if hit == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.lastEv[client]; ok && now.Sub(t) < 10*time.Minute {
		return
	}
	w.lastEv[client] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	mac := w.macOf(client)
	corroborated := w.recentARP(now)
	w.finds = append(w.finds, dnsMITMFinding{T: now.Unix(), Client: client, MAC: mac, Name: name, LANIP: hit.String(), Corroborated: corroborated})
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := client
	if n := w.nameOf(mac); n != "" {
		who = fmt.Sprintf("%s (%s)", n, client)
	} else if mac != "" {
		who = fmt.Sprintf("%s (%s)", client, mac)
	}
	if corroborated {
		w.emit(evt{T: now.Unix(), Kind: "dns_mitm_confirmed", Sev: sevAlert, Text: fmt.Sprintf("%s asked for %s and got back %s -- a LAN address for a public name, right after the ARP watch saw someone impersonating an address on this network. Together this looks like an active man-in-the-middle, not a glitch.", who, name, hit), Public: "A device's DNS lookup was redirected to an address on this network, alongside a separate sign of address impersonation"})
	} else {
		w.emit(evt{T: now.Unix(), Kind: "dns_mitm_suspect", Sev: sevAttention, Text: fmt.Sprintf("%s asked for %s and got back %s: a public name resolving to an address on this network is not something anything on this box ever does on purpose, so either the upstream answer was tampered with or something odd is happening with that name.", who, name, hit), Public: "A device's DNS lookup for a public name resolved to an address on this network"})
	}
}

type dnsMITMView struct {
	Findings []dnsMITMFinding `json:"findings"`
}

func (w *dnsMITMWatch) View() dnsMITMView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := dnsMITMView{Findings: []dnsMITMFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var dnsMITMMgr *dnsMITMWatch
