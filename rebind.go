package main

// DNS rebinding refusal: the enforcement half of dnsmitm.go. That detector notices a public name resolving to an address on this LAN and raises an event, but until now the
// answer still went to the device that asked. A DNS rebinding attack is exactly that answer: a page from an attacker's domain first resolves to their server, then (a short
// TTL later) to 192.168.1.1, 127.0.0.1 or a printer on the LAN, and the browser's same-origin rule now lets that page's script talk to the device as if it were the attacker's
// own host. Nothing on this box ever resolves a public name to a private address on purpose, so such an answer is refused (REFUSED, rcode 5, which a browser treats as a
// failure and caches nothing of) instead of relayed. What counts as private: RFC 1918, loopback, link-local, 0.0.0.0, carrier-grade NAT (100.64/10), the IPv6 equivalents
// (ULA, ::1, fe80::/10, IPv4-mapped forms of the same), and this box's own Tor bridge range 198.18/15, which only the stub itself may hand out (tor.go). An allow-list of
// name patterns (the same `*.example.com` shapes as the filter) exempts the few services that do this legitimately; `*.plex.direct` is in it from the start, since Plex
// resolves such names to a LAN address by design. The guard is on by default, because there is no quiet "watch first" to be had here: a rebinding answer is harmful on
// arrival, and dnsmitm.go still records every one it would have refused, so the card shows what happened either way. Local names never reach the stub (dnsmasq answers
// them first, see dnsproxy.go) and are never affected.

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
)

type rebindState struct {
	Enabled bool     `json:"enabled"`
	Allow   []string `json:"allow"` // name patterns whose private answers are let through
}

type rebindGuard struct {
	mu      sync.Mutex
	path    string
	st      rebindState
	refused uint64
}

var defaultRebindAllow = []string{"*.plex.direct"}

func newRebindGuard(path string) *rebindGuard {
	g := &rebindGuard{path: path, st: rebindState{Enabled: true, Allow: append([]string(nil), defaultRebindAllow...)}}
	if b, err := os.ReadFile(path); err == nil {
		var st rebindState
		if json.Unmarshal(b, &st) == nil {
			g.st = st
			if g.st.Allow == nil {
				g.st.Allow = []string{}
			}
		}
	}
	return g
}

func (g *rebindGuard) save() {
	if g.path == "" {
		return
	}
	b, _ := json.Marshal(g.st)
	writeFileAtomic(g.path, b, 0o600)
}

// privateAnswer says whether ip is one no public name should ever resolve to.
func privateAnswer(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4.IsPrivate(), ip4.IsLoopback(), ip4.IsLinkLocalUnicast(), ip4.IsUnspecified():
			return true
		case ip4[0] == 100 && ip4[1]&0xC0 == 64: // 100.64.0.0/10, carrier-grade NAT: a device could be reached through the carrier's own fabric
			return true
		case ip4[0] == 198 && ip4[1]&0xFE == 18: // 198.18.0.0/15: the Tor bridge range the stub itself hands out, and nothing else may
			return true
		}
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// answerIPs returns every A and AAAA address in a response's answer section, walking it the same bounded way aRecordIPs does.
func answerIPs(m []byte) []net.IP {
	if len(m) < 12 {
		return nil
	}
	qd, an := int(m[4])<<8|int(m[5]), int(m[6])<<8|int(m[7])
	off := 12
	skipName := func(at int) int {
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
		if (typ == 1 && rdlen == 4) || (typ == 28 && rdlen == 16) {
			out = append(out, net.IP(m[rd:rd+rdlen]))
		}
		off = rd + rdlen
	}
	return out
}

// Refuse says whether the answer for name should be withheld: it carries a private address and the name is not allowed to. hit is the offending address.
func (g *rebindGuard) Refuse(name string, resp []byte) (hit net.IP, refuse bool) {
	if g == nil {
		return nil, false
	}
	g.mu.Lock()
	enabled, allow := g.st.Enabled, g.st.Allow
	g.mu.Unlock()
	if !enabled {
		return nil, false
	}
	for _, ip := range answerIPs(resp) {
		if privateAnswer(ip) {
			hit = ip
			break
		}
	}
	if hit == nil {
		return nil, false
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, p := range allow {
		if matchWild(p, n) {
			return hit, false
		}
	}
	g.mu.Lock()
	g.refused++
	g.mu.Unlock()
	return hit, true
}

// matchWild matches the filter's wildcard shapes: a plain name matches itself and its subdomains; `*` matches any run of characters (`*.example.com`, `ads*.example.com`, `*track*`).
func matchWild(pattern, name string) bool {
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	if p == "" {
		return false
	}
	if !strings.Contains(p, "*") {
		return name == p || strings.HasSuffix(name, "."+p)
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	rest := name[len(parts[0]):]
	for i, part := range parts[1:] {
		if i == len(parts)-2 { // the last piece must end the name
			return strings.HasSuffix(rest, part)
		}
		at := strings.Index(rest, part)
		if at < 0 {
			return false
		}
		rest = rest[at+len(part):]
	}
	return true
}

type rebindView struct {
	Enabled bool     `json:"enabled"`
	Allow   []string `json:"allow"`
	Refused uint64   `json:"refused"` // since the daemon started
}

func (g *rebindGuard) View() rebindView {
	if g == nil {
		return rebindView{Allow: []string{}}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return rebindView{Enabled: g.st.Enabled, Allow: append([]string{}, g.st.Allow...), Refused: g.refused}
}

func (g *rebindGuard) SetEnabled(on bool) {
	g.mu.Lock()
	g.st.Enabled = on
	g.save()
	g.mu.Unlock()
}

func validAllowPattern(p string) error {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" || len(p) > 253 {
		return errors.New("give a name or pattern like *.example.com")
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '*' || c == '_') {
			return errors.New("a pattern may hold letters, digits, dots, dashes and *")
		}
	}
	if !strings.Contains(strings.Trim(p, "*."), ".") {
		return errors.New("a pattern needs at least one dot, like *.example.com; a bare * would allow every name")
	}
	return nil
}

// Allow adds (add) or removes a pattern.
func (g *rebindGuard) Allow(pattern string, add bool) error {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if add {
		if err := validAllowPattern(p); err != nil {
			return err
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var keep []string
	for _, x := range g.st.Allow {
		if x != p {
			keep = append(keep, x)
		}
	}
	if add {
		if len(keep) >= 50 {
			return errors.New("at most 50 patterns")
		}
		keep = append(keep, p)
	}
	if keep == nil {
		keep = []string{}
	}
	g.st.Allow = keep
	g.save()
	return nil
}

var rebindMgr *rebindGuard
