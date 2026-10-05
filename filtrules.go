package main

// Your own DNS block rules, with wildcards (0.46.0). A rule is a pattern, optionally for one device and optionally for a limited time.
//   example.com       the name and every subdomain
//   *.example.com     the subdomains only, not example.com itself
//   ads*.example.com  * stands for any run of characters (dots included), anywhere in the name
//   *track*, *.zip    substring and whole-top-level-domain rules
// Anything pasted is first reduced to a host name: scheme, user info, port, path, query and the adblock decorations (||host^) are dropped (DNS can only block a host, never a
// path). Allow-list entries use the same patterns and always win. The Orbic's own lookups (loopback clients) are exempt from custom rules, so a careless pattern cannot cut
// the router off from its list downloads or the Mullvad API.

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxCustomRules = 500

type customRule struct {
	Pattern string `json:"pattern"`
	IP      string `json:"ip,omitempty"` // "" = every device
	Note    string `json:"note,omitempty"`
	Added   int64  `json:"added"`
	Expires int64  `json:"expires,omitempty"` // unix seconds, 0 = never
}

// normalizePattern turns what a person pasted into a rule pattern, or says why it cannot be one.
func normalizePattern(in string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(in))
	s = strings.TrimPrefix(s, "||")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimSuffix(s, "^")
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s[:i], ":") {
		if _, err := time.ParseDuration(s[i+1:] + "s"); err == nil { // :8080
			s = s[:i]
		}
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("nothing to block: type a name such as ads.example.com or *.example.com")
	}
	if net.ParseIP(s) != nil {
		return "", errors.New("that is an address, not a name: DNS rules block names (use Blocked destinations for addresses)")
	}
	lit := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_':
			lit++
		case c == '.' || c == '*':
		case c >= 0x80:
			return "", errors.New("use the punycode form of an international name (xn--...)")
		default:
			return "", errors.New("a name may contain letters, digits, - _ . and * only")
		}
	}
	if len(s) > 253 {
		return "", errors.New("name too long")
	}
	if lit < 3 {
		return "", errors.New("too broad: a rule needs at least 3 letters or digits besides * and dots")
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return "", errors.New("misplaced dot")
	}
	return s, nil
}

// patternMatch applies one pattern to a lower-case name.
func patternMatch(pat, name string) bool {
	if !strings.Contains(pat, "*") {
		return name == pat || strings.HasSuffix(name, "."+pat)
	}
	if strings.HasPrefix(pat, "*.") && !strings.Contains(pat[2:], "*") {
		return strings.HasSuffix(name, pat[1:]) // ".example.com": subdomains only
	}
	return globMatch(pat, name)
}

// globMatch: * matches any run of characters (including none and dots).
func globMatch(p, s string) bool {
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && p[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

type customRules struct {
	mu    sync.RWMutex
	path  string
	rules []customRule
}

func newCustomRules(dir string) *customRules {
	c := &customRules{path: filepath.Join(dir, "custom.json")}
	if b, err := os.ReadFile(c.path); err == nil {
		var rs []customRule
		if json.Unmarshal(b, &rs) == nil {
			for _, r := range rs {
				if p, err := normalizePattern(r.Pattern); err == nil && len(c.rules) < maxCustomRules {
					r.Pattern = p
					c.rules = append(c.rules, r)
				}
			}
		}
	}
	return c
}

func (c *customRules) saveLocked() error {
	b, _ := json.MarshalIndent(c.rules, "", " ")
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Add takes one or several patterns (separated by newlines, spaces or commas). minutes 0 = permanent. It returns how many were added.
func (c *customRules) Add(input, ip, note string, minutes int) (int, error) {
	if ip != "" && net.ParseIP(ip) == nil {
		return 0, errors.New("not a device address")
	}
	if minutes < 0 || minutes > 365*24*60 {
		return 0, errors.New("minutes out of range")
	}
	if len(note) > 80 {
		note = note[:80]
	}
	parts := strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == ' ' || r == ',' || r == '\t' || r == '\r' })
	if len(parts) == 0 {
		return 0, errors.New("nothing to block: type a name such as ads.example.com or *.example.com")
	}
	if len(parts) > 50 {
		return 0, errors.New("at most 50 rules at a time")
	}
	var pats []string
	for _, p := range parts {
		n, err := normalizePattern(p)
		if err != nil {
			return 0, errors.New(p + ": " + err.Error())
		}
		pats = append(pats, n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	added := 0
	for _, p := range pats {
		dup := false
		for _, r := range c.rules {
			if r.Pattern == p && r.IP == ip {
				dup = true
			}
		}
		if dup {
			continue
		}
		if len(c.rules) >= maxCustomRules {
			return added, errors.New("too many rules (500)")
		}
		r := customRule{Pattern: p, IP: ip, Note: note, Added: now}
		if minutes > 0 {
			r.Expires = now + int64(minutes)*60
		}
		c.rules = append(c.rules, r)
		added++
	}
	return added, c.saveLocked()
}

func (c *customRules) Remove(pattern, ip string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.rules[:0]
	for _, r := range c.rules {
		if !(r.Pattern == pattern && r.IP == ip) {
			out = append(out, r)
		}
	}
	c.rules = out
	return c.saveLocked()
}

// List returns the live rules, newest first (expired ones are dropped from disk when seen).
func (c *customRules) List(now time.Time) []customRule {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := c.rules[:0]
	for _, r := range c.rules {
		if r.Expires == 0 || r.Expires > now.Unix() {
			live = append(live, r)
		}
	}
	if len(live) != len(c.rules) {
		c.rules = live
		c.saveLocked()
	}
	out := append([]customRule(nil), c.rules...)
	sort.Slice(out, func(i, j int) bool { return out[i].Added > out[j].Added })
	return out
}

// Match returns the first rule that blocks name for client.
func (c *customRules) Match(client, name string, now time.Time) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.rules {
		if (r.IP == "" || r.IP == client) && (r.Expires == 0 || r.Expires > now.Unix()) && patternMatch(r.Pattern, name) {
			return r.Pattern, true
		}
	}
	return "", false
}

// cnameTargets returns the CNAME targets in a DNS response (a tracker hidden behind an innocent name shows up here). Bounds-checked; a malformed message yields what was read.
func cnameTargets(m []byte) []string {
	if len(m) < 12 {
		return nil
	}
	qd, an := int(m[4])<<8|int(m[5]), int(m[6])<<8|int(m[7])
	off := 12
	readName := func(at int) (string, int) { // returns the name and the offset just after it in the message
		var parts []string
		next, jumped := -1, false
		for hops := 0; hops < 40 && at < len(m); hops++ {
			l := int(m[at])
			switch {
			case l == 0:
				if !jumped {
					next = at + 1
				}
				return strings.ToLower(strings.Join(parts, ".")), next
			case l&0xC0 == 0xC0:
				if at+1 >= len(m) {
					return "", -1
				}
				if !jumped {
					next = at + 2
				}
				jumped = true
				at = (l&0x3F)<<8 | int(m[at+1])
			default:
				if at+1+l > len(m) {
					return "", -1
				}
				parts = append(parts, string(m[at+1:at+1+l]))
				at += 1 + l
			}
		}
		return "", -1
	}
	for i := 0; i < qd; i++ {
		_, n := readName(off)
		if n < 0 || n+4 > len(m) {
			return nil
		}
		off = n + 4
	}
	var out []string
	for i := 0; i < an && i < 30; i++ {
		_, n := readName(off)
		if n < 0 || n+10 > len(m) {
			return out
		}
		typ, rdlen := int(m[n])<<8|int(m[n+1]), int(m[n+8])<<8|int(m[n+9])
		rd := n + 10
		if rd+rdlen > len(m) {
			return out
		}
		if typ == 5 {
			if t, _ := readName(rd); t != "" {
				out = append(out, t)
			}
		}
		off = rd + rdlen
	}
	return out
}
