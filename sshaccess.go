package main

// SSH access page: the authorized keys of dropbear's root login, the host key fingerprint, who may reach the port, and an audit trail read from dropbear's RAM log. The
// login is key-only (ed25519), so the key list is the whole access list. Adding takes a PUBLIC key line only; private keys are never generated or stored here. The standard
// restrictions (no port, agent or X11 forwarding) are always written. The last key can never be removed from this page: that would lock ssh out, and the way back is
// the USB cable (`wifi-recover-usb.sh`).

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const sshStdOptions = "no-port-forwarding,no-agent-forwarding,no-X11-forwarding"

type sshKey struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"`
	LastLogin   int64  `json:"last_login,omitempty"`
	LastFrom    string `json:"last_from,omitempty"`
	Logins      int    `json:"logins"`
	line        string
}

// parseKeyLine reads "[options] ssh-ed25519 BASE64 [comment]" and checks the key blob really is an ed25519 public key.
func parseKeyLine(l string) (sshKey, error) {
	l = strings.TrimSpace(l)
	f := strings.Fields(l)
	var k sshKey
	if len(f) < 2 {
		return k, errors.New("that does not look like a public key line (ssh-ed25519 AAAA... comment)")
	}
	i := 0
	if !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") && !strings.HasPrefix(f[0], "sk-") {
		k.Options, i = f[0], 1 // an options field (ours contain no spaces)
	}
	if len(f) < i+2 {
		return k, errors.New("that does not look like a public key line")
	}
	k.Type = f[i]
	if len(f) > i+2 {
		k.Comment = strings.Join(f[i+2:], " ")
	}
	blob, err := base64.StdEncoding.DecodeString(f[i+1])
	if err != nil {
		return k, errors.New("the key is not valid base64")
	}
	if k.Type != "ssh-ed25519" {
		return k, errors.New("only ssh-ed25519 keys are accepted here (the server's login is ed25519 only)")
	}
	// blob = string "ssh-ed25519" + string(32-byte key)
	if len(blob) != 4+11+4+32 || binary.BigEndian.Uint32(blob[:4]) != 11 || string(blob[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(blob[15:19]) != 32 {
		return k, errors.New("that is not a valid ed25519 public key")
	}
	sum := sha256.Sum256(blob)
	k.Fingerprint = "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
	k.line = l
	return k, nil
}

func parseAuthorizedKeys(text string) []sshKey {
	var keys []sshKey
	for _, l := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if k, err := parseKeyLine(l); err == nil {
			keys = append(keys, k)
		}
	}
	return keys
}

// ---- the audit trail ----

type sshEvent struct {
	Time   int64  `json:"time"`
	Kind   string `json:"kind"` // login | logout | failed | connect
	From   string `json:"from,omitempty"`
	Key    string `json:"key,omitempty"`
	Detail string `json:"detail,omitempty"`
}

var (
	logLineRe = regexp.MustCompile(`^\[(\d+)\] (\w{3} \d{2} \d{2}:\d{2}:\d{2}) (.*)$`)
	logAuthRe = regexp.MustCompile(`^Pubkey auth succeeded for '([^']*)' with ssh-ed25519 key (SHA256:\S+) from (\S+)`)
	logExitRe = regexp.MustCompile(`^Exit \(([^)]*)\) from <([^>]+)>: (.*)$`)
	logFailRe = regexp.MustCompile(`(?i)^(Exit before auth|Bad password|Login attempt for nonexistent user|Pubkey auth failed|Bad pubkey|Max auth tries|Failed|Login (attempt|failed))`)
	logAnyIP  = regexp.MustCompile(`from <?(\d{1,3}(?:\.\d{1,3}){3})`)
)

func sshHost(hp string) string {
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	return hp
}

// parseSSHLog reads dropbear's log. Dropbear writes no year, so the year comes from `now` (rolled back if that puts a line in the future).
func parseSSHLog(text string, now time.Time) []sshEvent {
	var ev []sshEvent
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 256*1024)
	for sc.Scan() {
		m := logLineRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		t, err := time.ParseInLocation("2006 Jan 02 15:04:05", fmt.Sprint(now.Year())+" "+m[2], now.Location())
		if err != nil {
			continue
		}
		if t.After(now.Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		msg := m[3]
		switch {
		case logAuthRe.MatchString(msg):
			a := logAuthRe.FindStringSubmatch(msg)
			ev = append(ev, sshEvent{Time: t.Unix(), Kind: "login", From: sshHost(a[3]), Key: a[2], Detail: a[1]})
		case logExitRe.MatchString(msg):
			a := logExitRe.FindStringSubmatch(msg)
			ev = append(ev, sshEvent{Time: t.Unix(), Kind: "logout", From: sshHost(a[2]), Detail: a[3]})
		case logFailRe.MatchString(msg):
			ip := ""
			if a := logAnyIP.FindStringSubmatch(msg); a != nil {
				ip = a[1]
			}
			ev = append(ev, sshEvent{Time: t.Unix(), Kind: "failed", From: ip, Detail: msg})
		}
	}
	return ev
}

type sshSummary struct {
	Logins   int      `json:"logins"`
	Failed   int      `json:"failed"`
	Sources  []string `json:"sources"` // addresses that logged in
	Failures []string `json:"failure_sources,omitempty"`
}

// sshAnnotate fills each key's last login and count from the events, and summarises the log.
func sshAnnotate(keys []sshKey, ev []sshEvent) sshSummary {
	by := map[string]*sshKey{}
	for i := range keys {
		by[keys[i].Fingerprint] = &keys[i]
	}
	src, fsrc := map[string]bool{}, map[string]bool{}
	var s sshSummary
	for _, e := range ev {
		switch e.Kind {
		case "login":
			s.Logins++
			src[e.From] = true
			if k := by[e.Key]; k != nil {
				k.Logins++
				if e.Time >= k.LastLogin {
					k.LastLogin, k.LastFrom = e.Time, e.From
				}
			}
		case "failed":
			s.Failed++
			if e.From != "" {
				fsrc[e.From] = true
			}
		}
	}
	for a := range src {
		s.Sources = append(s.Sources, a)
	}
	for a := range fsrc {
		s.Failures = append(s.Failures, a)
	}
	sort.Strings(s.Sources)
	sort.Strings(s.Failures)
	return s
}

// sshSources lists the addresses the firewall lets reach port 22, from `iptables -S INPUT`.
func sshSources(rules string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(rules, "\n") {
		if !strings.Contains(l, "--dport 22") || !strings.Contains(l, "-j ACCEPT") {
			continue
		}
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "-s" {
				ip := strings.TrimSuffix(f[i+1], "/32")
				if !seen[ip] {
					seen[ip] = true
					out = append(out, ip)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

type sshView struct {
	Keys        []sshKey   `json:"keys"`
	HostKey     string     `json:"host_fingerprint,omitempty"`
	AllowedFrom []string   `json:"allowed_from"`
	Events      []sshEvent `json:"events"`
	Summary     sshSummary `json:"summary"`
	LogNote     string     `json:"log_note"`
}

type sshManager struct {
	mu      sync.Mutex
	dir     string // dropbear's -D directory
	logPath string
	hostKey func() string
	rules   func() string
	now     func() time.Time
	maxKeys int
}

func defaultSSHManager() *sshManager {
	return &sshManager{dir: *sshDir, logPath: "/var/volatile/dropbear.log", now: time.Now, maxKeys: 8,
		hostKey: func() string {
			out, err := run("/data/proxy/dropbearkey", "-y", "-f", filepath.Join(*sshDir, "host_ed25519"))
			if err != nil {
				return ""
			}
			for _, l := range strings.Split(out, "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Fingerprint: "); ok {
					return v
				}
			}
			return ""
		},
		rules: func() string { out, _ := run("iptables", "-S", "INPUT"); return out }}
}

func (m *sshManager) keysFile() string { return filepath.Join(m.dir, "authorized_keys") }

func (m *sshManager) View() sshView {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := os.ReadFile(m.keysFile())
	keys := parseAuthorizedKeys(string(b))
	lb, _ := os.ReadFile(m.logPath)
	ev := parseSSHLog(string(lb), m.now())
	sum := sshAnnotate(keys, ev)
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Time > ev[j].Time })
	// collapse the endless "logout" noise: keep logins and failures, plus the newest 40 of everything
	var shown []sshEvent
	for _, e := range ev {
		if len(shown) < 60 && (e.Kind != "logout" || len(shown) < 20) {
			shown = append(shown, e)
		}
	}
	v := sshView{Keys: keys, Events: shown, Summary: sum, AllowedFrom: []string{}, LogNote: "kept in RAM: it starts over at every reboot and is trimmed at 256 KB"}
	if m.hostKey != nil {
		v.HostKey = m.hostKey()
	}
	if m.rules != nil {
		if s := sshSources(m.rules()); s != nil {
			v.AllowedFrom = s
		}
	}
	if v.Keys == nil {
		v.Keys = []sshKey{}
	}
	if v.Events == nil {
		v.Events = []sshEvent{}
	}
	return v
}

func (m *sshManager) write(lines []string) error {
	cur, _ := os.ReadFile(m.keysFile())
	if len(cur) > 0 {
		writeFileAtomic(m.keysFile()+".prev", cur, 0o600)
	}
	return writeFileAtomic(m.keysFile(), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// Add accepts one public key line; its options are replaced with the standard restrictions.
func (m *sshManager) Add(line string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if strings.ContainsAny(strings.TrimSpace(line), "\r\n") || len(line) > 2048 {
		return "", errors.New("paste exactly one public key line")
	}
	k, err := parseKeyLine(line)
	if err != nil {
		return "", err
	}
	if strings.Contains(k.Comment, "\x00") || len(k.Comment) > 80 {
		return "", errors.New("the key's comment is too long (80 characters)")
	}
	b, _ := os.ReadFile(m.keysFile())
	cur := parseAuthorizedKeys(string(b))
	for _, c := range cur {
		if c.Fingerprint == k.Fingerprint {
			return "", errors.New("that key is already authorised")
		}
	}
	if len(cur) >= m.maxKeys {
		return "", fmt.Errorf("too many keys (%d is the limit)", m.maxKeys)
	}
	f := strings.Fields(k.line)
	i := 0
	if k.Options != "" {
		i = 1
	}
	entry := sshStdOptions + " ssh-ed25519 " + f[i+1]
	if k.Comment != "" {
		entry += " " + k.Comment
	}
	var lines []string
	for _, c := range cur {
		lines = append(lines, c.line)
	}
	lines = append(lines, entry)
	if err := m.write(lines); err != nil {
		return "", err
	}
	return k.Fingerprint, nil
}

func (m *sshManager) Delete(fp string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := os.ReadFile(m.keysFile())
	cur := parseAuthorizedKeys(string(b))
	var lines []string
	for _, c := range cur {
		if c.Fingerprint != fp {
			lines = append(lines, c.line)
		}
	}
	if len(lines) == len(cur) {
		return errors.New("no such key")
	}
	if len(lines) == 0 {
		return errors.New("that is the only key: removing it would lock ssh out (the way back is the USB cable). Add the new key first, then remove this one")
	}
	return m.write(lines)
}
