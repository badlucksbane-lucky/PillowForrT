package main

// The onion door (design: ONION-SERVICE.md): a Tor onion service on the box that lets a few keyed devices reach the web page (read-only) from anywhere, with no open port. It is off until it is
// switched on over SSH with `tinyfwd -onion ...` (onionCLI below); the web page has no setting for it and no API to change it. There is no SSH through
// it (no SSH logins over the door). Three locks: (1) v3 client authorization, so a visitor without a listed key cannot even find the service; (2) the web login; (3) a read-only
// web page unless remote_write is on.
// This file is the pure part (validation, torrc lines, the authorized_clients directory) and the manager's settings methods. Everything fails closed: with no authorized client the service is
// NOT rendered at all (Tor treats an empty client list as "open to anyone with the address").

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

const (
	onionWebTarget  = "127.0.0.1:3130" // tinyfwd's loopback web listener for onion visitors (read-only by default)
	onionMaxClients = 8
)

var (
	onionNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)
	onionPubRe  = regexp.MustCompile(`^[A-Z2-7]{52}$`)
	onionAddrRe = regexp.MustCompile(`^[a-z2-7]{56}$`)
	onionB32    = base32.StdEncoding.WithPadding(base32.NoPadding)
)

type onionClient struct {
	Name string `json:"name"`
	Pub  string `json:"pub"` // the x25519 PUBLIC key, 52 base32 characters; the private half never reaches the box
}

type onionDoor struct {
	Enabled     bool          `json:"enabled"`      // port 80 of the service -> the loopback web listener (the only service)
	RemoteWrite bool          `json:"remote_write"` // the web page may change things over the onion (default: read-only)
	Clients     []onionClient `json:"clients"`
}

// onionPubOK: 52 base32 characters that decode to exactly 32 bytes with zero padding bits, and not the all-zero key.
func onionPubOK(s string) bool {
	if !onionPubRe.MatchString(s) {
		return false
	}
	raw, err := onionB32.DecodeString(s)
	if err != nil || len(raw) != 32 || onionB32.EncodeToString(raw) != s {
		return false
	}
	for _, b := range raw {
		if b != 0 {
			return true
		}
	}
	return false
}

// onionFingerprint is a short, safe-to-show digest of a public key (the page lists clients by it).
func onionFingerprint(pub string) string {
	raw, err := onionB32.DecodeString(pub)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:4])
}

// active says whether the service may be published at all: switched on and at least one authorized client (fail closed).
func (d onionDoor) active() bool { return d.Enabled && len(d.Clients) > 0 }

// onionTorrcLines renders the HiddenService lines, or nothing when the door is not active.
func onionTorrcLines(d onionDoor, dir string) []string {
	if !d.active() {
		return nil
	}
	return []string{"HiddenServiceDir " + dir, "HiddenServiceVersion 3", "HiddenServicePort 80 " + onionWebTarget, "HiddenServiceEnableIntroDoSDefense 1", "HiddenServiceMaxStreams 20", "HiddenServiceMaxStreamsCloseCircuit 1", "HiddenServiceNumIntroductionPoints 3"}
}

// withClient / withoutClient return a validated copy of the client list.
func withClient(cs []onionClient, name, pub string) ([]onionClient, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	pub = strings.ToUpper(strings.TrimSpace(pub))
	if !onionNameRe.MatchString(name) {
		return nil, errors.New("the name must be 1 to 24 characters: lower-case letters, digits and dashes, starting with a letter or digit")
	}
	if !onionPubOK(pub) {
		return nil, errors.New("that is not a public key: it must be 52 letters and digits (A-Z, 2-7), the PUBLIC half only")
	}
	for _, c := range cs {
		if c.Name == name {
			return nil, errors.New("a device with that name is already listed")
		}
		if c.Pub == pub {
			return nil, errors.New("that key is already listed (as " + c.Name + ")")
		}
	}
	if len(cs) >= onionMaxClients {
		return nil, fmt.Errorf("too many devices (%d is the limit)", onionMaxClients)
	}
	out := append(append([]onionClient(nil), cs...), onionClient{Name: name, Pub: pub})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func withoutClient(cs []onionClient, name string) ([]onionClient, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	var out []onionClient
	found := false
	for _, c := range cs {
		if c.Name == name {
			found = true
			continue
		}
		out = append(out, c)
	}
	return out, found
}

// syncOnionDir makes <dir>/authorized_clients hold exactly one <name>.auth file per client ("descriptor:x25519:<public key>"), the directories 0700 and, when run as root, owned by
// Tor's user (a running Tor re-reads them on SIGHUP). The service's identity key (hs_ed25519_secret_key) in <dir> is never touched here.
func syncOnionDir(dir string, d onionDoor, owner int) error {
	ac := filepath.Join(dir, "authorized_clients")
	if err := os.MkdirAll(ac, 0o700); err != nil {
		return err
	}
	for _, p := range []string{filepath.Dir(dir), dir, ac} {
		os.Chmod(p, 0o700)
	}
	want := map[string]string{}
	for _, c := range d.Clients {
		want[c.Name+".auth"] = "descriptor:x25519:" + c.Pub + "\n"
	}
	if entries, err := os.ReadDir(ac); err == nil {
		for _, e := range entries {
			if _, ok := want[e.Name()]; !ok {
				os.Remove(filepath.Join(ac, e.Name()))
			}
		}
	}
	for name, body := range want {
		if err := writeFileAtomic(filepath.Join(ac, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	if owner >= 0 {
		filepath.WalkDir(filepath.Dir(dir), func(p string, _ os.DirEntry, err error) error {
			if err == nil {
				os.Lchown(p, owner, owner)
			}
			return nil
		})
	}
	return nil
}

// readOnionAddress returns the service's address (without ".onion") once Tor has made it, or "".
func readOnionAddress(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "hostname"))
	if err != nil {
		return ""
	}
	a := strings.TrimSuffix(strings.TrimSpace(string(b)), ".onion")
	if !onionAddrRe.MatchString(a) {
		return ""
	}
	return a
}

// ---- the manager's side ----

func (m *torMgr) onionDir() string { return filepath.Join(m.dataDir, "onion", "admin") }

// renderTorrc is the one place the torrc is built (Tor's own lines plus the door's when it is active). The caller holds m.mu.
func (m *torMgr) renderTorrc() string {
	return torrcFor(m.dataDir, m.logPath, append(onionTorrcLines(m.cfg.Door, m.onionDir()), torVPNTorrcLines(m.cfg.OverVPN, m.proxyKey)...)...)
}

func torOwner() int {
	if os.Geteuid() == 0 {
		return 65534
	}
	return -1
}

// applyDoorLocked brings the directory, the SSH flag and (if Tor runs) the running Tor in line with the settings. The caller holds m.mu.
func (m *torMgr) applyDoorLocked() error {
	d := m.cfg.Door
	if err := syncOnionDir(m.onionDir(), d, torOwner()); err != nil {
		return err
	}
	if m.running() {
		if err := os.WriteFile(m.torrc, []byte(m.renderTorrc()), 0o600); err != nil {
			return err
		}
		if torOwner() >= 0 {
			os.Chmod(m.torrc, 0o644)
		}
		m.cmd.Process.Signal(syscall.SIGHUP) // Tor re-reads the torrc and the authorized_clients directory
	}
	return nil
}

type onionClientView struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

type onionView struct {
	Enabled     bool              `json:"enabled"`
	RemoteWrite bool              `json:"remote_write"`
	Active      bool              `json:"active"`            // Tor is told to publish the service
	Address     string            `json:"address,omitempty"` // shown on the logged-in page only; treat as private
	Clients     []onionClientView `json:"clients"`
	Note        string            `json:"note,omitempty"`
}

func (m *torMgr) DoorView() onionView {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.cfg.Door
	v := onionView{Enabled: d.Enabled, RemoteWrite: d.RemoteWrite, Active: d.active(), Clients: []onionClientView{}}
	for _, c := range d.Clients {
		v.Clients = append(v.Clients, onionClientView{Name: c.Name, Fingerprint: onionFingerprint(c.Pub)})
	}
	if v.Active {
		v.Address = readOnionAddress(m.onionDir())
	}
	switch {
	case d.Enabled && len(d.Clients) == 0:
		v.Note = "Switched on, but no device is authorized yet, so nothing is published."
	case v.Active && !m.cfg.Enabled:
		v.Note = "Ready, but Tor itself is switched off: the door is closed until Tor is on."
	}
	return v
}

// DoorSet changes the switches. It refuses to switch the door on without at least one authorized device.
func (m *torMgr) DoorSet(enabled, remoteWrite bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.cfg.Door
	d.Enabled, d.RemoteWrite = enabled, remoteWrite
	if enabled && len(d.Clients) == 0 {
		return errors.New("authorize at least one device first: with none, the service would be open to anyone who has the address")
	}
	m.cfg.Door = d
	m.save()
	return m.applyDoorLocked()
}

func (m *torMgr) DoorAddClient(name, pub string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs, err := withClient(m.cfg.Door.Clients, name, pub)
	if err != nil {
		return err
	}
	m.cfg.Door.Clients = cs
	m.save()
	return m.applyDoorLocked()
}

// DoorRemoveClient removes a device. Removing the last one while the door is on switches the door off (it must never run open).
func (m *torMgr) DoorRemoveClient(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cs, found := withoutClient(m.cfg.Door.Clients, name)
	if !found {
		return errors.New("no device with that name")
	}
	m.cfg.Door.Clients = cs
	if len(cs) == 0 {
		m.cfg.Door.Enabled = false
	}
	m.save()
	return m.applyDoorLocked()
}

// RemoteWrite: may the web page change things for a visitor who arrives through the onion door?
func (m *torMgr) RemoteWrite() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Door.RemoteWrite
}

// DoorEnabled says whether the door is switched on in the settings (the web listener for onion visitors starts only then).
func (m *torMgr) DoorEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Door.Enabled
}

// SetHouseOnion changes the house-wide .onion setting in the settings file and nothing else (no firewall or Tor change): it is for the SSH command, which runs with tinyfwd stopped or about
// to be restarted.
func (m *torMgr) SetHouseOnion(on bool) {
	m.mu.Lock()
	m.cfg.Onion = on
	m.save()
	m.mu.Unlock()
}

// onionCLI is the only way to change the .onion settings: `tinyfwd -onion "door=on,add=laptop:KEY"` over SSH. Nothing in the web page or its API can switch a .onion feature on or off, so a
// logged-in browser, or anyone who got hold of a session, cannot open one. Everything is off until set here. spec is a comma-separated list, done in order:
//
//	status               just show the state
//	house=on|off         .onion names for devices on this network (needs Tor on, from the Tor card)
//	door=on|off          publish the web page over a Tor onion service (needs at least one authorized device)
//	write=on|off         let the web page change things when reached through the door (off by default)
//	add=NAME:PUBKEY      authorize a device by its x25519 public key (52 base32 characters)
//	remove=NAME          remove a device (the last one going switches the door off)
//
// The changes are saved; a running tinyfwd reads them at its next start.
func onionCLI(m *torMgr, spec string) (string, error) {
	onoff := func(v string) (bool, error) {
		switch v {
		case "on":
			return true, nil
		case "off":
			return false, nil
		}
		return false, fmt.Errorf("%q: say on or off", v)
	}
	for _, part := range strings.Split(spec, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		var err error
		switch k {
		case "", "status":
		case "house":
			var b bool
			if b, err = onoff(v); err == nil {
				m.SetHouseOnion(b)
			}
		case "door", "write":
			var b bool
			if b, err = onoff(v); err == nil {
				m.mu.Lock()
				d := m.cfg.Door
				m.mu.Unlock()
				if k == "door" {
					err = m.DoorSet(b, d.RemoteWrite)
				} else {
					err = m.DoorSet(d.Enabled, b)
				}
			}
		case "add":
			name, pub, ok := strings.Cut(v, ":")
			if !ok {
				err = errors.New("add=NAME:PUBKEY")
			} else {
				err = m.DoorAddClient(name, pub)
			}
		case "remove":
			err = m.DoorRemoveClient(v)
		default:
			err = fmt.Errorf("unknown setting %q", k)
		}
		if err != nil {
			return "", err
		}
	}
	v := m.DoorView()
	m.mu.Lock()
	house := m.cfg.Onion
	m.mu.Unlock()
	var b strings.Builder
	yes := func(x bool) string {
		if x {
			return "on"
		}
		return "off"
	}
	fmt.Fprintf(&b, "house-wide .onion: %s\nonion door:        %s\nchanges through it: %s\n", yes(house), yes(v.Enabled), yes(v.RemoteWrite))
	for _, c := range v.Clients {
		fmt.Fprintf(&b, "  device %s  key %s\n", c.Name, c.Fingerprint)
	}
	if v.Address != "" {
		fmt.Fprintf(&b, "address: %s.onion (keep it private)\n", v.Address)
	}
	if v.Note != "" {
		fmt.Fprintln(&b, v.Note)
	}
	b.WriteString("Restart tinyfwd to apply: /etc/init.d/http_proxy stop; sleep 1; /etc/init.d/http_proxy start\n")
	return b.String(), nil
}
