package main

// Settings snapshots: one JSON file holding everything this page configures, kept on the Orbic (/data/proxy/secure/snapshots, 0700 dir, 0600 files), downloadable to
// keep a copy off the box (the flash can be wiped by a factory reset or a firmware update), and restorable per section. Sections: wifi (the stock settings XML, both bands),
// pool (DHCP range and lease time), reservations, blocklist, firewall (blocked destinations and schedules; live pauses are not kept), dns (filter mode, per-device modes,
// allow-list). NOT included on purpose: the VPN registration and its private key, the web login, the TLS key, the beat/UI tokens (they are the box's identity, and
// a snapshot you download must not carry them). The Wi-Fi password IS inside the wifi section (the XML holds it), so a downloaded snapshot is secret: the page says so.
// Restoring first saves an automatic "before restore" snapshot; Wi-Fi goes last and through the same verify-and-auto-revert path as any Wi-Fi change.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const snapFormat = "orbic-snapshot-1"

type snapDNS struct {
	Mode    string            `json:"mode"`
	Devices map[string]string `json:"devices,omitempty"`
	Allow   []string          `json:"allow,omitempty"`
	Lists   []string          `json:"lists,omitempty"`  // enabled block lists (0.46.0)
	Custom  []customRule      `json:"custom,omitempty"` // the owner's own rules (0.46.0)
}

type snapshot struct {
	Format   string `json:"format"`
	Created  string `json:"created"`
	Tinyfwd  string `json:"tinyfwd"`
	Label    string `json:"label,omitempty"`
	Sections struct {
		Wifi *struct {
			XML string `json:"xml"`
		} `json:"wifi,omitempty"`
		Pool         *dhcpPool `json:"pool,omitempty"`
		Reservations *struct {
			Text string `json:"text"`
		} `json:"reservations,omitempty"`
		Blocklist   *[]string           `json:"blocklist,omitempty"`
		Firewall    *fwState            `json:"firewall,omitempty"`
		DNS         *snapDNS            `json:"dns,omitempty"`
		DeviceNotes *map[string]devNote `json:"devicenotes,omitempty"`
	} `json:"sections"`
}

var snapSections = []string{"wifi", "pool", "reservations", "blocklist", "firewall", "dns", "devicenotes"}
var snapNameRe = regexp.MustCompile(`^(\d{8}-\d{6}|[a-z]+-\d{8}-\d{6})$`)

type snapStore struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
	// the live managers
	wifi  *wifiManager
	dhcp  *dhcpManager
	pool  *poolManager
	mac   *macFilter
	fw    *fwManager
	dns   func() *Filter
	notes *devNotes
}

func defaultSnapStore() *snapStore {
	return &snapStore{dir: filepath.Join(*secureDir, "snapshots"), now: func() time.Time { return time.Now().In(schedLoc()) }, wifi: wifi, dhcp: dhcpMgr, pool: poolMgr, mac: macMgr, fw: fwMgr, notes: devMgr,
		dns: func() *Filter {
			if dnsProxy != nil {
				return dnsProxy.Filter
			}
			return nil
		}}
}

// capture reads the live settings into a snapshot.
func (s *snapStore) capture(label string) (snapshot, error) {
	var sn snapshot
	sn.Format, sn.Created, sn.Tinyfwd, sn.Label = snapFormat, s.now().Format(time.RFC3339), version, label
	if b, err := os.ReadFile(s.wifi.env.xmlPath); err == nil {
		sn.Sections.Wifi = &struct {
			XML string `json:"xml"`
		}{string(b)}
	}
	if pv, err := s.pool.View(); err == nil {
		p := pv.dhcpPool
		sn.Sections.Pool = &p
	}
	if b, err := os.ReadFile(s.dhcp.path); err == nil {
		sn.Sections.Reservations = &struct {
			Text string `json:"text"`
		}{string(b)}
	}
	bl := append([]string{}, s.mac.List()...) // an empty list is still a section
	sn.Sections.Blocklist = &bl
	fs := s.fw.load()
	fs.Pause = map[string]int64{}
	sn.Sections.Firewall = &fs
	if s.notes != nil {
		n := s.notes.All()
		sn.Sections.DeviceNotes = &n
	}
	if f := s.dns(); f != nil {
		sn.Sections.DNS = &snapDNS{Mode: f.Mode(), Devices: f.DeviceModes(), Allow: f.AllowList(), Lists: f.EnabledLists(), Custom: f.CustomRules()}
	}
	return sn, nil
}

func (s *snapStore) save(sn snapshot, prefix string) (string, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", err
	}
	name := s.now().Format("20060102-150405")
	if prefix != "" {
		name = prefix + "-" + name
	}
	b, _ := json.MarshalIndent(sn, "", " ")
	if err := writeFileAtomic(filepath.Join(s.dir, name+".json"), b, 0o600); err != nil {
		return "", err
	}
	// keep the newest 20 (automatic ones count too)
	names := s.names()
	for len(names) > 20 {
		os.Remove(filepath.Join(s.dir, names[len(names)-1]+".json"))
		names = names[:len(names)-1]
	}
	return name, nil
}

// names lists snapshot names newest first.
func (s *snapStore) names() []string {
	es, _ := os.ReadDir(s.dir)
	var out []string
	for _, e := range es {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok && snapNameRe.MatchString(n) {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return stamp(out[i]) > stamp(out[j]) })
	return out
}

func stamp(name string) string { // sort by the date part whatever the prefix
	if i := strings.LastIndex(name, "-"); i > 8 {
		return name[strings.LastIndex(name[:i], "-")+1:]
	}
	return name
}

type snapInfo struct {
	Name     string   `json:"name"`
	Created  string   `json:"created"`
	Label    string   `json:"label,omitempty"`
	Tinyfwd  string   `json:"tinyfwd,omitempty"`
	Sections []string `json:"sections"`
	SizeB    int      `json:"size_b"`
}

func (s *snapStore) load(name string) (snapshot, int, error) {
	var sn snapshot
	if !snapNameRe.MatchString(name) {
		return sn, 0, errors.New("bad snapshot name")
	}
	b, err := os.ReadFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		return sn, 0, errors.New("no such snapshot")
	}
	if err := json.Unmarshal(b, &sn); err != nil || sn.Format != snapFormat {
		return sn, 0, errors.New("that file is not a snapshot this page wrote")
	}
	return sn, len(b), nil
}

func present(sn snapshot) []string {
	var p []string
	if sn.Sections.Wifi != nil {
		p = append(p, "wifi")
	}
	if sn.Sections.Pool != nil {
		p = append(p, "pool")
	}
	if sn.Sections.Reservations != nil {
		p = append(p, "reservations")
	}
	if sn.Sections.Blocklist != nil {
		p = append(p, "blocklist")
	}
	if sn.Sections.Firewall != nil {
		p = append(p, "firewall")
	}
	if sn.Sections.DNS != nil {
		p = append(p, "dns")
	}
	if sn.Sections.DeviceNotes != nil {
		p = append(p, "devicenotes")
	}
	return p
}

func (s *snapStore) List() []snapInfo {
	out := []snapInfo{}
	for _, n := range s.names() {
		if sn, size, err := s.load(n); err == nil {
			out = append(out, snapInfo{Name: n, Created: sn.Created, Label: sn.Label, Tinyfwd: sn.Tinyfwd, Sections: present(sn), SizeB: size})
		}
	}
	return out
}

func (s *snapStore) Create(label string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	label = strings.TrimSpace(label)
	if len(label) > 60 || strings.ContainsAny(label, "\x00\r\n") {
		return "", errors.New("the label is too long (60 characters)")
	}
	sn, err := s.capture(label)
	if err != nil {
		return "", err
	}
	return s.save(sn, "")
}

func (s *snapStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !snapNameRe.MatchString(name) {
		return errors.New("bad snapshot name")
	}
	if err := os.Remove(filepath.Join(s.dir, name+".json")); err != nil {
		return errors.New("no such snapshot")
	}
	return nil
}

func (s *snapStore) Raw(name string) ([]byte, error) {
	if !snapNameRe.MatchString(name) {
		return nil, errors.New("bad snapshot name")
	}
	b, err := os.ReadFile(filepath.Join(s.dir, name+".json"))
	if err != nil {
		return nil, errors.New("no such snapshot")
	}
	return b, nil
}

// Import stores an uploaded snapshot (a copy downloaded earlier) after checking it is one of ours and that every section in it passes the same validation a restore applies.
func (s *snapStore) Import(raw []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sn snapshot
	if json.Unmarshal(raw, &sn) != nil || sn.Format != snapFormat {
		return "", errors.New("that is not a snapshot file from this page")
	}
	if err := validateSnapshot(sn); err != nil {
		return "", err
	}
	sn.Label = strings.TrimSpace("imported " + sn.Label)
	return s.save(sn, "imported")
}

// validateSnapshot checks every section without applying anything.
func validateSnapshot(sn snapshot) error {
	if len(present(sn)) == 0 {
		return errors.New("the snapshot holds no settings")
	}
	if w := sn.Sections.Wifi; w != nil {
		if err := validateWifiXML(w.XML); err != nil {
			return fmt.Errorf("wifi: %v", err)
		}
	}
	if p := sn.Sections.Pool; p != nil {
		if err := validatePool(*p); err != nil {
			return fmt.Errorf("pool: %v", err)
		}
	}
	if r := sn.Sections.Reservations; r != nil {
		if _, err := checkReservations(parseReservations(r.Text)); err != nil {
			return fmt.Errorf("reservations: %v", err)
		}
	}
	if b := sn.Sections.Blocklist; b != nil {
		if len(*b) > 32 {
			return errors.New("blocklist: too many entries")
		}
		for _, m := range *b {
			if !macRe.MatchString(m) {
				return fmt.Errorf("blocklist: %q is not a MAC address", m)
			}
		}
	}
	if f := sn.Sections.Firewall; f != nil {
		if _, err := cleanFW(*f); err != nil {
			return fmt.Errorf("firewall: %v", err)
		}
	}
	if d := sn.Sections.DNS; d != nil {
		if !validGlobalMode(d.Mode) {
			return errors.New("dns: unknown filter mode")
		}
		for _, n := range d.Lists {
			if _, ok := listKnown(n); !ok {
				return errors.New("dns: unknown list " + n)
			}
		}
		for _, r := range d.Custom {
			if _, err := normalizePattern(r.Pattern); err != nil {
				return errors.New("dns: bad custom rule " + r.Pattern)
			}
		}
	}
	if n := sn.Sections.DeviceNotes; n != nil {
		if err := (&devNotes{path: os.DevNull}).checkAll(*n); err != nil {
			return fmt.Errorf("devicenotes: %v", err)
		}
	}
	return nil
}

func checkReservations(rs []reservation) ([]reservation, error) {
	if len(rs) > 64 {
		return nil, errors.New("too many reservations")
	}
	var ok []reservation
	for _, r := range rs {
		if err := validateReservation(r, ok); err != nil {
			return nil, fmt.Errorf("%s: %v", r.Name, err)
		}
		ok = append(ok, r)
	}
	return ok, nil
}

// cleanFW validates a firewall state taken from a snapshot and drops anything transient.
func cleanFW(in fwState) (fwState, error) {
	out := fwState{Pause: map[string]int64{}, Next: in.Next}
	if len(in.Dest) > 128 || len(in.Sched) > 32 {
		return out, errors.New("too many rules")
	}
	for _, d := range in.Dest {
		c, err := normDest(d.CIDR)
		if err != nil {
			return out, fmt.Errorf("%s: %v", d.CIDR, err)
		}
		out.Dest = append(out.Dest, fwDest{CIDR: c, Note: d.Note})
	}
	seen := map[int]bool{}
	for _, sc := range in.Sched {
		sort.Ints(sc.Days)
		if err := validateSched(sc); err != nil {
			return out, err
		}
		if sc.ID <= 0 || seen[sc.ID] {
			return out, errors.New("schedule numbers must be unique")
		}
		seen[sc.ID] = true
		if sc.ID > out.Next {
			out.Next = sc.ID
		}
		out.Sched = append(out.Sched, sc)
	}
	return out, nil
}

var wifiXMLKeys = [][2]string{{"Basic_0", "ssid"}, {"Basic_0", "psk"}, {"Basic_1", "ssid"}, {"Basic_1", "psk"}, {"Advance_0", "channel"}, {"Advance_1", "channel"}, {"Feature", "state"}}

// validateWifiXML makes sure a Wi-Fi settings file is complete and sane before it can ever be written back.
func validateWifiXML(raw string) error {
	if len(raw) < 200 || len(raw) > 65536 {
		return errors.New("the Wi-Fi settings are the wrong size")
	}
	for _, k := range wifiXMLKeys {
		if _, ok := xmlGet(raw, k[0], k[1]); !ok {
			return fmt.Errorf("the Wi-Fi settings lack %s/%s", k[0], k[1])
		}
	}
	s := parseWifiSettings(raw)
	if err := validSSID(s.SSID); err != nil {
		return err
	}
	psk, _ := xmlGet(raw, "Basic_0", "psk")
	if err := validWPAPassword(psk); err != nil {
		return err
	}
	if s.Five.Enabled {
		psk5, _ := xmlGet(raw, "Basic_1", "psk")
		if err := validWPAPassword(psk5); err != nil {
			return fmt.Errorf("5 GHz: %v", err)
		}
		if !validFiveChannel(s.Five.Channel) || s.Five.SSID == s.SSID {
			return errors.New("the 5 GHz settings are not usable (channel or name)")
		}
	}
	return nil
}

type restoreResult struct {
	Section string `json:"section"`
	Status  string `json:"status,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Restore applies the chosen sections of a snapshot. `self` is the asking device's MAC (the block list restore will not block it).
func (s *snapStore) Restore(name string, sections []string, self string) ([]restoreResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sn, _, err := s.load(name)
	if err != nil {
		return nil, err
	}
	if err := validateSnapshot(sn); err != nil {
		return nil, fmt.Errorf("this snapshot cannot be restored: %v", err)
	}
	want := map[string]bool{}
	for _, x := range sections {
		want[x] = true
	}
	if len(want) == 0 {
		return nil, errors.New("pick at least one section to restore")
	}
	for x := range want {
		ok := false
		for _, k := range snapSections {
			ok = ok || k == x
		}
		if !ok {
			return nil, fmt.Errorf("unknown section %q", x)
		}
	}
	have := map[string]bool{}
	for _, x := range present(sn) {
		have[x] = true
	}
	if auto, err := s.capture("before restoring " + name); err == nil {
		s.save(auto, "auto")
	}
	var res []restoreResult
	do := func(sec string, f func() (string, error)) {
		if !want[sec] {
			return
		}
		if !have[sec] {
			res = append(res, restoreResult{Section: sec, Error: "the snapshot does not hold this section"})
			return
		}
		msg, err := f()
		if err != nil {
			res = append(res, restoreResult{Section: sec, Error: err.Error()})
			return
		}
		res = append(res, restoreResult{Section: sec, Status: msg})
	}
	do("reservations", func() (string, error) {
		rs, _ := checkReservations(parseReservations(sn.Sections.Reservations.Text))
		return "restored", s.dhcp.ReplaceAll(rs)
	})
	do("pool", func() (string, error) {
		msg, err := s.pool.Set(*sn.Sections.Pool)
		if err != nil && err.Error() == "nothing to change" {
			return "already the same", nil
		}
		return trimSentence(msg), err
	})
	do("blocklist", func() (string, error) { return "restored", s.mac.Replace(*sn.Sections.Blocklist, self) })
	do("firewall", func() (string, error) {
		st, _ := cleanFW(*sn.Sections.Firewall)
		return "restored", s.fw.Replace(st)
	})
	do("dns", func() (string, error) { return "restored", s.restoreDNS(*sn.Sections.DNS) })
	do("devicenotes", func() (string, error) {
		if s.notes == nil {
			return "", errors.New("device notes are not available")
		}
		return "restored", s.notes.Replace(*sn.Sections.DeviceNotes)
	})
	do("wifi", func() (string, error) { return s.wifi.RestoreXML(sn.Sections.Wifi.XML, "restored from snapshot "+name) })
	return res, nil
}

func trimSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i]
	}
	return s
}

func (s *snapStore) restoreDNS(d snapDNS) error {
	f := s.dns()
	if f == nil {
		return errors.New("the DNS filter is not running")
	}
	if err := f.SetMode(d.Mode); err != nil {
		return err
	}
	if d.Lists != nil {
		f.SetEnabledLists(d.Lists)
	}
	if d.Custom != nil {
		f.ReplaceCustom(d.Custom)
	}
	for ip := range f.DeviceModes() {
		f.SetDeviceMode(ip, "default")
	}
	for ip, m := range d.Devices {
		if err := f.SetDeviceMode(ip, m); err != nil {
			return err
		}
	}
	for _, n := range f.AllowList() {
		f.AllowRemove(n)
	}
	for _, n := range d.Allow {
		if err := f.AllowAdd(n); err != nil {
			return err
		}
	}
	return nil
}
