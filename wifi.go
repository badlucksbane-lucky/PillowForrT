package main

// Wi-Fi settings, moved here from the stock admin. The stock admin edits /usrdata/data/usr/wlan/wlan_conf_6174.xml and tells `wland` to rebuild hostapd's configuration; we edit the
// same XML (so a reboot keeps it) and make `wland` rebuild by killing it: the supervisor (cpe_daemon) restarts it, it regenerates /tmp/hostapd_wlan0.conf from the XML and starts
// a fresh hostapd (about 3 seconds, tested 2026-10-02; devices rejoin within about 20 s). Every change is backed up first, verified against the regenerated hostapd config, and
// rolled back by itself if the check fails. The password is write-only: it is never returned by the API, logged or shown.

import (
	"bufio"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type wifiEnv struct {
	xmlPath, confPath, backupDir string
	confPath5                    string                     // hostapd's generated config for the 5 GHz radio (wlan1)
	hostapdState5                func() string              // "ENABLED" when the 5 GHz hostapd is up (nil: not checked)
	stations5                    func() string              // `hostapd_cli all_sta` for wlan1 only (nil: none)
	liveInfo5                    func() (channel, freq int) // what the 5 GHz radio is really on
	restart                      func() error               // make wland rebuild and restart hostapd
	hostapdState                 func() string              // "ENABLED" when hostapd is up
	stations                     func() string              // `hostapd_cli all_sta` output
	liveInfo                     func() (channel, freq int) // what the radio is really on
	kick                         func(mac string) error     // deauthenticate one station
	wait                         func(time.Duration)        // sleep (a hook for tests)
}

func hostapdStateOf(iface string) string {
	out, _ := run("hostapd_cli", "-p", "/tmp", "-i", iface, "status")
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "state="); ok {
			return v
		}
	}
	return ""
}

func defaultWifiEnv() *wifiEnv {
	return &wifiEnv{
		xmlPath: *wlanXMLFlag, confPath: "/tmp/hostapd_wlan0.conf", confPath5: "/tmp/hostapd_wlan1.conf", backupDir: filepath.Join(*secureDir, "backups"),
		hostapdState5: func() string { return hostapdStateOf("wlan1") },
		stations5:     func() string { out, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan1", "all_sta"); return out },
		liveInfo5: func() (int, int) {
			out, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan1", "status")
			freq := 0
			for _, l := range strings.Split(out, "\n") {
				if v, ok := strings.CutPrefix(l, "freq="); ok {
					freq, _ = strconv.Atoi(v)
				}
			}
			if freq >= 5180 && freq <= 5885 {
				return (freq - 5000) / 5, freq
			}
			return 0, freq
		},
		restart: func() error {
			out, err := run("sh", "-c", "kill $(pidof wland)")
			if err != nil {
				return fmt.Errorf("could not restart wland: %v %s", err, out)
			}
			return nil
		},
		hostapdState: func() string {
			out, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan0", "status")
			for _, l := range strings.Split(out, "\n") {
				if v, ok := strings.CutPrefix(l, "state="); ok {
					return v
				}
			}
			return ""
		},
		stations: func() string { // both radios: the page, the block list and the DHCP view see every Wi-Fi client
			a, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan0", "all_sta")
			b, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan1", "all_sta")
			return a + "\n" + b
		},
		liveInfo: func() (int, int) {
			out, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan0", "status")
			freq := 0
			for _, l := range strings.Split(out, "\n") {
				if v, ok := strings.CutPrefix(l, "freq="); ok {
					freq, _ = strconv.Atoi(v)
				}
			}
			ch := 0
			if freq >= 2412 && freq <= 2472 {
				ch = (freq - 2407) / 5
			}
			return ch, freq
		},
		kick: func(mac string) error {
			if out, err := run("hostapd_cli", "-p", "/tmp", "-i", "wlan0", "deauthenticate", mac); err != nil {
				return fmt.Errorf("%v %s", err, out)
			}
			return nil
		},
		wait: time.Sleep,
	}
}

// ---- the XML: edited in place, never rebuilt, so every field we do not know about survives byte for byte ----

func sectionRe(section, tag string) *regexp.Regexp {
	return regexp.MustCompile(`(?s)(<` + section + `>.*?<` + tag + `>)([^<]*)(</` + tag + `>.*?</` + section + `>)`)
}

func xmlGet(raw, section, tag string) (string, bool) {
	m := sectionRe(section, tag).FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	return html.UnescapeString(m[2]), true
}

func xmlSet(raw, section, tag, val string) (string, error) {
	re := sectionRe(section, tag)
	if !re.MatchString(raw) {
		return raw, fmt.Errorf("%s/%s not found in the Wi-Fi settings file", section, tag)
	}
	esc := html.EscapeString(val)
	return re.ReplaceAllStringFunc(raw, func(s string) string {
		m := re.FindStringSubmatch(s)
		return m[1] + esc + m[3]
	}), nil
}

// ---- values ----

type wifiSettings struct {
	SSID       string       `json:"ssid"`
	Hidden     bool         `json:"hidden"`
	MaxClients int          `json:"max_clients"`
	Channel    int          `json:"channel"` // 0 = automatic
	APIsolate  bool         `json:"ap_isolate"`
	Country    string       `json:"country"`
	Bandwidth  string       `json:"bandwidth_code"`
	Enabled    bool         `json:"enabled"`
	Five       fiveSettings `json:"five"`
}

// The 5 GHz network (stock Basic_1 / Advance_1). Only fixed channels work on this radio: automatic (0) leaves hostapd stuck in COUNTRY_UPDATE (tested 2026-10-02).
type fiveSettings struct {
	Enabled bool   `json:"enabled"`
	SSID    string `json:"ssid"`
	Hidden  bool   `json:"hidden"`
	Channel int    `json:"channel"`
}

// Only 36 and 149 are real choices. The radio runs 80 MHz channels (VHT80), so each channel is tied to a block: 36 to 48 and 149 to 161. Tested 2026-10-02: hostapd's config
// said 153 but the radio stayed on 149 (5745 MHz); 36 really moved it to 5180 MHz. DFS channels (52 to 144) need a radar wait and are not offered.
var fiveChannels = []int{36, 149}

func validFiveChannel(c int) bool {
	for _, x := range fiveChannels {
		if x == c {
			return true
		}
	}
	return false
}

func parseWifiSettings(raw string) wifiSettings {
	g := func(sec, tag string) string { v, _ := xmlGet(raw, sec, tag); return v }
	n := func(sec, tag string) int { i, _ := strconv.Atoi(g(sec, tag)); return i }
	return wifiSettings{SSID: g("Basic_0", "ssid"), Hidden: g("Basic_0", "broadcast_ssid") == "0", MaxClients: n("Basic_0", "max_client"), Channel: n("Advance_0", "channel"),
		APIsolate: g("Advance_0", "ap_isolate") == "1", Country: g("Advance_0", "country"), Bandwidth: g("Advance_0", "bandwidth"), Enabled: g("Feature", "state") == "1",
		Five: fiveSettings{Enabled: g("Basic_1", "state") == "1", SSID: g("Basic_1", "ssid"), Hidden: g("Basic_1", "broadcast_ssid") == "0", Channel: n("Advance_1", "channel")}}
}

type wifiChange struct {
	SSID            *string     `json:"ssid"`
	Password        *string     `json:"password"`
	PasswordConfirm *string     `json:"password_confirm"` // must equal Password when one is given
	Hidden          *bool       `json:"hidden"`
	MaxClients      *int        `json:"max_clients"`
	Channel         *int        `json:"channel"`
	APIsolate       *bool       `json:"ap_isolate"`
	Five            *fiveChange `json:"five"`
}

type fiveChange struct {
	Enabled         *bool   `json:"enabled"`
	SSID            *string `json:"ssid"`
	Password        *string `json:"password"`
	PasswordConfirm *string `json:"password_confirm"`
	Hidden          *bool   `json:"hidden"`
	Channel         *int    `json:"channel"`
}

func validSSID(s string) error {
	if len(s) < 1 || len(s) > 32 {
		return errors.New("the network name must be 1 to 32 bytes")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("the network name cannot contain control characters")
		}
	}
	return nil
}

func validWPAPassword(p string) error {
	if len(p) < 8 || len(p) > 63 {
		return errors.New("a Wi-Fi password must be 8 to 63 characters")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return errors.New("the Wi-Fi password may only use printable ASCII characters (WPA2 requirement)")
		}
	}
	return nil
}

// apply the requested changes to the XML text; returns the new text and a plain-language list of what changed (never the password)
func applyWifiChange(raw string, c wifiChange) (string, []string, error) {
	var changed []string
	var err error
	cur := parseWifiSettings(raw)
	if c.SSID != nil && *c.SSID != cur.SSID {
		if err := validSSID(*c.SSID); err != nil {
			return raw, nil, err
		}
		if raw, err = xmlSet(raw, "Basic_0", "ssid", *c.SSID); err != nil {
			return raw, nil, err
		}
		changed = append(changed, "network name")
	}
	if c.Password != nil && *c.Password != "" {
		if c.PasswordConfirm == nil || *c.PasswordConfirm != *c.Password {
			return raw, nil, errors.New("the two password boxes differ: type the new password twice, identically")
		}
		if err := validWPAPassword(*c.Password); err != nil {
			return raw, nil, err
		}
		if old, _ := xmlGet(raw, "Basic_0", "psk"); old != *c.Password {
			old5, _ := xmlGet(raw, "Basic_1", "psk")
			if raw, err = xmlSet(raw, "Basic_0", "psk", *c.Password); err != nil {
				return raw, nil, err
			}
			changed = append(changed, "password")
			if old5 == old && (c.Five == nil || c.Five.Password == nil || *c.Five.Password == "") { // the 5 GHz network shared the old password: it keeps sharing the new one
				if raw, err = xmlSet(raw, "Basic_1", "psk", *c.Password); err != nil {
					return raw, nil, err
				}
				changed = append(changed, "5 GHz password (same as 2.4 GHz)")
			}
		}
	}
	if c.Hidden != nil && *c.Hidden != cur.Hidden {
		v := "1"
		if *c.Hidden {
			v = "0"
		}
		if raw, err = xmlSet(raw, "Basic_0", "broadcast_ssid", v); err != nil {
			return raw, nil, err
		}
		changed = append(changed, "hidden network")
	}
	if c.MaxClients != nil && *c.MaxClients != cur.MaxClients {
		if *c.MaxClients < 1 || *c.MaxClients > 10 {
			return raw, nil, errors.New("the client limit must be 1 to 10 (the radio's limit)")
		}
		if raw, err = xmlSet(raw, "Basic_0", "max_client", strconv.Itoa(*c.MaxClients)); err != nil {
			return raw, nil, err
		}
		changed = append(changed, "client limit")
	}
	if c.Channel != nil && *c.Channel != cur.Channel {
		if *c.Channel < 0 || *c.Channel > 11 {
			return raw, nil, errors.New("the channel must be 0 (automatic) or 1 to 11")
		}
		if raw, err = xmlSet(raw, "Advance_0", "channel", strconv.Itoa(*c.Channel)); err != nil {
			return raw, nil, err
		}
		changed = append(changed, "channel")
	}
	if c.APIsolate != nil && *c.APIsolate != cur.APIsolate {
		v := "0"
		if *c.APIsolate {
			v = "1"
		}
		if raw, err = xmlSet(raw, "Advance_0", "ap_isolate", v); err != nil {
			return raw, nil, err
		}
		changed = append(changed, "device isolation")
	}
	if c.Five != nil {
		var ch5 []string
		if raw, ch5, err = applyFiveChange(raw, *c.Five); err != nil {
			return raw, nil, err
		}
		changed = append(changed, ch5...)
	}
	return raw, changed, nil
}

func applyFiveChange(raw string, f fiveChange) (string, []string, error) {
	var changed []string
	var err error
	cur := parseWifiSettings(raw)
	want := cur.Five
	if f.Enabled != nil {
		want.Enabled = *f.Enabled
	}
	if f.SSID != nil {
		want.SSID = *f.SSID
	}
	if f.Channel != nil {
		want.Channel = *f.Channel
	}
	if want.Enabled {
		if err := validSSID(want.SSID); err != nil {
			return raw, nil, errors.New("5 GHz: " + err.Error())
		}
		if want.SSID == cur.SSID {
			return raw, nil, errors.New("5 GHz: give it a different name from the 2.4 GHz network (two radios with one name confuse phones)")
		}
		if !validFiveChannel(want.Channel) {
			return raw, nil, fmt.Errorf("5 GHz: pick one of the channels %v (automatic does not work on this radio)", fiveChannels)
		}
	}
	set := func(sec, tag, v, what string) error {
		if raw, err = xmlSet(raw, sec, tag, v); err != nil {
			return err
		}
		changed = append(changed, what)
		return nil
	}
	if f.SSID != nil && *f.SSID != cur.Five.SSID {
		if err := validSSID(*f.SSID); err != nil {
			return raw, nil, errors.New("5 GHz: " + err.Error())
		}
		if err := set("Basic_1", "ssid", *f.SSID, "5 GHz network name"); err != nil {
			return raw, nil, err
		}
	}
	if f.Password != nil && *f.Password != "" {
		if f.PasswordConfirm == nil || *f.PasswordConfirm != *f.Password {
			return raw, nil, errors.New("5 GHz: the two password boxes differ: type the new password twice, identically")
		}
		if err := validWPAPassword(*f.Password); err != nil {
			return raw, nil, errors.New("5 GHz: " + err.Error())
		}
		if old, _ := xmlGet(raw, "Basic_1", "psk"); old != *f.Password {
			if err := set("Basic_1", "psk", *f.Password, "5 GHz password"); err != nil {
				return raw, nil, err
			}
		}
	}
	if f.Hidden != nil && *f.Hidden != cur.Five.Hidden {
		v := "1"
		if *f.Hidden {
			v = "0"
		}
		if err := set("Basic_1", "broadcast_ssid", v, "5 GHz hidden network"); err != nil {
			return raw, nil, err
		}
	}
	if f.Channel != nil && *f.Channel != cur.Five.Channel {
		if !validFiveChannel(*f.Channel) {
			return raw, nil, fmt.Errorf("5 GHz: pick one of the channels %v (automatic does not work on this radio)", fiveChannels)
		}
		if err := set("Advance_1", "channel", strconv.Itoa(*f.Channel), "5 GHz channel"); err != nil {
			return raw, nil, err
		}
	}
	if f.Enabled != nil && *f.Enabled != cur.Five.Enabled {
		v, what := "0", "turn the 5 GHz network off"
		if *f.Enabled {
			v, what = "1", "turn the 5 GHz network on"
		}
		if err := set("Basic_1", "state", v, what); err != nil {
			return raw, nil, err
		}
	}
	return raw, changed, nil
}

// ---- hostapd's regenerated config, used to verify a change took ----

func confValue(conf, key string) string {
	for _, l := range strings.Split(conf, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+"="); ok {
			return v
		}
	}
	return ""
}

// matches reports whether hostapd's config reflects the XML (SSID, password, channel, client limit, hidden, isolation).
func confMatches(conf, raw string) bool {
	s := parseWifiSettings(raw)
	psk, _ := xmlGet(raw, "Basic_0", "psk")
	hid := "0"
	if s.Hidden {
		hid = "1"
	}
	iso := "0"
	if s.APIsolate {
		iso = "1"
	}
	return confValue(conf, "ssid") == s.SSID && confValue(conf, "wpa_passphrase") == psk && confValue(conf, "channel") == strconv.Itoa(s.Channel) &&
		confValue(conf, "max_num_sta") == strconv.Itoa(s.MaxClients) && confValue(conf, "ignore_broadcast_ssid") == hid && confValue(conf, "ap_isolate") == iso
}

// matches5 reports whether the 5 GHz hostapd config reflects the XML (only meaningful while the 5 GHz network is enabled).
func matches5(conf, raw string) bool {
	f := parseWifiSettings(raw).Five
	psk, _ := xmlGet(raw, "Basic_1", "psk")
	hid := "0"
	if f.Hidden {
		hid = "1"
	}
	return confValue(conf, "ssid") == f.SSID && confValue(conf, "wpa_passphrase") == psk && confValue(conf, "channel") == strconv.Itoa(f.Channel) && confValue(conf, "ignore_broadcast_ssid") == hid
}

// ---- stations ----

type wifiStation struct {
	MAC        string `json:"mac"`
	Authorized bool   `json:"authorized"`
	Connected  int    `json:"connected_s"`
	Band       string `json:"band,omitempty"` // "5 GHz" for the 5 GHz radio
	IP         string `json:"ip,omitempty"`
	Name       string `json:"name,omitempty"`
}

func countAuthorized(out string) int {
	n := 0
	for _, s := range parseStations(out) {
		if s.Authorized {
			n++
		}
	}
	return n
}

func parseStations(out string) []wifiStation {
	var res []wifiStation
	var cur *wifiStation
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if len(l) == 17 && strings.Count(l, ":") == 5 {
			res = append(res, wifiStation{MAC: strings.ToLower(l)})
			cur = &res[len(res)-1]
			continue
		}
		if strings.HasPrefix(l, "flags=") && cur != nil {
			cur.Authorized = strings.Contains(l, "[AUTHORIZED]")
		}
		if v, ok := strings.CutPrefix(l, "connected_time="); ok && cur != nil {
			cur.Connected, _ = strconv.Atoi(v)
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].MAC < res[j].MAC })
	return res
}

// ---- the manager ----

type wifiManager struct {
	mu       sync.Mutex
	env      *wifiEnv
	state    string // idle | applying | waiting | ok | failed
	message  string
	at       time.Time
	last     time.Time
	deadline time.Time     // while waiting: when the old settings come back by themselves
	window   time.Duration // how long a device has to rejoin after a change (default 5 minutes)
}

type wifiView struct {
	Settings  wifiSettings  `json:"settings"`
	State     string        `json:"state"`
	Message   string        `json:"message,omitempty"`
	Live      wifiLive      `json:"live"`
	Live5     *wifiLive     `json:"live5,omitempty"`
	Clients   []wifiStation `json:"clients"`
	Backups   []string      `json:"backups"`
	WaitLeftS int           `json:"wait_left_s,omitempty"` // while waiting for a device to rejoin: seconds until the automatic revert
}
type wifiLive struct {
	Hostapd string `json:"hostapd"`
	Channel int    `json:"channel"`
	FreqMHz int    `json:"freq_mhz"`
}

func newWifiManager(env *wifiEnv) *wifiManager {
	return &wifiManager{env: env, state: "idle", window: 5 * time.Minute}
}

func (m *wifiManager) backups() []string {
	es, _ := os.ReadDir(m.env.backupDir)
	var names []string
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "wlan_conf-") && strings.HasSuffix(e.Name(), ".xml") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(e.Name(), "wlan_conf-"), ".xml"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names
}

func (m *wifiManager) View(names map[string]string, ipOf map[string]string) (wifiView, error) {
	raw, err := os.ReadFile(m.env.xmlPath)
	if err != nil {
		return wifiView{}, err
	}
	ch, freq := m.env.liveInfo()
	st := parseStations(m.env.stations())
	for i := range st {
		st[i].IP = ipOf[st[i].MAC]
		st[i].Name = names[st[i].IP]
	}
	on5 := map[string]bool{}
	if m.env.stations5 != nil {
		for _, c := range parseStations(m.env.stations5()) {
			on5[c.MAC] = true
		}
	}
	for i := range st {
		if on5[st[i].MAC] {
			st[i].Band = "5 GHz"
		}
	}
	var live5 *wifiLive
	if m.env.hostapdState5 != nil {
		c5, f5 := 0, 0
		if m.env.liveInfo5 != nil {
			c5, f5 = m.env.liveInfo5()
		}
		live5 = &wifiLive{m.env.hostapdState5(), c5, f5}
	}
	m.mu.Lock()
	state, msg, dl := m.state, m.message, m.deadline
	m.mu.Unlock()
	left := 0
	if state == "waiting" {
		left = int(time.Until(dl).Seconds())
		if left < 0 {
			left = 0
		}
	}
	return wifiView{WaitLeftS: left, Settings: parseWifiSettings(string(raw)), State: state, Message: msg, Live: wifiLive{m.env.hostapdState(), ch, freq}, Live5: live5, Clients: st, Backups: m.backups()}, nil
}

func (m *wifiManager) backup(raw []byte) (string, error) {
	if err := os.MkdirAll(m.env.backupDir, 0o700); err != nil {
		return "", err
	}
	stamp := time.Now().Format("20060102-150405")
	if err := os.WriteFile(filepath.Join(m.env.backupDir, "wlan_conf-"+stamp+".xml"), raw, 0o600); err != nil {
		return "", err
	}
	for i, n := range m.backups() { // keep the latest 8
		if i >= 8 {
			os.Remove(filepath.Join(m.env.backupDir, "wlan_conf-"+n+".xml"))
		}
	}
	return stamp, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *wifiManager) setState(state, msg string) {
	m.mu.Lock()
	m.state, m.message, m.at = state, msg, time.Now()
	m.mu.Unlock()
}

// Apply validates and starts the change; the slow part (the restart and the check) runs in the background and reports through View().
func (m *wifiManager) Apply(c wifiChange) (string, error) {
	m.mu.Lock()
	if m.state == "applying" || m.state == "waiting" {
		m.mu.Unlock()
		return "", errors.New("a Wi-Fi change is still being applied or confirmed: wait for it to finish")
	}
	if time.Since(m.last) < 30*time.Second && !m.last.IsZero() {
		m.mu.Unlock()
		return "", errors.New("wait 30 seconds between Wi-Fi changes")
	}
	m.mu.Unlock()
	raw, err := os.ReadFile(m.env.xmlPath)
	if err != nil {
		return "", err
	}
	next, changed, err := applyWifiChange(string(raw), c)
	if err != nil {
		return "", err
	}
	if len(changed) == 0 {
		return "nothing to change", nil
	}
	m.mu.Lock()
	m.state, m.message, m.last = "applying", "restarting Wi-Fi: "+strings.Join(changed, ", "), time.Now()
	m.mu.Unlock()
	go m.run(raw, next, changed)
	return "applying: " + strings.Join(changed, ", "), nil
}

func (m *wifiManager) run(old []byte, next string, changed []string) {
	before := countAuthorized(m.env.stations()) // how many devices are connected now
	if _, err := m.backup(old); err != nil {
		m.setState("failed", "could not save a backup, nothing was changed: "+err.Error())
		return
	}
	if err := writeFileAtomic(m.env.xmlPath, []byte(next), 0o755); err != nil {
		m.setState("failed", "could not write the settings: "+err.Error())
		return
	}
	if err := m.restartAndCheck(next); err != nil {
		// roll back: the old file, a second restart
		writeFileAtomic(m.env.xmlPath, old, 0o755)
		rerr := m.restartAndCheck(string(old))
		msg := "the change did not take (" + err.Error() + "); the previous settings were restored"
		if rerr != nil {
			msg += ", but Wi-Fi did not confirm after the restore: " + rerr.Error()
		}
		m.setState("failed", msg)
		return
	}
	// The radio is up with the new settings, but that does not prove any device can join (a mistyped password never can). If devices were connected before the change,
	// wait for one to rejoin; if none does within the window, put the old settings back by itself. Without this the page that offers "undo" could be unreachable.
	if before > 0 {
		m.mu.Lock()
		m.state, m.deadline = "waiting", time.Now().Add(m.window)
		m.message = "Wi-Fi restarted with: " + strings.Join(changed, ", ") + ". Rejoin one device with the new settings; if none joins by itself the old settings come back automatically"
		m.mu.Unlock()
		end := time.Now().Add(m.window)
		for time.Now().Before(end) {
			if countAuthorized(m.env.stations()) > 0 {
				m.setState("ok", "applied and confirmed (a device joined): "+strings.Join(changed, ", "))
				return
			}
			m.env.wait(5 * time.Second)
		}
		writeFileAtomic(m.env.xmlPath, old, 0o755)
		rerr := m.restartAndCheck(string(old))
		msg := "No device joined within " + m.window.String() + " after the change (" + strings.Join(changed, ", ") + "), so the previous Wi-Fi settings were restored"
		if rerr != nil {
			msg += ", but Wi-Fi did not confirm after the restore: " + rerr.Error()
		}
		m.setState("failed", msg)
		return
	}
	m.setState("ok", "applied: "+strings.Join(changed, ", "))
}

func (m *wifiManager) restartAndCheck(raw string) error {
	if err := m.env.restart(); err != nil {
		return err
	}
	m.env.wait(4 * time.Second)
	for i := 0; i < 20; i++ {
		if m.env.hostapdState() == "ENABLED" {
			conf, _ := os.ReadFile(m.env.confPath)
			if confMatches(string(conf), raw) && m.fiveOK(raw) {
				return nil
			}
		}
		m.env.wait(2 * time.Second)
	}
	return errors.New("hostapd did not come back with the new settings within 45 seconds")
}

// fiveOK: when the 5 GHz network is enabled in `raw`, its hostapd must be up with matching settings; when disabled there is nothing to check.
func (m *wifiManager) fiveOK(raw string) bool {
	if m.env.hostapdState5 == nil || !parseWifiSettings(raw).Five.Enabled {
		return true
	}
	conf, _ := os.ReadFile(m.env.confPath5)
	return m.env.hostapdState5() == "ENABLED" && matches5(string(conf), raw)
}

// Restore puts a saved copy back (the most recent one when stamp is empty).
func (m *wifiManager) Restore(stamp string) (string, error) {
	bs := m.backups()
	if len(bs) == 0 {
		return "", errors.New("there is no backup yet")
	}
	if stamp == "" {
		stamp = bs[0]
	}
	if !regexp.MustCompile(`^\d{8}-\d{6}$`).MatchString(stamp) {
		return "", errors.New("bad backup name")
	}
	old, err := os.ReadFile(filepath.Join(m.env.backupDir, "wlan_conf-"+stamp+".xml"))
	if err != nil {
		return "", errors.New("no such backup")
	}
	cur, err := os.ReadFile(m.env.xmlPath)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	if m.state == "applying" {
		m.mu.Unlock()
		return "", errors.New("a Wi-Fi change is already being applied")
	}
	if m.state == "waiting" { // restoring while waiting is the manual "revert now"
		m.deadline = time.Now()
	}
	m.state, m.message, m.last = "applying", "restoring the Wi-Fi settings saved at "+stamp, time.Now()
	m.mu.Unlock()
	go m.run(cur, string(old), []string{"restored " + stamp})
	return "restoring " + stamp, nil
}

// RestoreXML puts a complete Wi-Fi settings file (from a snapshot) in place through the same backup, verify and auto-revert path as any Wi-Fi change.
func (m *wifiManager) RestoreXML(next, what string) (string, error) {
	cur, err := os.ReadFile(m.env.xmlPath)
	if err != nil {
		return "", err
	}
	if string(cur) == next {
		return "already the same", nil
	}
	m.mu.Lock()
	if m.state == "applying" || m.state == "waiting" {
		m.mu.Unlock()
		return "", errors.New("a Wi-Fi change is still being applied or confirmed: wait for it to finish")
	}
	m.state, m.message, m.last = "applying", "restoring the Wi-Fi settings: "+what, time.Now()
	m.mu.Unlock()
	go m.run(cur, next, []string{what})
	return "restoring: Wi-Fi restarts, every device drops for about 10 seconds", nil
}

func (m *wifiManager) Kick(mac string) error {
	if !regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`).MatchString(strings.ToLower(mac)) {
		return errors.New("not a MAC address")
	}
	return m.env.kick(strings.ToLower(mac))
}
