package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// the shape of the real file: one line, with sections the page never touches
const wlanSample = `<?xml version="1.0" encoding="UTF-8"?><wlan><Feature><state>1</state><work_mode>3</work_mode></Feature><Basic_0><state>1</state><ssid>ExampleNet</ssid><security>3</security><psk>old-secret-pass</psk><encrypt>2</encrypt><broadcast_ssid>1</broadcast_ssid><max_client>10</max_client></Basic_0><Advance_0><country>US</country><wifi80211mode>4</wifi80211mode><band>0</band><bandwidth>2</bandwidth><channel>0</channel><channel_list>1-11</channel_list><wifiofftime>0</wifiofftime><ap_isolate>0</ap_isolate><ap_wmm>1</ap_wmm></Advance_0><WPS_0><wps_enable>0</wps_enable><wps_default_ap_pin>12345670</wps_default_ap_pin></WPS_0><Basic_1><state>0</state><ssid>ExampleNet</ssid><psk>old-secret-pass</psk><broadcast_ssid>1</broadcast_ssid><max_client>10</max_client></Basic_1><Advance_1><channel>0</channel><ap_isolate>0</ap_isolate></Advance_1></wlan>`

func sp[T any](v T) *T { return &v }

func TestXMLGetSet(t *testing.T) {
	if v, _ := xmlGet(wlanSample, "Basic_0", "ssid"); v != "ExampleNet" {
		t.Errorf("ssid %q", v)
	}
	// the second SSID has the same tag names: a change to section 0 must not touch section 1
	n, err := xmlSet(wlanSample, "Basic_0", "ssid", "Moon & Stars <1>")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := xmlGet(n, "Basic_0", "ssid"); v != "Moon & Stars <1>" {
		t.Errorf("round trip %q", v)
	}
	if v, _ := xmlGet(n, "Basic_1", "ssid"); v != "ExampleNet" {
		t.Error("section 1 was changed")
	}
	if !strings.Contains(n, "&amp;") || strings.Contains(n, "<1>") {
		t.Error("the value was not XML-escaped")
	}
	if strings.Replace(n, "Moon &amp; Stars &lt;1&gt;", "ExampleNet", 1) != wlanSample {
		t.Error("something other than the SSID changed")
	}
	if _, err := xmlSet(wlanSample, "Basic_9", "ssid", "x"); err == nil {
		t.Error("a missing section was not reported")
	}
	s := parseWifiSettings(wlanSample)
	if s.SSID != "ExampleNet" || s.Hidden || s.MaxClients != 10 || s.Channel != 0 || s.APIsolate || s.Country != "US" || !s.Enabled {
		t.Errorf("%+v", s)
	}
}

func TestApplyWifiChange(t *testing.T) {
	n, ch, err := applyWifiChange(wlanSample, wifiChange{SSID: sp("ExampleNet"), Password: sp(""), Hidden: sp(false), Channel: sp(0)})
	if err != nil || len(ch) != 0 || n != wlanSample {
		t.Errorf("no-op: %v %v", ch, err)
	}
	n, ch, err = applyWifiChange(wlanSample, wifiChange{SSID: sp("Example"), Password: sp("a-better-password"), PasswordConfirm: sp("a-better-password"), Hidden: sp(true), MaxClients: sp(6), Channel: sp(6), APIsolate: sp(true)})
	if err != nil || len(ch) != 7 { // 6, plus the 5 GHz password that shared the old one and follows it
		t.Fatalf("%v %v", ch, err)
	}
	if v, _ := xmlGet(n, "Basic_1", "psk"); v != "a-better-password" {
		t.Error("the 5 GHz password did not follow the 2.4 GHz one")
	}
	s := parseWifiSettings(n)
	if s.SSID != "Example" || !s.Hidden || s.MaxClients != 6 || s.Channel != 6 || !s.APIsolate {
		t.Errorf("%+v", s)
	}
	if v, _ := xmlGet(n, "Basic_0", "psk"); v != "a-better-password" {
		t.Error("password not set")
	}
	if strings.Contains(strings.Join(ch, " "), "better") {
		t.Error("the password appears in the list of changes")
	}
	for _, bad := range []wifiChange{
		{Password: sp("a-valid-password")}, {Password: sp("a-valid-password"), PasswordConfirm: sp("a-valid-passw0rd")}, {SSID: sp("")}, {SSID: sp(strings.Repeat("x", 33))}, {SSID: sp("bad\x01name")}, {Password: sp("short")}, {Password: sp(strings.Repeat("p", 64))}, {Password: sp("café-password")},
		{MaxClients: sp(0)}, {MaxClients: sp(11)}, {Channel: sp(12)}, {Channel: sp(-1)},
	} {
		if _, _, err := applyWifiChange(wlanSample, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestStations(t *testing.T) {
	out := "00:00:5e:00:53:06\nflags=[AUTH][ASSOC][AUTHORIZED]\nconnected_time=1788\nrx_bytes=0\n00:00:5e:00:53:07\nflags=x\nconnected_time=60\n"
	st := parseStations(out)
	if len(st) != 2 || st[0].MAC != "00:00:5e:00:53:06" || st[0].Connected != 1788 || st[1].MAC != "00:00:5e:00:53:07" || st[1].Connected != 60 {
		t.Errorf("%+v", st)
	}
}

// a fake wland: "restarting" regenerates the hostapd config from the XML, like the real one (and can be told to misbehave)
type fakeRadio struct {
	env         *wifiEnv
	restarts    int
	breakNew    bool // regenerate WITHOUT applying the new settings (to test the rollback)
	down        bool
	stationsOut string // what `hostapd_cli all_sta` says
}

func newFakeRadio(t *testing.T) *fakeRadio {
	dir := t.TempDir()
	f := &fakeRadio{}
	f.env = &wifiEnv{xmlPath: filepath.Join(dir, "wlan.xml"), confPath: filepath.Join(dir, "hostapd.conf"), backupDir: filepath.Join(dir, "backups"),
		wait: func(time.Duration) {}, hostapdState: func() string {
			if f.down {
				return ""
			}
			return "ENABLED"
		},
		stations: func() string { return f.stationsOut }, liveInfo: func() (int, int) { return 3, 2422 }, kick: func(string) error { return nil }}
	f.env.restart = func() error {
		f.restarts++
		raw, _ := os.ReadFile(f.env.xmlPath)
		s := parseWifiSettings(string(raw))
		psk, _ := xmlGet(string(raw), "Basic_0", "psk")
		if f.breakNew && strings.Contains(string(raw), "Example") {
			s.SSID = "ExampleNet"
		}
		hid, iso := "0", "0"
		if s.Hidden {
			hid = "1"
		}
		if s.APIsolate {
			iso = "1"
		}
		conf := "ssid=" + s.SSID + "\nchannel=" + itoa(s.Channel) + "\nmax_num_sta=" + itoa(s.MaxClients) + "\nignore_broadcast_ssid=" + hid + "\nap_isolate=" + iso + "\nwpa_passphrase=" + psk + "\n"
		return os.WriteFile(f.env.confPath, []byte(conf), 0o600)
	}
	os.WriteFile(f.env.xmlPath, []byte(wlanSample), 0o755)
	f.env.restart()
	f.restarts = 0
	f.stationsOut = ""
	return f
}

func itoa(i int) string { return strconv.Itoa(i) }

func waitState(t *testing.T, m *wifiManager, want string) {
	for i := 0; i < 200; i++ {
		m.mu.Lock()
		s := m.state
		m.mu.Unlock()
		if s == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never reached state %q (now %q: %s)", want, m.state, m.message)
}

func TestWifiApplyAndRollback(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	msg, err := m.Apply(wifiChange{SSID: sp("Example"), Channel: sp(6)})
	if err != nil || !strings.Contains(msg, "network name") {
		t.Fatal(msg, err)
	}
	waitState(t, m, "ok")
	raw, _ := os.ReadFile(f.env.xmlPath)
	if s := parseWifiSettings(string(raw)); s.SSID != "Example" || s.Channel != 6 || f.restarts != 1 {
		t.Errorf("after apply: %+v restarts=%d", s, f.restarts)
	}
	if len(m.backups()) != 1 {
		t.Errorf("backups %v", m.backups())
	}
	if fi, _ := os.Stat(f.env.xmlPath); fi.Mode().Perm() != 0o755 {
		t.Errorf("xml mode %v", fi.Mode().Perm())
	}
	if _, err := m.Apply(wifiChange{Hidden: sp(true)}); err == nil || !strings.Contains(err.Error(), "30 seconds") {
		t.Errorf("no rate limit: %v", err)
	}
	// a change that does not take is rolled back by itself, with a second restart
	m2 := newWifiManager(f.env)
	os.WriteFile(f.env.xmlPath, []byte(wlanSample), 0o755)
	f.env.restart()
	f.restarts, f.breakNew = 0, true
	if _, err := m2.Apply(wifiChange{SSID: sp("Example")}); err != nil {
		t.Fatal(err)
	}
	waitState(t, m2, "failed")
	raw, _ = os.ReadFile(f.env.xmlPath)
	if s := parseWifiSettings(string(raw)); s.SSID != "ExampleNet" {
		t.Errorf("not rolled back: %q", s.SSID)
	}
	if f.restarts != 2 || !strings.Contains(m2.message, "previous settings were restored") {
		t.Errorf("restarts %d, message %q", f.restarts, m2.message)
	}
	// hostapd never comes back: reported, restored
	f.breakNew = false
	m3 := newWifiManager(f.env)
	f.down = true
	m3.Apply(wifiChange{Channel: sp(11)})
	waitState(t, m3, "failed")
	f.down = false
	// restore the most recent backup
	m4 := newWifiManager(f.env)
	if _, err := m4.Restore("../../etc/passwd"); err == nil {
		t.Error("a path was accepted as a backup name")
	}
	if _, err := m4.Restore(""); err != nil {
		t.Fatal(err)
	}
	waitState(t, m4, "ok")
}

func TestWifiNeverLeaksPassword(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	v, _ := m.View(nil, nil)
	if b := strings.Join([]string{v.Message, v.Settings.SSID}, " "); strings.Contains(b, "old-secret-pass") {
		t.Error("the password is in the view")
	}
	m.Apply(wifiChange{Password: sp("brand-new-secret"), PasswordConfirm: sp("brand-new-secret")})
	waitState(t, m, "ok")
	v, _ = m.View(nil, nil)
	if strings.Contains(v.Message, "brand-new-secret") {
		t.Error("the new password is in the status message")
	}
}

func TestReservations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp_hosts")
	os.WriteFile(path, []byte("# header\n00:00:5e:00:53:01,192.168.1.10,phone-c\n00:00:5e:00:53:04,192.168.1.40,phone-d\nbroken line\n"), 0o666)
	reloads := 0
	d := &dhcpManager{path: path, backupDir: filepath.Join(dir, "b"), reload: func() error { reloads++; return nil }}
	rs := d.List()
	if len(rs) != 2 || rs[0].MAC != "00:00:5e:00:53:01" {
		t.Fatalf("%+v", rs)
	}
	if err := d.Set(reservation{MAC: "00:00:5e:00:53:08", IP: "192.168.1.20", Name: "phone-b"}); err != nil || reloads != 1 {
		t.Fatal(err, reloads)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v (the old file was world-writable)", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), dhcpHeader) || strings.Index(string(b), "192.168.1.10") > strings.Index(string(b), "192.168.1.20") {
		t.Errorf("file:\n%s", b)
	}
	// changing an existing MAC's address keeps one entry
	d.Set(reservation{MAC: "00:00:5e:00:53:08", IP: "192.168.1.21", Name: "phone-b"})
	if rs := d.List(); len(rs) != 3 {
		t.Errorf("%d reservations", len(rs))
	}
	for _, bad := range []reservation{
		{MAC: "nope", IP: "192.168.1.50", Name: "x"}, {MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.1", Name: "gw"}, {MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.254", Name: "svc"},
		{MAC: "aa:aa:aa:aa:aa:01", IP: "10.0.0.5", Name: "far"}, {MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.10", Name: "dup-ip"}, {MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.60", Name: "PHONE-C"},
		{MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.60", Name: "bad name!"}, {MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.60", Name: ""},
	} {
		if d.Set(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if err := d.Delete("00:00:5e:00:53:01"); err != nil || len(d.List()) != 2 {
		t.Error("delete")
	}
	if d.Delete("00:00:00:00:00:00") == nil {
		t.Error("deleting a missing MAC did not complain")
	}
	if es, _ := os.ReadDir(d.backupDir); len(es) == 0 {
		t.Error("no backup of the old file")
	}
	d.reload = func() error { return errors.New("dnsmasq is not running") }
	if err := d.Set(reservation{MAC: "aa:aa:aa:aa:aa:02", IP: "192.168.1.70", Name: "late"}); err == nil || !strings.Contains(err.Error(), "saved, but") {
		t.Errorf("a failed reload must say the file was saved: %v", err)
	}
	if len(d.List()) != 3 {
		t.Error("the file was not saved when the reload failed")
	}
}

func TestDHCPView(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp_hosts")
	os.WriteFile(path, []byte("00:00:5e:00:53:01,192.168.1.10,phone-c\n00:00:5e:00:53:04,192.168.1.40,phone-d\n"), 0o644)
	d := &dhcpManager{path: path, backupDir: dir, reload: func() error { return nil }}
	arp := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.10    0x1         0x2         00:00:5e:00:53:01     *        bridge0\n192.168.1.77    0x1         0x2         de:ad:be:ef:00:01     *        bridge0\n192.168.1.41    0x1         0x2         00:00:5e:00:53:04     *        bridge0\n"
	v := d.View(arp, "", []wifiStation{{MAC: "de:ad:be:ef:00:01"}}, "dnsmasq --dhcp-range=bridge0,192.168.1.100,192.168.1.200,255.255.255.0,86400 --x")
	if len(v.Reservations) != 2 || !v.Reservations[0].Online || v.Reservations[0].SeenAs != "" {
		t.Errorf("%+v", v.Reservations)
	}
	if v.Reservations[1].SeenAs != "192.168.1.41" { // the iPhone is online at an address that is not its reservation
		t.Errorf("seen_as %+v", v.Reservations[1])
	}
	var guest *lanDevice
	for i := range v.Devices {
		if v.Devices[i].MAC == "de:ad:be:ef:00:01" {
			guest = &v.Devices[i]
		}
	}
	if guest == nil || guest.Reserved || !guest.Wifi || guest.IP != "192.168.1.77" {
		t.Errorf("devices %+v", v.Devices)
	}
	if v.Range != "192.168.1.100 to 192.168.1.200, leases 1 day(s)" {
		t.Errorf("range %q", v.Range)
	}
}

const oneStation = "00:00:5e:00:53:06\nflags=[AUTH][ASSOC][AUTHORIZED]\nconnected_time=5\n"
const wrongPSKStation = "00:00:5e:00:53:06\nflags=[AUTH][ASSOC]\nconnected_time=5\n" // associated but never authorised: the 4-way handshake failed

func TestStationAuthorised(t *testing.T) {
	if countAuthorized(oneStation) != 1 || countAuthorized(wrongPSKStation) != 0 || countAuthorized("") != 0 {
		t.Error("authorised counting")
	}
}

// the mistyped-password case: devices were connected, the change makes none of them able to rejoin, so the old settings must come back by themselves
func TestWifiRevertsWhenNoDeviceRejoins(t *testing.T) {
	f := newFakeRadio(t)
	f.stationsOut = oneStation // connected before the change
	m := newWifiManager(f.env)
	m.window = 150 * time.Millisecond
	f.env.wait = func(d time.Duration) { time.Sleep(time.Millisecond) }
	calls := 0
	f.env.stations = func() string { // after the restart nothing can join (only the pre-change reading shows a device)
		calls++
		if calls <= 1 {
			return oneStation
		}
		return wrongPSKStation
	}
	if _, err := m.Apply(wifiChange{Password: sp("a-typo'd-password"), PasswordConfirm: sp("a-typo'd-password")}); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "waiting")
	if v, _ := m.View(nil, nil); v.WaitLeftS < 0 || v.State != "waiting" {
		t.Errorf("view %+v", v)
	}
	waitState(t, m, "failed")
	raw, _ := os.ReadFile(f.env.xmlPath)
	if p, _ := xmlGet(string(raw), "Basic_0", "psk"); p != "old-secret-pass" {
		t.Errorf("the old password was not restored: %q", p)
	}
	if !strings.Contains(m.message, "previous Wi-Fi settings were restored") || f.restarts != 2 {
		t.Errorf("message %q restarts %d", m.message, f.restarts)
	}
}

func TestWifiConfirmedWhenADeviceRejoins(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	m.window = 2 * time.Second
	f.env.wait = func(d time.Duration) { time.Sleep(time.Millisecond) }
	calls := 0
	f.env.stations = func() string {
		calls++
		if calls <= 4 { // connected before, then the radio restarts and nobody is authorised yet, then a phone joins with the new password
			if calls == 1 {
				return oneStation
			}
			return wrongPSKStation
		}
		return oneStation
	}
	if _, err := m.Apply(wifiChange{SSID: sp("Example")}); err != nil {
		t.Fatal(err)
	}
	waitState(t, m, "ok")
	raw, _ := os.ReadFile(f.env.xmlPath)
	if s := parseWifiSettings(string(raw)); s.SSID != "Example" || !strings.Contains(m.message, "confirmed") {
		t.Errorf("%q %q", s.SSID, m.message)
	}
	if f.restarts != 1 {
		t.Errorf("restarts %d: a confirmed change must not restart again", f.restarts)
	}
}

func TestWifiNoStationsBeforeMeansNoWatchdog(t *testing.T) {
	f := newFakeRadio(t) // nobody connected: nothing to judge by, so the change is simply applied
	m := newWifiManager(f.env)
	m.window = time.Hour
	m.Apply(wifiChange{Channel: sp(7)})
	waitState(t, m, "ok")
}

func TestWifiBlocksSecondChangeWhileWaiting(t *testing.T) {
	f := newFakeRadio(t)
	f.stationsOut = oneStation
	m := newWifiManager(f.env)
	m.window = time.Hour
	f.env.wait = func(time.Duration) { time.Sleep(5 * time.Millisecond) }
	calls := 0
	f.env.stations = func() string {
		calls++
		if calls == 1 {
			return oneStation
		}
		return ""
	}
	m.Apply(wifiChange{Channel: sp(5)})
	waitState(t, m, "waiting")
	m.last = time.Now().Add(-time.Hour)
	if _, err := m.Apply(wifiChange{Channel: sp(9)}); err == nil || !strings.Contains(err.Error(), "still being applied or confirmed") {
		t.Errorf("a second change was accepted while waiting: %v", err)
	}
}

func TestBuildRelease(t *testing.T) {
	p, err := buildRelease("192.168.1.147", "00:00:5e:00:53:05", "192.168.1.1")
	if err != nil || len(p) != 548 {
		t.Fatal(err, len(p))
	}
	if p[0] != 1 || p[1] != 1 || p[2] != 6 || net.IP(p[12:16]).String() != "192.168.1.147" || net.HardwareAddr(p[28:34]).String() != "00:00:5e:00:53:05" {
		t.Errorf("header % x", p[:40])
	}
	if p[236] != 0x63 || p[237] != 0x82 || p[238] != 0x53 || p[239] != 0x63 {
		t.Error("magic cookie")
	}
	want := []byte{53, 1, 7, 54, 4, 192, 168, 1, 1, 61, 7, 1, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x05, 255}
	if !bytes.Equal(p[240:240+len(want)], want) {
		t.Errorf("options % x", p[240:262])
	}
	for _, bad := range [][3]string{{"nope", "00:00:5e:00:53:05", "192.168.1.1"}, {"192.168.1.147", "zz", "192.168.1.1"}, {"192.168.1.147", "00:00:5e:00:53:05", ""}} {
		if _, err := buildRelease(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestMoveNowAndStaleLease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp_hosts")
	os.WriteFile(path, []byte("00:00:5e:00:53:05,192.168.1.30,phone-a\n"), 0o644)
	var released [][2]string
	cur := "192.168.1.147"
	d := &dhcpManager{path: path, backupDir: dir, reload: func() error { return nil },
		release: func(ip, mac string) error { released = append(released, [2]string{ip, mac}); return nil },
		curIP:   func(mac string) string { return cur }}
	old, err := d.MoveNow("00:00:5e:00:53:05")
	if err != nil || old != "192.168.1.147" || len(released) != 1 || released[0] != [2]string{"192.168.1.147", "00:00:5e:00:53:05"} {
		t.Fatalf("%v %v %v", old, err, released)
	}
	if _, err := d.MoveNow("aa:aa:aa:aa:aa:aa"); err == nil {
		t.Error("a device without a reservation was moved")
	}
	cur = "192.168.1.30"
	if _, err := d.MoveNow("00:00:5e:00:53:05"); err == nil || len(released) != 1 {
		t.Error("a device already at its address was released")
	}
	cur = ""
	if _, err := d.MoveNow("00:00:5e:00:53:05"); err == nil {
		t.Error("an absent device was released")
	}
	// saving a reservation for a device that holds another address drops that lease; a device already in place is left alone
	released, cur = nil, "192.168.1.143"
	d.Set(reservation{MAC: "00:00:5e:00:53:07", IP: "192.168.1.20", Name: "phone-b"})
	if len(released) != 1 || released[0][0] != "192.168.1.143" {
		t.Errorf("stale lease not dropped: %v", released)
	}
	released, cur = nil, "192.168.1.20"
	d.Set(reservation{MAC: "00:00:5e:00:53:07", IP: "192.168.1.20", Name: "phone-b"})
	if len(released) != 0 {
		t.Errorf("released a lease that already matches: %v", released)
	}
}

func TestForgetAndDeleteDropLeases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp_hosts")
	os.WriteFile(path, []byte("00:00:5e:00:53:07,192.168.1.20,phone-b\n"), 0o644)
	leases := map[string]string{"00:00:5e:00:53:07": "192.168.1.20", "00:00:5e:00:53:06": "192.168.1.30"}
	var released [][2]string
	d := &dhcpManager{path: path, backupDir: dir, reload: func() error { return nil },
		release: func(ip, mac string) error { released = append(released, [2]string{ip, mac}); return nil },
		leaseIP: func(mac string) string { return leases[mac] }}
	if ip, err := d.Forget("00:00:5e:00:53:06"); err != nil || ip != "192.168.1.30" || len(released) != 1 {
		t.Fatal(ip, err, released)
	}
	if _, err := d.Forget("00:00:00:00:00:01"); err == nil {
		t.Error("forgot a lease that does not exist")
	}
	if _, err := d.Forget("nope"); err == nil {
		t.Error("accepted a bad MAC")
	}
	released = nil
	if err := d.Delete("00:00:5e:00:53:07"); err != nil || len(released) != 1 || released[0][0] != "192.168.1.20" {
		t.Errorf("delete did not release its lease: %v %v", err, released)
	}
}

func TestLeaseOfParsesTheLeaseFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "leases")
	os.WriteFile(f, []byte("1790 00:00:5e:00:53:06 192.168.1.30 * 01:22\nduid 00:01\n1790 00:00:5e:00:53:05 192.168.1.147 phone-a 01:00\n"), 0o644)
	old := *leasesFile
	*leasesFile = f
	defer func() { *leasesFile = old }()
	d := &dhcpManager{}
	if d.leaseOf("00:00:5e:00:53:06") != "192.168.1.30" || d.leaseOf("00:00:5e:00:53:05") != "192.168.1.147" || d.leaseOf("aa:aa:aa:aa:aa:aa") != "" {
		t.Error("lease lookup")
	}
}

func TestApplyFiveChange(t *testing.T) {
	on := sp(true)
	n, ch, err := applyWifiChange(wlanSample, wifiChange{Five: &fiveChange{Enabled: on, SSID: sp("ExampleNet-5G"), Channel: sp(149)}})
	if err != nil || len(ch) != 3 {
		t.Fatalf("%v %v", ch, err)
	}
	f := parseWifiSettings(n).Five
	if !f.Enabled || f.SSID != "ExampleNet-5G" || f.Channel != 149 || parseWifiSettings(n).SSID != "ExampleNet" {
		t.Errorf("%+v", f)
	}
	if v, _ := xmlGet(n, "Basic_1", "psk"); v != func() string { x, _ := xmlGet(wlanSample, "Basic_0", "psk"); return x }() {
		t.Error("the 5 GHz password should stay the old shared one when none is given")
	}
	// turning it off keeps its settings
	n2, ch, err := applyWifiChange(n, wifiChange{Five: &fiveChange{Enabled: sp(false)}})
	if err != nil || len(ch) != 1 || parseWifiSettings(n2).Five.Enabled || parseWifiSettings(n2).Five.SSID != "ExampleNet-5G" {
		t.Errorf("off: %v %v", ch, err)
	}
	for name, c := range map[string]fiveChange{
		"same name":        {Enabled: on, SSID: sp("ExampleNet"), Channel: sp(149)},
		"auto channel":     {Enabled: on, SSID: sp("Five"), Channel: sp(0)},
		"dfs channel":      {Enabled: on, SSID: sp("Five"), Channel: sp(100)},
		"in-block channel": {Enabled: on, SSID: sp("Five"), Channel: sp(153)},
		"2.4 channel":      {Enabled: on, SSID: sp("Five"), Channel: sp(6)},
		"password typo":    {Enabled: on, SSID: sp("Five"), Channel: sp(36), Password: sp("long-enough-pw"), PasswordConfirm: sp("long-enough-px")},
		"short password":   {Enabled: on, SSID: sp("Five"), Channel: sp(36), Password: sp("short"), PasswordConfirm: sp("short")},
	} {
		c := c
		if _, _, err := applyWifiChange(wlanSample, wifiChange{Five: &c}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	n3, ch, err := applyWifiChange(n, wifiChange{Five: &fiveChange{Password: sp("another-password"), PasswordConfirm: sp("another-password"), Hidden: on, Channel: sp(36)}})
	if err != nil || len(ch) != 3 || strings.Contains(strings.Join(ch, " "), "another") {
		t.Fatalf("%v %v", ch, err)
	}
	if v, _ := xmlGet(n3, "Basic_1", "psk"); v != "another-password" {
		t.Error("5 GHz password not set")
	}
	if v, _ := xmlGet(n3, "Basic_0", "psk"); v == "another-password" {
		t.Error("the 2.4 GHz password was changed by a 5 GHz change")
	}
	if !matches5("ssid=ExampleNet-5G\nwpa_passphrase=another-password\nchannel=36\nignore_broadcast_ssid=1\n", n3) || matches5("ssid=ExampleNet-5G\nchannel=149\n", n3) {
		t.Error("matches5")
	}
}
