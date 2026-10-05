package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newSnapStore(t *testing.T) (*snapStore, *dhcpManager, *macFilter, *fwManager, *poolManager, string) {
	dir := t.TempDir()
	xml := filepath.Join(dir, "wlan.xml")
	os.WriteFile(xml, []byte(wlanSample), 0o755)
	w := newWifiManager(&wifiEnv{xmlPath: xml, confPath: filepath.Join(dir, "hostapd.conf"), backupDir: filepath.Join(dir, "wbk"), restart: func() error { return nil },
		hostapdState: func() string { return "ENABLED" }, stations: func() string { return "" }, liveInfo: func() (int, int) { return 6, 2437 }, kick: func(string) error { return nil }, wait: func(time.Duration) {}})
	hosts := filepath.Join(dir, "dhcp_hosts")
	os.WriteFile(hosts, []byte("aa:bb:cc:dd:ee:01,192.168.1.50,alpha\n"), 0o644)
	d := &dhcpManager{path: hosts, backupDir: filepath.Join(dir, "dbk"), reload: func() error { return nil }}
	pm, _, _ := newPoolMgr(t, func(o, n []string) error { return nil })
	mf, _ := newMF(t)
	fm, _, _ := newFW(t)
	clock := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	s := &snapStore{dir: filepath.Join(dir, "snaps"), now: func() time.Time { clock = clock.Add(time.Second); return clock }, wifi: w, dhcp: d, pool: pm, mac: mf, fw: fm, dns: func() *Filter { return nil }}
	return s, d, mf, fm, pm, xml
}

func TestSnapshotCreateAndRestore(t *testing.T) {
	s, d, mf, fm, pm, _ := newSnapStore(t)
	mf.Add("11:22:33:44:55:66", "")
	fm.AddDest("203.0.113.0/24", "spam")
	name, err := s.Create("baseline")
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(s.dir, name+".json"))
	raw, _ := s.Raw(name)
	if fi.Mode().Perm() != 0o600 || strings.Contains(string(raw), "priv_key") || !strings.Contains(string(raw), "203.0.113.0/24") {
		t.Errorf("file mode %v or contents wrong", fi.Mode())
	}
	if l := s.List(); len(l) != 1 || l[0].Label != "baseline" || len(l[0].Sections) < 5 {
		t.Fatalf("%+v", l)
	}
	// change everything, then restore
	d.save([]reservation{{MAC: "aa:bb:cc:dd:ee:09", IP: "192.168.1.99", Name: "other"}})
	mf.Remove("11:22:33:44:55:66")
	fm.DeleteDest("203.0.113.0/24")
	pm.Set(dhcpPool{"192.168.1.50", "192.168.1.150", 7200})
	res, err := s.Restore(name, []string{"reservations", "pool", "blocklist", "firewall"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Error != "" {
			t.Errorf("%s: %s", r.Section, r.Error)
		}
	}
	if rs := d.List(); len(rs) != 1 || rs[0].Name != "alpha" {
		t.Errorf("reservations %+v", rs)
	}
	if l := mf.List(); len(l) != 1 || l[0] != "11:22:33:44:55:66" {
		t.Errorf("blocklist %v", l)
	}
	if v := fm.View(nil); len(v.Dest) != 1 || v.Dest[0].CIDR != "203.0.113.0/24" {
		t.Errorf("firewall %+v", v.Dest)
	}
	if pv, _ := pm.View(); pv.Start != "192.168.1.100" || pv.LeaseSecs != 86400 {
		t.Errorf("pool %+v", pv)
	}
	var autos int
	for _, n := range s.names() {
		if strings.HasPrefix(n, "auto-") {
			autos++
		}
	}
	if autos != 1 {
		t.Errorf("expected one automatic before-restore snapshot, got %d (%v)", autos, s.names())
	}
}

func TestSnapshotRestoreGuards(t *testing.T) {
	s, _, mf, _, _, xml := newSnapStore(t)
	mf.Add("11:22:33:44:55:66", "")
	name, _ := s.Create("")
	if _, err := s.Restore(name, nil, ""); err == nil {
		t.Error("no sections accepted")
	}
	if _, err := s.Restore(name, []string{"bogus"}, ""); err == nil {
		t.Error("unknown section accepted")
	}
	if _, err := s.Restore("../../etc/passwd", []string{"wifi"}, ""); err == nil {
		t.Error("path traversal accepted")
	}
	res, _ := s.Restore(name, []string{"blocklist"}, "11:22:33:44:55:66") // restoring a list that blocks the asker
	if len(res) != 1 || !strings.Contains(res[0].Error, "cut you off") {
		t.Errorf("self-block restore: %+v", res)
	}
	res, _ = s.Restore(name, []string{"dns"}, "")
	if len(res) != 1 || res[0].Error == "" {
		t.Errorf("dns without a filter should say so: %+v", res)
	}
	// wifi: identical file is a no-op, a changed one is restored through the manager
	res, _ = s.Restore(name, []string{"wifi"}, "")
	if len(res) != 1 || res[0].Status != "already the same" {
		t.Errorf("wifi same: %+v", res)
	}
	os.WriteFile(xml, []byte(strings.Replace(wlanSample, "<ssid>ExampleNet</ssid>", "<ssid>Changed</ssid>", 1)), 0o755)
	res, _ = s.Restore(name, []string{"wifi"}, "")
	if len(res) != 1 || res[0].Error != "" || !strings.Contains(res[0].Status, "restoring") {
		t.Errorf("wifi restore: %+v", res)
	}
	for i := 0; i < 500; i++ { // let the background Wi-Fi restore finish before the temp dir goes away
		s.wifi.mu.Lock()
		st := s.wifi.state
		s.wifi.mu.Unlock()
		if st != "applying" && st != "waiting" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSnapshotImportValidation(t *testing.T) {
	s, _, _, _, _, _ := newSnapStore(t)
	for name, body := range map[string]string{
		"not json":     "nope",
		"wrong format": `{"format":"other","sections":{}}`,
		"empty":        `{"format":"orbic-snapshot-1","sections":{}}`,
		"bad wifi":     `{"format":"orbic-snapshot-1","sections":{"wifi":{"xml":"<wlan></wlan>"}}}`,
		"bad mac":      `{"format":"orbic-snapshot-1","sections":{"blocklist":["zz"]}}`,
		"bad pool":     `{"format":"orbic-snapshot-1","sections":{"pool":{"start":"10.0.0.1","end":"10.0.0.99","lease_secs":100}}}`,
		"bad dest":     `{"format":"orbic-snapshot-1","sections":{"firewall":{"dest":[{"cidr":"0.0.0.0/0"}]}}}`,
		"bad dns mode": `{"format":"orbic-snapshot-1","sections":{"dns":{"mode":"evil"}}}`,
		"dup reserv":   `{"format":"orbic-snapshot-1","sections":{"reservations":{"text":"aa:bb:cc:dd:ee:01,192.168.1.5,a\naa:bb:cc:dd:ee:02,192.168.1.5,b\n"}}}`,
	} {
		if _, err := s.Import([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	good := `{"format":"orbic-snapshot-1","created":"x","sections":{"blocklist":["11:22:33:44:55:66"],"dns":{"mode":"both"}}}`
	name, err := s.Import([]byte(good))
	if err != nil || !strings.HasPrefix(name, "imported-") {
		t.Fatalf("%v %v", name, err)
	}
	if l := s.List(); len(l) != 1 || !strings.Contains(l[0].Label, "imported") {
		t.Errorf("%+v", l)
	}
}

func TestSnapshotKeepsTwentyAndSortsNewestFirst(t *testing.T) {
	s, _, _, _, _, _ := newSnapStore(t)
	var last string
	for i := 0; i < 23; i++ {
		last, _ = s.Create("")
	}
	n := s.names()
	if len(n) != 20 || n[0] != last {
		t.Errorf("%d kept, newest %q first? %q", len(n), last, n[0])
	}
	if s.Delete(last) != nil || s.Delete(last) == nil || s.Delete("../x") == nil {
		t.Error("delete behaviour")
	}
}

func TestSnapshotEmptyBlocklistIsStillASection(t *testing.T) {
	s, _, _, _, _, _ := newSnapStore(t)
	name, _ := s.Create("")
	sn, _, err := s.load(name)
	if err != nil || sn.Sections.Blocklist == nil || len(*sn.Sections.Blocklist) != 0 {
		t.Errorf("%v %+v", err, sn.Sections.Blocklist)
	}
}
