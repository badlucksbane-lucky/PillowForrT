package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemParsers(t *testing.T) {
	if tot, av := parseMeminfo("MemTotal:         163736 kB\nMemFree:           13116 kB\nMemAvailable:      80336 kB\n"); tot != 163736 || av != 80336 {
		t.Errorf("%d %d", tot, av)
	}
	if propVal("a=1\nro.product.name=mdm9607-base\n", "ro.product.name") != "mdm9607-base" || propVal("a=1", "b") != "" {
		t.Error("kv")
	}
	b := parseBattery("[1] ###M### odm_notify: volt_avg=3700 bat_level=2 bat_temperature=30\n[2] x\n[3] ###M### odm_notify: volt_avg=3763 bat_level=3 bat_temperature=31\n")
	if !b.Known || b.MV != 3763 || b.Level != 3 || b.TempC != 31 {
		t.Errorf("newest line must win: %+v", b)
	}
	if parseBattery("nothing here").Known {
		t.Error("invented a battery")
	}
}

func TestServiceTable(t *testing.T) {
	dir := t.TempDir()
	mk := func(pid, comm, cmd string) {
		os.MkdirAll(filepath.Join(dir, pid), 0o755)
		os.WriteFile(filepath.Join(dir, pid, "stat"), []byte(pid+" ("+comm+") S 1 1 1 0 -1 4194560 0 0 0 0\n"), 0o644)
		os.WriteFile(filepath.Join(dir, pid, "cmdline"), []byte(strings.ReplaceAll(cmd, " ", "\x00")), 0o644)
	}
	mk("10", "tinyfwd", "/data/proxy/tinyfwd -4")
	mk("11", "hostapd", "hostapd -B /tmp/hostapd_wlan0.conf")
	mk("12", "sh", "/bin/sh ./wpad-guard.sh")
	mk("13", "QCMAP_Connectio", "QCMAP_ConnectionManager /usrdata/data/qcmap/mobileap_cfg.xml d")
	mk("14", "upgrade", "/usr/bin/upgrade")
	os.WriteFile(filepath.Join(dir, "14", "stat"), []byte("14 (upgrade) T 1 1 1 0 -1 4194560 0 0 0 0\n"), 0o644) // stopped
	os.MkdirAll(filepath.Join(dir, "self"), 0o755)                                                               // not a pid: ignored
	comms, stopped, lines := scanProcs(dir)
	want := map[string]string{"tinyfwd (proxy, DNS filter, this page)": "running", "hostapd, 2.4 GHz": "running", "hostapd, 5 GHz": "not running", "dnsmasq (DHCP and DNS)": "not running",
		"guard (firewall, reservations, FOTA hold)": "running", "QCMAP (the cellular data connection)": "running", "carrier updates (upgrade)": "held"}
	for _, s := range serviceTable(comms, stopped, lines) {
		if w, ok := want[s.Name]; ok && w != s.State {
			t.Errorf("%s: %s, want %s", s.Name, s.State, w)
		}
		delete(want, s.Name)
	}
	if len(want) != 0 {
		t.Errorf("services missing from the table: %v", want)
	}
}

func TestReboot(t *testing.T) {
	n := 0
	old := rebootNow
	rebootNow = func() error { n++; return nil }
	defer func() { rebootNow = old }()
	for _, c := range []string{"", "yes", "REBOOT", "reboot now"} {
		if doReboot(c) == nil {
			t.Errorf("%q rebooted", c)
		}
	}
	if n != 0 || doReboot("reboot") != nil || n != 1 {
		t.Errorf("reboot count %d", n)
	}
}
