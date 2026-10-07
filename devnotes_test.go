package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevNotes(t *testing.T) {
	d := &devNotes{path: filepath.Join(t.TempDir(), "n.json")}
	if err := d.Set("AA:BB:CC:DD:EE:01", " Kitchen bulb ", "bought 2024, Zigbee"); err != nil {
		t.Fatal(err)
	}
	m := d.All()
	if n := m["aa:bb:cc:dd:ee:01"]; n.Label != "Kitchen bulb" || n.Note != "bought 2024, Zigbee" {
		t.Errorf("%+v", m)
	}
	if fi, _ := os.Stat(d.path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	for name, c := range map[string][3]string{"bad mac": {"nope", "x", ""}, "long label": {"aa:bb:cc:dd:ee:02", strings.Repeat("x", 41), ""}, "long note": {"aa:bb:cc:dd:ee:02", "", strings.Repeat("n", 201)}, "newline": {"aa:bb:cc:dd:ee:02", "a\nb", ""}, "control": {"aa:bb:cc:dd:ee:02", "", "x\x00y"}} {
		if d.Set(c[0], c[1], c[2]) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := d.Set("aa:bb:cc:dd:ee:01", "", "  "); err != nil || len(d.All()) != 0 {
		t.Errorf("empty label and note must remove the entry: %v %v", err, d.All())
	}
	for i := 0; i < 128; i++ {
		d.Set("aa:bb:cc:dd:00:"+hex2(i), "x", "")
	}
	if d.Set("aa:bb:cc:dd:ff:ff", "x", "") == nil {
		t.Error("129th entry accepted")
	}
}

func TestMagicPacket(t *testing.T) {
	p, err := magicPacket("AA:BB:CC:DD:EE:01")
	if err != nil || len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Fatalf("%v %d", err, len(p))
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(p[6+i*6:12+i*6], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}) {
			t.Fatalf("repetition %d wrong", i)
		}
	}
	for _, bad := range []string{"", "xx", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:01:02:03"} {
		if _, err := magicPacket(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDevicesCarryLabelsAndShowOfflineLabelled(t *testing.T) {
	in := devInputs{ARP: devARP, Notes: map[string]devNote{"00:00:5e:00:53:02": {Label: "Alex's phone", Note: "worker 3"}, "aa:aa:aa:aa:aa:aa": {Label: "attic sensor"}}}
	ds := buildDevices(in)
	by := map[string]devView{}
	for _, d := range ds {
		by[d.MAC] = d
	}
	if m := by["00:00:5e:00:53:02"]; m.Label != "Alex's phone" || m.Note != "worker 3" || !m.Online {
		t.Errorf("%+v", m)
	}
	if s, ok := by["aa:aa:aa:aa:aa:aa"]; !ok || s.Online || s.Label != "attic sensor" {
		t.Errorf("a labelled device that is not on the network must still be listed: %+v", s)
	}
}

func TestSnapshotCarriesDeviceNotes(t *testing.T) {
	s, _, _, _, _, _ := newSnapStore(t)
	s.notes = &devNotes{path: filepath.Join(t.TempDir(), "n.json")}
	s.notes.Set("aa:bb:cc:dd:ee:01", "Bulb", "kitchen")
	name, _ := s.Create("")
	s.notes.Set("aa:bb:cc:dd:ee:01", "", "")
	s.notes.Set("aa:bb:cc:dd:ee:02", "Other", "")
	res, err := s.Restore(name, []string{"devicenotes"}, "")
	if err != nil || len(res) != 1 || res[0].Error != "" {
		t.Fatalf("%v %+v", err, res)
	}
	if m := s.notes.All(); len(m) != 1 || m["aa:bb:cc:dd:ee:01"].Label != "Bulb" {
		t.Errorf("%+v", m)
	}
	if _, err := s.Import([]byte(`{"format":"orbic-snapshot-1","sections":{"devicenotes":{"nope":{"label":"x"}}}}`)); err == nil {
		t.Error("a snapshot with a bad MAC in its notes was imported")
	}
}

func TestSettingsPathsRouted(t *testing.T) { // a path handled in handleSettings but missing from the routing table answers "not found": guard against that
	for _, p := range []string{"wifi", "wifi/apply", "wifi/macfilter", "dhcp", "dhcp/pool", "dhcp/pool/set", "fw", "fw/pause", "cell", "diag", "diag/run", "diag/report", "cert", "cert/renew", "cert/download",
		"ssh", "ssh/add", "ssh/delete", "sms", "devices", "devices/note", "devices/wake", "devices/watch", "graphs", "canary", "canary/set", "canary/ignore", "actions", "actions/set", "actions/run", "actions/delete", "events", "notify/set", "system", "system/reboot", "system/stockadmin", "system/lanv6", "egress", "egress/set", "egress/allow", "egress/remove", "egress/service",
		"dnscanary", "dnscanary/set", "macchurn", "torbypass", "beacon", "beacon/ignore", "dganxdomain", "tlssni", "dnsmitm", "dhcpfp"} {
		if !isSettingsPath(p) {
			t.Errorf("%s is not routed to the settings handler", p)
		}
	}
	for _, p := range []string{"dns", "vpn", "session", "backup", "backup/create", "account/password"} {
		if isSettingsPath(p) {
			t.Errorf("%s must not be taken by the settings handler", p)
		}
	}
}
