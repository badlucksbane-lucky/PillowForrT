package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testKey1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOJferu6TFFd54WhC+rKW/hooKkWtOLbDOKd6/Qw67XO test-one"
	testKey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBZbDqwPvVLYTtfmvh06tmFO1hvfH46KvaXJwc2uxslx test two"
	testRSA  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCckuX1k6349G5hd5p1L+DL5PhXNpzMsLPE5Rz2xk3fF/WwENepXLQvJ/Ua8/maLNfn9o6hpd4wpN0Cye6bRTkkwOdxo13Fc0AwGgAu2R2yKW2LVCRPwxfWMuyuqJbPo6XFicCX0NtIACk87v6JbWSM1JYdJU4bfrg1W0WO/Vl8Iy7CfbxWrzSu7rE+zIzfdfIHD+SErgH9SCUzGIs5kIHKWRdOHUiiqCAABzHASkgFmFKGZbqV1gL4O6A+s4R9c+y7yxmxtS8RihAMgDa5/QoRDYD/GJSlJkv2I0h/Xl/DbH0ZIhGPEqqyLdc1xQz639Yi7u8FtfV+uE9pa3ke5v/b"
	testFP1  = "SHA256:+dBcDCQ4IsoT7IUrMkxPF1AjVIj7KucE3xZg0tP6AYY"
	testFP2  = "SHA256:Wx/TM1SF23LoawGPu7WQBTNL/Q8u2a9IeqTSAYNLtRc"
)

func TestParseKeyLine(t *testing.T) {
	k, err := parseKeyLine(testKey1)
	if err != nil || k.Fingerprint != testFP1 || k.Comment != "test-one" || k.Type != "ssh-ed25519" {
		t.Fatalf("%+v %v", k, err)
	}
	k, err = parseKeyLine("no-port-forwarding,no-agent-forwarding " + testKey2)
	if err != nil || k.Fingerprint != testFP2 || k.Options != "no-port-forwarding,no-agent-forwarding" || k.Comment != "test two" {
		t.Fatalf("with options and a spaced comment: %+v %v", k, err)
	}
	for name, bad := range map[string]string{"empty": "", "one word": "ssh-ed25519", "rsa": testRSA, "bad base64": "ssh-ed25519 !!!notbase64", "short blob": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", "private": "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		if _, err := parseKeyLine(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func newSSH(t *testing.T) *sshManager {
	dir := t.TempDir()
	return &sshManager{dir: dir, logPath: filepath.Join(dir, "log"), now: func() time.Time { return time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC) }, maxKeys: 3,
		hostKey: func() string { return "SHA256:hostkey" }, rules: func() string { return "" }}
}

func TestSSHAddDelete(t *testing.T) {
	m := newSSH(t)
	os.WriteFile(m.keysFile(), []byte(sshStdOptions+" "+testKey1+"\n"), 0o600)
	fp, err := m.Add("command=\"/bin/sh\" " + testKey2) // an attacker-style options field must be replaced, not kept
	if err != nil || fp != testFP2 {
		t.Fatalf("%v %q", err, fp)
	}
	b, _ := os.ReadFile(m.keysFile())
	if strings.Contains(string(b), "command=") || strings.Count(string(b), sshStdOptions) != 2 {
		t.Errorf("options not normalised:\n%s", b)
	}
	if fi, _ := os.Stat(m.keysFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if _, err := os.Stat(m.keysFile() + ".prev"); err != nil {
		t.Error("no .prev backup")
	}
	if _, err := m.Add(testKey2); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := m.Add(testKey1 + "\n" + testKey2); err == nil {
		t.Error("two lines accepted")
	}
	if _, err := m.Add(testRSA); err == nil {
		t.Error("rsa accepted")
	}
	if err := m.Delete("SHA256:nope"); err == nil {
		t.Error("deleting a missing key did not complain")
	}
	if err := m.Delete(testFP1); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(testFP2); err == nil || !strings.Contains(err.Error(), "only key") {
		t.Errorf("the last key must be protected: %v", err)
	}
	if v := m.View(); len(v.Keys) != 1 || v.Keys[0].Fingerprint != testFP2 || v.HostKey != "SHA256:hostkey" {
		t.Errorf("%+v", v)
	}
}

func TestSSHKeyLimit(t *testing.T) {
	m := newSSH(t)
	os.WriteFile(m.keysFile(), []byte(sshStdOptions+" "+testKey1+"\n"), 0o600)
	m.maxKeys = 1
	if _, err := m.Add(testKey2); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("%v", err)
	}
}

const sshLog = `[100] Oct 02 08:55:34 Child connection from 192.168.1.2:37896
[100] Oct 02 08:55:34 Port forwarding disabled.
[100] Oct 02 08:55:34 Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:AAA from 192.168.1.2:37896
[100] Oct 02 08:56:00 Exit (root) from <192.168.1.2:37896>: Disconnect received
[101] Oct 02 09:10:00 Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:BBB from 192.168.1.10:5555
[102] Oct 02 09:20:00 Exit before auth from <192.168.1.99:4444>: (user 'root', 0 fails): Max auth tries reached
[103] Oct 02 09:21:00 Bad password attempt for 'root' from 192.168.1.99:4445
[104] Dec 31 23:59:59 Pubkey auth succeeded for 'root' with ssh-ed25519 key SHA256:AAA from 192.168.1.2:1
garbage line
`

func TestParseSSHLogAndAnnotate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ev := parseSSHLog(sshLog, now)
	var logins, fails, outs int
	for _, e := range ev {
		switch e.Kind {
		case "login":
			logins++
		case "failed":
			fails++
		case "logout":
			outs++
		}
	}
	if logins != 3 || fails != 2 || outs != 1 {
		t.Fatalf("logins %d fails %d outs %d: %+v", logins, fails, outs, ev)
	}
	for _, e := range ev {
		if e.Kind == "login" && e.Key == "SHA256:AAA" && time.Unix(e.Time, 0).UTC().Month() == 12 && time.Unix(e.Time, 0).UTC().Year() != 2025 {
			t.Errorf("a December line seen in October belongs to last year: %v", time.Unix(e.Time, 0).UTC())
		}
	}
	keys := []sshKey{{Fingerprint: "SHA256:AAA"}, {Fingerprint: "SHA256:BBB"}, {Fingerprint: "SHA256:CCC"}}
	s := sshAnnotate(keys, ev)
	if keys[0].Logins != 2 || keys[1].Logins != 1 || keys[2].Logins != 0 || keys[1].LastFrom != "192.168.1.10" || s.Failed != 2 || len(s.Failures) != 1 || s.Failures[0] != "192.168.1.99" {
		t.Errorf("%+v %+v", keys, s)
	}
}

func TestSSHSources(t *testing.T) {
	r := "-A INPUT -s 192.168.1.2/32 -d 192.168.1.254/32 -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -s 192.168.1.10/32 -d 192.168.1.254/32 -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 12/min -j ACCEPT\n-A INPUT -d 192.168.1.254/32 -p tcp -m tcp --dport 22 -j DROP\n-A INPUT -s 10.9.9.9/32 -p tcp --dport 80 -j ACCEPT\n"
	got := sshSources(r)
	if len(got) != 2 || got[0] != "192.168.1.10" || got[1] != "192.168.1.2" {
		t.Errorf("%v", got)
	}
}
