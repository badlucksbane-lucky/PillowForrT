package main

import (
	"os"
	"strings"
	"testing"
)

// `tinyfwd -set-wifi NAME [-set-wifi-5ghz-name NAME5]`: the installer sets the Wi-Fi name and password over USB, with the same backup, hostapd check
// and rollback as the web page, but without waiting for a device to rejoin (nothing is connected during a first install).

func xmlOf(t *testing.T, f *fakeRadio) string {
	b, err := os.ReadFile(f.env.xmlPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetWifiCLISetsBothRadios(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	msg, err := setWifiCLI(m, "Hearth", "Hearth-5G", strings.NewReader("a-fresh-long-password\n"))
	if err != nil || !strings.Contains(msg, "network name") || !strings.Contains(msg, "password") {
		t.Fatalf("msg %q err %v", msg, err)
	}
	raw := xmlOf(t, f)
	for _, c := range [][3]string{{"Basic_0", "ssid", "Hearth"}, {"Basic_0", "psk", "a-fresh-long-password"}, {"Basic_1", "ssid", "Hearth-5G"}, {"Basic_1", "psk", "a-fresh-long-password"}} {
		if v, _ := xmlGet(raw, c[0], c[1]); v != c[2] {
			t.Errorf("%s/%s = %q, want %q", c[0], c[1], v, c[2])
		}
	}
	if f.restarts != 1 || len(m.backups()) != 1 {
		t.Errorf("restarts %d, backups %v (want 1 and 1)", f.restarts, m.backups())
	}
	if strings.Contains(msg, "a-fresh-long-password") {
		t.Error("the message leaked the password")
	}
}

func TestSetWifiCLINameOnlyKeepsPasswordAndLeavesFiveAlone(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	if _, err := setWifiCLI(m, "Hearth", "", strings.NewReader("\n")); err != nil {
		t.Fatal(err)
	}
	raw := xmlOf(t, f)
	if v, _ := xmlGet(raw, "Basic_0", "psk"); v != "old-secret-pass" {
		t.Errorf("password changed to %q with an empty password line", v)
	}
	if want, _ := xmlGet(wlanSample, "Basic_1", "ssid"); true {
		if v, _ := xmlGet(raw, "Basic_1", "ssid"); v != want {
			t.Errorf("5 GHz name touched: %q (was %q)", v, want)
		}
	}
}

func TestSetWifiCLIRefusesBadInputWithoutTouchingAnything(t *testing.T) {
	for name, c := range map[string]struct{ n, n5, pw string }{
		"short password":   {"Hearth", "", "short\n"},
		"empty name":       {"", "", "a-fresh-long-password\n"},
		"name too long":    {strings.Repeat("x", 33), "", "a-fresh-long-password\n"},
		"control in name":  {"bad\x01name", "", "a-fresh-long-password\n"},
		"password 64 long": {"Hearth", "", strings.Repeat("p", 64) + "\n"},
	} {
		f := newFakeRadio(t)
		before := xmlOf(t, f)
		m := newWifiManager(f.env)
		if _, err := setWifiCLI(m, c.n, c.n5, strings.NewReader(c.pw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if xmlOf(t, f) != before || f.restarts != 0 || len(m.backups()) != 0 {
			t.Errorf("%s: touched the unit (restarts %d, backups %v)", name, f.restarts, m.backups())
		}
	}
}

func TestSetWifiCLIRollsBackWhenItDoesNotTake(t *testing.T) {
	f := newFakeRadio(t)
	before := xmlOf(t, f)
	f.down = true // hostapd never comes back, so the new settings cannot be confirmed
	m := newWifiManager(f.env)
	_, err := setWifiCLI(m, "Hearth", "", strings.NewReader("a-fresh-long-password\n"))
	if err == nil || !strings.Contains(err.Error(), "previous settings were restored") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "a-fresh-long-password") {
		t.Error("the error leaked the password")
	}
	if xmlOf(t, f) != before || f.restarts != 2 {
		t.Errorf("not restored (restarts %d)", f.restarts)
	}
}

func TestSetWifiCLINothingToChange(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	orig, _ := xmlGet(wlanSample, "Basic_0", "ssid")
	msg, err := setWifiCLI(m, orig, "", strings.NewReader("old-secret-pass\n"))
	if err != nil || msg != "nothing to change" || f.restarts != 0 {
		t.Errorf("msg %q err %v restarts %d", msg, err, f.restarts)
	}
}

func TestSetWifiCLIReadsOnlyFirstLine(t *testing.T) {
	f := newFakeRadio(t)
	m := newWifiManager(f.env)
	if _, err := setWifiCLI(m, "Hearth", "", strings.NewReader("a-fresh-long-password\nignored second line\n")); err != nil {
		t.Fatal(err)
	}
	if v, _ := xmlGet(xmlOf(t, f), "Basic_0", "psk"); v != "a-fresh-long-password" {
		t.Errorf("psk %q", v)
	}
}
