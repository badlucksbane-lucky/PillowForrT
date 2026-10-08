package main

import (
	"errors"
	"strings"
	"testing"
)

type fakeTor struct {
	macs map[string]bool
	log  *[]string
}

func (f *fakeTor) SetDevice(mac string, on bool) error {
	*f.log = append(*f.log, "tor:"+mac+":"+map[bool]string{true: "on", false: "off"}[on])
	if on {
		f.macs[mac] = true
	} else {
		delete(f.macs, mac)
	}
	return nil
}
func (f *fakeTor) HasDevice(mac string) bool { return f.macs[mac] }

type fakeVPN struct {
	exits map[string]string
	log   *[]string
	err   error
}

func (f *fakeVPN) SetDeviceExit(ip, e string) error {
	if f.err != nil {
		return f.err
	}
	*f.log = append(*f.log, "vpn:"+ip+":"+e)
	if e == "default" {
		delete(f.exits, ip)
	} else {
		f.exits[ip] = e
	}
	return nil
}

func testModeDeps() (modeDeps, *fakeTor, *fakeVPN, *[]string) {
	var log []string
	ft := &fakeTor{macs: map[string]bool{}, log: &log}
	fv := &fakeVPN{exits: map[string]string{}, log: &log}
	return modeDeps{tor: ft, vpn: fv, macOfIP: func() map[string]string { return map[string]string{"192.168.1.50": torMAC} }}, ft, fv, &log
}

// Leaving Mullvad for Tor and Tor for Mullvad is make-before-break: the new mode is on before the old one is taken away.
func TestDeviceModeMakeBeforeBreak(t *testing.T) {
	d, ft, fv, log := testModeDeps()
	fv.exits["192.168.1.50"] = "mullvad"
	if err := d.set("192.168.1.50", "", "tor"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*log, ",") != "tor:"+torMAC+":on,vpn:192.168.1.50:default" {
		t.Errorf("Mullvad -> Tor must turn Tor on first, then drop the exit override: %v", *log)
	}
	if !ft.macs[torMAC] || fv.exits["192.168.1.50"] != "" {
		t.Errorf("the device must be in exactly one mode: tor=%v exits=%v", ft.macs, fv.exits)
	}
	*log = nil
	if err := d.set("192.168.1.50", "", "mullvad"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(*log, ",") != "vpn:192.168.1.50:mullvad,tor:"+torMAC+":off" {
		t.Errorf("Tor -> Mullvad must put the exit in place first, then take the device off Tor: %v", *log)
	}
	if ft.macs[torMAC] || fv.exits["192.168.1.50"] != "mullvad" {
		t.Errorf("after the switch: tor=%v exits=%v", ft.macs, fv.exits)
	}
}

// A refused new mode must leave the old one in force: the device is never released first.
func TestDeviceModeFailedSwitchKeepsOldMode(t *testing.T) {
	d, ft, fv, _ := testModeDeps()
	ft.macs[torMAC] = true
	fv.err = errors.New("register this Orbic with your Mullvad account first")
	if err := d.set("192.168.1.50", "", "mullvad"); err == nil {
		t.Fatal("the error must come back")
	}
	if !ft.macs[torMAC] {
		t.Error("a failed move to Mullvad must not take the device off Tor")
	}
}

func TestDeviceModeRefusals(t *testing.T) {
	d, _, _, log := testModeDeps()
	if d.set("192.168.1.50", "", "bogus") == nil {
		t.Error("unknown mode refused")
	}
	if d.set("", "", "tor") == nil {
		t.Error("no device refused")
	}
	if d.set("192.168.1.99", "", "tor") == nil {
		t.Error("a device with no known MAC cannot be assigned to Tor")
	}
	if d.set("", "aa:aa:aa:aa:aa:aa", "mullvad") == nil {
		t.Error("a MAC with no known address cannot be given an exit")
	}
	if len(*log) != 0 {
		t.Errorf("nothing may change when a request is refused: %v", *log)
	}
	if got := d.current("192.168.1.50", "", func(string) string { return "" }); got != "default" {
		t.Errorf("current: %s", got)
	}
}
