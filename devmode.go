package main

// One mode per device: Default, Direct, Mullvad or Tor. The settings behind them live in two places (Tor keeps a MAC list, the VPN keeps an exit per IPv4 address), and a device used to be
// able to sit in both, or in neither for a moment while it was moved. setDeviceMode changes both together, make-before-break: the new mode is switched on first and the old one is
// taken away last, so there is never a moment when the device is on neither (which for a device leaving Tor or Mullvad would mean its traffic and its lookups going out the plain way).
// The Tor rules come before the VPN rules everywhere (nat before the mark, the DNS hook before the exit), so while a device is in both it is a Tor device.

import (
	"errors"
	"strings"
)

type torDevices interface {
	SetDevice(mac string, on bool) error
	HasDevice(mac string) bool
}

type vpnExits interface {
	SetDeviceExit(ip, exit string) error
}

type modeDeps struct {
	tor     torDevices
	vpn     vpnExits
	macOfIP func() map[string]string
}

var validDeviceModes = map[string]bool{"default": true, "direct": true, "mullvad": true, "tor": true}

// resolveDevice fills in whichever of ip and mac is missing, from the ARP table and the leases.
func (d modeDeps) resolveDevice(ip, mac string) (string, string, error) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	ip = strings.TrimSpace(ip)
	m := d.macOfIP()
	switch {
	case mac == "" && ip != "":
		mac = m[ip]
	case ip == "" && mac != "":
		for i, mm := range m {
			if mm == mac {
				ip = i
				break
			}
		}
	}
	if ip == "" && mac == "" {
		return "", "", errors.New("say which device")
	}
	return ip, mac, nil
}

func (d modeDeps) set(ip, mac, mode string) error {
	if !validDeviceModes[mode] {
		return errors.New("mode must be default, direct, mullvad or tor")
	}
	ip, mac, err := d.resolveDevice(ip, mac)
	if err != nil {
		return err
	}
	if mode == "tor" {
		if d.tor == nil {
			return errors.New("Tor is not available on this build")
		}
		if mac == "" {
			return errors.New("that device is not on the network now, so its address is not known; Tor is assigned by address")
		}
		if err := d.tor.SetDevice(mac, true); err != nil { // Tor first: from this moment the device is a Tor device
			return err
		}
		if ip != "" && d.vpn != nil {
			return d.vpn.SetDeviceExit(ip, "default") // then the exit override goes, so the page does not show two modes
		}
		return nil
	}
	if ip == "" {
		return errors.New("that device is not on the network now, so its address is not known; the exit is set by address")
	}
	if d.vpn == nil {
		if mode != "default" {
			return errors.New("the VPN is not available on this build")
		}
	} else if err := d.vpn.SetDeviceExit(ip, mode); err != nil { // the new exit first (its mark is in place while Tor still holds the device)
		return err
	}
	if mac != "" && d.tor != nil && d.tor.HasDevice(mac) {
		return d.tor.SetDevice(mac, false) // Tor last
	}
	return nil
}

// currentDeviceMode names the mode a device is in (for the page and the tests).
func (d modeDeps) current(ip, mac string, exit func(ip string) string) string {
	ip, mac, _ = d.resolveDevice(ip, mac)
	if mac != "" && d.tor != nil && d.tor.HasDevice(mac) {
		return "tor"
	}
	if e := exit(ip); e != "" {
		return e
	}
	return "default"
}

func liveModeDeps() modeDeps {
	d := modeDeps{macOfIP: func() map[string]string {
		if torMgrG != nil && torMgrG.macOfIP != nil {
			return torMgrG.macOfIP()
		}
		return map[string]string{}
	}}
	if torMgrG != nil {
		d.tor = torMgrG
	}
	if vpn != nil {
		d.vpn = vpn
	}
	return d
}
