package main

// The block list: devices (by MAC) that are cut off from the network. The stock admin's own Wi-Fi list only works through an internal request nothing else can make
// (found 2026-10-02: editing ACL_0 in the settings file never fills hostapd's deny file), and even a filled deny file does not hold on this driver: a device dropped by a
// hostapd reload walked straight back in (tested 2026-10-02). So the block is enforced where it does hold:
//   - the iptables chain HS_MACBLOCK drops everything from that MAC (INPUT and FORWARD, hooked first): no DHCP, no DNS, no internet, no LAN, and established flows die;
//   - the device is deauthenticated whenever it is seen associated (it may rejoin the radio, but is cut off at once and kicked again within seconds).
// The list of record is /data/proxy/macblock.list (survives reboots). A reconcile loop re-asserts the chain (the stock firmware rebuilds its own chains at times) and
// re-kicks. No radio restart, so nobody else is disturbed.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const macBlockHeader = "# Block list (one MAC per line), managed from https://orbic/ . Enforced by tinyfwd (iptables chain HS_MACBLOCK and deauthentication).\n"

type macFilter struct {
	mu       sync.Mutex
	listPath string
	firewall func(list []string) error // make the iptables chain match the list (idempotent)
	kick     func(mac string) error    // deauthenticate one station
	online   func() []string           // MACs currently associated
}

func defaultMacFilter() *macFilter {
	return &macFilter{listPath: *macBlockFile, firewall: applyMacChain,
		kick: func(mac string) error {
			_, err := run("hostapd_cli", "-p", "/tmp", "-i", "wlan0", "deauthenticate", mac)
			return err
		},
		online: func() []string {
			out, _ := run("hostapd_cli", "-p", "/tmp", "-i", "wlan0", "all_sta")
			var m []string
			for _, s := range parseStations(out) {
				m = append(m, s.MAC)
			}
			return m
		}}
}

// applyMacChain builds HS_MACBLOCK: one DROP per MAC, hooked at the top of INPUT and FORWARD. The MACs are validated before they get here.
func applyMacChain(list []string) error {
	var b strings.Builder
	b.WriteString("iptables -N HS_MACBLOCK 2>/dev/null\n")
	b.WriteString(fmt.Sprintf("[ \"$(iptables -S HS_MACBLOCK | grep -c -- '-j DROP')\" = %d ] && ", len(list)))
	for _, m := range list {
		b.WriteString(fmt.Sprintf("iptables -C HS_MACBLOCK -m mac --mac-source %s -j DROP 2>/dev/null && ", m))
	}
	b.WriteString("true || { iptables -F HS_MACBLOCK")
	for _, m := range list {
		b.WriteString(fmt.Sprintf(" && iptables -A HS_MACBLOCK -m mac --mac-source %s -j DROP", m))
	}
	b.WriteString("; }\n")
	for _, c := range []string{"INPUT", "FORWARD"} {
		b.WriteString(fmt.Sprintf("[ \"$(iptables -S %s | sed -n 2p)\" = '-A %s -j HS_MACBLOCK' ] || { while iptables -D %s -j HS_MACBLOCK 2>/dev/null; do :; done; iptables -I %s 1 -j HS_MACBLOCK; }\n", c, c, c, c))
	}
	out, err := run("sh", "-c", b.String())
	if err != nil {
		return fmt.Errorf("firewall: %v %s", err, out)
	}
	return nil
}

func readMACSet(path string) []string {
	b, _ := os.ReadFile(path)
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.ToLower(strings.TrimSpace(l))
		if macRe.MatchString(l) && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

func (f *macFilter) List() []string { f.mu.Lock(); defer f.mu.Unlock(); return readMACSet(f.listPath) }

func (f *macFilter) write(list []string) error {
	return writeFileAtomic(f.listPath, []byte(macBlockHeader+strings.Join(list, "\n")+"\n"), 0o600)
}

// Add blocks a MAC. `self` is the MAC of whoever is asking (never blockable: it would cut off the page being used).
func (f *macFilter) Add(mac, self string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	if mac == self {
		return errors.New("that is the device you are using right now: blocking it would cut you off")
	}
	list := readMACSet(f.listPath)
	for _, m := range list {
		if m == mac {
			return errors.New("already blocked")
		}
	}
	if len(list) >= 32 {
		return errors.New("too many blocked devices (32 is the limit)")
	}
	list = append(list, mac)
	sort.Strings(list)
	if err := f.write(list); err != nil {
		return err
	}
	if err := f.firewall(list); err != nil {
		return fmt.Errorf("saved, but %v (it is re-applied within 20 seconds)", err)
	}
	f.kick(mac)
	return nil
}

func (f *macFilter) Remove(mac string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	mac = strings.ToLower(strings.TrimSpace(mac))
	list := readMACSet(f.listPath)
	var keep []string
	for _, m := range list {
		if m != mac {
			keep = append(keep, m)
		}
	}
	if len(keep) == len(list) {
		return errors.New("that MAC address is not blocked")
	}
	if err := f.write(keep); err != nil {
		return err
	}
	if err := f.firewall(keep); err != nil {
		return fmt.Errorf("saved, but %v (it is re-applied within 20 seconds)", err)
	}
	return nil
}

// Reconcile re-asserts the firewall chain from the list and kicks any blocked device that is associated.
func (f *macFilter) Reconcile() {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := readMACSet(f.listPath)
	if err := f.firewall(list); err != nil {
		log.Printf("mac filter: %v", err)
		return
	}
	if len(list) == 0 {
		return
	}
	on := map[string]bool{}
	for _, m := range f.online() {
		on[m] = true
	}
	for _, m := range list {
		if on[m] {
			f.kick(m)
		}
	}
}

func (f *macFilter) Run() {
	for {
		f.Reconcile()
		time.Sleep(20 * time.Second)
	}
}

type blockedView struct {
	MAC    string `json:"mac"`
	Name   string `json:"name,omitempty"`
	Online bool   `json:"online"` // associated with the radio right now (cut off all the same)
}

func (f *macFilter) View(names map[string]string, stations string) []blockedView {
	on := map[string]bool{}
	for _, s := range parseStations(stations) {
		on[s.MAC] = true
	}
	out := []blockedView{}
	for _, m := range f.List() {
		out = append(out, blockedView{MAC: m, Name: names[m], Online: on[m]})
	}
	return out
}

// Replace swaps the whole block list (a restore). `self` can never be on it.
func (f *macFilter) Replace(list []string, self string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var clean []string
	for _, m := range list {
		m = strings.ToLower(strings.TrimSpace(m))
		if !macRe.MatchString(m) || seen[m] {
			continue
		}
		if m == self {
			return errors.New("that list blocks the device you are using right now: restoring it would cut you off")
		}
		seen[m] = true
		clean = append(clean, m)
	}
	if len(clean) > 32 {
		return errors.New("too many blocked devices (32 is the limit)")
	}
	sort.Strings(clean)
	if err := f.write(clean); err != nil {
		return err
	}
	if err := f.firewall(clean); err != nil {
		return fmt.Errorf("saved, but %v (it is re-applied within 20 seconds)", err)
	}
	for _, m := range clean {
		f.kick(m)
	}
	return nil
}
