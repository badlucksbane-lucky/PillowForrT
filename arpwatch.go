package main

// ARP spoof detection: ARP has no authentication, so any device on the network can claim to be the gateway (or any other address) and pull that traffic through itself. The box
// watches every ARP frame on the bridge, passively, through an AF_PACKET socket with a kernel filter that passes only ARP, and looks at who CLAIMS an address (the sender fields of
// requests and replies; the 0.0.0.0 "is anyone using this?" probes claim nothing). Three findings:
//   - arp_gateway (alert): a MAC that is not the box's own claims one of the box's addresses (.1 gateway, .254, the canary): someone is impersonating the router.
//   - arp_conflict (alert): a MAC claims an address reserved for a different device.
//   - arp_flip (attention): an address held by one MAC a moment ago (within 10 minutes) is now claimed by another; a quick change of owner is how poisoning looks, though a device
//     that rejoined under a new random MAC can look the same, so it is only "to look at".
//   - arp_sweep (attention): one MAC asking "who has?" for 20 or more different LAN addresses within a minute. That is a host scan, the first step of nmap, of a worm and of a
//     network-discovery app alike, and it is the recon the canary only catches when it happens to touch the decoy address. A new phone enumerating the LAN for printers and
//     Chromecasts does the same once, so it is only "to look at". Only addresses inside the LAN's /24 count: a device with a wrong netmask asks for the whole internet and that
//     is a misconfiguration, not a scan. The box's own requests never count.
// One event per address (per asker, for a sweep) per 10 minutes; the public text never names a device or address. Nothing is ever sent. Honest limit: unicast ARP between two
// Wi-Fi clients is relayed inside the radio and never reaches the bridge, so the broadcast announcements (which is what a sweep is made of) and anything aimed at the box are
// what can be seen.

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// arpBPF accepts only ARP frames. Classic BPF.
func arpBPF() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12] the ethertype
		{Code: 0x15, Jt: 0, Jf: 1, K: 0x0806}, // 1 jeq ARP else -> 3 (drop)
		{Code: 0x06, K: 65535},                // 2 accept
		{Code: 0x06, K: 0},                    // 3 drop
	}
}

type arpClaim struct{ IP, MAC string }

// parseARPClaim returns the address a frame's sender claims. ok is false for anything that is not a well-formed IPv4-over-Ethernet ARP request or reply, and for the all-zero sender
// of an address probe.
func parseARPClaim(b []byte) (arpClaim, bool) {
	var c arpClaim
	if len(b) < 42 || binary.BigEndian.Uint16(b[12:14]) != 0x0806 || binary.BigEndian.Uint16(b[14:16]) != 1 || binary.BigEndian.Uint16(b[16:18]) != 0x0800 || b[18] != 6 || b[19] != 4 {
		return c, false
	}
	if op := binary.BigEndian.Uint16(b[20:22]); op != 1 && op != 2 {
		return c, false
	}
	ip := net.IP(b[28:32])
	if ip.Equal(net.IPv4zero) {
		return c, false
	}
	mac := macStr(b[22:28])
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return c, false
	}
	return arpClaim{IP: ip.String(), MAC: mac}, true
}

// parseARPRequest returns who asked and which address they asked for in an ARP request ("who has X?"). An address probe (sender 0.0.0.0) counts: a scanner with no address yet
// still asks. ok is false for replies and for anything malformed.
func parseARPRequest(b []byte) (mac, senderIP, target string, ok bool) {
	if len(b) < 42 || binary.BigEndian.Uint16(b[12:14]) != 0x0806 || binary.BigEndian.Uint16(b[14:16]) != 1 || binary.BigEndian.Uint16(b[16:18]) != 0x0800 || b[18] != 6 || b[19] != 4 {
		return "", "", "", false
	}
	if binary.BigEndian.Uint16(b[20:22]) != 1 {
		return "", "", "", false
	}
	mac = macStr(b[22:28])
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return "", "", "", false
	}
	t := net.IP(b[38:42])
	if t.Equal(net.IPv4zero) {
		return "", "", "", false
	}
	if s := net.IP(b[28:32]); !s.Equal(net.IPv4zero) {
		senderIP = s.String()
	}
	return mac, senderIP, t.String(), true
}

const (
	arpSweepWindow    = time.Minute
	arpSweepThreshold = 20
)

// arpSweep is what one MAC has asked for lately.
type arpSweep struct {
	Targets map[string]time.Time // address asked for -> when, pruned to the window
	IP      string               // the asker's own address, when it gave one
	Last    time.Time
}

type arpBinding struct {
	MAC  string
	Last time.Time
}

type arpFinding struct {
	T     int64  `json:"t"`
	Kind  string `json:"kind"` // arp_gateway | arp_conflict | arp_flip
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Other string `json:"other,omitempty"` // the MAC that held it before (flip) or owns it (conflict)
	Count int    `json:"count,omitempty"` // sweep: how many different addresses were asked for
	Name  string `json:"name,omitempty"`
}

type arpWatch struct {
	mu       sync.Mutex
	own      func() map[string]bool // the box's own addresses
	selfMAC  func() string
	reserved func() map[string]reservation // by IP
	nameOf   func(mac string) string
	lan      *net.IPNet // the LAN; only addresses inside it count towards a sweep
	bind     map[string]*arpBinding
	sweep    map[string]*arpSweep // by asking MAC
	lastEv   map[string]time.Time
	finds    []arpFinding
	claims   int
	now      func() time.Time
	emit     func(evt)
	capOK    bool
	capOnce  bool
}

func newARPWatch() *arpWatch {
	_, lan, _ := net.ParseCIDR(lanCIDR)
	return &arpWatch{bind: map[string]*arpBinding{}, sweep: map[string]*arpSweep{}, lastEv: map[string]time.Time{}, now: time.Now, lan: lan,
		own: func() map[string]bool {
			m := map[string]bool{"192.168.1.1": true, "192.168.1.254": true}
			if canaryMgr != nil {
				m[canaryMgr.ip.String()] = true
			} else {
				m["192.168.1.253"] = true
			}
			return m
		},
		selfMAC: func() string {
			if ifc, err := net.InterfaceByName("bridge0"); err == nil {
				return macStr(ifc.HardwareAddr)
			}
			return ""
		},
		reserved: func() map[string]reservation {
			m := map[string]reservation{}
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					m[r.IP] = r
				}
			}
			return m
		},
		nameOf: func(mac string) string {
			if dhcpMgr != nil {
				for _, r := range dhcpMgr.List() {
					if r.MAC == mac {
						return r.Name
					}
				}
			}
			return ""
		},
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		}}
}

func (w *arpWatch) label(mac string) string {
	if n := w.nameOf(mac); n != "" {
		return n + " (" + mac + ")"
	}
	return mac
}

func (w *arpWatch) observe(c arpClaim) {
	own, self, resv := w.own(), w.selfMAC(), w.reserved()
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	w.claims++
	if macChurnMgr != nil { // macchurn.go: a wider, two-directional view of the same claims
		macChurnMgr.Observe(c, now)
	}
	prev := w.bind[c.IP]
	w.bind[c.IP] = &arpBinding{MAC: c.MAC, Last: now}
	if len(w.bind) > 2048 { // a flood of invented addresses must not grow memory: drop the stale ones
		for k, b := range w.bind {
			if now.Sub(b.Last) > time.Hour {
				delete(w.bind, k)
			}
		}
		for k := range w.bind { // still too many (a fast flood): forget arbitrary ones down to half
			if len(w.bind) <= 1024 {
				break
			}
			delete(w.bind, k)
		}
	}
	var f *arpFinding
	switch {
	case own[c.IP] && self != "" && c.MAC != self:
		f = &arpFinding{Kind: "arp_gateway", Other: self}
	case resv[c.IP].MAC != "" && resv[c.IP].MAC != c.MAC && !own[c.IP]:
		f = &arpFinding{Kind: "arp_conflict", Other: resv[c.IP].MAC}
	case prev != nil && prev.MAC != c.MAC && now.Sub(prev.Last) < 10*time.Minute && !own[c.IP]:
		f = &arpFinding{Kind: "arp_flip", Other: prev.MAC}
	}
	if f == nil {
		return
	}
	f.T, f.IP, f.MAC, f.Name = now.Unix(), c.IP, c.MAC, w.nameOf(c.MAC)
	if !w.keep(f, f.Kind+"|"+c.IP, now) {
		return
	}
	var e evt
	switch f.Kind {
	case "arp_gateway":
		e = evt{Kind: f.Kind, Sev: sevAlert, Text: fmt.Sprintf("%s is claiming to be the box's own address %s: someone may be impersonating the router.", w.label(c.MAC), c.IP), Public: "A device on the network is impersonating the router's address"}
	case "arp_conflict":
		e = evt{Kind: f.Kind, Sev: sevAlert, Text: fmt.Sprintf("%s is claiming %s, which is reserved for %s.", w.label(c.MAC), c.IP, w.label(f.Other)), Public: "A device is claiming an address reserved for another device"}
	default:
		e = evt{Kind: f.Kind, Sev: sevAttention, Text: fmt.Sprintf("The address %s changed hands within 10 minutes: it was %s, now %s claims it. A device that rejoined under a new random MAC looks the same, so this is one to look at, not proof.", c.IP, w.label(f.Other), w.label(c.MAC)), Public: "An address on the network quickly changed owner"}
	}
	e.T = f.T
	w.emit(e)
}

// keep records a finding unless the same one (by key) was raised within the last 10 minutes. Must hold w.mu.
func (w *arpWatch) keep(f *arpFinding, key string, now time.Time) bool {
	if t, ok := w.lastEv[key]; ok && now.Sub(t) < 10*time.Minute {
		return false
	}
	w.lastEv[key] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	w.finds = append(w.finds, *f)
	if len(w.finds) > 50 {
		w.finds = w.finds[len(w.finds)-50:]
	}
	return true
}

// observeRequest counts one "who has X?" towards a sweep by the asker: arpSweepThreshold different LAN addresses within arpSweepWindow is a host scan.
func (w *arpWatch) observeRequest(mac, senderIP, target string) {
	if mac == w.selfMAC() {
		return
	}
	if t := net.ParseIP(target); t == nil || (w.lan != nil && !w.lan.Contains(t)) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	s := w.sweep[mac]
	if s == nil {
		if len(w.sweep) >= 256 { // a flood of invented senders must not grow memory
			for k, o := range w.sweep {
				if now.Sub(o.Last) > arpSweepWindow {
					delete(w.sweep, k)
				}
			}
			for k := range w.sweep {
				if len(w.sweep) < 128 {
					break
				}
				delete(w.sweep, k)
			}
		}
		s = &arpSweep{Targets: map[string]time.Time{}}
		w.sweep[mac] = s
	}
	s.Last = now
	if senderIP != "" {
		s.IP = senderIP
	}
	for k, t := range s.Targets {
		if now.Sub(t) > arpSweepWindow {
			delete(s.Targets, k)
		}
	}
	if len(s.Targets) < 4*arpSweepThreshold { // enough to say "a scan"; the count shown is capped, the memory with it
		s.Targets[target] = now
	}
	if len(s.Targets) < arpSweepThreshold {
		return
	}
	f := &arpFinding{T: now.Unix(), Kind: "arp_sweep", IP: s.IP, MAC: mac, Count: len(s.Targets), Name: w.nameOf(mac)}
	if !w.keep(f, "arp_sweep|"+mac, now) {
		return
	}
	s.Targets = map[string]time.Time{} // the next event needs a fresh run of asks, not the tail of this one
	w.emit(evt{T: f.T, Kind: f.Kind, Sev: sevAttention,
		Text:   fmt.Sprintf("%s asked the network for %d different addresses within a minute: that is a host scan, the way nmap, a worm and a network-discovery app all start. A new phone looking for printers and Chromecasts does the same once, so this is one to look at, not proof.", w.label(mac), f.Count),
		Public: "A device is scanning the network for other devices"})
}

func (w *arpWatch) Start() {
	w.mu.Lock()
	if w.capOnce {
		w.mu.Unlock()
		return
	}
	w.capOnce = true
	w.mu.Unlock()
	go func() {
		for {
			if err := w.capture(); err != nil {
				log.Printf("ARP watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *arpWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := arpBPF()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	w.mu.Lock()
	w.capOK = true
	w.mu.Unlock()
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if c, ok := parseARPClaim(buf[:n]); ok {
			w.observe(c)
		}
		if mac, sender, target, ok := parseARPRequest(buf[:n]); ok {
			w.observeRequest(mac, sender, target)
		}
	}
}

type arpView struct {
	Available bool         `json:"available"`
	CaptureOK bool         `json:"capture_ok"`
	Claims    int          `json:"claims_seen"`
	Addresses int          `json:"addresses"`
	Findings  []arpFinding `json:"findings"` // newest first, last 24 hours
	Alerts    int          `json:"alerts"`   // arp_gateway and arp_conflict in the last 24 hours
	Sweeps    int          `json:"sweeps"`   // arp_sweep in the last 24 hours; the rest of Findings are flips
}

// RecentImpersonation reports whether an arp_gateway or arp_conflict finding (never arp_flip, which is only "to look at") landed within the last `within` of now. Used by
// dnsmitm.go to raise a suspect DNS redirect to a confirmed one when both signs show up close together.
func (w *arpWatch) RecentImpersonation(within time.Duration, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.finds) - 1; i >= 0; i-- {
		f := w.finds[i]
		if now.Unix()-f.T > int64(within.Seconds()) {
			break
		}
		if f.Kind == "arp_gateway" || f.Kind == "arp_conflict" {
			return true
		}
	}
	return false
}

func (w *arpWatch) View() arpView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := arpView{Available: true, CaptureOK: w.capOK, Claims: w.claims, Addresses: len(w.bind), Findings: []arpFinding{}}
	cut := w.now().Add(-24 * time.Hour).Unix()
	for i := len(w.finds) - 1; i >= 0; i-- {
		f := w.finds[i]
		if f.T < cut {
			continue
		}
		v.Findings = append(v.Findings, f)
		switch f.Kind {
		case "arp_gateway", "arp_conflict":
			v.Alerts++
		case "arp_sweep":
			v.Sweeps++
		}
	}
	sort.SliceStable(v.Findings, func(i, j int) bool { return v.Findings[i].T > v.Findings[j].T })
	return v
}

var arpMgr *arpWatch
