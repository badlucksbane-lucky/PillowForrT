package main

// ARP spoof detection: ARP has no authentication, so any device on the network can claim to be the gateway (or any other address) and pull that traffic through itself. The Orbic
// watches every ARP frame on the bridge, passively, through an AF_PACKET socket with a kernel filter that passes only ARP, and looks at who CLAIMS an address (the sender fields of
// requests and replies; the 0.0.0.0 "is anyone using this?" probes claim nothing). Three findings:
//   - arp_gateway (alert): a MAC that is not the Orbic's own claims one of the Orbic's addresses (.1 gateway, .254, the canary): someone is impersonating the router.
//   - arp_conflict (alert): a MAC claims an address reserved for a different device.
//   - arp_flip (attention): an address held by one MAC a moment ago (within 10 minutes) is now claimed by another; a quick change of owner is how poisoning looks, though a device
//     that rejoined under a new random MAC can look the same, so it is only "to look at".
// One event per address per 10 minutes; the public text never names a device or address. Nothing is ever sent. Honest limit: unicast ARP between two Wi-Fi clients is relayed inside
// the radio and never reaches the bridge, so the broadcast announcements and anything aimed at the Orbic are what can be seen.

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
	Name  string `json:"name,omitempty"`
}

type arpWatch struct {
	mu       sync.Mutex
	own      func() map[string]bool // the Orbic's own addresses
	selfMAC  func() string
	reserved func() map[string]reservation // by IP
	nameOf   func(mac string) string
	bind     map[string]*arpBinding
	lastEv   map[string]time.Time
	finds    []arpFinding
	claims   int
	now      func() time.Time
	emit     func(evt)
	capOK    bool
	capOnce  bool
}

func newARPWatch() *arpWatch {
	return &arpWatch{bind: map[string]*arpBinding{}, lastEv: map[string]time.Time{}, now: time.Now,
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
	key := f.Kind + "|" + c.IP
	if t, ok := w.lastEv[key]; ok && now.Sub(t) < 10*time.Minute {
		return
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
	var e evt
	switch f.Kind {
	case "arp_gateway":
		e = evt{Kind: f.Kind, Sev: sevAlert, Text: fmt.Sprintf("%s is claiming to be the Orbic's own address %s: someone may be impersonating the router.", w.label(c.MAC), c.IP), Public: "A device on the network is impersonating the router's address"}
	case "arp_conflict":
		e = evt{Kind: f.Kind, Sev: sevAlert, Text: fmt.Sprintf("%s is claiming %s, which is reserved for %s.", w.label(c.MAC), c.IP, w.label(f.Other)), Public: "A device is claiming an address reserved for another device"}
	default:
		e = evt{Kind: f.Kind, Sev: sevAttention, Text: fmt.Sprintf("The address %s changed hands within 10 minutes: it was %s, now %s claims it. A device that rejoined under a new random MAC looks the same, so this is one to look at, not proof.", c.IP, w.label(f.Other), w.label(c.MAC)), Public: "An address on the network quickly changed owner"}
	}
	e.T = f.T
	w.emit(e)
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
	}
}

type arpView struct {
	Available bool         `json:"available"`
	CaptureOK bool         `json:"capture_ok"`
	Claims    int          `json:"claims_seen"`
	Addresses int          `json:"addresses"`
	Findings  []arpFinding `json:"findings"` // newest first, last 24 hours
	Alerts    int          `json:"alerts"`   // arp_gateway and arp_conflict in the last 24 hours
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
		if f.Kind != "arp_flip" {
			v.Alerts++
		}
	}
	sort.SliceStable(v.Findings, func(i, j int) bool { return v.Findings[i].T > v.Findings[j].T })
	return v
}

var arpMgr *arpWatch
