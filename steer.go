package main

// The steering watch: the messages that tell a device to change its router. Rogue DHCP (rogue.go) covers the IPv4 way of taking over a LAN's routing; this covers the three
// others, all of them one unauthenticated frame that every operating system honours by default:
//   - an IPv6 router advertisement (ICMPv6 type 134). Whoever sends one becomes a default router for every Windows, Android, Apple and Linux device that hears it, and the
//     RDNSS option in it hands them a DNS server as well, which Windows prefers over the IPv4 one it got from DHCP. That is the mitm6 attack. It works on the LAN even though
//     LAN IPv6 is off on this box (lanv6.go): "off" stops the box's own advertisements and refuses LAN IPv6 towards the cellular side, but the devices still listen to each
//     other, and a rogue advertiser needs no uplink to put itself between two of them or to answer their name lookups itself. The only honest advertiser on this bridge is the
//     the box (radish relaying the carrier's advertisements while LAN IPv6 is on, and the withdraw advertisement while it is off), always from the bridge's own MAC.
//   - an ICMPv6 redirect (type 137) and an ICMPv4 redirect (type 5): "send traffic for X through Y instead". Only a router sends them, the box is the only router here, and a
//     redirect from anything else steers one device's traffic through another.
// Every such frame from a MAC other than the bridge's own is an alert (ra_rogue, redirect_rogue), once per source per kind per 10 minutes. A second router the owner runs on
// purpose can be allowed by its MAC, as with rogue DHCP; never by address, which is what a forger controls. Read passively through an AF_PACKET socket filtered in the kernel to
// those three message types; nothing is ever sent. Honest limits: a router advertisement is multicast to every node, so it reaches the bridge whichever radio it came from, but
// a redirect is unicast to its victim, and one aimed by a Wi-Fi client at another on the same band is relayed inside the radio and never seen (one crossing bands, or aimed at
// a wired or USB device, is). The kernel filter expects ICMPv6 directly after the fixed IPv6 header, so an advertisement hidden behind an extension header or a fragment
// (which no honest router sends, and some evasion tools do) is not inspected.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// steerBPF accepts an ICMPv6 router advertisement (134) or redirect (137) carried directly after the fixed IPv6 header, and an ICMPv4 redirect (type 5). Nothing else.
func steerBPF() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0  ldh [12]            ethertype
		{Code: 0x15, Jt: 0, Jf: 5, K: 0x86dd}, // 1  jeq IPv6 -> 2, else -> 7 (try IPv4)
		{Code: 0x30, K: 20},                   // 2  ldb [20]            IPv6 next header
		{Code: 0x15, Jt: 0, Jf: 10, K: 58},    // 3  jeq ICMPv6 -> 4, else drop (14)
		{Code: 0x30, K: 54},                   // 4  ldb [54]            ICMPv6 type
		{Code: 0x15, Jt: 7, Jf: 0, K: 134},    // 5  jeq RA -> accept (13), else -> 6
		{Code: 0x15, Jt: 6, Jf: 7, K: 137},    // 6  jeq redirect -> accept (13), else drop (14)
		{Code: 0x15, Jt: 0, Jf: 6, K: 0x0800}, // 7  jeq IPv4 -> 8, else drop (14)
		{Code: 0x30, K: 23},                   // 8  ldb [23]            IP protocol
		{Code: 0x15, Jt: 0, Jf: 4, K: 1},      // 9  jeq ICMP -> 10, else drop (14)
		{Code: 0xb1, K: 14},                   // 10 ldx 4*([14]&0xf)    IP header length
		{Code: 0x50, K: 14},                   // 11 ldb [x+14]          ICMP type
		{Code: 0x15, Jt: 0, Jf: 1, K: 5},      // 12 jeq redirect -> accept (13), else drop (14)
		{Code: 0x06, K: 65535},                // 13 accept
		{Code: 0x06, K: 0},                    // 14 drop
	}
}

// steerMsg is one steering message read off the wire.
type steerMsg struct {
	T        int64    `json:"t"`
	Kind     string   `json:"kind"` // ra | redirect6 | redirect4
	MAC      string   `json:"mac"`
	IP       string   `json:"ip"`                 // the sender's address (link-local for IPv6)
	Lifetime int      `json:"lifetime,omitempty"` // ra: router lifetime in seconds; 0 means "do not use me as a default router" (a withdrawal)
	Managed  bool     `json:"managed,omitempty"`  // ra: the M flag, "get your address from DHCPv6"
	Prefixes []string `json:"prefixes,omitempty"` // ra: prefixes offered for address autoconfiguration
	DNS      []string `json:"dns,omitempty"`      // ra: recursive DNS servers offered (RDNSS)
	Search   bool     `json:"search,omitempty"`   // ra: a DNS search list was offered too (DNSSL)
	Victim   string   `json:"victim,omitempty"`   // redirect: the device being told
	Dest     string   `json:"dest,omitempty"`     // redirect: for traffic to this destination
	Via      string   `json:"via,omitempty"`      // redirect: use this router instead
	Name     string   `json:"name,omitempty"`
}

// parseSteer reads one frame that passed steerBPF. ok is false for anything truncated or not one of the three messages.
func parseSteer(b []byte) (steerMsg, bool) {
	var m steerMsg
	if len(b) < 34 {
		return m, false
	}
	m.MAC = macStr(b[6:12])
	switch binary.BigEndian.Uint16(b[12:14]) {
	case 0x86dd:
		if len(b) < 54+8 || b[20] != 58 {
			return m, false
		}
		m.IP = net.IP(b[22:38]).String()
		icmp := b[54:]
		switch icmp[0] {
		case 134:
			if len(icmp) < 16 {
				return m, false
			}
			m.Kind = "ra"
			m.Managed = icmp[5]&0x80 != 0
			m.Lifetime = int(binary.BigEndian.Uint16(icmp[6:8]))
			for o := icmp[16:]; len(o) >= 2; {
				l := int(o[1]) * 8
				if l == 0 || l > len(o) {
					break
				}
				switch {
				case o[0] == 3 && l == 32 && len(m.Prefixes) < 4: // prefix information
					m.Prefixes = append(m.Prefixes, fmt.Sprintf("%s/%d", net.IP(o[16:32]), o[2]))
				case o[0] == 25 && l >= 24: // RDNSS
					for i := 8; i+16 <= l && len(m.DNS) < 4; i += 16 {
						m.DNS = append(m.DNS, net.IP(o[i:i+16]).String())
					}
				case o[0] == 31: // DNSSL
					m.Search = true
				}
				o = o[l:]
			}
		case 137:
			if len(icmp) < 40 {
				return m, false
			}
			m.Kind, m.Victim, m.Via, m.Dest = "redirect6", net.IP(b[38:54]).String(), net.IP(icmp[8:24]).String(), net.IP(icmp[24:40]).String()
		default:
			return m, false
		}
	case 0x0800:
		ihl := int(b[14]&0x0f) * 4
		if ihl < 20 || len(b) < 14+ihl+8 || b[23] != 1 {
			return m, false
		}
		icmp := b[14+ihl:]
		if icmp[0] != 5 {
			return m, false
		}
		m.Kind, m.IP, m.Victim, m.Via = "redirect4", net.IP(b[26:30]).String(), net.IP(b[30:34]).String(), net.IP(icmp[4:8]).String()
		if len(icmp) >= 8+20 { // the original datagram's IP header follows: its destination is what the victim was trying to reach
			m.Dest = net.IP(icmp[8+16 : 8+20]).String()
		}
	default:
		return m, false
	}
	return m, true
}

type steerAllowed struct {
	MAC  string `json:"mac"`
	Seen int    `json:"seen"`
	Last int64  `json:"last,omitempty"`
}

type steerWatch struct {
	path    string
	mu      sync.Mutex
	allow   []string
	allowed map[string]*steerAllowed
	msgs    []steerMsg
	lastEv  map[string]time.Time
	honest  int // the box's own advertisements and redirects
	selfMAC func() string
	nameOf  func(mac string) string
	now     func() time.Time
	emit    func(evt)
	capOK   bool
	capOnce bool
}

func newSteerWatch(path string) *steerWatch {
	w := &steerWatch{path: path, allowed: map[string]*steerAllowed{}, lastEv: map[string]time.Time{}, now: time.Now,
		selfMAC: func() string {
			if ifc, err := net.InterfaceByName("bridge0"); err == nil {
				return macStr(ifc.HardwareAddr)
			}
			return ""
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
	if w.path != "" {
		if b, err := os.ReadFile(w.path); err == nil {
			var f struct {
				Allow []string `json:"allow"`
			}
			if json.Unmarshal(b, &f) == nil {
				w.allow = f.Allow
			}
		}
	}
	return w
}

func (w *steerWatch) save() {
	if w.path == "" {
		return
	}
	b, _ := json.Marshal(struct {
		Allow []string `json:"allow"`
	}{w.allow})
	writeFileAtomic(w.path, b, 0o600)
}

func (w *steerWatch) isAllowed(mac string) bool {
	for _, m := range w.allow {
		if m == mac {
			return true
		}
	}
	return false
}

// Allow adds or removes a router MAC from the allow-list. Allowing also forgets its messages from the card.
func (w *steerWatch) Allow(mac string, add bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var keep []string
	for _, m := range w.allow {
		if m != mac {
			keep = append(keep, m)
		}
	}
	if add {
		if len(keep) >= 8 {
			return errors.New("too many allowed routers (8 is the limit)")
		}
		if mac == w.selfMAC() {
			return errors.New("that is the box's own address: it is always trusted")
		}
		keep = append(keep, mac)
		var rest []steerMsg
		for _, m := range w.msgs {
			if m.MAC != mac {
				rest = append(rest, m)
			}
		}
		w.msgs = rest
	} else {
		delete(w.allowed, mac)
	}
	w.allow = keep
	w.save()
	return nil
}

func (w *steerWatch) label(mac string) string {
	if n := w.nameOf(mac); n != "" {
		return n + " (" + mac + ")"
	}
	return mac
}

// Observe records one steering message and raises the alert, once per source per kind per 10 minutes.
func (w *steerWatch) Observe(m steerMsg, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if self := w.selfMAC(); self != "" && m.MAC == self {
		w.honest++
		return
	}
	if w.isAllowed(m.MAC) {
		a := w.allowed[m.MAC]
		if a == nil {
			a = &steerAllowed{MAC: m.MAC}
			w.allowed[m.MAC] = a
		}
		a.Seen, a.Last = a.Seen+1, now.Unix()
		return
	}
	m.T, m.Name = now.Unix(), w.nameOf(m.MAC)
	w.msgs = append(w.msgs, m)
	if len(w.msgs) > 100 {
		w.msgs = w.msgs[len(w.msgs)-100:]
	}
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	key := m.Kind + "|" + m.MAC
	if t, ok := w.lastEv[key]; ok && now.Sub(t) < 10*time.Minute {
		return
	}
	w.lastEv[key] = now
	who := w.label(m.MAC)
	var e evt
	if m.Kind == "ra" {
		var d []string
		if m.Lifetime > 0 {
			d = append(d, fmt.Sprintf("default router for %d s", m.Lifetime))
		} else {
			d = append(d, "router lifetime 0, a withdrawal")
		}
		if m.Managed {
			d = append(d, "addresses by DHCPv6")
		}
		if len(m.Prefixes) > 0 {
			d = append(d, "prefix "+strings.Join(m.Prefixes, ", "))
		}
		if len(m.DNS) > 0 {
			d = append(d, "DNS servers "+strings.Join(m.DNS, ", "))
		}
		dns := ""
		if len(m.DNS) > 0 || m.Search {
			dns = " It offered DNS servers too, which Windows prefers over the ones DHCP gave it, so those devices' name lookups go around the encrypted DNS stub."
		}
		e = evt{Kind: "ra_rogue", Sev: sevAlert, Public: "A device on the network is announcing itself as a router",
			Text: fmt.Sprintf("%s is sending IPv6 router advertisements (%s). Only the box may do that: every device that listens sends traffic through the announcer, on the LAN whether or not LAN IPv6 is on. This is how mitm6-style attacks start; a second router you run yourself can be allowed on the card.%s", who, strings.Join(d, "; "), dns)}
	} else {
		fam := "ICMP"
		if m.Kind == "redirect6" {
			fam = "ICMPv6"
		}
		dest := ""
		if m.Dest != "" {
			dest = " for traffic to " + m.Dest
		}
		e = evt{Kind: "redirect_rogue", Sev: sevAlert, Public: "A device on the network is redirecting another device's traffic",
			Text: fmt.Sprintf("%s sent an %s redirect telling %s to use %s as its router%s. Only a router sends redirects and the box is the only router here, so this steers one device's traffic through another.", who, fam, m.Victim, m.Via, dest)}
	}
	e.T = m.T
	w.emit(e)
}

func (w *steerWatch) Start() {
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
				log.Printf("steering watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *steerWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := steerBPF()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	w.mu.Lock()
	w.capOK = true
	w.mu.Unlock()
	buf := make([]byte, 512) // an advertisement with a few options; anything longer is read truncated, and the options past the cut are simply not listed
	for {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n > len(buf) {
			n = len(buf)
		}
		if m, ok := parseSteer(buf[:n]); ok {
			w.Observe(m, w.now())
		}
	}
}

type steerView struct {
	Available bool           `json:"available"`
	CaptureOK bool           `json:"capture_ok"`
	Honest    int            `json:"honest"`   // the box's own messages seen
	Messages  []steerMsg     `json:"messages"` // newest first
	Alerts    int            `json:"alerts"`   // messages from anything other than the box in the last 24 hours
	Sources   int            `json:"sources"`  // distinct MACs behind them
	Allowed   []steerAllowed `json:"allowed"`
}

func (w *steerWatch) View() steerView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := steerView{Available: true, CaptureOK: w.capOK, Honest: w.honest, Messages: []steerMsg{}, Allowed: []steerAllowed{}}
	cut := w.now().Add(-24 * time.Hour).Unix()
	seen := map[string]bool{}
	for i := len(w.msgs) - 1; i >= 0; i-- {
		m := w.msgs[i]
		v.Messages = append(v.Messages, m)
		if m.T >= cut {
			v.Alerts++
			if !seen[m.MAC] {
				seen[m.MAC] = true
				v.Sources++
			}
		}
	}
	for _, mac := range w.allow {
		a := steerAllowed{MAC: mac}
		if s := w.allowed[mac]; s != nil {
			a = *s
		}
		v.Allowed = append(v.Allowed, a)
	}
	return v
}

var steerMgr *steerWatch
