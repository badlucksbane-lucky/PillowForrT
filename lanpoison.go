package main

// Name-poisoning responder watch: catches a Responder-style tool that answers every LLMNR (UDP 5355, unicast, RFC 4795) and NetBIOS Name Service (UDP 137, RFC 1002)
// name query on the LAN, the classic way to harvest NTLM credentials from a Windows box that could not find a name on a real DNS server and fell back to asking the
// whole segment. Both protocols reuse the DNS wire format closely enough that lanannounce.go's name reader (readName) parses either one: a 12-byte header whose
// top bit of byte 2 is the QR (response) bit, a question count, then that many length-prefixed, zero-terminated names. An honest host only ever answers for its own
// name (and NetBIOS/LLMNR traffic is usually quiet besides); a single source answering for ten or more different names inside a short window is not something any
// normal device does, since nothing on an ordinary LAN needs to resolve everyone else's name faster than the real server. Passive only: this never sends a query.
// Honest limits: the window is per source address only, so a NAT boundary or a very busy legitimate name server (rare on a home LAN) could in principle look the
// same; and like lanannounce.go this is IPv4 only and reads the names as sent, never verifying them.

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// bpfLLMNRNBNS accepts IPv4 UDP datagrams to port 5355 (LLMNR) or 137 (NetBIOS Name Service).
func bpfLLMNRNBNS() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]                the ethertype
		{Code: 0x15, Jt: 0, Jf: 7, K: 0x0800}, // 1 jeq IPv4 -> 2, else -> 9 (reject)
		{Code: 0x30, K: 23},                   // 2 ldb [23]                the IP protocol
		{Code: 0x15, Jt: 0, Jf: 5, K: 17},     // 3 jeq UDP  -> 4, else -> 9
		{Code: 0xb1, K: 14},                   // 4 ldx 4*([14]&0xf)        the IP header length into X
		{Code: 0x48, K: 14},                   // 5 ldh [x+14]              the UDP source port (the poisoner answers FROM 5355/137)
		{Code: 0x15, Jt: 1, Jf: 0, K: 5355},   // 6 jeq 5355 -> 8 (accept)
		{Code: 0x15, Jt: 0, Jf: 1, K: 137},    // 7 jeq 137  -> 8 (accept), else -> 9
		{Code: 0x06, K: 65535},                // 8 accept
		{Code: 0x06, K: 0},                    // 9 drop
	}
}

// parseResponderNames reads the questions of an LLMNR or NBNS message (both close enough to the DNS wire format
// for lanannounce.go's readName to decode) and reports whether the QR bit marked it a response. ok is false for
// anything too short or malformed to say either way.
func parseResponderNames(m []byte) (isResponse bool, names []string, ok bool) {
	if len(m) < 12 {
		return false, nil, false
	}
	isResponse = m[2]&0x80 != 0
	qd := be16(m[4:6])
	off := 12
	for i := 0; i < qd && i < 16; i++ {
		name, n, good := readName(m, off)
		if !good || n+4 > len(m) {
			return isResponse, names, i > 0
		}
		if name != "" {
			names = append(names, name)
		}
		off = n + 4 // QTYPE + QCLASS
	}
	return isResponse, names, true
}

const (
	poisonWindow    = 2 * time.Minute
	poisonThreshold = 10 // distinct names answered by one source inside the window
)

type poisonFinding struct {
	T     int64  `json:"t"`
	MAC   string `json:"mac,omitempty"`
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type nameAnswer struct {
	name string
	at   time.Time
}

type lanPoisonWatch struct {
	mu      sync.Mutex
	answers map[string][]nameAnswer // source IP -> recent (name, time) answers
	lastEv  map[string]time.Time
	finds   []poisonFinding
	now     func() time.Time
	emit    func(evt)
	macOf   func(ip string) string
	nameOf  func(mac string) string
	capOK   bool
	capOnce bool
}

func newLANPoisonWatch() *lanPoisonWatch {
	return &lanPoisonWatch{answers: map[string][]nameAnswer{}, lastEv: map[string]time.Time{}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
		},
		macOf: func(ip string) string {
			b, _ := os.ReadFile("/proc/net/arp")
			for mac, a := range parseARP(string(b)) {
				if a == ip {
					return mac
				}
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
		}}
}

func (w *lanPoisonWatch) label(ip, mac string) string {
	if n := w.nameOf(mac); n != "" {
		return fmt.Sprintf("%s (%s)", n, ip)
	}
	if mac != "" {
		return fmt.Sprintf("%s (%s)", ip, mac)
	}
	return ip
}

// observe handles one accepted LLMNR/NBNS response, from source src, answering for name.
func (w *lanPoisonWatch) observe(src, name string, now time.Time) {
	_, lan, _ := net.ParseCIDR(lanCIDR)
	ip := net.ParseIP(src)
	if ip == nil || !lan.Contains(ip) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-poisonWindow)
	list := w.answers[src]
	kept := list[:0]
	for _, a := range list {
		if a.at.After(cutoff) {
			kept = append(kept, a)
		}
	}
	kept = append(kept, nameAnswer{name: name, at: now})
	w.answers[src] = kept
	distinct := map[string]bool{}
	for _, a := range kept {
		distinct[a.name] = true
	}
	if len(distinct) < poisonThreshold {
		return
	}
	if t, had := w.lastEv[src]; had && now.Sub(t) < time.Hour {
		return
	}
	w.lastEv[src] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > 2*time.Hour {
			delete(w.lastEv, k)
		}
	}
	mac := w.macOf(src)
	f := poisonFinding{T: now.Unix(), MAC: mac, IP: src, Count: len(distinct)}
	w.finds = append(w.finds, f)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := w.label(src, mac)
	w.emit(evt{T: f.T, Kind: "lan_name_poison", Sev: sevAlert,
		Text:   fmt.Sprintf("%s answered LLMNR/NetBIOS name queries for %d different names in the last %s: an honest device only answers for its own name, so this is the signature of a Responder-style credential-harvesting tool.", who, f.Count, poisonWindow),
		Public: "A device on the network is answering name lookups it was never asked for"})
}

func (w *lanPoisonWatch) Start() {
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
				log.Printf("LAN name-poisoning watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *lanPoisonWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfLLMNRNBNS()
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
		if f, ok := parseUDPFrame(buf[:n]); ok {
			isResp, names, good := parseResponderNames(f.Payload)
			if !good || !isResp {
				continue
			}
			now := w.now()
			for _, name := range names {
				w.observe(f.Src, name, now)
			}
		}
	}
}

type lanPoisonView struct {
	CaptureOK bool            `json:"capture_ok"`
	Findings  []poisonFinding `json:"findings"`
}

func (w *lanPoisonWatch) View() lanPoisonView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := lanPoisonView{CaptureOK: w.capOK, Findings: []poisonFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	sort.Slice(v.Findings, func(i, j int) bool { return v.Findings[i].T > v.Findings[j].T })
	return v
}

var lanPoisonMgr *lanPoisonWatch
