package main

// Rogue DHCP detection: a second DHCP server on the house network (a plugged-in router, a phone sharing its connection, a hostile device) can hand out its own gateway and DNS and
// steer every device that listens to it. The Orbic is the only legitimate server, so tinyfwd watches the bridge, through an AF_PACKET socket with a kernel filter that lets only
// UDP frames from port 67 through, and looks at every DHCP reply (offer, ack, nak). A reply is honest only if it comes from one of the Orbic's own addresses AND from the bridge's
// own MAC address (so a device that merely forges the gateway's IP is caught too). Anything else is a rogue server: one event per server per 10 minutes, and the page lists it.
// Purely passive: nothing is ever sent. Honest limit: a reply the radio relays Wi-Fi to Wi-Fi without touching the bridge is invisible, though a DHCP reply to a client's
// broadcast normally is not.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// rogueBPF accepts only IPv4 UDP frames whose source port is 67 (the DHCP server side). Classic BPF; the IPv4 header length is read from the frame.
func rogueBPF() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]          the ethertype
		{Code: 0x15, Jt: 0, Jf: 6, K: 0x0800}, // 1 jeq IPv4 else -> 8 (drop)
		{Code: 0x30, K: 23},                   // 2 ldb [23]          the IP protocol
		{Code: 0x15, Jt: 0, Jf: 4, K: 17},     // 3 jeq UDP else -> 8
		{Code: 0xb1, K: 14},                   // 4 ldxb 4*([14]&0xf) the IPv4 header length
		{Code: 0x48, K: 14},                   // 5 ldh [x+14]        the UDP source port
		{Code: 0x15, Jt: 0, Jf: 1, K: 67},     // 6 jeq 67 else -> 8
		{Code: 0x06, K: 65535},                // 7 accept
		{Code: 0x06, K: 0},                    // 8 drop
	}
}

type dhcpReply struct {
	SrcIP, SrcMAC, ServerID string
	Type                    string // offer | ack | nak
	Yiaddr                  string
	ClientMAC               string
}

// parseDHCPReply reads one frame that passed the filter. ok is false unless it is a BOOTP reply carrying a DHCP offer, ack or nak.
func parseDHCPReply(b []byte) (dhcpReply, bool) {
	var r dhcpReply
	if len(b) < 14+20+8+240 || binary.BigEndian.Uint16(b[12:14]) != 0x0800 || b[23] != 17 {
		return r, false
	}
	ihl := int(b[14]&0x0f) * 4
	if ihl < 20 || len(b) < 14+ihl+8+240 || binary.BigEndian.Uint16(b[14+ihl:]) != 67 {
		return r, false
	}
	d := b[14+ihl+8:]
	if d[0] != 2 || binary.BigEndian.Uint32(d[236:240]) != 0x63825363 { // op BOOTREPLY and the DHCP magic cookie
		return r, false
	}
	r.SrcIP, r.SrcMAC = net.IP(b[26:30]).String(), macStr(b[6:12])
	r.Yiaddr = net.IP(d[16:20]).String()
	r.ClientMAC = macStr(d[28:34])
	o := d[240:]
	for i := 0; i < len(o); {
		code := o[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(o) || i+2+int(o[i+1]) > len(o) {
			break
		}
		v := o[i+2 : i+2+int(o[i+1])]
		switch {
		case code == 53 && len(v) == 1:
			switch v[0] {
			case 2:
				r.Type = "offer"
			case 5:
				r.Type = "ack"
			case 6:
				r.Type = "nak"
			}
		case code == 54 && len(v) == 4:
			r.ServerID = net.IP(v).String()
		}
		i += 2 + int(o[i+1])
	}
	return r, r.Type != ""
}

type rogueServer struct {
	IP, MAC, ServerID string
	First, Last       time.Time
	Replies           int
	Types             map[string]bool
	Gave              string // the last address it offered or acked
	Client            string
	LastEvent         time.Time
}

// An allowed server is one the owner runs on purpose (a second router in the house, a lab DHCP server): identified by its MAC address, never by IP, so a forged address does not
// inherit the trust. Its replies are counted and listed but raise nothing.
type rogueAllowed struct {
	IP      string
	Last    time.Time
	Replies int
}

type rogueWatch struct {
	path    string
	allow   []string
	allowed map[string]*rogueAllowed
	mu      sync.Mutex
	legitIP map[string]bool
	selfMAC func() string // the bridge's own MAC: the honest server's frames carry it
	servers map[string]*rogueServer
	honest  int
	now     func() time.Time
	emit    func(evt)
	capOK   bool
	capOnce bool
}

func newRogueWatch() *rogueWatch {
	w := &rogueWatch{path: *rogueFile, allowed: map[string]*rogueAllowed{}, legitIP: map[string]bool{"192.168.1.1": true, "192.168.1.254": true}, servers: map[string]*rogueServer{}, now: time.Now,
		selfMAC: func() string {
			if ifc, err := net.InterfaceByName("bridge0"); err == nil {
				return macStr(ifc.HardwareAddr)
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

func (w *rogueWatch) save() {
	if w.path == "" {
		return
	}
	b, _ := json.Marshal(struct {
		Allow []string `json:"allow"`
	}{w.allow})
	writeFileAtomic(w.path, b, 0o600)
}

func (w *rogueWatch) isAllowed(mac string) bool {
	for _, m := range w.allow {
		if m == mac {
			return true
		}
	}
	return false
}

// Allow adds or removes a server MAC from the allow-list. Allowing also forgets it from the list of rogue servers.
func (w *rogueWatch) Allow(mac string, add bool) error {
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
			return errors.New("too many allowed servers (8 is the limit)")
		}
		if mac == w.selfMAC() {
			return errors.New("that is the Orbic's own address: it is always trusted")
		}
		keep = append(keep, mac)
		for k, s := range w.servers {
			if s.MAC == mac {
				delete(w.servers, k)
			}
		}
	} else {
		delete(w.allowed, mac)
	}
	w.allow = keep
	w.save()
	return nil
}

// honestReply says whether a DHCP reply came from us: our own address, our own MAC. With no MAC known (the bridge unreadable) the address alone decides, rather than raising false alarms.
func (w *rogueWatch) honestReply(r dhcpReply) bool {
	if !w.legitIP[r.SrcIP] {
		return false
	}
	m := w.selfMAC()
	return m == "" || r.SrcMAC == m
}

func (w *rogueWatch) record(r dhcpReply) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.honestReply(r) {
		w.honest++
		return
	}
	now := w.now()
	if w.isAllowed(r.SrcMAC) {
		a := w.allowed[r.SrcMAC]
		if a == nil {
			a = &rogueAllowed{}
			w.allowed[r.SrcMAC] = a
		}
		a.IP, a.Last, a.Replies = r.SrcIP, now, a.Replies+1
		return
	}
	for k, s := range w.servers { // forget servers quiet for a day
		if now.Sub(s.Last) > 24*time.Hour {
			delete(w.servers, k)
		}
	}
	key := r.SrcIP + "|" + r.SrcMAC
	s := w.servers[key]
	if s == nil {
		s = &rogueServer{IP: r.SrcIP, MAC: r.SrcMAC, First: now, Types: map[string]bool{}}
		w.servers[key] = s
	}
	s.Last, s.Replies, s.ServerID, s.Client = now, s.Replies+1, r.ServerID, r.ClientMAC
	s.Types[r.Type] = true
	if r.Type != "nak" && r.Yiaddr != "0.0.0.0" {
		s.Gave = r.Yiaddr
	}
	if s.LastEvent.IsZero() || now.Sub(s.LastEvent) > 10*time.Minute {
		s.LastEvent = now
		given := ""
		if s.Gave != "" {
			given = ", offering " + s.Gave
		}
		w.emit(evt{T: now.Unix(), Kind: "rogue_dhcp", Sev: sevAlert, Text: fmt.Sprintf("Another DHCP server is answering on the network: %s (%s)%s. Devices that listen to it can be sent to the wrong gateway or DNS.", s.IP, s.MAC, given), Public: "An unexpected DHCP server is answering on the network"})
	}
}

func (w *rogueWatch) Start() {
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
				log.Printf("rogue DHCP watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *rogueWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := rogueBPF()
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
		if r, ok := parseDHCPReply(buf[:n]); ok {
			w.record(r)
		}
	}
}

type rogueServerView struct {
	IP      string   `json:"ip"`
	MAC     string   `json:"mac"`
	Name    string   `json:"name,omitempty"`
	Replies int      `json:"replies"`
	Types   []string `json:"types"`
	Gave    string   `json:"offered,omitempty"`
	First   int64    `json:"first"`
	Last    int64    `json:"last"`
}

type rogueAllowedView struct {
	MAC     string `json:"mac"`
	IP      string `json:"ip,omitempty"` // the address it last answered from, if it has answered since the Orbic started
	Replies int    `json:"replies"`
	Last    int64  `json:"last,omitempty"`
}

type rogueView struct {
	Allowed   []rogueAllowedView `json:"allowed"`
	Available bool               `json:"available"`
	CaptureOK bool               `json:"capture_ok"`
	Honest    int                `json:"honest_replies"`
	Servers   []rogueServerView  `json:"servers"`
}

func (w *rogueWatch) View() rogueView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := rogueView{Available: true, CaptureOK: w.capOK, Honest: w.honest, Servers: []rogueServerView{}, Allowed: []rogueAllowedView{}}
	for _, m := range w.allow {
		av := rogueAllowedView{MAC: m}
		if a := w.allowed[m]; a != nil {
			av.IP, av.Replies, av.Last = a.IP, a.Replies, a.Last.Unix()
		}
		v.Allowed = append(v.Allowed, av)
	}
	for _, s := range w.servers {
		sv := rogueServerView{IP: s.IP, MAC: s.MAC, Replies: s.Replies, Gave: s.Gave, First: s.First.Unix(), Last: s.Last.Unix()}
		for t := range s.Types {
			sv.Types = append(sv.Types, t)
		}
		sort.Strings(sv.Types)
		v.Servers = append(v.Servers, sv)
	}
	sort.Slice(v.Servers, func(i, j int) bool { return v.Servers[i].Last > v.Servers[j].Last })
	return v
}

var rogueMgr *rogueWatch
