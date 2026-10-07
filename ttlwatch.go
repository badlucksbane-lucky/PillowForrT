package main

// Hidden-router detection from the IP time-to-live: every operating system starts its packets with a fixed TTL (64 for Linux, Android, iOS and macOS; 128 for Windows; 255 for
// some BSDs and network gear; 32 on a few old stacks), and every router a packet crosses takes one off. A packet that arrives on the bridge from a device's MAC with a TTL
// one short of any of those (63, 127, 254) has already crossed a router: the device is forwarding for something behind it. That is what a phone re-sharing this hotspot, a
// travel router plugged into it, or a guest hiding a second machine behind a NAT looks like, and it is exactly how carriers detect tethering. A second shape is the same
// MAC presenting two different initial TTLs at once (64 and 128 together): two operating systems answering from one address. Both are read passively from the first packet of
// each connection (a TCP SYN, or a DNS query to the stub), through an AF_PACKET socket filtered in-kernel to those two packet kinds and nothing else, so the cost is a few
// bytes per new connection. Honest limits: a laptop running containers or a virtual machine behind its own NAT looks the same as a hidden router (its own traffic arrives
// one hop short), which is why this is never more than "to look at", at most once per device per day, and a device can be marked expected from the page. A tethering tool
// that sets its TTL one higher on purpose (65 arriving as 64) defeats it entirely. Traffic the radio relays Wi-Fi-to-Wi-Fi never reaches the bridge, but the first packet of
// every connection to the internet or to this box does.

import (
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

// bpfFirstPackets accepts only the first packet of an IPv4 connection: a TCP SYN without ACK, or a UDP datagram to port 53.
func bpfFirstPackets() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                    // 0  ldh [12]           ethertype
		{Code: 0x15, Jt: 0, Jf: 11, K: 0x0800}, // 1  jeq IPv4 -> 2, else drop (13)
		{Code: 0x30, K: 23},                    // 2  ldb [23]           IP protocol
		{Code: 0x15, Jt: 0, Jf: 4, K: 6},       // 3  jeq TCP -> 4, else -> 8
		{Code: 0xb1, K: 14},                    // 4  ldx 4*([14]&0xf)   IP header length
		{Code: 0x50, K: 27},                    // 5  ldb [x+27]         TCP flags (byte 13 of the TCP header)
		{Code: 0x54, K: 0x12},                  // 6  and SYN|ACK
		{Code: 0x15, Jt: 4, Jf: 5, K: 0x02},    // 7  jeq SYN only -> accept (12), else drop (13)
		{Code: 0x15, Jt: 0, Jf: 4, K: 17},      // 8  jeq UDP -> 9, else drop (13)
		{Code: 0xb1, K: 14},                    // 9  ldx 4*([14]&0xf)
		{Code: 0x48, K: 16},                    // 10 ldh [x+16]         UDP destination port
		{Code: 0x15, Jt: 0, Jf: 1, K: 53},      // 11 jeq 53 -> accept (12), else drop (13)
		{Code: 0x06, K: 65535},                 // 12 accept
		{Code: 0x06, K: 0},                     // 13 drop
	}
}

var initialTTLs = []int{32, 64, 128, 255}

// ttlClass says which initial TTL a seen value most likely started from and how many routers it crossed. ok is false for a value too far from any (more than 8 hops),
// which is not something a device on the LAN produces and is not learned.
func ttlClass(ttl int) (initial, hops int, ok bool) {
	for _, in := range initialTTLs {
		if ttl <= in {
			if in-ttl > 8 {
				return 0, 0, false
			}
			return in, in - ttl, true
		}
	}
	return 0, 0, false
}

// parseFirstPacket reads the source MAC, source address and TTL off one frame that passed the filter.
func parseFirstPacket(b []byte) (mac, ip string, ttl int, ok bool) {
	if len(b) < 34 {
		return "", "", 0, false
	}
	return macStr(b[6:12]), net.IP(b[26:30]).String(), int(b[22]), true
}

type ttlTrack struct {
	MAC       string         `json:"mac"`
	IP        string         `json:"ip"`
	Direct    int            `json:"direct"`  // first packets that arrived with an initial TTL (sent by the device itself)
	Behind    int            `json:"behind"`  // first packets that arrived one or more hops short (sent by something behind the device)
	Classes   map[string]int `json:"classes"` // initial TTL -> count, for the direct packets
	Last      int64          `json:"last"`
	window    time.Time      // when the counters began
	lastEvent time.Time
}

type ttlFinding struct {
	T    int64  `json:"t"`
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Kind string `json:"kind"` // ttl_forwarding | ttl_two_stacks
	Note string `json:"note"`
}

type ttlState struct {
	Ignore []string `json:"ignore"` // MACs marked expected (a router or a container host you run on purpose)
}

type ttlWatch struct {
	mu      sync.Mutex
	path    string
	st      ttlState
	tracks  map[string]*ttlTrack
	finds   []ttlFinding
	own     map[string]bool
	ownMAC  string
	now     func() time.Time
	emit    func(evt)
	nameOf  func(mac string) string
	capOK   bool
	capOnce bool
}

const (
	ttlWindow       = 10 * time.Minute
	ttlBehindMin    = 20 // one-hop-short first packets in a window before a device counts as forwarding
	ttlTwoStacksMin = 10 // direct first packets of EACH of two initial TTLs in a window before two stacks are called
)

func newTTLWatch(path string) *ttlWatch {
	w := &ttlWatch{path: path, tracks: map[string]*ttlTrack{}, own: map[string]bool{"192.168.1.1": true, "192.168.1.254": true, "192.168.1.253": true}, now: time.Now,
		emit: func(e evt) {
			if events != nil {
				events.Add([]evt{e})
			}
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
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &w.st)
	}
	if w.st.Ignore == nil {
		w.st.Ignore = []string{}
	}
	return w
}

func (w *ttlWatch) save() {
	if w.path == "" {
		return
	}
	b, _ := json.Marshal(w.st)
	writeFileAtomic(w.path, b, 0o600)
}

func (w *ttlWatch) label(mac, ip string) string {
	if n := w.nameOf(mac); n != "" {
		return fmt.Sprintf("%s (%s)", n, ip)
	}
	return fmt.Sprintf("%s (%s)", ip, mac)
}

// Observe is the pure half: counters per MAC over a 10-minute window, and the two findings. Kept apart from the capture loop so it is testable without a socket.
func (w *ttlWatch) Observe(mac, ip string, ttl int, now time.Time) {
	if mac == "" || w.own[ip] || (w.ownMAC != "" && mac == w.ownMAC) {
		return
	}
	initial, hops, ok := ttlClass(ttl)
	if !ok {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range w.st.Ignore {
		if m == mac {
			return
		}
	}
	for k, t := range w.tracks {
		if now.Sub(time.Unix(t.Last, 0)) > 24*time.Hour {
			delete(w.tracks, k)
		}
	}
	t := w.tracks[mac]
	if t == nil || now.Sub(t.window) > ttlWindow {
		last := time.Time{}
		if t != nil {
			last = t.lastEvent
		}
		t = &ttlTrack{MAC: mac, Classes: map[string]int{}, window: now, lastEvent: last}
		w.tracks[mac] = t
	}
	t.IP, t.Last = ip, now.Unix()
	if hops == 0 {
		t.Direct++
		t.Classes[fmt.Sprint(initial)]++
	} else {
		t.Behind++
	}
	if now.Sub(t.lastEvent) < 24*time.Hour {
		return
	}
	who := w.label(mac, ip)
	switch {
	case t.Behind >= ttlBehindMin:
		t.lastEvent = now
		note := fmt.Sprintf("%d of its connections arrived one hop short", t.Behind)
		w.addFinding(ttlFinding{T: now.Unix(), MAC: mac, IP: ip, Kind: "ttl_forwarding", Note: note})
		w.emit(evt{T: now.Unix(), Kind: "ttl_forwarding", Sev: sevAttention, Text: fmt.Sprintf("%s is passing traffic for something behind it: %s (a router, a shared connection, or containers or a virtual machine on that device).", who, note), Public: "A device on the network appears to be forwarding for other devices behind it"})
	case twoStacks(t.Classes):
		t.lastEvent = now
		note := "two different initial TTLs from one address: " + classesText(t.Classes)
		w.addFinding(ttlFinding{T: now.Unix(), MAC: mac, IP: ip, Kind: "ttl_two_stacks", Note: note})
		w.emit(evt{T: now.Unix(), Kind: "ttl_two_stacks", Sev: sevAttention, Text: fmt.Sprintf("%s looks like two operating systems answering from one address (%s): a device sharing its connection without NAT, or two machines on one MAC.", who, note), Public: "Two different operating systems appear to be sharing one address on the network"})
	}
}

func twoStacks(classes map[string]int) bool {
	n := 0
	for _, c := range classes {
		if c >= ttlTwoStacksMin {
			n++
		}
	}
	return n >= 2
}

func classesText(classes map[string]int) string {
	var ks []string
	for k := range classes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var parts []string
	for _, k := range ks {
		parts = append(parts, fmt.Sprintf("TTL %s x%d", k, classes[k]))
	}
	return strings.Join(parts, ", ")
}

func (w *ttlWatch) addFinding(f ttlFinding) {
	w.finds = append(w.finds, f)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
}

func (w *ttlWatch) IgnoreMAC(mac string, add bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if _, err := net.ParseMAC(mac); err != nil || len(mac) != 17 {
		return errors.New("that is not a MAC address")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	keep := []string{}
	for _, m := range w.st.Ignore {
		if m != mac {
			keep = append(keep, m)
		}
	}
	if add {
		if len(keep) >= 50 {
			return errors.New("at most 50 devices")
		}
		keep = append(keep, mac)
		delete(w.tracks, mac)
	}
	w.st.Ignore = keep
	w.save()
	return nil
}

func (w *ttlWatch) Start() {
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
				log.Printf("TTL watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *ttlWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	w.ownMAC = macStr(ifc.HardwareAddr)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfFirstPackets()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	w.mu.Lock()
	w.capOK = true
	w.mu.Unlock()
	buf := make([]byte, 128) // the headers are all that is read; the rest of the frame is left in the kernel
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
		if mac, ip, ttl, ok := parseFirstPacket(buf[:n]); ok {
			w.Observe(mac, ip, ttl, w.now())
		}
	}
}

type ttlView struct {
	CaptureOK bool         `json:"capture_ok"`
	Ignore    []string     `json:"ignore"`
	Devices   []ttlTrack   `json:"devices"` // the current window, per device
	Findings  []ttlFinding `json:"findings"`
}

func (w *ttlWatch) View() ttlView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := ttlView{CaptureOK: w.capOK, Ignore: append([]string{}, w.st.Ignore...), Devices: []ttlTrack{}, Findings: []ttlFinding{}}
	for _, t := range w.tracks {
		c := *t
		c.Classes = map[string]int{}
		for k, n := range t.Classes {
			c.Classes[k] = n
		}
		v.Devices = append(v.Devices, c)
	}
	sort.Slice(v.Devices, func(i, j int) bool { return v.Devices[i].IP < v.Devices[j].IP })
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var ttlMgr *ttlWatch
