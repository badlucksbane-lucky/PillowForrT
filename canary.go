package main

// The canary address (192.168.1.253): a decoy host that no honest device has any reason to talk to, so anything that touches it is looking around: a port scanner, a worm, a
// compromised device, a curious guest. tinyfwd gives the Orbic that address as an alias on the LAN bridge (so the kernel answers ARP for it), listens on a set of tempting TCP
// ports there (a slow tarpit, never a real service), and watches the wire for ANY packet or ARP request aimed at it, including pings and ports nothing listens on, through an
// AF_PACKET socket with a kernel packet filter (so only frames for .253 ever reach us). The first touch from a source raises an event "to look at"; a source that tries five or more
// ports raises a scan event; each at most once per 10 minutes per source. Nothing is ever sent beyond a trickle of banner bytes, no payload is stored, and the address is never
// handed out by DHCP or allowed in a reservation. Honest limits: Wi-Fi to Wi-Fi traffic the radio relays by itself never reaches the bridge, but a probe of .253 does (the address
// belongs to the Orbic, so the frames come to it), and the ARP sweep that precedes most scans is broadcast.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var canaryTCPPorts = []int{21, 22, 23, 25, 110, 139, 143, 445, 1433, 3306, 3389, 5900, 9100}

type canaryHit struct {
	T     int64  `json:"t"`
	Src   string `json:"src"`
	MAC   string `json:"mac,omitempty"`
	Proto string `json:"proto"` // tcp | udp | icmp | arp
	Port  int    `json:"port,omitempty"`
	Kind  string `json:"kind"` // syn | connect | udp | echo | who-has
}

type canarySource struct {
	First, Last   time.Time
	MAC           string
	Ports         map[string]bool
	Hits          int
	LastEvent     time.Time
	LastScanEvent time.Time
}

type canaryState struct {
	Enabled bool     `json:"enabled"`
	Ignore  []string `json:"ignore,omitempty"` // MACs that may touch it without an event
}

type canary struct {
	mu        sync.Mutex
	ip        net.IP
	path      string
	st        canaryState
	hits      []canaryHit
	sources   map[string]*canarySource
	now       func() time.Time
	emit      func(evt)
	nameOf    func(mac string) string
	own       map[string]bool
	listeners []net.Listener
	active    int
	perSrc    map[string]int
	maxConns  int
	lifetime  time.Duration
	aliasOK   bool
	capOK     bool
	capFD     int
	capOnce   bool
	lastHitAt time.Time
	macOf     func(ip string) string // the MAC behind an address (the ARP table): a tarpit connection carries none
	listen    func(addr string) (net.Listener, error)
	ensureIP  func(add bool) bool
}

func newCanary(ip net.IP) *canary {
	c := &canary{ip: ip.To4(), path: *canaryFile, sources: map[string]*canarySource{}, now: time.Now, own: map[string]bool{"192.168.1.1": true, "192.168.1.254": true, ip.String(): true},
		perSrc: map[string]int{}, maxConns: 16, lifetime: 90 * time.Second, listen: func(a string) (net.Listener, error) { return net.Listen("tcp4", a) }, capFD: -1,
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
	c.st.Enabled = true // on by default; the page can switch it off
	if b, err := os.ReadFile(c.path); err == nil {
		json.Unmarshal(b, &c.st)
	}
	c.ensureIP = c.aliasCmd
	return c
}

func (c *canary) save() {
	b, _ := json.Marshal(c.st)
	writeFileAtomic(c.path, b, 0o600)
}

// ---- the packet filter and the frame parser ----

// bpfProgram accepts an Ethernet frame only if it is IPv4 addressed to ip, or an ARP packet whose target is ip. Classic BPF: nothing else ever reaches user space.
func bpfProgram(ip net.IP) []unix.SockFilter {
	k := binary.BigEndian.Uint32(ip.To4())
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]              the ethertype
		{Code: 0x15, Jt: 0, Jf: 2, K: 0x0800}, // 1 jeq IPv4  -> 2, else -> 4
		{Code: 0x20, K: 30},                   // 2 ld  [30]              the IPv4 destination address
		{Code: 0x15, Jt: 3, Jf: 4, K: k},      // 3 jeq canary -> 7 (accept), else -> 8
		{Code: 0x15, Jt: 0, Jf: 3, K: 0x0806}, // 4 jeq ARP   -> 5, else -> 8 (A still holds the ethertype)
		{Code: 0x20, K: 38},                   // 5 ld  [38]              the ARP target protocol address
		{Code: 0x15, Jt: 0, Jf: 1, K: k},      // 6 jeq canary -> 7, else -> 8
		{Code: 0x06, K: 65535},                // 7 accept
		{Code: 0x06, K: 0},                    // 8 drop
	}
}

func macStr(b []byte) string { return strings.ToLower(net.HardwareAddr(b).String()) }

// parseCanaryFrame reads one frame that passed the filter. ok is false for anything that is not a probe worth recording.
func parseCanaryFrame(b []byte, canaryIP net.IP, now time.Time) (canaryHit, bool) {
	h := canaryHit{T: now.Unix()}
	if len(b) < 34 {
		return h, false
	}
	switch binary.BigEndian.Uint16(b[12:14]) {
	case 0x0806: // ARP
		if len(b) < 42 || binary.BigEndian.Uint16(b[20:22]) != 1 || !net.IP(b[38:42]).Equal(canaryIP) {
			return h, false
		}
		sender := net.IP(b[28:32])
		if sender.Equal(net.IPv4zero) { // an address-conflict probe (RFC 5227) from a device choosing its own address: sender 0.0.0.0, still a touch, so keep it
			h.Src = "0.0.0.0"
		} else {
			h.Src = sender.String()
		}
		h.MAC, h.Proto, h.Kind = macStr(b[22:28]), "arp", "who-has"
		return h, true
	case 0x0800:
		ihl := int(b[14]&0x0f) * 4
		if ihl < 20 || len(b) < 14+ihl+4 || !net.IP(b[30:34]).Equal(canaryIP) {
			return h, false
		}
		h.Src, h.MAC = net.IP(b[26:30]).String(), macStr(b[6:12])
		t := b[14+ihl:]
		switch b[23] {
		case 6: // TCP: only the first packet of a connection attempt (SYN without ACK); the rest of a conversation is noise
			if len(t) < 14 || t[13]&0x12 != 0x02 {
				return h, false
			}
			h.Proto, h.Kind, h.Port = "tcp", "syn", int(binary.BigEndian.Uint16(t[2:4]))
		case 17:
			h.Proto, h.Kind, h.Port = "udp", "udp", int(binary.BigEndian.Uint16(t[2:4]))
		case 1:
			if t[0] != 8 {
				return h, false
			}
			h.Proto, h.Kind = "icmp", "echo"
		default:
			return h, false
		}
		return h, true
	}
	return h, false
}

// ---- recording and the events ----

func (c *canary) record(h canaryHit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Enabled || c.own[h.Src] {
		return
	}
	for _, m := range c.st.Ignore {
		if m == h.MAC && m != "" {
			return
		}
	}
	now := c.now()
	if n := len(c.hits); n > 0 { // the bridge can present the same frame twice: an identical touch within half a second counts once
		if l := c.hits[n-1]; l.Src == h.Src && l.Proto == h.Proto && l.Port == h.Port && l.Kind == h.Kind && h.T-l.T <= 0 && now.Sub(c.lastHitAt) < 500*time.Millisecond {
			return
		}
	}
	c.lastHitAt = now
	c.hits = append(c.hits, h)
	if len(c.hits) > 200 {
		c.hits = c.hits[len(c.hits)-200:]
	}
	for k, s := range c.sources { // forget sources quiet for an hour
		if now.Sub(s.Last) > time.Hour {
			delete(c.sources, k)
		}
	}
	s := c.sources[h.Src]
	if s == nil {
		s = &canarySource{First: now, Ports: map[string]bool{}}
		c.sources[h.Src] = s
	}
	s.Last, s.Hits = now, s.Hits+1
	if h.MAC != "" {
		s.MAC = h.MAC
	}
	if h.Port != 0 {
		s.Ports[h.Proto+"/"+strconv.Itoa(h.Port)] = true
	}
	what := h.Kind
	if h.Port != 0 {
		what = fmt.Sprintf("%s port %d", h.Proto, h.Port)
	} else if h.Proto == "arp" {
		what = "an ARP lookup"
	} else if h.Proto == "icmp" {
		what = "a ping"
	}
	who := h.Src
	if n := c.nameOf(s.MAC); n != "" {
		who += " (" + n + ")"
	} else if s.MAC != "" {
		who += " (" + s.MAC + ")"
	}
	if s.LastEvent.IsZero() || now.Sub(s.LastEvent) > 10*time.Minute {
		s.LastEvent = now
		c.emit(evt{T: now.Unix(), Kind: "canary", Sev: sevAttention, Text: fmt.Sprintf("Something touched the canary address %s: %s tried %s", c.ip, who, what), Public: "Something on the network probed the decoy address"})
	}
	if len(s.Ports) >= 5 && (s.LastScanEvent.IsZero() || now.Sub(s.LastScanEvent) > 10*time.Minute) {
		s.LastScanEvent = now
		var ports []string
		for p := range s.Ports {
			ports = append(ports, p)
		}
		sort.Strings(ports)
		if len(ports) > 12 {
			ports = append(ports[:12], "...")
		}
		c.emit(evt{T: now.Unix(), Kind: "canary_scan", Sev: sevAttention, Text: fmt.Sprintf("%s is scanning the network: %d ports on the canary address (%s)", who, len(s.Ports), strings.Join(ports, ", ")), Public: "Something on the network is port-scanning the decoy address"})
	}
}

// ---- the alias address, the listeners and the capture ----

func (c *canary) aliasCmd(add bool) bool {
	have, _ := run("sh", "-c", "ip -4 addr show dev bridge0 | grep -c 'inet "+c.ip.String()+"/'")
	present := strings.TrimSpace(have) != "0"
	switch {
	case add && !present:
		run("ip", "addr", "add", c.ip.String()+"/32", "dev", "bridge0")
	case !add && present:
		run("ip", "addr", "del", c.ip.String()+"/32", "dev", "bridge0")
	}
	have, _ = run("sh", "-c", "ip -4 addr show dev bridge0 | grep -c 'inet "+c.ip.String()+"/'")
	return (strings.TrimSpace(have) != "0") == add
}

func (c *canary) Reconcile() {
	c.mu.Lock()
	enabled := c.st.Enabled
	c.mu.Unlock()
	ok := c.ensureIP(enabled)
	c.mu.Lock()
	c.aliasOK = ok
	c.mu.Unlock()
	if !enabled {
		c.closeListeners()
		return
	}
	c.openListeners()
	c.startCapture()
}

func (c *canary) closeListeners() {
	c.mu.Lock()
	ls := c.listeners
	c.listeners = nil
	c.mu.Unlock()
	for _, l := range ls {
		l.Close()
	}
}

func (c *canary) openListeners() {
	c.mu.Lock()
	if len(c.listeners) > 0 {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	for _, p := range canaryTCPPorts {
		l, err := c.listen(net.JoinHostPort(c.ip.String(), strconv.Itoa(p)))
		if err != nil {
			continue // a port that something else owns on the wildcard address: the capture still sees every touch
		}
		c.mu.Lock()
		c.listeners = append(c.listeners, l)
		c.mu.Unlock()
		go c.accept(l, p)
	}
}

func (c *canary) accept(l net.Listener, port int) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go c.hold(conn, port)
	}
}

// hold is the tarpit: a banner trickled out slowly for up to `lifetime`, at most maxConns at once and 3 per source, so a scanner wastes time and we spend almost nothing.
func (c *canary) hold(conn net.Conn, port int) {
	defer conn.Close()
	src := ""
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		src = a.IP.String()
	}
	c.mu.Lock()
	if c.active >= c.maxConns || c.perSrc[src] >= 3 {
		c.mu.Unlock()
		return
	}
	c.active++
	c.perSrc[src]++
	life := c.lifetime
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.active--
		if c.perSrc[src]--; c.perSrc[src] <= 0 {
			delete(c.perSrc, src)
		}
		c.mu.Unlock()
	}()
	mac := ""
	if c.macOf != nil {
		mac = c.macOf(src)
	}
	c.record(canaryHit{T: c.now().Unix(), Src: src, MAC: mac, Proto: "tcp", Port: port, Kind: "connect"})
	deadline := time.Now().Add(life)
	conn.SetDeadline(deadline)
	step := 8 * time.Second
	if life < 3*step {
		step = life / 4
	}
	var banner string
	switch port {
	case 22:
		banner = "SSH-2.0-OpenSSH_9.2p1\r\n"
	case 21:
		banner = "220 FTP server ready\r\n"
	case 25:
		banner = "220 mail ESMTP\r\n"
	case 110:
		banner = "+OK POP3 ready\r\n"
	case 143:
		banner = "* OK IMAP ready\r\n"
	}
	if banner != "" {
		conn.Write([]byte(banner[:4])) // only the start of it: the rest never comes
	}
	for time.Now().Before(deadline) {
		time.Sleep(step)
		if _, err := conn.Write([]byte(string(rune('a' + rand.Intn(26))))); err != nil {
			return
		}
	}
}

func (c *canary) startCapture() {
	c.mu.Lock()
	if c.capOnce {
		c.mu.Unlock()
		return
	}
	c.capOnce = true
	c.mu.Unlock()
	go func() {
		for {
			if err := c.captureLoop(); err != nil {
				log.Printf("canary capture: %v (retrying in a minute)", err)
			}
			c.mu.Lock()
			c.capOK = false
			c.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (c *canary) captureLoop() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfProgram(c.ip)
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	c.mu.Lock()
	c.capOK = true
	c.mu.Unlock()
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if h, ok := parseCanaryFrame(buf[:n], c.ip, c.now()); ok {
			c.record(h)
		}
	}
}

func (c *canary) Run() {
	for {
		c.Reconcile()
		time.Sleep(20 * time.Second)
	}
}

// ---- the page ----

type canaryView struct {
	Enabled   bool               `json:"enabled"`
	Address   string             `json:"address"`
	AliasOK   bool               `json:"alias_ok"`
	CaptureOK bool               `json:"capture_ok"`
	Ports     []int              `json:"ports"`
	Open      []int              `json:"listening"`
	Hits      []canaryHit        `json:"hits"`
	Sources   []canarySourceView `json:"sources"`
	Ignore    []string           `json:"ignore"`
}

type canarySourceView struct {
	Src   string   `json:"src"`
	MAC   string   `json:"mac,omitempty"`
	Name  string   `json:"name,omitempty"`
	Hits  int      `json:"hits"`
	Ports []string `json:"ports"`
	First int64    `json:"first"`
	Last  int64    `json:"last"`
}

func (c *canary) View() canaryView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := canaryView{Enabled: c.st.Enabled, Address: c.ip.String(), AliasOK: c.aliasOK, CaptureOK: c.capOK, Ports: canaryTCPPorts, Ignore: append([]string{}, c.st.Ignore...), Hits: []canaryHit{}, Sources: []canarySourceView{}, Open: []int{}}
	for _, l := range c.listeners {
		if a, ok := l.Addr().(*net.TCPAddr); ok {
			v.Open = append(v.Open, a.Port)
		}
	}
	sort.Ints(v.Open)
	for i := len(c.hits) - 1; i >= 0 && len(v.Hits) < 40; i-- {
		v.Hits = append(v.Hits, c.hits[i])
	}
	for src, s := range c.sources {
		sv := canarySourceView{Src: src, MAC: s.MAC, Hits: s.Hits, First: s.First.Unix(), Last: s.Last.Unix(), Name: c.nameOf(s.MAC)}
		for p := range s.Ports {
			sv.Ports = append(sv.Ports, p)
		}
		sort.Strings(sv.Ports)
		v.Sources = append(v.Sources, sv)
	}
	sort.Slice(v.Sources, func(i, j int) bool {
		if v.Sources[i].Last != v.Sources[j].Last {
			return v.Sources[i].Last > v.Sources[j].Last
		}
		return v.Sources[i].Src < v.Sources[j].Src
	})
	return v
}

func (c *canary) SetEnabled(on bool) {
	c.mu.Lock()
	c.st.Enabled = on
	c.save()
	c.mu.Unlock()
	c.Reconcile()
}

func (c *canary) IgnoreMAC(mac string, add bool) error {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if !macRe.MatchString(mac) {
		return errors.New("the MAC address must look like aa:bb:cc:dd:ee:ff")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var keep []string
	found := false
	for _, m := range c.st.Ignore {
		if m == mac {
			found = true
			if add {
				keep = append(keep, m)
			}
		} else {
			keep = append(keep, m)
		}
	}
	if add && !found {
		if len(keep) >= 16 {
			return errors.New("too many ignored devices (16 is the limit)")
		}
		keep = append(keep, mac)
	}
	c.st.Ignore = keep
	c.save()
	return nil
}

var canaryMgr *canary

// canaryReserved says whether an address is the canary's (reservations and the DHCP pool must never include it).
func canaryReserved(ip string) bool {
	return canaryMgr != nil && canaryMgr.ip.String() == ip || canaryMgr == nil && ip == "192.168.1.253"
}
