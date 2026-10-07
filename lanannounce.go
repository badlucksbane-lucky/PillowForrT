package main

// LAN announcements: the two protocols devices use to say what they are, read passively off the bridge. mDNS (UDP 5353, RFC 6762/6763) carries a device's .local host
// name and the services it offers (_airplay._tcp, _googlecast._tcp, _http._tcp, _printer._tcp ...), each with an instance name and port; SSDP (UDP 1900, UPnP) carries
// NOTIFY announcements with a device type, a USN and the URL of a description document, and M-SEARCH requests from anything looking for devices. Both are multicast, so
// they reach the bridge even from devices the radio would otherwise relay Wi-Fi-to-Wi-Fi, which makes this the one tap that sees every announcing device.
// What comes out: an inventory per device (host name, services, UPnP server string and device types) that the page shows and that nothing else on this box could know;
// an info event the first time a device announces a service it never announced before (new hardware, a new app, or a device starting to offer something it should not);
// and two "to look at" findings in the shape of an impersonation: two addresses answering for the same .local host name (the mDNS version of arpwatch.go's claim conflict:
// a phone with a fresh random MAC does this too, so never more than attention), and an SSDP announcement whose description URL points at a different address than the one
// that sent it (the shape of a UPnP redirection, though a dual-homed device does it honestly). A device sending M-SEARCH for ssdp:all is counted, not flagged: media apps on
// phones do it all day. Honest limits: IPv4 only, since LAN IPv6 is off by default here; mDNS records are taken at face value (nothing is verified, and a device can
// announce whatever it likes); the inventory is a cap of 64 devices and 32 services each, oldest out; it is kept on flash (default /data/proxy/lanannounce.json) so
// "first time" means first time ever, not since the last reboot. Nothing here ever sends a query.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
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

// bpfUDPAnnounce accepts IPv4 UDP datagrams to port 5353 (mDNS) or 1900 (SSDP).
func bpfUDPAnnounce() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]                the ethertype
		{Code: 0x15, Jt: 0, Jf: 7, K: 0x0800}, // 1 jeq IPv4 -> 2, else -> 9 (reject)
		{Code: 0x30, K: 23},                   // 2 ldb [23]                the IP protocol
		{Code: 0x15, Jt: 0, Jf: 5, K: 17},     // 3 jeq UDP  -> 4, else -> 9
		{Code: 0xb1, K: 14},                   // 4 ldx 4*([14]&0xf)        the IP header length into X
		{Code: 0x48, K: 16},                   // 5 ldh [x+16]              the UDP destination port
		{Code: 0x15, Jt: 1, Jf: 0, K: 5353},   // 6 jeq 5353 -> 8 (accept)
		{Code: 0x15, Jt: 0, Jf: 1, K: 1900},   // 7 jeq 1900 -> 8 (accept), else -> 9
		{Code: 0x06, K: 65535},                // 8 accept
		{Code: 0x06, K: 0},                    // 9 drop
	}
}

// udpFrame is one accepted datagram with its addresses.
type udpFrame struct {
	Src, Dst         string
	SrcPort, DstPort int
	Payload          []byte
}

func parseUDPFrame(b []byte) (udpFrame, bool) {
	var f udpFrame
	if len(b) < 42 {
		return f, false
	}
	ihl := int(b[14]&0x0f) * 4
	if ihl < 20 || len(b) < 14+ihl+8 {
		return f, false
	}
	ip := b[14:]
	udp := b[14+ihl:]
	f.Src, f.Dst = net.IP(ip[12:16]).String(), net.IP(ip[16:20]).String()
	f.SrcPort, f.DstPort = be16(udp[0:2]), be16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		f.Payload = udp[8:]
	} else {
		f.Payload = udp[8:udpLen]
	}
	return f, len(f.Payload) > 0
}

// readName decodes a possibly compressed DNS name at off and returns it as sent (case kept: a DNS-SD instance name is a label a person wrote) without the trailing dot, and the offset just past it in the uncompressed stream.
func readName(m []byte, off int) (string, int, bool) {
	var parts []string
	end := -1
	for hops := 0; hops < 40 && off < len(m); hops++ {
		l := int(m[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(parts, "."), end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(m) {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = int(m[off]&0x3f)<<8 | int(m[off+1])
		default:
			if off+1+l > len(m) {
				return "", 0, false
			}
			parts = append(parts, string(m[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, false
}

// mdnsRecord is one resource record of interest from an mDNS response.
type mdnsRecord struct {
	Name   string
	Type   uint16
	Target string // PTR/SRV target, or the A address
	Port   int    // SRV
}

// parseMDNS reads the records of an mDNS message. isResponse is the QR bit; queries are returned with no records (only whether they were one).
func parseMDNS(m []byte) (isResponse bool, recs []mdnsRecord, ok bool) {
	if len(m) < 12 {
		return false, nil, false
	}
	isResponse = m[2]&0x80 != 0
	qd := be16(m[4:6])
	total := be16(m[6:8]) + be16(m[8:10]) + be16(m[10:12])
	off := 12
	for i := 0; i < qd; i++ {
		_, n, good := readName(m, off)
		if !good || n+4 > len(m) {
			return isResponse, nil, false
		}
		off = n + 4
	}
	if !isResponse {
		return false, nil, true
	}
	for i := 0; i < total && i < 64; i++ {
		name, n, good := readName(m, off)
		if !good || n+10 > len(m) {
			break
		}
		typ := uint16(be16(m[n : n+2]))
		rdlen := be16(m[n+8 : n+10])
		rd := n + 10
		if rd+rdlen > len(m) {
			break
		}
		r := mdnsRecord{Name: name, Type: typ}
		switch typ {
		case 1: // A
			if rdlen == 4 {
				r.Target = net.IP(m[rd : rd+4]).String()
				recs = append(recs, r)
			}
		case 12: // PTR
			if t, _, good := readName(m, rd); good {
				r.Target = t
				recs = append(recs, r)
			}
		case 33: // SRV
			if rdlen >= 7 {
				r.Port = be16(m[rd+4 : rd+6])
				if t, _, good := readName(m, rd+6); good {
					r.Target = t
					recs = append(recs, r)
				}
			}
		}
		off = rd + rdlen
	}
	return true, recs, true
}

// serviceType splits "Living Room._googlecast._tcp.local" into ("_googlecast._tcp", "Living Room"); ok is false for a name that is not a DNS-SD instance.
func serviceType(name string) (typ, instance string, ok bool) {
	if strings.HasSuffix(strings.ToLower(name), ".local") {
		name = name[:len(name)-len(".local")]
	}
	lower := strings.ToLower(name)
	i := strings.LastIndex(lower, "._tcp")
	if j := strings.LastIndex(lower, "._udp"); j > i {
		i = j
	}
	if i < 0 {
		return "", "", false
	}
	head := name[:i]
	k := strings.LastIndex(head, "._")
	if k < 0 {
		return "", "", false
	}
	return strings.ToLower(head[k+1:] + name[i:]), head[:k], true
}

// ssdpMessage is the part of a NOTIFY or M-SEARCH that describes the sender.
type ssdpMessage struct {
	Method   string // NOTIFY | M-SEARCH
	NT       string // NT (notify) or ST (search)
	USN      string
	Location string
	Server   string
	Alive    bool
}

func parseSSDP(b []byte) (ssdpMessage, bool) {
	var m ssdpMessage
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	if !sc.Scan() {
		return m, false
	}
	first := strings.Fields(sc.Text())
	if len(first) < 2 {
		return m, false
	}
	m.Method = strings.ToUpper(first[0])
	if m.Method != "NOTIFY" && m.Method != "M-SEARCH" {
		return m, false
	}
	for sc.Scan() {
		ln := sc.Text()
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "NT", "ST":
			m.NT = v
		case "USN":
			m.USN = v
		case "LOCATION":
			m.Location = v
		case "SERVER":
			m.Server = v
		case "NTS":
			m.Alive = strings.EqualFold(v, "ssdp:alive")
		}
	}
	return m, true
}

// locationHost returns the host part of an SSDP LOCATION URL.
func locationHost(loc string) string {
	rest := loc
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		rest = rest[:i]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		return h
	}
	return rest
}

type lanService struct {
	Type     string `json:"type"`               // "_googlecast._tcp" or a UPnP device type
	Instance string `json:"instance,omitempty"` // the DNS-SD instance name, or the USN
	Port     int    `json:"port,omitempty"`
	Via      string `json:"via"` // mdns | ssdp
	First    int64  `json:"first"`
	Last     int64  `json:"last"`
}

type announcer struct {
	IP        string       `json:"ip"`
	Host      string       `json:"host,omitempty"` // the .local host name
	Server    string       `json:"server,omitempty"`
	Services  []lanService `json:"services"`
	Searches  int          `json:"searches"` // M-SEARCH ssdp:all sent
	First     int64        `json:"first"`
	Last      int64        `json:"last"`
	MDNSCount int          `json:"mdns"`
	SSDPCount int          `json:"ssdp"`
}

type lanState struct {
	Devices map[string]*announcer `json:"devices"`
	Hosts   map[string]string     `json:"hosts"` // .local host name -> the IP that last answered for it
}

type lanFinding struct {
	T    int64  `json:"t"`
	Kind string `json:"kind"`
	MAC  string `json:"mac,omitempty"`
	IP   string `json:"ip"`
	Name string `json:"name"`          // the host name, service, or location
	Was  string `json:"was,omitempty"` // the previous holder of the name
}

const (
	lanDevicesMax  = 64
	lanServicesMax = 32
)

type lanAnnounceWatch struct {
	mu      sync.Mutex
	path    string
	st      lanState
	lastEv  map[string]time.Time
	finds   []lanFinding
	now     func() time.Time
	emit    func(evt)
	macOf   func(ip string) string
	nameOf  func(mac string) string
	capOK   bool
	capOnce bool
	dirty   bool
}

func newLANAnnounceWatch(path string) *lanAnnounceWatch {
	w := &lanAnnounceWatch{path: path, st: lanState{Devices: map[string]*announcer{}, Hosts: map[string]string{}}, lastEv: map[string]time.Time{}, now: time.Now,
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
	if b, err := os.ReadFile(path); err == nil {
		var st lanState
		if json.Unmarshal(b, &st) == nil && st.Devices != nil {
			if st.Hosts == nil {
				st.Hosts = map[string]string{}
			}
			w.st = st
		}
	}
	return w
}

func (w *lanAnnounceWatch) save() {
	if w.path == "" {
		return
	}
	b, _ := json.Marshal(w.st)
	writeFileAtomic(w.path, b, 0o600)
}

func (w *lanAnnounceWatch) label(ip, mac string) string {
	if n := w.nameOf(mac); n != "" {
		return fmt.Sprintf("%s (%s)", n, ip)
	}
	if mac != "" {
		return fmt.Sprintf("%s (%s)", ip, mac)
	}
	return ip
}

func (w *lanAnnounceWatch) device(ip string, now time.Time) *announcer {
	d, ok := w.st.Devices[ip]
	if ok {
		d.Last = now.Unix()
		return d
	}
	if len(w.st.Devices) >= lanDevicesMax {
		oldest, at := "", int64(0)
		for k, x := range w.st.Devices {
			if oldest == "" || x.Last < at {
				oldest, at = k, x.Last
			}
		}
		delete(w.st.Devices, oldest)
	}
	d = &announcer{IP: ip, First: now.Unix(), Last: now.Unix(), Services: []lanService{}}
	w.st.Devices[ip] = d
	w.dirty = true
	return d
}

// addService records a service on a device and reports whether it is new to that device.
func (w *lanAnnounceWatch) addService(d *announcer, s lanService, now time.Time) bool {
	for i := range d.Services {
		if d.Services[i].Type == s.Type && d.Services[i].Via == s.Via {
			d.Services[i].Last = now.Unix()
			if s.Instance != "" {
				d.Services[i].Instance = s.Instance
			}
			if s.Port != 0 {
				d.Services[i].Port = s.Port
			}
			return false
		}
	}
	s.First, s.Last = now.Unix(), now.Unix()
	d.Services = append(d.Services, s)
	if len(d.Services) > lanServicesMax {
		sort.Slice(d.Services, func(i, j int) bool { return d.Services[i].Last > d.Services[j].Last })
		d.Services = d.Services[:lanServicesMax]
	}
	w.dirty = true
	return true
}

// observe handles one datagram.
func (w *lanAnnounceWatch) observe(f udpFrame, now time.Time) {
	_, lan, _ := net.ParseCIDR(lanCIDR)
	src := net.ParseIP(f.Src)
	if src == nil || !lan.Contains(src) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch f.DstPort {
	case 5353:
		w.observeMDNS(f, now)
	case 1900:
		w.observeSSDP(f, now)
	}
}

func (w *lanAnnounceWatch) observeMDNS(f udpFrame, now time.Time) {
	isResp, recs, ok := parseMDNS(f.Payload)
	if !ok || !isResp {
		return
	}
	d := w.device(f.Src, now)
	d.MDNSCount++
	instPort := map[string]int{}
	for _, r := range recs {
		if r.Type == 33 {
			instPort[r.Name] = r.Port
		}
	}
	for _, r := range recs {
		switch r.Type {
		case 1:
			r.Name = strings.ToLower(r.Name)
			if !strings.HasSuffix(r.Name, ".local") || r.Target != f.Src {
				continue // a device only speaks for its own address here; another address in an A record is not a conflict but is not inventory either
			}
			if d.Host != r.Name {
				d.Host = r.Name
				w.dirty = true
			}
			if prev, had := w.st.Hosts[r.Name]; had && prev != f.Src {
				if _, alive := w.st.Devices[prev]; alive && now.Unix()-w.st.Devices[prev].Last < 600 {
					w.raise(lanFinding{Kind: "lan_host_conflict", IP: f.Src, Name: r.Name, Was: prev}, now)
				}
			}
			if w.st.Hosts[r.Name] != f.Src {
				w.st.Hosts[r.Name] = f.Src
				w.dirty = true
			}
		case 12:
			typ, inst, good := serviceType(r.Target)
			if !good || strings.HasPrefix(strings.ToLower(r.Name), "_services._dns-sd") {
				continue
			}
			s := lanService{Type: typ, Instance: inst, Via: "mdns", Port: instPort[r.Target]}
			if w.addService(d, s, now) {
				label := typ
				if inst != "" {
					label += " (" + inst + ")"
				}
				w.raise(lanFinding{Kind: "lan_service_new", IP: f.Src, Name: label}, now)
			}
		}
	}
}

func (w *lanAnnounceWatch) observeSSDP(f udpFrame, now time.Time) {
	m, ok := parseSSDP(f.Payload)
	if !ok {
		return
	}
	d := w.device(f.Src, now)
	d.SSDPCount++
	if m.Method == "M-SEARCH" {
		if strings.EqualFold(m.NT, "ssdp:all") {
			d.Searches++
			w.dirty = true
		}
		return
	}
	if !m.Alive {
		return
	}
	if m.Server != "" && d.Server != m.Server {
		d.Server = m.Server
		w.dirty = true
	}
	if m.Location != "" {
		if h := locationHost(m.Location); h != "" && h != f.Src {
			if ip := net.ParseIP(h); ip != nil || !strings.HasSuffix(h, ".local") {
				w.raise(lanFinding{Kind: "lan_ssdp_elsewhere", IP: f.Src, Name: m.Location}, now)
			}
		}
	}
	typ := m.NT
	if typ == "" || strings.HasPrefix(typ, "uuid:") || typ == "upnp:rootdevice" {
		return // the root and the bare UUID say nothing about what the device is; device: and service: types do
	}
	if w.addService(d, lanService{Type: typ, Instance: m.USN, Via: "ssdp"}, now) {
		w.raise(lanFinding{Kind: "lan_service_new", IP: f.Src, Name: typ}, now)
	}
}

// raise records a finding and emits its event, one per (kind, device, name) per hour.
func (w *lanAnnounceWatch) raise(f lanFinding, now time.Time) {
	key := f.Kind + "|" + f.IP + "|" + f.Name
	if t, had := w.lastEv[key]; had && now.Sub(t) < time.Hour {
		return
	}
	w.lastEv[key] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > 2*time.Hour {
			delete(w.lastEv, k)
		}
	}
	f.T = now.Unix()
	f.MAC = w.macOf(f.IP)
	w.finds = append(w.finds, f)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := w.label(f.IP, f.MAC)
	switch f.Kind {
	case "lan_service_new":
		w.emit(evt{T: f.T, Kind: f.Kind, Sev: sevInfo, Text: fmt.Sprintf("%s announced a service it had not announced before: %s.", who, f.Name), Public: "A device announced a new service on the network"})
	case "lan_host_conflict":
		w.emit(evt{T: f.T, Kind: f.Kind, Sev: sevAttention, Text: fmt.Sprintf("%s answered for the name %s, which %s was answering for minutes ago: a device taking another's name looks like this, and so does a phone back with a fresh random address.", who, f.Name, f.Was), Public: "Two devices answered for the same local host name"})
	case "lan_ssdp_elsewhere":
		w.emit(evt{T: f.T, Kind: f.Kind, Sev: sevAttention, Text: fmt.Sprintf("%s announced a UPnP device whose description lives at %s, not at the announcing address: a dual-homed device does this honestly, a redirection does it on purpose.", who, f.Name), Public: "A UPnP announcement pointed at a different address than its sender"})
	}
}

func (w *lanAnnounceWatch) Start() {
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
				log.Printf("LAN announcement watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
	go func() {
		for range time.Tick(time.Minute) {
			w.mu.Lock()
			if w.dirty {
				w.dirty = false
				w.save()
			}
			w.mu.Unlock()
		}
	}()
}

func (w *lanAnnounceWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfUDPAnnounce()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	w.mu.Lock()
	w.capOK = true
	w.mu.Unlock()
	buf := make([]byte, 9000)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if f, ok := parseUDPFrame(buf[:n]); ok {
			w.observe(f, w.now())
		}
	}
}

type lanAnnounceView struct {
	CaptureOK bool         `json:"capture_ok"`
	Devices   []announcer  `json:"devices"`
	Findings  []lanFinding `json:"findings"`
}

func (w *lanAnnounceWatch) View() lanAnnounceView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := lanAnnounceView{CaptureOK: w.capOK, Devices: []announcer{}, Findings: []lanFinding{}}
	for _, d := range w.st.Devices {
		c := *d
		c.Services = append([]lanService{}, d.Services...)
		sort.Slice(c.Services, func(i, j int) bool { return c.Services[i].Type < c.Services[j].Type })
		v.Devices = append(v.Devices, c)
	}
	sort.Slice(v.Devices, func(i, j int) bool { return v.Devices[i].Last > v.Devices[j].Last })
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var lanAnnounceMgr *lanAnnounceWatch
