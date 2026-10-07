package main

// The packet tap: GET /api/tap streams what the LAN bridge sees as a pcap file, so Suricata, Snort, Zeek or Wireshark on a companion computer can read it live:
//
//   curl -sN -H "X-UI-Token: $TOKEN" "https://orbic:3129/api/tap?filter=all&seconds=600" | suricata -r /dev/stdin
//
// Neither Suricata nor Snort fits in 77 MB of RAM, but they do not need to run here: the box already reads the bridge through AF_PACKET for the detectors, and this is the
// same socket with a filter you choose and pcap framing on the way out. Honest limits: the bridge never sees traffic the radio relays Wi-Fi-to-Wi-Fi, so an IDS fed from
// here sees what the detectors see (broadcasts, multicast, anything aimed at the router, and everything headed for the internet), not more. And this is the one feature
// that exports raw frames with addresses in them, which cuts against the rule that nothing named leaves the box: so it is OFF until switched on from the page, served
// only to the LAN (never through the onion door), behind the login or the script token, one tap at a time, for at most an hour per request. The tap's own HTTPS
// connection is excluded in the kernel filter so the stream does not capture itself.

import (
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	tapMaxSeconds = 3600
	tapDefSeconds = 300
	tapMaxSnap    = 2048
	tapDefSnap    = 1600
)

var tapBusy atomic.Bool

// tapFilters are the filters a client may ask for; each is a classic BPF fragment that ends in accept (65535) or drop (0).
var tapFilters = map[string]string{"all": "everything", "arp": "ARP only", "dns": "UDP port 53", "dhcp": "UDP ports 67 and 68", "tls": "TCP port 443", "icmp": "ICMP"}

// tapBPF builds the kernel filter: first the exclusion of the tap's own TCP flow (our listener port <-> the client's port), then the chosen filter. Only the opcodes
// the test simulator knows (ldh/ldb abs, ldx msh, ldh/ldb ind, and, jeq, ret). A jump of k from index i lands at i+1+k.
func tapBPF(filter string, selfPort, peerPort uint16) []unix.SockFilter {
	p := []unix.SockFilter{
		{Code: 0x28, K: 12},                             // 0  ldh [12]            ethertype
		{Code: 0x15, Jt: 0, Jf: 11, K: 0x0800},          // 1  IPv4 -> 2, else the filter (13)
		{Code: 0x30, K: 23},                             // 2  ldb [23]            protocol
		{Code: 0x15, Jt: 0, Jf: 9, K: 6},                // 3  TCP -> 4, else the filter (13)
		{Code: 0xb1, K: 14},                             // 4  ldx 4*([14]&0xf)
		{Code: 0x48, K: 14},                             // 5  ldh [x+14]          source port
		{Code: 0x15, Jt: 0, Jf: 2, K: uint32(selfPort)}, // 6  ours -> 7, else -> 9
		{Code: 0x48, K: 16},                             // 7  ldh [x+16]          destination port
		{Code: 0x15, Jt: 3, Jf: 4, K: uint32(peerPort)}, // 8  the client's -> drop (12), else the filter (13)
		{Code: 0x15, Jt: 0, Jf: 3, K: uint32(peerPort)}, // 9  source is the client's -> 10, else the filter (13)
		{Code: 0x48, K: 16},                             // 10 ldh [x+16]          destination port
		{Code: 0x15, Jt: 0, Jf: 1, K: uint32(selfPort)}, // 11 ours -> drop (12), else the filter (13)
		{Code: 0x06, K: 0},                              // 12 drop: the tap's own flow
	}
	add := func(code uint16, jt, jf uint8, k uint32) {
		p = append(p, unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k})
	}
	switch filter {
	case "arp":
		add(0x28, 0, 0, 12)
		add(0x15, 0, 1, 0x0806)
		add(0x06, 0, 0, 65535)
		add(0x06, 0, 0, 0)
	case "icmp":
		add(0x28, 0, 0, 12)
		add(0x15, 0, 3, 0x0800)
		add(0x30, 0, 0, 23)
		add(0x15, 0, 1, 1)
		add(0x06, 0, 0, 65535)
		add(0x06, 0, 0, 0)
	case "dns", "dhcp", "tls":
		proto, ports := uint32(17), []uint32{53}
		if filter == "dhcp" {
			ports = []uint32{67, 68}
		}
		if filter == "tls" {
			proto, ports = 6, []uint32{443}
		}
		// Relative to this block: 0..5 header checks, 6..6+n-1 source-port checks, 6+n load destination port, 7+n..7+2n-1 destination checks, 7+2n accept, 8+2n drop.
		n := uint8(len(ports))
		accept, drop := 7+2*n, 8+2*n
		add(0x28, 0, 0, 12)
		add(0x15, 0, drop-2, 0x0800)
		add(0x30, 0, 0, 23)
		add(0x15, 0, drop-4, proto)
		add(0xb1, 0, 0, 14)
		add(0x48, 0, 0, 14)
		for i, pt := range ports {
			idx := 6 + uint8(i)
			add(0x15, accept-idx-1, 0, pt)
		}
		add(0x48, 0, 0, 16)
		for i, pt := range ports {
			idx := 7 + n + uint8(i)
			jf := uint8(0)
			if i == len(ports)-1 {
				jf = drop - idx - 1
			}
			add(0x15, accept-idx-1, jf, pt)
		}
		add(0x06, 0, 0, 65535)
		add(0x06, 0, 0, 0)
	default: // all
		add(0x06, 0, 0, 65535)
	}
	return p
}

// pcapHeader is the 24-byte file header, little-endian, link type Ethernet.
func pcapHeader(snaplen int) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:6], 2)
	binary.LittleEndian.PutUint16(h[6:8], 4)
	binary.LittleEndian.PutUint32(h[16:20], uint32(snaplen))
	binary.LittleEndian.PutUint32(h[20:24], 1)
	return h
}

// pcapRecord frames one captured packet: seconds, microseconds, bytes included, bytes on the wire.
func pcapRecord(t time.Time, pkt []byte, origLen int) []byte {
	r := make([]byte, 16+len(pkt))
	binary.LittleEndian.PutUint32(r[0:4], uint32(t.Unix()))
	binary.LittleEndian.PutUint32(r[4:8], uint32(t.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(r[8:12], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(r[12:16], uint32(origLen))
	copy(r[16:], pkt)
	return r
}

func portOf(addr string) uint16 {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return uint16(n)
}

func handleTap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if exports == nil || !exports.Cfg().Tap.Enabled {
		writeJSON(w, 403, map[string]string{"error": "the packet tap is switched off: turn it on in the Export card first"})
		return
	}
	if viaOnion(r) {
		writeJSON(w, 403, map[string]string{"error": "the packet tap is not served through the onion door"})
		return
	}
	q := r.URL.Query()
	filter := q.Get("filter")
	if filter == "" {
		filter = "all"
	}
	if _, ok := tapFilters[filter]; !ok {
		writeJSON(w, 400, map[string]string{"error": "filter must be one of all, arp, dns, dhcp, tls, icmp"})
		return
	}
	secs, _ := strconv.Atoi(q.Get("seconds"))
	if secs <= 0 {
		secs = tapDefSeconds
	}
	if secs > tapMaxSeconds {
		secs = tapMaxSeconds
	}
	snap, _ := strconv.Atoi(q.Get("snaplen"))
	if snap <= 0 {
		snap = tapDefSnap
	}
	if snap < 64 {
		snap = 64
	}
	if snap > tapMaxSnap {
		snap = tapMaxSnap
	}
	if !tapBusy.CompareAndSwap(false, true) {
		writeJSON(w, 409, map[string]string{"error": "a tap is already running; one at a time"})
		return
	}
	defer tapBusy.Store(false)
	exports.mu.Lock()
	exports.tapActive, exports.tapLast = true, time.Now().Unix()
	exports.mu.Unlock()
	defer func() {
		exports.mu.Lock()
		exports.tapActive = false
		exports.mu.Unlock()
	}()

	var selfPort uint16
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		selfPort = portOf(la.String())
	}
	peerPort := portOf(r.RemoteAddr)

	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "no bridge0 on this box"})
		return
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not open a capture socket: " + err.Error()})
		return
	}
	defer unix.Close(fd)
	prog := tapBPF(filter, selfPort, peerPort)
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "packet filter: " + err.Error()})
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "bind: " + err.Error()})
		return
	}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1})

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", "inline; filename=\"bridge0.pcap\"")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	if _, err := w.Write(pcapHeader(snap)); err != nil {
		return
	}
	if fl != nil {
		fl.Flush()
	}
	ctx := r.Context()
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	buf := make([]byte, snap)
	for !ctxDone(ctx) && time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			return
		}
		orig := n
		if n > len(buf) {
			n = len(buf)
		}
		if _, err := w.Write(pcapRecord(time.Now(), buf[:n], orig)); err != nil {
			return
		}
		if fl != nil {
			fl.Flush()
		}
	}
}
