package main

// DHCP fingerprint drift: a device's DHCP client advertises, in cleartext, option 55 (the "parameter request list" -- which DHCP options it wants back) in a fixed order and
// shape that is characteristic of its OS and DHCP stack; this is the same passive fingerprinting technique tools like Fingerbank and p0f use. A MAC address whose fingerprint
// has been STABLE for a while and then suddenly changes is either new firmware (an update legitimately changed its network stack) or a different device now answering for
// that MAC (a clone, a spoof, or someone's phone with its address manually set to match a trusted one). Reading this needs nothing new on the wire: the DHCP broadcast is
// already there every time a device joins or renews, read passively through an AF_PACKET socket filtered in-kernel to UDP destination port 67, the same shape as
// arpwatch.go's capture.
// Deliberately conservative: a fingerprint seen only once is never a baseline (every device's very first DHCP request would otherwise look like "drift" from nothing), and a
// MAC is allowed to settle on a new fingerprint without repeat alarms (at most one event per MAC per day). A device that rotates its MAC on purpose (Wi-Fi private addressing)
// never triggers this: that is a new MAC for arpwatch.go and mac_churn to see, not a changed fingerprint on an old one.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// bpfUDP67 accepts only IPv4 UDP datagrams whose destination port is 67 (the DHCP server port -- so DISCOVER, REQUEST and INFORM from a client, never a server's reply).
func bpfUDP67() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]            the ethertype
		{Code: 0x15, Jt: 0, Jf: 6, K: 0x0800}, // 1 jeq IPv4 -> 2, else -> 8
		{Code: 0x30, K: 23},                   // 2 ldb [23]            the IP protocol
		{Code: 0x15, Jt: 0, Jf: 4, K: 17},     // 3 jeq UDP  -> 4, else -> 8
		{Code: 0xb1, K: 14},                   // 4 ldx 4*([14]&0xf)   the IP header length into X
		{Code: 0x48, K: 16},                   // 5 ldh [x+16]         the UDP destination port
		{Code: 0x15, Jt: 0, Jf: 1, K: 67},     // 6 jeq 67   -> 7 (accept), else -> 8
		{Code: 0x06, K: 65535},                // 7 accept
		{Code: 0x06, K: 0},                    // 8 drop
	}
}

const bootpFixedLen = 236 // op..file, before the 4-byte magic cookie and the options

// dhcpFingerprint reads one DHCP client packet's chaddr and option-55 parameter request list off its UDP payload. ok is false for anything too short or malformed to trust;
// fp is "" when the packet has no option 55 at all (still a valid, if less specific, observation).
func dhcpFingerprint(udpPayload []byte) (mac, fp string, ok bool) {
	if len(udpPayload) < bootpFixedLen+4 {
		return "", "", false
	}
	if udpPayload[0] != 1 { // op: 1 = BOOTREQUEST (from a client); a server's own reply is op 2 and not interesting here
		return "", "", false
	}
	htype, hlen := udpPayload[1], int(udpPayload[2])
	if htype != 1 || hlen != 6 || len(udpPayload) < 28+6 { // Ethernet, a 6-byte MAC: anything else is not fingerprinted here
		return "", "", false
	}
	mac = net.HardwareAddr(udpPayload[28 : 28+6]).String()
	if !bytesEqual(udpPayload[bootpFixedLen:bootpFixedLen+4], []byte{0x63, 0x82, 0x53, 0x63}) {
		return mac, "", true // no magic cookie: a BOOTP packet with no DHCP options, a valid (if fingerprint-less) observation
	}
	opts := udpPayload[bootpFixedLen+4:]
	for i := 0; i+2 <= len(opts) && opts[i] != 0xff; {
		code, l := opts[i], int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		if code == 55 {
			return mac, hex.EncodeToString(opts[i+2 : i+2+l]), true
		}
		if code == 0 { // pad
			i++
			continue
		}
		i += 2 + l
	}
	return mac, "", true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type dhcpFPTrack struct {
	fp        string
	count     int
	lastSeen  time.Time
	lastEvent time.Time
}

type dhcpFPFinding struct {
	T   int64  `json:"t"`
	MAC string `json:"mac"`
	Was string `json:"was"`
	Now string `json:"now"`
}

type dhcpFPWatch struct {
	mu      sync.Mutex
	tracks  map[string]*dhcpFPTrack
	finds   []dhcpFPFinding
	now     func() time.Time
	emit    func(evt)
	nameOf  func(mac string) string
	capOK   bool
	capOnce bool
}

func newDHCPFPWatch() *dhcpFPWatch {
	return &dhcpFPWatch{tracks: map[string]*dhcpFPTrack{}, now: time.Now,
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
}

func (w *dhcpFPWatch) label(mac string) string {
	if n := w.nameOf(mac); n != "" {
		return n + " (" + mac + ")"
	}
	return mac
}

// Observe is pure state update plus event emission, kept separate from the capture loop so it is unit-testable without a socket.
func (w *dhcpFPWatch) Observe(mac, fp string, now time.Time) {
	if mac == "" || fp == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, t := range w.tracks {
		if now.Sub(t.lastSeen) > 30*24*time.Hour {
			delete(w.tracks, k)
		}
	}
	t := w.tracks[mac]
	if t == nil {
		w.tracks[mac] = &dhcpFPTrack{fp: fp, count: 1, lastSeen: now}
		return
	}
	if t.fp == fp {
		t.count++
		t.lastSeen = now
		return
	}
	stable := t.count >= 2 // a fingerprint seen only once is not yet a baseline worth defending
	was := t.fp
	t.fp, t.count, t.lastSeen = fp, 1, now
	if !stable || now.Sub(t.lastEvent) < 24*time.Hour {
		return
	}
	t.lastEvent = now
	w.finds = append(w.finds, dhcpFPFinding{T: now.Unix(), MAC: mac, Was: was, Now: fp})
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	w.emit(evt{T: now.Unix(), Kind: "dhcp_fingerprint_drift", Sev: sevAttention, Text: fmt.Sprintf("%s's DHCP fingerprint changed after staying the same for a while: this can be new firmware or an OS update, or something else now answering for that address.", w.label(mac)), Public: "A device's DHCP fingerprint changed unexpectedly"})
}

func (w *dhcpFPWatch) Start() {
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
				log.Printf("DHCP fingerprint watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *dhcpFPWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfUDP67()
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
		if payload, ok := udpPayload(buf[:n]); ok {
			if mac, fp, ok := dhcpFingerprint(payload); ok && fp != "" {
				_ = mac
				w.Observe(mac, fp, w.now())
			}
		}
	}
}

// udpPayload strips the Ethernet, IPv4 and UDP headers off one captured frame.
func udpPayload(b []byte) ([]byte, bool) {
	if len(b) < 34 {
		return nil, false
	}
	ihl := int(b[14]&0x0f) * 4
	if ihl < 20 || len(b) < 14+ihl+8 {
		return nil, false
	}
	udp := b[14+ihl:]
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || len(udp) < udpLen {
		return udp[8:], true // trust what was captured over a malformed length field
	}
	return udp[8:udpLen], true
}

type dhcpFPView struct {
	CaptureOK bool            `json:"capture_ok"`
	Findings  []dhcpFPFinding `json:"findings"`
}

func (w *dhcpFPWatch) View() dhcpFPView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := dhcpFPView{CaptureOK: w.capOK, Findings: []dhcpFPFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var dhcpFPMgr *dhcpFPWatch
