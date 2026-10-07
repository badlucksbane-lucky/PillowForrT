package main

// Bare-IP / SNI-less TLS tripwire: almost every browser and well-behaved app sends the hostname it is asking for in the clear, in the TLS ClientHello's server_name extension
// (SNI), even though everything after it is encrypted. A TLS connection with NO SNI, or one whose SNI is literally the destination's IP address, is unusual enough on an
// ordinary LAN to be worth a look: hand-rolled C2 clients, some port scanners doing a TLS probe, and a few IoT devices talking straight to a hard-coded address all skip it.
// This needs no decryption: the ClientHello is the one plaintext part of a TLS 1.2 or 1.3 handshake, read passively the same way canary.go reads a SYN, through an AF_PACKET
// socket with a kernel filter that passes only LAN->anywhere TCP port 443 traffic.
// Honest limits, stated rather than hidden: (1) a certificate is only visible this way in TLS 1.2 (TLS 1.3 encrypts the Certificate message), so this cannot also check for a
// self-signed cert or a suspicious validity window as originally floated -- that would need decrypting the connection, which this box deliberately never does; (2) a ClientHello
// split across more than one TCP segment (rare, but some clients with many extensions do this) is simply skipped, never guessed at, so this undercounts rather than invents
// evidence; (3) QUIC/HTTP3 (UDP 443) carries its own encrypted ClientHello and is invisible here entirely.

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// bpfTCP443 accepts only IPv4 TCP segments whose destination port is 443. Classic BPF; the MSH (masked header length) op skips a variable-length IP header.
func bpfTCP443() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]                the ethertype
		{Code: 0x15, Jt: 0, Jf: 6, K: 0x0800}, // 1 jeq IPv4 -> 2, else -> 8 (reject)
		{Code: 0x30, K: 23},                   // 2 ldb [23]                the IP protocol
		{Code: 0x15, Jt: 0, Jf: 4, K: 6},      // 3 jeq TCP  -> 4, else -> 8
		{Code: 0xb1, K: 14},                   // 4 ldx 4*([14]&0xf)        the IP header length into X
		{Code: 0x48, K: 16},                   // 5 ldh [x+16]              the TCP destination port
		{Code: 0x15, Jt: 0, Jf: 1, K: 443},    // 6 jeq 443  -> 7 (accept), else -> 8
		{Code: 0x06, K: 65535},                // 7 accept
		{Code: 0x06, K: 0},                    // 8 drop
	}
}

// tlsFrame is one accepted frame, already sliced down to its Ethernet/IP/TCP headers and payload.
type tlsFrame struct {
	Src, Dst string
	Payload  []byte
}

// parseTLSFrame reads the Ethernet+IPv4+TCP headers off one accepted packet and returns the TCP payload, if any. ok is false for a header that does not parse (too short,
// bad IHL) or that carries no payload (a bare SYN or ACK).
func parseTLSFrame(b []byte) (tlsFrame, bool) {
	var f tlsFrame
	if len(b) < 34 {
		return f, false
	}
	ihl := int(b[14]&0x0f) * 4
	if ihl < 20 || len(b) < 14+ihl+20 {
		return f, false
	}
	ip := b[14:]
	tcp := b[14+ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) <= dataOff {
		return f, false
	}
	f.Src, f.Dst = net.IP(ip[12:16]).String(), net.IP(ip[16:20]).String()
	f.Payload = tcp[dataOff:]
	return f, true
}

func be16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }
func be24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// parseClientHelloSNI reads a TLS record that is expected to be a complete ClientHello in one TCP segment. ok is false whenever it cannot say either way -- not a handshake
// record, a ClientHello split across more than one segment, or a malformed length -- never guessed, since a wrong guess here is a false alarm on someone's TLS connection.
// hasSNI is only meaningful when ok is true; name is the hostname asked for when hasSNI is true.
func parseClientHelloSNI(payload []byte) (name string, hasSNI bool, ok bool) {
	if len(payload) < 5 || payload[0] != 0x16 { // 0x16 = handshake record
		return "", false, false
	}
	recLen := be16(payload[3:5])
	if len(payload) < 5+recLen {
		return "", false, false // split across more than one segment: cannot say
	}
	hs := payload[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 { // 0x01 = client_hello
		return "", false, false
	}
	hsLen := be24(hs[1:4])
	body := hs[4:]
	if len(body) < hsLen {
		return "", false, false
	}
	body = body[:hsLen]
	pos := 2 + 32 // client_version, random
	if len(body) < pos+1 {
		return "", false, false
	}
	pos += 1 + int(body[pos]) // session_id
	if len(body) < pos+2 {
		return "", false, false
	}
	pos += 2 + be16(body[pos:pos+2]) // cipher_suites
	if len(body) < pos+1 {
		return "", false, false
	}
	pos += 1 + int(body[pos]) // compression_methods
	if len(body) < pos+2 {
		return "", true, true // a pre-TLS1.2-extensions hello: no SNI, parsed cleanly
	}
	extEnd := pos + 2 + be16(body[pos:pos+2])
	pos += 2
	if extEnd > len(body) {
		extEnd = len(body)
	}
	for pos+4 <= extEnd {
		etype, elen := be16(body[pos:pos+2]), be16(body[pos+2:pos+4])
		pos += 4
		if pos+elen > len(body) {
			break
		}
		if etype == 0 && elen >= 5 { // server_name
			nameLen := be16(body[pos+3 : pos+5])
			if pos+5+nameLen <= len(body) {
				return string(body[pos+5 : pos+5+nameLen]), true, true
			}
		}
		pos += elen
	}
	return "", false, true
}

// clientHello is everything the JA3 fingerprint and the bare-IP check both need, pulled from one ClientHello in a single pass.
type clientHello struct {
	Version   int
	Ciphers   []int
	ExtTypes  []int
	Curves    []int
	PtFormats []int
	SNI       string
	HasSNI    bool
}

// grease marks the reserved "ignore me" values TLS clients insert into cipher/extension/group lists to test server
// tolerance (RFC 8701, values of the form 0x?a?a). JA3 excludes them, or every Chrome connection would fingerprint
// differently depending on which GREASE value it happened to roll.
func grease(v int) bool { return v&0x0f0f == 0x0a0a }

// parseClientHello reads a TLS record expected to be one complete ClientHello in a single TCP segment, the same
// honest limits as the old parseClientHelloSNI: a record split across segments or malformed is reported as !ok,
// never guessed at.
func parseClientHello(payload []byte) (ch clientHello, ok bool) {
	if len(payload) < 5 || payload[0] != 0x16 {
		return ch, false
	}
	recLen := be16(payload[3:5])
	if len(payload) < 5+recLen {
		return ch, false
	}
	hs := payload[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 {
		return ch, false
	}
	hsLen := be24(hs[1:4])
	body := hs[4:]
	if len(body) < hsLen {
		return ch, false
	}
	body = body[:hsLen]
	if len(body) < 2 {
		return ch, false
	}
	ch.Version = be16(body[0:2])
	pos := 2 + 32 // client_version, random
	if len(body) < pos+1 {
		return ch, false
	}
	pos += 1 + int(body[pos]) // session_id
	if len(body) < pos+2 {
		return ch, false
	}
	csLen := be16(body[pos : pos+2])
	pos += 2
	if len(body) < pos+csLen {
		return ch, false
	}
	for i := 0; i+2 <= csLen; i += 2 {
		ch.Ciphers = append(ch.Ciphers, be16(body[pos+i:pos+i+2]))
	}
	pos += csLen
	if len(body) < pos+1 {
		return ch, false
	}
	pos += 1 + int(body[pos]) // compression_methods
	if len(body) < pos+2 {
		return ch, true // a pre-TLS1.2-extensions hello: everything else stays empty, parsed cleanly
	}
	extEnd := pos + 2 + be16(body[pos:pos+2])
	pos += 2
	if extEnd > len(body) {
		extEnd = len(body)
	}
	for pos+4 <= extEnd {
		etype, elen := be16(body[pos:pos+2]), be16(body[pos+2:pos+4])
		pos += 4
		if pos+elen > len(body) {
			break
		}
		ext := body[pos : pos+elen]
		ch.ExtTypes = append(ch.ExtTypes, etype)
		switch etype {
		case 0: // server_name
			if elen >= 5 {
				nameLen := be16(ext[3:5])
				if 5+nameLen <= len(ext) {
					ch.SNI, ch.HasSNI = string(ext[5:5+nameLen]), true
				}
			}
		case 10: // supported_groups (elliptic curves)
			if elen >= 2 {
				n := be16(ext[0:2])
				for i := 0; i+2 <= n && 2+i+2 <= len(ext); i += 2 {
					ch.Curves = append(ch.Curves, be16(ext[2+i:2+i+2]))
				}
			}
		case 11: // ec_point_formats
			if elen >= 1 {
				n := int(ext[0])
				for i := 0; i < n && 1+i < len(ext); i++ {
					ch.PtFormats = append(ch.PtFormats, int(ext[1+i]))
				}
			}
		}
		pos += elen
	}
	return ch, true
}

// ja3 renders the standard JA3 string (SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats,
// dash-joined within a field, GREASE values dropped) and its MD5 hash, the fingerprint https://github.com/salesforce/ja3
// defined and that most threat-intel JA3 blocklists key on.
func ja3(ch clientHello) (string, string) {
	join := func(vals []int, skipGrease bool) string {
		parts := make([]string, 0, len(vals))
		for _, v := range vals {
			if skipGrease && grease(v) {
				continue
			}
			parts = append(parts, strconv.Itoa(v))
		}
		return strings.Join(parts, "-")
	}
	s := fmt.Sprintf("%d,%s,%s,%s,%s", ch.Version, join(ch.Ciphers, true), join(ch.ExtTypes, true), join(ch.Curves, true), join(ch.PtFormats, false))
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

// ja3List is the JA3-hash-to-name blocklist, loaded from disk the same way torExitList (torbypass.go) loads its
// relay list: this box fetches nothing on its own, so the file starts out missing and the list starts out empty,
// which means tls_ja3_match never fires -- silence, not a false "nothing is wrong" and not a guessed-at claim like
// "this is Cobalt Strike" from a hash nobody actually verified. Populate it from a threat-intel JA3 feed you trust
// (e.g. Abuse.ch's SSL Blacklist), one `<md5 hash>,<name>` pair per line, `#` comments allowed.
type ja3List struct {
	mu   sync.Mutex
	path string
	by   map[string]string
}

func newJA3List(path string) *ja3List {
	l := &ja3List{path: path, by: map[string]string{}}
	l.Reload()
	return l
}

// Reload re-reads the blocklist from disk. Safe to call on a timer after a feed refreshes the file; a missing or
// empty file just means the list stays empty.
func (l *ja3List) Reload() {
	f, err := os.Open(l.path)
	if err != nil {
		return
	}
	defer f.Close()
	by := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		hash, name, ok := strings.Cut(ln, ",")
		hash, name = strings.TrimSpace(hash), strings.TrimSpace(name)
		if !ok || len(hash) != 32 || name == "" {
			continue
		}
		by[strings.ToLower(hash)] = name
	}
	l.mu.Lock()
	l.by = by
	l.mu.Unlock()
}

// Lookup reports whether hash is on the blocklist and, if so, the name to put in the event.
func (l *ja3List) Lookup(hash string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	name, ok := l.by[hash]
	return name, ok
}

type tlsSNIFinding struct {
	T       int64  `json:"t"`
	MAC     string `json:"mac,omitempty"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Name    string `json:"name,omitempty"` // set only when the SNI was literally the bare IP
	JA3     string `json:"ja3,omitempty"`
	JA3Name string `json:"ja3_name,omitempty"` // set only on a blocklist match
}

type tlsSNIWatch struct {
	mu      sync.Mutex
	lastEv  map[string]time.Time
	finds   []tlsSNIFinding
	ja3     *ja3List
	now     func() time.Time
	emit    func(evt)
	macOf   func(ip string) string
	nameOf  func(mac string) string
	capOK   bool
	capOnce bool
}

func newTLSSNIWatch(ja3File string) *tlsSNIWatch {
	return &tlsSNIWatch{lastEv: map[string]time.Time{}, ja3: newJA3List(ja3File), now: time.Now,
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

func (w *tlsSNIWatch) label(ip, mac string) string {
	if n := w.nameOf(mac); n != "" {
		return fmt.Sprintf("%s (%s)", n, ip)
	}
	if mac != "" {
		return fmt.Sprintf("%s (%s)", ip, mac)
	}
	return ip
}

// observe decides whether one frame's TCP payload is a ClientHello worth flagging, and records it if so.
func (w *tlsSNIWatch) observe(f tlsFrame, now time.Time) {
	_, lan, _ := net.ParseCIDR(lanCIDR)
	src, dst := net.ParseIP(f.Src), net.ParseIP(f.Dst)
	if src == nil || dst == nil || !lan.Contains(src) || lan.Contains(dst) {
		return // only a LAN device opening TLS to something outside is in scope
	}
	ch, ok := parseClientHello(f.Payload)
	if !ok {
		return
	}
	bare := !ch.HasSNI || ch.SNI == f.Dst
	_, hash := ja3(ch)
	badName, flagged := w.ja3.Lookup(hash)
	if !bare && !flagged {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	key := f.Src + "|" + f.Dst
	if t, had := w.lastEv[key]; had && now.Sub(t) < 10*time.Minute {
		return
	}
	w.lastEv[key] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	mac := w.macOf(f.Src)
	find := tlsSNIFinding{T: now.Unix(), MAC: mac, Src: f.Src, Dst: f.Dst, JA3: hash}
	if ch.HasSNI {
		find.Name = ch.SNI
	}
	if flagged {
		find.JA3Name = badName
	}
	w.finds = append(w.finds, find)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := w.label(f.Src, mac)
	if flagged {
		text := fmt.Sprintf("%s opened a TLS connection to %s whose fingerprint (JA3 %s) matches a known %s client: this is a strong signal, not a guess from SNI alone.", who, f.Dst, hash, badName)
		w.emit(evt{T: now.Unix(), Kind: "tls_ja3_match", Sev: sevAlert, Text: text, Public: "A device's TLS fingerprint matched a known malicious client"})
		return
	}
	var text string
	if ch.HasSNI {
		text = fmt.Sprintf("%s opened a TLS connection to %s and sent that address itself as the TLS server name, instead of a hostname: unusual, though some hand-configured tools do this on purpose.", who, f.Dst)
	} else {
		text = fmt.Sprintf("%s opened a TLS connection to %s with no server name (SNI) at all: almost every browser and app sends one, so this is worth a look, though a few IoT devices and local tools skip it.", who, f.Dst)
	}
	w.emit(evt{T: now.Unix(), Kind: "tls_bare_ip", Sev: sevAttention, Text: text, Public: "A device opened a TLS connection without the usual hostname field"})
}

func (w *tlsSNIWatch) Start() {
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
				log.Printf("TLS SNI watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
}

func (w *tlsSNIWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfTCP443()
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		return fmt.Errorf("packet filter: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		return err
	}
	w.mu.Lock()
	w.capOK = true
	w.mu.Unlock()
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if f, ok := parseTLSFrame(buf[:n]); ok && len(f.Payload) > 0 {
			w.observe(f, w.now())
		}
	}
}

type tlsSNIView struct {
	CaptureOK bool            `json:"capture_ok"`
	Findings  []tlsSNIFinding `json:"findings"`
}

func (w *tlsSNIWatch) View() tlsSNIView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := tlsSNIView{CaptureOK: w.capOK, Findings: []tlsSNIFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var tlsSNIMgr *tlsSNIWatch
