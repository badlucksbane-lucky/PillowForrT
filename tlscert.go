package main

// Certificate-change watch: the server's half of a TLS handshake is also partly in the clear, and this reads the two pieces that are, without decrypting anything.
// (1) The ServerHello, in every TLS version, says which version was negotiated. (2) In TLS 1.2 and older, the Certificate message that follows it carries the server's
// certificate chain in plaintext. Keyed by the hostname the client asked for (the SNI from the ClientHello, so a CDN moving the name between addresses does not matter), the
// box remembers the leaf certificate's fingerprint and issuer and the best TLS version each name has negotiated, and raises an event when one of these changes in the way an
// upstream interception looks: a name that was signed by a public CA is suddenly self-signed (alert), the certificate presented for a name no longer covers that name
// (to look at), the issuer changes to a different organisation (to look at), or a name that always negotiated TLS 1.3 is talked down to 1.2 (to look at, since an interception
// box that cannot do 1.3 does exactly this). An ordinary renewal, same issuer and a new fingerprint, is recorded silently; so is the first sight of any name, which is the
// baseline. Only a LAN device talking to something outside is in scope.
// Honest limits: TLS 1.3 encrypts the Certificate message, so for a name that negotiates 1.3 only the version is watched, and an interceptor that itself speaks 1.3 is
// invisible here; the handshake must arrive in order (a flow with a missing or reordered server segment is dropped, never guessed at); a resumed session carries no
// certificate and is ignored; QUIC is invisible; and a name whose edges genuinely present certificates from different issuers will be flagged once per issuer change.
// The baseline is kept on flash (default /data/proxy/tlscert.json, at most 1000 names, nothing per device) so a reboot does not turn every known name back into a first sight.
// Cost: the kernel filter passes every server->device TCP segment on port 443 to this process; a segment that belongs to no handshake in progress is dropped after one map
// lookup, so the cost is the kernel-to-user copy, about what one tcpdump on the bridge costs.

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
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

// bpfTCP443Both accepts IPv4 TCP segments with source port 443 or destination port 443.
func bpfTCP443Both() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // 0 ldh [12]                the ethertype
		{Code: 0x15, Jt: 0, Jf: 8, K: 0x0800}, // 1 jeq IPv4 -> 2, else -> 10 (reject)
		{Code: 0x30, K: 23},                   // 2 ldb [23]                the IP protocol
		{Code: 0x15, Jt: 0, Jf: 6, K: 6},      // 3 jeq TCP  -> 4, else -> 10
		{Code: 0xb1, K: 14},                   // 4 ldx 4*([14]&0xf)        the IP header length into X
		{Code: 0x48, K: 14},                   // 5 ldh [x+14]              the TCP source port
		{Code: 0x15, Jt: 2, Jf: 0, K: 443},    // 6 jeq 443  -> 9 (accept)
		{Code: 0x48, K: 16},                   // 7 ldh [x+16]              the TCP destination port
		{Code: 0x15, Jt: 0, Jf: 1, K: 443},    // 8 jeq 443  -> 9 (accept), else -> 10
		{Code: 0x06, K: 65535},                // 9 accept
		{Code: 0x06, K: 0},                    // 10 drop
	}
}

// tcpFrame is one accepted frame with the parts of the TCP header a reassembler needs.
type tcpFrame struct {
	Src, Dst         string
	SrcPort, DstPort int
	Seq              uint32
	Payload          []byte
}

// parseTCPFrame reads Ethernet+IPv4+TCP and returns the payload with ports and sequence number. ok is false for a header that does not parse or a segment with no payload.
func parseTCPFrame(b []byte) (tcpFrame, bool) {
	var f tcpFrame
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
	f.SrcPort, f.DstPort = be16(tcp[0:2]), be16(tcp[2:4])
	f.Seq = binary.BigEndian.Uint32(tcp[4:8])
	f.Payload = tcp[dataOff:]
	return f, true
}

// serverHello is what the one plaintext message every TLS server sends tells us: the version actually negotiated (from supported_versions when present, which is how
// TLS 1.3 says so, else the legacy field).
func parseServerHello(body []byte) (version int, ok bool) {
	if len(body) < 2+32+1 {
		return 0, false
	}
	version = be16(body[0:2])
	pos := 2 + 32
	pos += 1 + int(body[pos]) // session_id
	if len(body) < pos+3 {
		return 0, false
	}
	pos += 2 + 1 // cipher_suite, compression_method
	if len(body) < pos+2 {
		return version, true // no extensions: TLS 1.2 or older
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
		if etype == 43 && elen == 2 { // supported_versions: the server form carries exactly the selected version
			return be16(body[pos : pos+2]), true
		}
		pos += elen
	}
	return version, true
}

// leafFromCertificate pulls the first (leaf) certificate out of a TLS 1.2 Certificate message body, which may still be arriving: it needs only the list length, the first
// entry's length and that many bytes. more is true when the body is simply not long enough yet.
func leafFromCertificate(body []byte) (leaf []byte, more bool) {
	if len(body) < 6 {
		return nil, true
	}
	n := be24(body[3:6])
	if n == 0 || n > 16384 {
		return nil, false
	}
	if len(body) < 6+n {
		return nil, true
	}
	return body[6 : 6+n], false
}

// certFlow is one handshake in progress: the name the client asked for and the server's bytes so far, reassembled strictly in order.
type certFlow struct {
	name    string
	dst     string
	started time.Time
	buf     []byte
	nextSeq uint32
	haveSeq bool
}

const (
	certFlowMax   = 256
	certFlowBytes = 8192
	certFlowTTL   = 15 * time.Second
	certNamesMax  = 1000
)

// certSeen is the baseline kept for one name.
type certSeen struct {
	Name       string   `json:"name"`
	Version    int      `json:"version"`               // the best TLS version this name has negotiated
	Prints     []string `json:"prints,omitempty"`      // recent leaf SHA-256 fingerprints, newest last, at most four
	Issuer     string   `json:"issuer,omitempty"`      // organisation (or CN) of the last leaf's issuer
	SelfSigned bool     `json:"self_signed,omitempty"` // the last leaf was self-signed
	Covers     bool     `json:"covers"`                // the last leaf covered the name
	First      int64    `json:"first"`
	Last       int64    `json:"last"`
}

type certState struct {
	Names map[string]*certSeen `json:"names"`
}

type tlsCertFinding struct {
	T     int64  `json:"t"`
	Kind  string `json:"kind"`
	MAC   string `json:"mac,omitempty"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Name  string `json:"name"`
	Was   string `json:"was,omitempty"` // the issuer, or the version, before
	Now   string `json:"now,omitempty"` // and after
	Print string `json:"print,omitempty"`
}

type tlsCertWatch struct {
	mu      sync.Mutex
	path    string
	st      certState
	flows   map[string]*certFlow
	lastEv  map[string]time.Time
	finds   []tlsCertFinding
	now     func() time.Time
	emit    func(evt)
	macOf   func(ip string) string
	nameOf  func(mac string) string
	capOK   bool
	capOnce bool
	dirty   bool
}

func newTLSCertWatch(path string) *tlsCertWatch {
	w := &tlsCertWatch{path: path, st: certState{Names: map[string]*certSeen{}}, flows: map[string]*certFlow{}, lastEv: map[string]time.Time{}, now: time.Now,
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
		var st certState
		if json.Unmarshal(b, &st) == nil && st.Names != nil {
			w.st = st
		}
	}
	return w
}

func (w *tlsCertWatch) save() {
	if w.path == "" {
		return
	}
	b, _ := json.Marshal(w.st)
	writeFileAtomic(w.path, b, 0o600)
}

func (w *tlsCertWatch) label(ip, mac string) string {
	if n := w.nameOf(mac); n != "" {
		return fmt.Sprintf("%s (%s)", n, ip)
	}
	if mac != "" {
		return fmt.Sprintf("%s (%s)", ip, mac)
	}
	return ip
}

// observe feeds one accepted segment in either direction. Client->server segments open a flow when they carry a ClientHello with a hostname; server->client segments are
// reassembled in order until the ServerHello and, for TLS 1.2, the leaf certificate have arrived, or the flow is given up.
func (w *tlsCertWatch) observe(f tcpFrame, now time.Time) {
	_, lan, _ := net.ParseCIDR(lanCIDR)
	src, dst := net.ParseIP(f.Src), net.ParseIP(f.Dst)
	if src == nil || dst == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if f.DstPort == 443 && lan.Contains(src) && !lan.Contains(dst) {
		ch, ok := parseClientHello(f.Payload)
		if !ok || !ch.HasSNI || ch.SNI == "" || net.ParseIP(ch.SNI) != nil {
			return
		}
		if len(w.flows) >= certFlowMax {
			w.sweep(now)
			if len(w.flows) >= certFlowMax {
				return
			}
		}
		key := fmt.Sprintf("%s:%d", f.Src, f.SrcPort)
		w.flows[key] = &certFlow{name: strings.ToLower(ch.SNI), dst: f.Dst, started: now}
		return
	}
	if f.SrcPort != 443 {
		return
	}
	key := fmt.Sprintf("%s:%d", f.Dst, f.DstPort)
	fl, ok := w.flows[key]
	if !ok {
		return
	}
	if now.Sub(fl.started) > certFlowTTL {
		delete(w.flows, key)
		return
	}
	if fl.haveSeq {
		if f.Seq != fl.nextSeq {
			if int32(f.Seq-fl.nextSeq) < 0 {
				return // a retransmit of something already held
			}
			delete(w.flows, key) // a gap: never guess
			return
		}
	}
	fl.haveSeq = true
	fl.nextSeq = f.Seq + uint32(len(f.Payload))
	fl.buf = append(fl.buf, f.Payload...)
	if len(fl.buf) > certFlowBytes {
		delete(w.flows, key)
		return
	}
	done := w.consume(fl, f.Dst, now)
	if done {
		delete(w.flows, key)
	}
}

// consume walks the TLS records held so far. It returns true when the flow has told everything it can (or cannot be used), false when more bytes are needed.
func (w *tlsCertWatch) consume(fl *certFlow, client string, now time.Time) bool {
	var hs []byte
	pos := 0
	for pos+5 <= len(fl.buf) {
		rtype, rlen := fl.buf[pos], be16(fl.buf[pos+3:pos+5])
		if rtype != 0x16 {
			break // ChangeCipherSpec or application data before a certificate: a resumed session, or nothing we can read
		}
		end := pos + 5 + rlen
		if end > len(fl.buf) {
			hs = append(hs, fl.buf[pos+5:]...)
			break
		}
		hs = append(hs, fl.buf[pos+5:end]...)
		pos = end
	}
	version := 0
	hpos := 0
	for hpos+4 <= len(hs) {
		mtype, mlen := hs[hpos], be24(hs[hpos+1:hpos+4])
		body := hs[hpos+4:]
		switch mtype {
		case 2: // server_hello
			if len(body) < mlen {
				return false
			}
			v, ok := parseServerHello(body[:mlen])
			if !ok {
				return true
			}
			version = v
			w.noteVersion(fl, client, version, now)
			if version >= 0x0304 {
				return true // TLS 1.3: the certificate that follows is encrypted
			}
		case 11: // certificate
			if version == 0 {
				return true
			}
			if len(body) > mlen {
				body = body[:mlen]
			}
			leaf, more := leafFromCertificate(body)
			if more {
				return false
			}
			if leaf != nil {
				w.noteLeaf(fl, client, leaf, now)
			}
			return true
		default:
			if version == 0 {
				return true
			}
		}
		if len(body) < mlen {
			return false
		}
		hpos += 4 + mlen
	}
	if pos < len(fl.buf) && fl.buf[pos] != 0x16 {
		return true
	}
	return false
}

func (w *tlsCertWatch) seen(name string, now time.Time) (*certSeen, bool) {
	s, had := w.st.Names[name]
	if had {
		s.Last = now.Unix()
		return s, true
	}
	if len(w.st.Names) >= certNamesMax {
		w.evictOldest()
	}
	s = &certSeen{Name: name, First: now.Unix(), Last: now.Unix(), Covers: true}
	w.st.Names[name] = s
	return s, false
}

func (w *tlsCertWatch) evictOldest() {
	type nl struct {
		n string
		l int64
	}
	all := make([]nl, 0, len(w.st.Names))
	for n, s := range w.st.Names {
		all = append(all, nl{n, s.Last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].l < all[j].l })
	for i := 0; i < len(all)/10+1 && i < len(all); i++ {
		delete(w.st.Names, all[i].n)
	}
}

func (w *tlsCertWatch) noteVersion(fl *certFlow, client string, version int, now time.Time) {
	s, had := w.seen(fl.name, now)
	w.dirty = true
	if !had || version > s.Version {
		s.Version = version
		return
	}
	if s.Version >= 0x0304 && version < 0x0304 {
		w.raise(tlsCertFinding{Kind: "tls_downgrade", Src: client, Dst: fl.dst, Name: fl.name, Was: tlsVersionName(s.Version), Now: tlsVersionName(version)}, now)
	}
}

func tlsVersionName(v int) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

func issuerName(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.CommonName
}

func (w *tlsCertWatch) noteLeaf(fl *certFlow, client string, leaf []byte, now time.Time) {
	c, err := x509.ParseCertificate(leaf)
	if err != nil {
		return
	}
	sum := sha256.Sum256(leaf)
	print := hex.EncodeToString(sum[:])
	self := bytes.Equal(c.RawIssuer, c.RawSubject)
	covers := c.VerifyHostname(fl.name) == nil
	issuer := issuerName(c)
	s, had := w.seen(fl.name, now)
	w.dirty = true
	if had {
		for _, p := range s.Prints {
			if p == print {
				return
			}
		}
	}
	if had && len(s.Prints) > 0 {
		find := tlsCertFinding{Src: client, Dst: fl.dst, Name: fl.name, Was: s.Issuer, Now: issuer, Print: print}
		switch {
		case self && !s.SelfSigned:
			find.Kind = "tls_cert_selfsigned"
			w.raise(find, now)
		case !covers && s.Covers:
			find.Kind = "tls_cert_mismatch"
			w.raise(find, now)
		case issuer != s.Issuer:
			find.Kind = "tls_cert_issuer"
			w.raise(find, now)
		}
	}
	s.Prints = append(s.Prints, print)
	if len(s.Prints) > 4 {
		s.Prints = s.Prints[len(s.Prints)-4:]
	}
	s.Issuer, s.SelfSigned, s.Covers = issuer, self, covers
}

// raise records a finding and emits its event, at most one per name per 10 minutes.
func (w *tlsCertWatch) raise(f tlsCertFinding, now time.Time) {
	key := f.Kind + "|" + f.Name
	if t, had := w.lastEv[key]; had && now.Sub(t) < 10*time.Minute {
		return
	}
	w.lastEv[key] = now
	for k, t := range w.lastEv {
		if now.Sub(t) > time.Hour {
			delete(w.lastEv, k)
		}
	}
	f.T = now.Unix()
	f.MAC = w.macOf(f.Src)
	w.finds = append(w.finds, f)
	if len(w.finds) > 100 {
		w.finds = w.finds[len(w.finds)-100:]
	}
	who := w.label(f.Src, f.MAC)
	var text, public string
	sev := sevAttention
	switch f.Kind {
	case "tls_cert_selfsigned":
		sev = sevAlert
		text = fmt.Sprintf("%s was handed a self-signed certificate for %s, a name that was signed by %s before: this is what an interception box in the path looks like.", who, f.Name, f.Was)
		public = "A server's certificate changed from a public CA to self-signed"
	case "tls_cert_mismatch":
		text = fmt.Sprintf("%s was handed a certificate for %s that does not cover that name (issued by %s): a misconfigured edge does this, and so does something answering in the server's place.", who, f.Name, f.Now)
		public = "A server presented a certificate that does not cover its name"
	case "tls_cert_issuer":
		text = fmt.Sprintf("%s saw the certificate for %s change issuer, from %s to %s: sites do switch CAs, so look rather than worry, unless the new issuer is one you have never heard of.", who, f.Name, f.Was, f.Now)
		public = "A server's certificate issuer changed"
	case "tls_downgrade":
		text = fmt.Sprintf("%s negotiated %s with %s, a name that has always done %s from here: an interception box that cannot speak the newer version causes exactly this.", who, f.Now, f.Name, f.Was)
		public = "A server negotiated an older TLS version than it has before"
	}
	w.emit(evt{T: f.T, Kind: f.Kind, Sev: sev, Text: text, Public: public})
}

func (w *tlsCertWatch) sweep(now time.Time) {
	for k, fl := range w.flows {
		if now.Sub(fl.started) > certFlowTTL {
			delete(w.flows, k)
		}
	}
}

func (w *tlsCertWatch) Start() {
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
				log.Printf("TLS certificate watch: %v (retrying in a minute)", err)
			}
			w.mu.Lock()
			w.capOK = false
			w.mu.Unlock()
			time.Sleep(time.Minute)
		}
	}()
	go func() {
		for range time.Tick(30 * time.Second) {
			w.mu.Lock()
			w.sweep(w.now())
			if w.dirty {
				w.dirty = false
				w.save()
			}
			w.mu.Unlock()
		}
	}()
}

func (w *tlsCertWatch) capture() error {
	ifc, err := net.InterfaceByName("bridge0")
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	prog := bpfTCP443Both()
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
		if f, ok := parseTCPFrame(buf[:n]); ok {
			w.observe(f, w.now())
		}
	}
}

type tlsCertView struct {
	CaptureOK bool             `json:"capture_ok"`
	Names     int              `json:"names"`
	Findings  []tlsCertFinding `json:"findings"`
}

func (w *tlsCertWatch) View() tlsCertView {
	w.mu.Lock()
	defer w.mu.Unlock()
	v := tlsCertView{CaptureOK: w.capOK, Names: len(w.st.Names), Findings: []tlsCertFinding{}}
	for i := len(w.finds) - 1; i >= 0; i-- {
		v.Findings = append(v.Findings, w.finds[i])
	}
	return v
}

var tlsCertMgr *tlsCertWatch
