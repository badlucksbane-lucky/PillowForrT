package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"
)

// Test builders for the three plaintext handshake pieces the watch reads.

func tcBuildClientHello(sni string) []byte {
	name := []byte(sni)
	sniExt := append([]byte{0x00, 0x00, byte((5 + len(name)) >> 8), byte(5 + len(name)), byte((3 + len(name)) >> 8), byte(3 + len(name)), 0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher
	body = append(body, 0x01, 0x00)             // compression
	body = append(body, byte(len(sniExt)>>8), byte(len(sniExt)))
	body = append(body, sniExt...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func tcHandshakeMsg(mtype byte, body []byte) []byte {
	return append([]byte{mtype, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func tcRecord(rtype byte, body []byte) []byte {
	return append([]byte{rtype, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
}

func tcServerHello(v13 bool) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)       // session_id
	body = append(body, 0x13, 0x01) // cipher
	body = append(body, 0x00)       // compression
	if v13 {
		ext := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
		body = append(body, 0x00, byte(len(ext)))
		body = append(body, ext...)
	}
	return tcHandshakeMsg(2, body)
}

func tcCertificateMsg(leaf []byte) []byte {
	entry := append([]byte{byte(len(leaf) >> 16), byte(len(leaf) >> 8), byte(len(leaf))}, leaf...)
	return tcHandshakeMsg(11, append([]byte{byte(len(entry) >> 16), byte(len(entry) >> 8), byte(len(entry))}, entry...))
}

// tcCert makes a leaf for name. When issuerOrg is "", it is self-signed; otherwise it is signed by a throwaway CA of that organisation.
func tcCert(t *testing.T, name, issuerOrg string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	parent, parentKey := tmpl, key
	if issuerOrg != "" {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{issuerOrg}, CommonName: issuerOrg + " CA"}, IsCA: true, BasicConstraintsValid: true,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		parent, parentKey = ca, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tcHarness wires a watch with a captured event list and a fixed clock.
type tcHarness struct {
	w      *tlsCertWatch
	events []evt
	now    time.Time
	port   int
}

func newTCHarness(t *testing.T) *tcHarness {
	h := &tcHarness{now: time.Unix(1_700_000_000, 0), port: 40000}
	h.w = newTLSCertWatch("")
	h.w.now = func() time.Time { return h.now }
	h.w.emit = func(e evt) { h.events = append(h.events, e) }
	h.w.macOf = func(string) string { return "aa:bb:cc:dd:ee:ff" }
	h.w.nameOf = func(string) string { return "laptop" }
	return h
}

// handshake plays one client hello and then the server's bytes, in the given segments, through observe.
func (h *tcHarness) handshake(name string, segments ...[]byte) {
	h.port++
	h.w.observe(tcpFrame{Src: "192.168.1.20", Dst: "203.0.113.5", SrcPort: h.port, DstPort: 443, Seq: 1, Payload: tcBuildClientHello(name)}, h.now)
	seq := uint32(1000)
	for _, s := range segments {
		h.w.observe(tcpFrame{Src: "203.0.113.5", Dst: "192.168.1.20", SrcPort: 443, DstPort: h.port, Seq: seq, Payload: s}, h.now)
		seq += uint32(len(s))
	}
}

func tcFlight12(leaf []byte) []byte {
	return tcRecord(0x16, append(append([]byte{}, tcServerHello(false)...), tcCertificateMsg(leaf)...))
}

func TestTLSCertBaselineThenSelfSigned(t *testing.T) {
	h := newTCHarness(t)
	h.handshake("example.com", tcFlight12(tcCert(t, "example.com", "Good CA")))
	if len(h.events) != 0 {
		t.Fatalf("first sight is the baseline, got %+v", h.events)
	}
	if s := h.w.st.Names["example.com"]; s == nil || s.Issuer != "Good CA" || s.SelfSigned || !s.Covers || len(s.Prints) != 1 {
		t.Fatalf("baseline not recorded: %+v", s)
	}
	h.now = h.now.Add(time.Hour)
	h.handshake("example.com", tcFlight12(tcCert(t, "example.com", "")))
	if len(h.events) != 1 || h.events[0].Kind != "tls_cert_selfsigned" || h.events[0].Sev != sevAlert {
		t.Fatalf("self-signed after a CA cert should be an alert, got %+v", h.events)
	}
	if h.events[0].Public == "" || h.events[0].Text == "" {
		t.Fatal("event needs both texts")
	}
	if v := h.w.View(); len(v.Findings) != 1 || v.Findings[0].Name != "example.com" || v.Findings[0].Was != "Good CA" || v.Findings[0].MAC == "" {
		t.Fatalf("finding: %+v", v.Findings)
	}
}

func TestTLSCertRenewalSilentIssuerChangeFlagged(t *testing.T) {
	h := newTCHarness(t)
	h.handshake("a.example", tcFlight12(tcCert(t, "a.example", "Good CA")))
	h.handshake("a.example", tcFlight12(tcCert(t, "a.example", "Good CA")))
	if len(h.events) != 0 {
		t.Fatalf("a renewal from the same issuer is silent, got %+v", h.events)
	}
	if n := len(h.w.st.Names["a.example"].Prints); n != 2 {
		t.Fatalf("both fingerprints kept, got %d", n)
	}
	h.handshake("a.example", tcFlight12(tcCert(t, "a.example", "Other CA")))
	if len(h.events) != 1 || h.events[0].Kind != "tls_cert_issuer" || h.events[0].Sev != sevAttention {
		t.Fatalf("issuer change: %+v", h.events)
	}
	// the same change again inside the rate window is not repeated, and the new issuer is now the baseline
	h.handshake("a.example", tcFlight12(tcCert(t, "a.example", "Other CA")))
	if len(h.events) != 1 {
		t.Fatalf("new issuer should be the baseline now, got %+v", h.events)
	}
}

func TestTLSCertMismatch(t *testing.T) {
	h := newTCHarness(t)
	h.handshake("shop.example", tcFlight12(tcCert(t, "shop.example", "Good CA")))
	h.handshake("shop.example", tcFlight12(tcCert(t, "elsewhere.example", "Good CA")))
	if len(h.events) != 1 || h.events[0].Kind != "tls_cert_mismatch" {
		t.Fatalf("a cert that no longer covers the name: %+v", h.events)
	}
}

func TestTLSCertSplitSegmentsAndGap(t *testing.T) {
	h := newTCHarness(t)
	flight := tcFlight12(tcCert(t, "split.example", "Good CA"))
	cut := len(flight) / 2
	h.handshake("split.example", flight[:cut], flight[cut:])
	if h.w.st.Names["split.example"] == nil || len(h.w.st.Names["split.example"].Prints) != 1 {
		t.Fatal("a certificate split across two in-order segments should be reassembled")
	}
	if len(h.w.flows) != 0 {
		t.Fatal("finished flow should be dropped")
	}
	// a gap: the second segment is lost, the third arrives; the flow is dropped, nothing is recorded
	h2 := newTCHarness(t)
	third := len(flight) / 3
	h2.port++
	h2.w.observe(tcpFrame{Src: "192.168.1.20", Dst: "203.0.113.5", SrcPort: h2.port, DstPort: 443, Seq: 1, Payload: tcBuildClientHello("gap.example")}, h2.now)
	h2.w.observe(tcpFrame{Src: "203.0.113.5", Dst: "192.168.1.20", SrcPort: 443, DstPort: h2.port, Seq: 1000, Payload: flight[:third]}, h2.now)
	h2.w.observe(tcpFrame{Src: "203.0.113.5", Dst: "192.168.1.20", SrcPort: 443, DstPort: h2.port, Seq: 1000 + uint32(2*third), Payload: flight[2*third:]}, h2.now)
	if len(h2.w.flows) != 0 {
		t.Fatal("a gap should drop the flow, never guess")
	}
	if s := h2.w.st.Names["gap.example"]; s != nil && len(s.Prints) != 0 {
		t.Fatalf("nothing should be recorded from a flow with a gap, got %+v", s)
	}
}

func TestTLSCertVersionDowngrade(t *testing.T) {
	h := newTCHarness(t)
	h.handshake("modern.example", tcRecord(0x16, tcServerHello(true)))
	if s := h.w.st.Names["modern.example"]; s == nil || s.Version != 0x0304 {
		t.Fatalf("TLS 1.3 should be recorded from supported_versions: %+v", s)
	}
	if len(h.w.flows) != 0 {
		t.Fatal("a 1.3 flow has nothing more to tell and should be dropped")
	}
	h.handshake("modern.example", tcFlight12(tcCert(t, "modern.example", "Good CA")))
	if len(h.events) != 1 || h.events[0].Kind != "tls_downgrade" || h.events[0].Sev != sevAttention {
		t.Fatalf("1.3 name negotiating 1.2: %+v", h.events)
	}
	// the other way round is an upgrade and never an event
	h2 := newTCHarness(t)
	h2.handshake("old.example", tcFlight12(tcCert(t, "old.example", "Good CA")))
	h2.handshake("old.example", tcRecord(0x16, tcServerHello(true)))
	if len(h2.events) != 0 {
		t.Fatalf("upgrade should be silent: %+v", h2.events)
	}
}

func TestTLSCertResumedSessionIgnored(t *testing.T) {
	h := newTCHarness(t)
	h.handshake("resume.example", append(tcRecord(0x16, tcServerHello(false)), tcRecord(0x14, []byte{0x01})...))
	if len(h.events) != 0 || len(h.w.flows) != 0 {
		t.Fatalf("ServerHello then ChangeCipherSpec is a resumed session: no cert, no event, flow dropped (%d flows, %+v)", len(h.w.flows), h.events)
	}
	if s := h.w.st.Names["resume.example"]; s == nil || s.Version != 0x0303 {
		t.Fatal("the version is still recorded")
	}
}

func TestTLSCertScopeAndLimits(t *testing.T) {
	h := newTCHarness(t)
	// a bare-IP SNI, no SNI, or a LAN destination never opens a flow
	h.w.observe(tcpFrame{Src: "192.168.1.20", Dst: "203.0.113.5", SrcPort: 1, DstPort: 443, Seq: 1, Payload: tcBuildClientHello("203.0.113.5")}, h.now)
	h.w.observe(tcpFrame{Src: "192.168.1.20", Dst: "192.168.1.1", SrcPort: 2, DstPort: 443, Seq: 1, Payload: tcBuildClientHello("router.lan")}, h.now)
	h.w.observe(tcpFrame{Src: "192.168.1.20", Dst: "203.0.113.5", SrcPort: 3, DstPort: 443, Seq: 1, Payload: buildClientHelloJA3()}, h.now)
	if len(h.w.flows) != 0 {
		t.Fatalf("out-of-scope hellos opened %d flows", len(h.w.flows))
	}
	// a server segment for no known flow is dropped after one lookup
	h.w.observe(tcpFrame{Src: "203.0.113.5", Dst: "192.168.1.20", SrcPort: 443, DstPort: 9, Seq: 5, Payload: []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}}, h.now)
	// a flow that outlives its TTL is dropped on the next segment; a sweep clears stale ones
	h.port++
	h.w.observe(tcpFrame{Src: "192.168.1.20", Dst: "203.0.113.5", SrcPort: h.port, DstPort: 443, Seq: 1, Payload: tcBuildClientHello("slow.example")}, h.now)
	h.now = h.now.Add(certFlowTTL + time.Second)
	h.w.sweep(h.now)
	if len(h.w.flows) != 0 {
		t.Fatal("stale flow should be swept")
	}
	// the name table is capped
	for i := 0; i < certNamesMax+50; i++ {
		h.now = h.now.Add(time.Second)
		h.w.seen(string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26))+".example", h.now)
	}
	if len(h.w.st.Names) > certNamesMax {
		t.Fatalf("name table grew to %d", len(h.w.st.Names))
	}
}

func TestTLSCertPersistence(t *testing.T) {
	path := t.TempDir() + "/tlscert.json"
	w := newTLSCertWatch(path)
	w.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	w.emit = func(evt) {}
	w.macOf = func(string) string { return "" }
	w.nameOf = func(string) string { return "" }
	w.observe(tcpFrame{Src: "192.168.1.20", Dst: "203.0.113.5", SrcPort: 7, DstPort: 443, Seq: 1, Payload: tcBuildClientHello("keep.example")}, w.now())
	w.observe(tcpFrame{Src: "203.0.113.5", Dst: "192.168.1.20", SrcPort: 443, DstPort: 7, Seq: 1, Payload: tcFlight12(tcCert(t, "keep.example", "Good CA"))}, w.now())
	w.save()
	w2 := newTLSCertWatch(path)
	if s := w2.st.Names["keep.example"]; s == nil || s.Issuer != "Good CA" || len(s.Prints) != 1 {
		t.Fatalf("baseline should survive a restart: %+v", s)
	}
}

func TestParseServerHello(t *testing.T) {
	if v, ok := parseServerHello(tcServerHello(false)[4:]); !ok || v != 0x0303 {
		t.Fatalf("1.2 hello: %x %v", v, ok)
	}
	if v, ok := parseServerHello(tcServerHello(true)[4:]); !ok || v != 0x0304 {
		t.Fatalf("1.3 hello: %x %v", v, ok)
	}
	if _, ok := parseServerHello([]byte{0x03, 0x03, 0x00}); ok {
		t.Fatal("truncated hello should not parse")
	}
}

func TestParseTCPFrame(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	b := make([]byte, 14+20+20+len(payload))
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	ip[9] = 6
	copy(ip[12:16], net.ParseIP("203.0.113.5").To4())
	copy(ip[16:20], net.ParseIP("192.168.1.20").To4())
	tcp := b[34:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 51234)
	binary.BigEndian.PutUint32(tcp[4:8], 0xdeadbeef)
	tcp[12] = 5 << 4
	copy(tcp[20:], payload)
	f, ok := parseTCPFrame(b)
	if !ok || f.Src != "203.0.113.5" || f.Dst != "192.168.1.20" || f.SrcPort != 443 || f.DstPort != 51234 || f.Seq != 0xdeadbeef || len(f.Payload) != len(payload) {
		t.Fatalf("frame: %+v %v", f, ok)
	}
	if _, ok := parseTCPFrame(b[:54]); ok {
		t.Fatal("a segment with no payload is not interesting")
	}
}
