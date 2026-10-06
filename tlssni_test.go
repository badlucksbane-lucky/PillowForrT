package main

import "testing"

// buildClientHello assembles a minimal, well-formed TLS record containing a ClientHello, optionally with an SNI extension for hostName (empty = no SNI extension at all).
func buildClientHello(hostName string) []byte {
	var exts []byte
	if hostName != "" {
		sni := append([]byte{0x00, byte(len(hostName) >> 8), byte(len(hostName))}, hostName...) // type=0 (host_name), len, name
		sniList := append([]byte{byte(len(sni) >> 8), byte(len(sni))}, sni...)
		ext := append([]byte{0x00, 0x00}, byte(len(sniList)>>8), byte(len(sniList)))
		ext = append(ext, sniList...)
		exts = append(exts, ext...)
	}
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)             // client_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id_len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites_len=2, one suite
	body = append(body, 0x01, 0x00)             // compression_methods_len=1, one method
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

func TestParseClientHelloSNI(t *testing.T) {
	t.Run("with SNI", func(t *testing.T) {
		name, has, ok := parseClientHelloSNI(buildClientHello("example.com"))
		if !ok || !has || name != "example.com" {
			t.Fatalf("name=%q has=%v ok=%v, want example.com true true", name, has, ok)
		}
	})
	t.Run("no SNI", func(t *testing.T) {
		_, has, ok := parseClientHelloSNI(buildClientHello(""))
		if !ok || has {
			t.Fatalf("has=%v ok=%v, want false true", has, ok)
		}
	})
	t.Run("SNI is the bare IP", func(t *testing.T) {
		name, has, ok := parseClientHelloSNI(buildClientHello("203.0.113.9"))
		if !ok || !has || name != "203.0.113.9" {
			t.Fatalf("name=%q has=%v ok=%v", name, has, ok)
		}
	})
	t.Run("not a handshake record", func(t *testing.T) {
		if _, _, ok := parseClientHelloSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}); ok {
			t.Fatal("an application-data record must never be read as a ClientHello")
		}
	})
	t.Run("truncated / split across segments", func(t *testing.T) {
		full := buildClientHello("example.com")
		if _, _, ok := parseClientHelloSNI(full[:len(full)-5]); ok {
			t.Fatal("a ClientHello whose declared length exceeds what's present must not be guessed at")
		}
	})
	t.Run("empty payload", func(t *testing.T) {
		if _, _, ok := parseClientHelloSNI(nil); ok {
			t.Fatal("empty payload must not parse")
		}
	})
}

func TestParseTLSFrameAndBPF(t *testing.T) {
	// A minimal Ethernet+IPv4+TCP frame carrying one byte of payload, dst port 443.
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5 (20 bytes)
	copy(ip[12:16], []byte{192, 168, 1, 50})
	copy(ip[16:20], []byte{93, 184, 216, 34})
	ip[9] = 6 // TCP
	tcp := make([]byte, 20+1)
	tcp[2], tcp[3] = 0x01, 0xbb // dst port 443
	tcp[12] = 5 << 4            // data offset 20 bytes
	tcp[20] = 0x16              // one payload byte: a handshake record's first byte
	pkt := append(append(eth, ip...), tcp...)

	f, ok := parseTLSFrame(pkt)
	if !ok {
		t.Fatal("a well-formed frame with payload should parse")
	}
	if f.Src != "192.168.1.50" || f.Dst != "93.184.216.34" || len(f.Payload) != 1 {
		t.Fatalf("got %+v", f)
	}

	if out := runBPF(bpfTCP443(), pkt); out == 0 {
		t.Error("the BPF filter should accept a TCP segment to port 443")
	}
	tcp443to80 := append([]byte(nil), pkt...)
	tcp443to80[14+20+2], tcp443to80[14+20+3] = 0x00, 0x50 // dst port 80
	if out := runBPF(bpfTCP443(), tcp443to80); out != 0 {
		t.Error("the BPF filter should reject a TCP segment to port 80")
	}
}
