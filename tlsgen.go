package main

// The web page's certificate: self-signed, made on first start and kept (cert.pem, key.pem mode 0600) so a browser's "trust this" survives restarts. ECDSA P-256 (cheap on
// this core). Valid 800 days (Apple will not trust a longer-lived certificate even when you install it yourself); remade, with a new fingerprint, only when it is about to
// expire or no longer covers the names and addresses below.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func covers(c *x509.Certificate, names []string, ips []net.IP) bool {
	for _, n := range names {
		if c.VerifyHostname(n) != nil {
			return false
		}
	}
	for _, ip := range ips {
		if c.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

func loadOrCreateCert(dir string, names []string, ips []net.IP, now time.Time) (cert tls.Certificate, fp string, created bool, err error) {
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if c, e := tls.LoadX509KeyPair(cp, kp); e == nil {
		if leaf, e := x509.ParseCertificate(c.Certificate[0]); e == nil && leaf.NotAfter.After(now.Add(60*24*time.Hour)) && covers(leaf, names, ips) {
			c.Leaf = leaf
			return c, fingerprint(leaf.Raw), false, nil
		}
	}
	cert, fp, err = createCert(dir, names, ips, now)
	return cert, fp, err == nil, err
}

// createCert makes a fresh key and self-signed certificate and writes both (key 0600) so that a crash between the two renames can only leave a mismatched pair, which
// loadOrCreateCert treats as "make a new one". The previous pair is kept as cert.pem.prev / key.pem.prev.
func createCert(dir string, names []string, ips []net.IP, now time.Time) (tls.Certificate, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, "", err
	}
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "orbic", Organization: []string{"Stone of Heimdall"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(800 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	for _, f := range []string{kp, cp} { // keep the pair being replaced
		if b, err := os.ReadFile(f); err == nil {
			writeFileAtomic(f+".prev", b, 0o600)
		}
	}
	if err := writeFileAtomic(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFileAtomic(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, fingerprint(der), nil
}
