package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCM(t *testing.T) (*certManager, string) {
	dir := filepath.Join(t.TempDir(), "tls")
	m, created, err := newCertManager(dir, []string{"pillowforrt", "wpad"}, []net.IP{net.ParseIP("192.168.1.254")})
	if err != nil || !created {
		t.Fatal(created, err)
	}
	return m, dir
}

func servedFP(t *testing.T, m *certManager) string {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: m.GetCertificate}) // a plain listener: httptest would add its own certificate
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return fingerprint(conn.ConnectionState().PeerCertificates[0].Raw)
}

func TestCertRenewIsServedWithoutRestart(t *testing.T) {
	m, dir := newCM(t)
	fp1 := servedFP(t, m)
	if fp1 != m.Fingerprint() {
		t.Fatal("served certificate is not the manager's")
	}
	m.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	fp2, err := m.Renew()
	if err != nil || fp2 == fp1 {
		t.Fatalf("%v same=%v", err, fp2 == fp1)
	}
	if got := servedFP(t, m); got != fp2 {
		t.Errorf("the new certificate is not being served: %s", got)
	}
	for _, f := range []string{"cert.pem.prev", "key.pem.prev"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("no %s", f)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "key.pem")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Join(dir, "key.pem.prev")); fi.Mode().Perm() != 0o600 {
		t.Errorf("old key copy mode %v", fi.Mode().Perm())
	}
	if _, err := m.Renew(); err == nil || !strings.Contains(err.Error(), "just renewed") {
		t.Errorf("a renewal right after another was allowed: %v", err)
	}
	// a restart picks up the renewed pair from disk
	m2, created, err := newCertManager(dir, m.names, m.ips)
	if err != nil || created || m2.Fingerprint() != fp2 {
		t.Errorf("restart: %v %v", created, err)
	}
}

func TestCertAutoRenewWhenDue(t *testing.T) {
	m, _ := newCM(t)
	if due, _ := m.due(); due {
		t.Fatal("a fresh certificate is due")
	}
	fp1 := m.Fingerprint()
	m.Check()
	if m.Fingerprint() != fp1 {
		t.Error("renewed a good certificate")
	}
	m.now = func() time.Time { return time.Now().Add(750 * 24 * time.Hour) } // 50 days left
	due, why := m.due()
	if !due || !strings.Contains(why, "60 days") {
		t.Fatalf("%v %q", due, why)
	}
	m.Check()
	if m.Fingerprint() == fp1 {
		t.Error("the loop did not renew a certificate with under 60 days left")
	}
	m.now = time.Now
	m.names = append(m.names, "brand-new-name")
	if due, why := m.due(); !due || !strings.Contains(why, "cover") {
		t.Errorf("a missing name should make it due: %v %q", due, why)
	}
}

func TestCertViewAndDownload(t *testing.T) {
	m, dir := newCM(t)
	v := m.View()
	if v.Subject != "pillowforrt" || v.Algorithm != "ECDSA P-256" || v.DaysLeft < 798 || v.DaysLeft > 800 || len(v.Missing) != 0 || v.Due || len(v.IPs) != 1 || v.Fingerprint != m.Fingerprint() {
		t.Errorf("%+v", v)
	}
	if v.RenewsAt != v.NotAfter-int64(certRenewBefore.Seconds()) {
		t.Error("renews_at")
	}
	pem, err := m.PEM()
	if err != nil || !strings.Contains(string(pem), "BEGIN CERTIFICATE") || strings.Contains(string(pem), "PRIVATE KEY") {
		t.Error("the download must be the public certificate only")
	}
	key, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
	if strings.Contains(string(pem), string(key[:40])) {
		t.Error("key material in the download")
	}
	m.names = append(m.names, "elsewhere")
	if v := m.View(); len(v.Missing) != 1 || v.Missing[0] != "elsewhere" {
		t.Errorf("missing %+v", v.Missing)
	}
}

// The certificate is a CA so a phone's installer accepts it, and it can vouch for nothing but the box's own names and addresses.
func TestCertIsConstrainedCA(t *testing.T) {
	dir := t.TempDir()
	names := []string{"pillowforrt", "pillowforrt.lan"}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	c, _, err := createCert(dir, names, ips, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca := c.Leaf
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 || !ca.PermittedDNSDomainsCritical {
		t.Fatalf("not a constrained CA: %+v", ca)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	// the box's own page still verifies against itself
	for _, n := range []string{"pillowforrt", "pillowforrt.lan", "192.168.1.1"} {
		if _, err := ca.Verify(x509.VerifyOptions{Roots: roots, DNSName: n}); err != nil {
			t.Errorf("the box's own %s must verify: %v", n, err)
		}
	}
	// a certificate this key signs for any other name or address is refused by the constraint
	sign := func(dns string, ip net.IP) error {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if dns != "" {
			tpl.DNSNames = []string{dns}
		}
		if ip != nil {
			tpl.IPAddresses = []net.IP{ip}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, c.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		host := dns
		if ip != nil {
			host = ip.String()
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
		return err
	}
	if err := sign("pillowforrt", nil); err != nil {
		t.Errorf("a leaf for the box's own name should verify: %v", err)
	}
	for _, bad := range []string{"bank.example", "www.google.com", "evil.pillowforrt.example"} {
		if sign(bad, nil) == nil {
			t.Errorf("a certificate for %s must be refused by the name constraint", bad)
		}
	}
	if sign("", net.ParseIP("8.8.8.8")) == nil {
		t.Error("a certificate for a public address must be refused by the name constraint")
	}
}

// A certificate made before it was a CA is replaced once; a current one is kept.
func TestCertNonCAIsReplacedOnce(t *testing.T) {
	dir := t.TempDir()
	names := []string{"pillowforrt"}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pillowforrt"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(700 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, DNSNames: names, IPAddresses: ips}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kb, _ := x509.MarshalECPrivateKey(k)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	_, fp1, created, err := loadOrCreateCert(dir, names, ips, time.Now())
	if err != nil || !created {
		t.Fatalf("an old non-CA certificate should be replaced: created=%v err=%v", created, err)
	}
	if fp1 == fingerprint(der) {
		t.Fatal("the fingerprint should have changed")
	}
	_, fp2, created, err := loadOrCreateCert(dir, names, ips, time.Now())
	if err != nil || created || fp2 != fp1 {
		t.Fatalf("the new certificate must be kept on the next start: created=%v err=%v", created, err)
	}
}
