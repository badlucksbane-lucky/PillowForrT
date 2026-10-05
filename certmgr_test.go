package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCM(t *testing.T) (*certManager, string) {
	dir := filepath.Join(t.TempDir(), "tls")
	m, created, err := newCertManager(dir, []string{"orbic", "wpad"}, []net.IP{net.ParseIP("192.168.1.254")})
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
	if v.Subject != "orbic" || v.Algorithm != "ECDSA P-256" || v.DaysLeft < 798 || v.DaysLeft > 800 || len(v.Missing) != 0 || v.Due || len(v.IPs) != 1 || v.Fingerprint != m.Fingerprint() {
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
