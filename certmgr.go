package main

// The web page's certificate, renewable while running. The server asks this manager for its certificate on every new connection (tls.Config.GetCertificate), so a renewal
// takes effect at once without a restart. It renews by itself when the certificate has under 60 days left or stops covering the names and addresses it must, and on demand
// from the page. A renewal makes a NEW key and a NEW fingerprint, so browsers and anything that pinned the old certificate must trust the new one again; the previous pair
// is kept as cert.pem.prev / key.pem.prev. The public certificate can be downloaded to install as trusted on a device.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const certRenewBefore = 60 * 24 * time.Hour

type certManager struct {
	mu    sync.RWMutex
	dir   string
	names []string
	ips   []net.IP
	now   func() time.Time
	cert  tls.Certificate
	fp    string
	last  time.Time // when it was last renewed in this run
}

func newCertManager(dir string, names []string, ips []net.IP) (*certManager, bool, error) {
	m := &certManager{dir: dir, names: names, ips: ips, now: time.Now}
	c, fp, created, err := loadOrCreateCert(dir, names, ips, m.now())
	if err != nil {
		return nil, false, err
	}
	m.cert, m.fp = c, fp
	return m, created, nil
}

func (m *certManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cert
	return &c, nil
}

func (m *certManager) Fingerprint() string { m.mu.RLock(); defer m.mu.RUnlock(); return m.fp }

// Renew makes a new key and certificate and starts serving it.
func (m *certManager) Renew() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.last.IsZero() && m.now().Sub(m.last) < time.Minute {
		return "", errors.New("it was only just renewed: wait a minute")
	}
	c, fp, err := createCert(m.dir, m.names, m.ips, m.now())
	if err != nil {
		return "", err
	}
	m.cert, m.fp, m.last = c, fp, m.now()
	return fp, nil
}

// due says whether the certificate needs renewing now, and why.
func (m *certManager) due() (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l := m.cert.Leaf
	if l == nil {
		return true, "no certificate"
	}
	if !l.NotAfter.After(m.now().Add(certRenewBefore)) {
		return true, "less than 60 days left"
	}
	if !covers(l, m.names, m.ips) {
		return true, "it no longer covers every name and address"
	}
	return false, ""
}

// Check renews when due (the daily loop).
func (m *certManager) Check() {
	if due, why := m.due(); due {
		if fp, err := m.Renew(); err != nil {
			log.Printf("certificate renewal (%s) failed: %v", why, err)
		} else {
			log.Printf("certificate renewed (%s); new SHA-256 %s", why, fp)
		}
	}
}

func (m *certManager) Run() {
	for {
		time.Sleep(6 * time.Hour)
		m.Check()
	}
}

type certView struct {
	Subject     string   `json:"subject"`
	Names       []string `json:"names"`
	IPs         []string `json:"ips"`
	NotBefore   int64    `json:"not_before"`
	NotAfter    int64    `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	Fingerprint string   `json:"fingerprint"`
	Algorithm   string   `json:"algorithm"`
	Serial      string   `json:"serial"`
	RenewsAt    int64    `json:"renews_at"`
	Due         bool     `json:"due"`
	Reason      string   `json:"reason,omitempty"`
	Missing     []string `json:"missing,omitempty"` // names the page needs that the certificate does not cover
}

func (m *certManager) View() certView {
	due, why := m.due()
	m.mu.RLock()
	defer m.mu.RUnlock()
	l := m.cert.Leaf
	v := certView{Fingerprint: m.fp, Due: due, Reason: why}
	if l == nil {
		return v
	}
	v.Subject, v.NotBefore, v.NotAfter = l.Subject.CommonName, l.NotBefore.Unix(), l.NotAfter.Unix()
	v.DaysLeft = int(l.NotAfter.Sub(m.now()).Hours() / 24)
	v.RenewsAt = l.NotAfter.Add(-certRenewBefore).Unix()
	v.Names = append([]string{}, l.DNSNames...)
	for _, ip := range l.IPAddresses {
		v.IPs = append(v.IPs, ip.String())
	}
	sort.Strings(v.Names)
	v.Algorithm = l.PublicKeyAlgorithm.String()
	if l.PublicKeyAlgorithm == x509.ECDSA {
		v.Algorithm = "ECDSA P-256"
	}
	v.Serial = l.SerialNumber.Text(16)
	for _, n := range m.names {
		if l.VerifyHostname(n) != nil {
			v.Missing = append(v.Missing, n)
		}
	}
	for _, ip := range m.ips {
		if l.VerifyHostname(ip.String()) != nil {
			v.Missing = append(v.Missing, ip.String())
		}
	}
	return v
}

// PEM is the public certificate (never the key), for installing as trusted.
func (m *certManager) PEM() ([]byte, error) { return os.ReadFile(filepath.Join(m.dir, "cert.pem")) }
