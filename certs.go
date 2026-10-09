package main

import (
	"crypto/x509"
	_ "embed"
)

// caBundle is the Mozilla root set (a Debian /etc/ssl/certs/ca-certificates.crt, copied 2026-10-01). The box's own /etc/ssl/certs has four
// DigiCert files and cannot verify Cloudflare (SSL.com) or other newer chains, so the daemon carries its own. Refresh with:
//
//	cp /etc/ssl/certs/ca-certificates.crt ca-bundle.pem   (then rebuild and redeploy)
//
//go:embed ca-bundle.pem
var caBundle []byte

func rootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(caBundle)
	return p
}
