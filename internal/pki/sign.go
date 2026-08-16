package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// SignClientCertificate issues a client certificate from a CSR (POP):
//   - the CSR signature must verify (proof of possession);
//   - the key algorithm must be Ed25519;
//   - the CN must be a valid client id;
//   - the serial is a fresh random 128-bit value;
//   - KeyUsage=DigitalSignature, ExtKeyUsage=ClientAuth;
//   - NotBefore=now-5min, NotAfter=min(now+validityDays, CA NotAfter).
func SignClientCertificate(ca *CA, csrPEM []byte, validityDays int) ([]byte, error) {
	if ca == nil || ca.Cert == nil {
		return nil, fmt.Errorf("ca is required")
	}
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if csr.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, fmt.Errorf("CSR key algorithm must be Ed25519 (got %v)", csr.PublicKeyAlgorithm)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid (proof of possession failed): %w", err)
	}
	if err := ValidateClientID(csr.Subject.CommonName); err != nil {
		return nil, fmt.Errorf("CSR CN: %w", err)
	}
	if validityDays < 1 || validityDays > 825 {
		return nil, fmt.Errorf("validity days must be in [1,825] (got %d)", validityDays)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(time.Duration(validityDays) * 24 * time.Hour)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         csr.Subject.CommonName,
			Organization:       []string{"qoqtun-client"},
			OrganizationalUnit: csr.Subject.OrganizationalUnit,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SignServerCertificate issues the single server certificate (TLS ServerAuth)
// with SAN entries covering the provided IPs and DNS names. It returns the
// certificate PEM and the private key PEM separately for storage.
func SignServerCertificate(ca *CA, validityDays int, ips []net.IP, dnsNames []string) (certPEM, keyPEM []byte, err error) {
	if ca == nil || ca.Cert == nil {
		return nil, nil, fmt.Errorf("ca is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	notAfter := now.Add(time.Duration(validityDays) * 24 * time.Hour)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "qoqtun server"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign server certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal server key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
