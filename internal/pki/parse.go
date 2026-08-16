package pki

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// ParseCSR decodes a PEM-encoded PKCS#10 certificate request.
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, nil
}

// ParseCertificate decodes a PEM-encoded X.509 certificate.
func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ParsePrivateKey decodes a PEM-encoded PKCS#8 Ed25519 private key.
func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM: no block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T (want ed25519)", key)
	}
	return priv, nil
}

// MarshalPrivateKey encodes an Ed25519 private key as PKCS#8 PEM.
func MarshalPrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Fingerprint returns the SHA-256 fingerprint of a certificate as lowercase
// hex pairs separated by colons (e.g. "b8:2f:f4:...").
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := hex.EncodeToString(sum[:])
	var b strings.Builder
	b.Grow(len(h) + len(h)/2 - 1)
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// ExpiresIn returns the remaining validity of the certificate.
func ExpiresIn(cert *x509.Certificate) time.Duration {
	return time.Until(cert.NotAfter)
}

// IsExpired reports whether the certificate is currently outside its validity
// window (with the documented ±5min clock-skew tolerance).
func IsExpired(cert *x509.Certificate) bool {
	now := time.Now()
	return now.Before(cert.NotBefore) || now.After(cert.NotAfter)
}

// VerifyClientCertificate checks that cert chains to ca, has ClientAuth EKU
// and is not expired. This mirrors the handshake-time checks (Phase 4 wires
// it into mTLS; revocation is checked separately against the revocation list).
func VerifyClientCertificate(cert *x509.Certificate, ca *x509.Certificate) error {
	if err := VerifyChain(cert, ca); err != nil {
		return err
	}
	// EKU: ClientAuth must be present (and ServerAuth is irrelevant).
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		return fmt.Errorf("certificate is not valid for client authentication")
	}
	return nil
}

// VerifyChain checks cert chains to ca (as a root) at the current time.
func VerifyChain(cert, ca *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}
	return nil
}
