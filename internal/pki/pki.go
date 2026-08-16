// Package pki implements the qoqtun CA / CSR / certificate logic
// (docs/plan/03-pki-enrollment.md). It is pure function oriented and uses
// only the standard library: crypto/ed25519, crypto/x509, crypto/x509/pkix,
// crypto/rand, crypto/sha256 and PEM encoding. No self-designed crypto.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"time"
)

// CA is a loaded Root CA with its signing key.
type CA struct {
	Cert *x509.Certificate
	Key  ed25519.PrivateKey
}

// GenerateCA creates a self-signed Ed25519 Root CA (03-pki-enrollment.md §1):
// 128-bit random serial, IsCA=true, KeyUsage=CertSign|CRLSign, validity
// from now-5min (clock-skew tolerance) to now+validity.
func GenerateCA(validity time.Duration) (*CA, error) {
	if validity <= 0 {
		return nil, fmt.Errorf("ca validity must be positive")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "qoqtun Root CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // direct issuance only, no intermediate CAs
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{Cert: cert, Key: priv}, nil
}

// GenerateKey creates a fresh Ed25519 private key from crypto/rand.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return priv, nil
}

// base32Lower encodes without padding using the lowercase, unambiguous
// base32 alphabet (a-z2-7: no 0/1 and no case ambiguity).
var base32Lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var clientIDRe = regexp.MustCompile(`^cl_[a-z2-7]{26}$`)

// ValidateClientID checks the canonical client id format.
func ValidateClientID(id string) error {
	if !clientIDRe.MatchString(id) {
		return fmt.Errorf("invalid client id %q (want cl_ + 26 lowercase base32 chars)", id)
	}
	return nil
}

// ClientID generates a client identifier: "cl_" + lowercase base32 of 16
// random bytes (03-pki-enrollment.md §2).
func ClientID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate client id: %w", err)
	}
	return "cl_" + base32Lower.EncodeToString(buf), nil
}

// CreateCSR builds a PKCS#10 certificate signing request (POP): the CSR is
// self-signed with the private key, proving possession.
// CN = clientID, Organization = ["qoqtun-client"], OU[0] = name (≤64 chars).
func CreateCSR(key ed25519.PrivateKey, clientID, name string) ([]byte, error) {
	if err := ValidateClientID(clientID); err != nil {
		return nil, err
	}
	ou := name
	if len(ou) > 64 {
		ou = ou[:64]
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         clientID,
			Organization:       []string{"qoqtun-client"},
			OrganizationalUnit: []string{ou},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// randomSerial returns a 128-bit random serial number.
func randomSerial() (*big.Int, error) {
	serial := make([]byte, 16)
	if _, err := rand.Read(serial); err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	n := new(big.Int).SetBytes(serial)
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("generated serial is not positive")
	}
	return n, nil
}
