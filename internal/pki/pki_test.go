package pki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := GenerateCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestGenerateCAProperties(t *testing.T) {
	ca := testCA(t)
	if !ca.Cert.IsCA {
		t.Fatal("CA must have IsCA=true")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 || ca.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("CA must have KeyUsage CertSign|CRLSign")
	}
	if ca.Cert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatalf("CA must use Ed25519, got %v", ca.Cert.PublicKeyAlgorithm)
	}
	if ca.Cert.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial must be 128-bit, got %d bits", ca.Cert.SerialNumber.BitLen())
	}
	if err := VerifyChain(ca.Cert, ca.Cert); err != nil {
		t.Fatalf("self-signed CA must verify against itself: %v", err)
	}
}

func TestClientIDFormat(t *testing.T) {
	id, err := ClientID()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateClientID(id); err != nil {
		t.Fatalf("generated client id %q must validate: %v", id, err)
	}
	for _, bad := range []string{"", "cl_", "cl_abc", "CL_abcdefghijklmnopqrstuvwxyz2345", "x_" + id[3:]} {
		if err := ValidateClientID(bad); err == nil {
			t.Errorf("client id %q must be rejected", bad)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ca := testCA(t)
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientID, _ := ClientID()
	csr, err := CreateCSR(key, clientID, "my-device")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := SignClientCertificate(ca, csr, 90)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// CN == client_id, chain verifies, EKU ClientAuth, not expired
	if cert.Subject.CommonName != clientID {
		t.Fatalf("CN = %q, want %q", cert.Subject.CommonName, clientID)
	}
	if err := VerifyClientCertificate(cert, ca.Cert); err != nil {
		t.Fatalf("client cert must verify: %v", err)
	}
	if IsExpired(cert) {
		t.Fatal("freshly issued cert must not be expired")
	}
	// fingerprint format: 64 hex chars separated by colons
	fp := Fingerprint(cert)
	if len(fp) != 95 || fp[2] != ':' {
		t.Fatalf("fingerprint format unexpected: %q", fp)
	}
}

// Signed certs must chain to a DIFFERENT CA only after that CA signs them;
// cross-CA verification must fail.
func TestCrossCARejected(t *testing.T) {
	ca1 := testCA(t)
	ca2 := testCA(t)
	key, _ := GenerateKey()
	id, _ := ClientID()
	csr, _ := CreateCSR(key, id, "d")
	certPEM, err := SignClientCertificate(ca1, csr, 90)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCertificate(certPEM)
	if err := VerifyClientCertificate(cert, ca2.Cert); err == nil {
		t.Fatal("cert signed by CA1 must not verify against CA2")
	}
}

func TestSignRejectsBadCSR(t *testing.T) {
	ca := testCA(t)
	key, _ := GenerateKey()
	id, _ := ClientID()

	// 1. tampered CSR (signature broken) must be rejected
	csr, err := CreateCSR(key, id, "d")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csr)
	block.Bytes[len(block.Bytes)-3] ^= 0xFF
	tampered := pem.EncodeToMemory(block)
	if _, err := SignClientCertificate(ca, tampered, 90); err == nil {
		t.Fatal("tampered CSR must be rejected")
	}

	// 2. non-Ed25519 (RSA) CSR must be rejected
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: id},
	}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: rsaCSR})
	if _, err := SignClientCertificate(ca, rsaCSRPEM, 90); err == nil {
		t.Fatal("RSA CSR must be rejected (Ed25519 only)")
	}

	// 3. invalid CN format must be rejected
	badCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "not-a-client-id"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	badCSRPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badCSR})
	if _, err := SignClientCertificate(ca, badCSRPEM, 90); err == nil {
		t.Fatal("CSR with invalid CN must be rejected")
	}
}

func TestSerialUniqueness(t *testing.T) {
	ca := testCA(t)
	key, _ := GenerateKey()
	id, _ := ClientID()
	csr, _ := CreateCSR(key, id, "d")
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		certPEM, err := SignClientCertificate(ca, csr, 90)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := ParseCertificate(certPEM)
		s := cert.SerialNumber.String()
		if seen[s] {
			t.Fatalf("duplicate serial %s", s)
		}
		seen[s] = true
	}
}

func TestNotAfterClampedToCA(t *testing.T) {
	ca := testCA(t) // 365d
	key, _ := GenerateKey()
	id, _ := ClientID()
	csr, _ := CreateCSR(key, id, "d")
	// request 500 days but CA has 365 -> clamp to CA NotAfter
	certPEM, err := SignClientCertificate(ca, csr, 500)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCertificate(certPEM)
	if !cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("NotAfter = %v, want clamped to CA %v", cert.NotAfter, ca.Cert.NotAfter)
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()
	future := &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}
	if !IsExpired(future) {
		t.Fatal("not-yet-valid cert must be reported expired")
	}
	past := &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}
	if !IsExpired(past) {
		t.Fatal("already-expired cert must be reported expired")
	}
}

func TestServerCertificateSAN(t *testing.T) {
	ca := testCA(t)
	certPEM, keyPEM, err := SignServerCertificate(ca, 90,
		[]net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
		[]string{"tunnel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("server cert/key PEM must be non-empty")
	}
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.IPAddresses) != 2 || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "tunnel.example.com" {
		t.Fatalf("SAN mismatch: ips=%v dns=%v", cert.IPAddresses, cert.DNSNames)
	}
	// key PEM parses and matches the cert public key
	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub := cert.PublicKey.(ed25519.PublicKey)
	if !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
		t.Fatal("server key does not match certificate public key")
	}
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Fatal("server cert must have ExtKeyUsage ServerAuth")
	}
}

func TestRevocationListPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")
	rl, err := LoadRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := rl.Revoke("12345", "device lost"); err != nil {
		t.Fatal(err)
	}
	if !rl.IsRevoked("12345") {
		t.Fatal("serial must be revoked in-memory")
	}
	// reload from disk
	rl2, err := LoadRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	if !rl2.IsRevoked("12345") {
		t.Fatal("revocation must persist to disk")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("revoked.json must be 0600, got %o", fi.Mode().Perm())
	}
	if len(rl2.Revoked()) != 1 || rl2.Revoked()[0].Reason != "device lost" {
		t.Fatalf("unexpected revoked entries: %+v", rl2.Revoked())
	}
}

func TestClientRegistryPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.json")
	r, err := LoadClientRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ClientID()
	rec := ClientRecord{ClientID: id, Name: "nas", CertSerial: "42", CreatedAt: time.Now().UTC()}
	if err := r.Add(rec); err != nil {
		t.Fatal(err)
	}
	if !r.Exists(id) {
		t.Fatal("record must exist")
	}
	got, ok := r.Get(id)
	if !ok || got.Name != "nas" {
		t.Fatalf("unexpected record: %+v", got)
	}
	r2, err := LoadClientRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Exists(id) {
		t.Fatal("registry must persist to disk")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("clients.json must be 0600, got %o", fi.Mode().Perm())
	}
}

// A server certificate (no ClientAuth EKU) must be rejected by
// VerifyClientCertificate.
func TestVerifyClientCertificateRejectsServerCert(t *testing.T) {
	ca := testCA(t)
	serverPEM, _, err := SignServerCertificate(ca, 90, []net.IP{net.ParseIP("192.0.2.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(serverPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyClientCertificate(cert, ca.Cert); err == nil {
		t.Fatal("server cert must not verify as a client cert")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParseCertificate([]byte("not pem")); err == nil {
		t.Fatal("bad cert PEM must error")
	}
	if _, err := ParseCSR([]byte("not pem")); err == nil {
		t.Fatal("bad CSR PEM must error")
	}
	if _, err := ParsePrivateKey([]byte("not pem")); err == nil {
		t.Fatal("bad key PEM must error")
	}
	ca := testCA(t)
	key, _ := GenerateKey()
	id, _ := ClientID()
	csr, _ := CreateCSR(key, id, "d")
	certPEM, err := SignClientCertificate(ca, csr, 90)
	if err != nil {
		t.Fatal(err)
	}
	// wrong block type
	block, _ := pem.Decode(certPEM)
	block.Type = "CERTIFICATE REQUEST"
	bad := pem.EncodeToMemory(block)
	if _, err := ParseCertificate(bad); err == nil {
		t.Fatal("wrong PEM type must error")
	}
}

func TestSignClientCertInvalidParams(t *testing.T) {
	ca := testCA(t)
	key, _ := GenerateKey()
	id, _ := ClientID()
	csr, _ := CreateCSR(key, id, "d")
	if _, err := SignClientCertificate(nil, csr, 90); err == nil {
		t.Fatal("nil CA must error")
	}
	if _, err := SignClientCertificate(ca, []byte("garbage"), 90); err == nil {
		t.Fatal("garbage CSR must error")
	}
	if _, err := SignClientCertificate(ca, csr, 0); err == nil {
		t.Fatal("validity 0 must error")
	}
	if _, err := SignClientCertificate(ca, csr, 826); err == nil {
		t.Fatal("validity > 825 must error")
	}
}

func TestGenerateCAInvalidValidity(t *testing.T) {
	if _, err := GenerateCA(0); err == nil {
		t.Fatal("zero validity must error")
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ed25519.PrivateKey(key).Seed(), ed25519.PrivateKey(back).Seed()) {
		t.Fatal("private key round-trip mismatch")
	}
}
