package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/auth"
	"github.com/hidxt/qoqtun/internal/pki"
)

type testEnv struct {
	ca       *pki.CA
	server   *Server
	addr     string
	tokens   *auth.TokenStore
	registry *pki.ClientRegistry
	revoked  *pki.RevocationList
	cancel   context.CancelFunc
	done     chan error
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.GenerateCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.LoadTokenStore(filepath.Join(dir, "tokens.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := pki.LoadClientRegistry(filepath.Join(dir, "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := pki.LoadRevocationList(filepath.Join(dir, "revoked.json"))
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := pki.SignServerCertificate(ca, 90, []net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		CA:                     ca,
		CertPEM:                serverCert,
		KeyPEM:                 serverKey,
		Tokens:                 tokens,
		Registry:               registry,
		Revoked:                revoked,
		ClientCertValidityDays: 90,
		Limiter:                NewIPLimiter(nil),
		Log:                    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	tlsCfg, err := srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	return &testEnv{
		ca: ca, server: srv, addr: ln.Addr().String(),
		tokens: tokens, registry: registry, revoked: revoked,
		cancel: cancel, done: done,
	}
}

func (e *testEnv) close() {
	e.cancel()
	<-e.done
}

func (e *testEnv) newToken(t *testing.T) string {
	t.Helper()
	plain, id, _, err := auth.CreateToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.tokens.Create(plain, id, "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	return plain
}

// newClientKeyCSR creates a fresh client key + CSR with the given client id.
func newClientKeyCSR(t *testing.T, id string) (ed25519.PrivateKey, []byte) {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, id, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	return key, csr
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestEnrollFullFlow(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, csr := newClientKeyCSR(t, mustClientID(t))
	client := &Client{ServerAddr: env.addr}
	res, err := client.Enroll(context.Background(), EnrollOptions{
		Token: env.newToken(t), CSR: csr, Meta: Meta{Name: "nas", OS: "linux"},
		ClientKey: key,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if res.ClientID == "" || res.ExpiresAt.IsZero() {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !env.registry.Exists(res.ClientID) {
		t.Fatal("client must be registered server-side")
	}
	if env.tokens.All() == nil || env.tokens.All()[0].Used != true {
		t.Fatal("token must be marked used after enroll")
	}
}

func TestEnrollBadCSR(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	client := &Client{ServerAddr: env.addr}
	_, err := client.Enroll(context.Background(), EnrollOptions{
		Token: env.newToken(t), CSR: []byte("not-a-csr"),
	})
	if err == nil || !strings.Contains(err.Error(), "server refused") {
		t.Fatalf("bad CSR must be refused, got %v", err)
	}
}

func TestEnrollTokenReuseRejected(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	tok := env.newToken(t)
	key, csr := newClientKeyCSR(t, mustClientID(t))
	c := &Client{ServerAddr: env.addr}
	if _, err := c.Enroll(context.Background(), EnrollOptions{Token: tok, CSR: csr, ClientKey: key}); err != nil {
		t.Fatal(err)
	}
	// second use of the same token must fail
	key2, csr2 := newClientKeyCSR(t, mustClientID(t))
	if _, err := c.Enroll(context.Background(), EnrollOptions{Token: tok, CSR: csr2, ClientKey: key2}); err == nil {
		t.Fatal("token reuse must be rejected")
	}
}

func TestEnrollNameConflict(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, csr := newClientKeyCSR(t, mustClientID(t))
	c := &Client{ServerAddr: env.addr}
	if _, err := c.Enroll(context.Background(), EnrollOptions{Token: env.newToken(t), CSR: csr, ClientKey: key}); err != nil {
		t.Fatal(err)
	}
	// same CSR (same client id) with a fresh token -> conflict
	if _, err := c.Enroll(context.Background(), EnrollOptions{Token: env.newToken(t), CSR: csr, ClientKey: key}); err == nil {
		t.Fatal("duplicate client id must be rejected")
	}
}

func TestEnrollThenMTLSThenRevoke(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, csr := newClientKeyCSR(t, mustClientID(t))
	c := &Client{ServerAddr: env.addr}
	res, err := c.Enroll(context.Background(), EnrollOptions{Token: env.newToken(t), CSR: csr, ClientKey: key})
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := pki.ParseCertificate(res.ClientCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	serial := clientCert.SerialNumber.String()

	// mTLS handshake to the enroll listener with the issued certificate
	// renew performs a real mTLS exchange over the enroll listener and is how
	// the revoked-certificate rejection is observed end to end.
	renew := func() error {
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		cert, err := tls.X509KeyPair(res.ClientCertPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AddCert(env.ca.Cert)
		conn, err := tls.Dial("tcp", env.addr, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      roots,
			ServerName:   "127.0.0.1",
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := writeFrame(conn, &Request{Type: "renew", CSR: string(csr)}); err != nil {
			return err
		}
		var resp Response
		if err := readFrame(conn, &resp); err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("renew refused: %s %s", resp.Error.Code, resp.Error.Message)
		}
		return nil
	}
	if err := renew(); err != nil {
		t.Fatalf("mTLS renew with valid cert must succeed: %v", err)
	}

	// revoke -> the next mTLS exchange must be rejected
	if err := env.revoked.Revoke(serial, "test revoke"); err != nil {
		t.Fatal(err)
	}
	if err := renew(); err == nil {
		t.Fatal("mTLS exchange must fail after revocation")
	}
}

func mustClientID(t *testing.T) string {
	t.Helper()
	id, err := pki.ClientID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestRenewFlow verifies mTLS renewal issues a fresh certificate for the
// same identity.
func TestRenewFlow(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, csr := newClientKeyCSR(t, mustClientID(t))
	client := &Client{ServerAddr: env.addr}
	res, err := client.Enroll(context.Background(), EnrollOptions{Token: env.newToken(t), CSR: csr, ClientKey: key})
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := mustSerial(t, res.ClientCertPEM)

	// renew with the existing cert (mTLS)
	renewed, err := client.Enroll(context.Background(), EnrollOptions{
		CSR:        csr,
		ClientCert: res.ClientCertPEM,
		ClientKey:  key,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	newSerial := mustSerial(t, renewed.ClientCertPEM)
	if newSerial == oldSerial {
		t.Fatal("renew must issue a new serial")
	}
	if renewed.ClientID != res.ClientID {
		t.Fatal("renew must keep the same identity")
	}
}

func mustSerial(t *testing.T, certPEM []byte) string {
	t.Helper()
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert.SerialNumber.String()
}

// TestRateLimit verifies the per-IP limiter rejects a burst beyond 5/min.
func TestRateLimit(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	client := &Client{ServerAddr: env.addr}
	rejected := 0
	for i := 0; i < 8; i++ {
		_, err := client.Enroll(context.Background(), EnrollOptions{
			Token: "qen_bogus", CSR: []byte("x"),
		})
		if err != nil && strings.Contains(err.Error(), "ERR_RATE_LIMITED") {
			rejected++
		}
	}
	if rejected == 0 {
		t.Fatal("burst beyond burst size must be rate limited")
	}
}

var _ = x509.Certificate{}
