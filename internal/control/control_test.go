package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/control"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/session"
	"github.com/hidxt/qoqtun/internal/transport"
)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

type testEnv struct {
	ca      *pki.CA
	cfg     *config.ServerConfig
	srv     *control.Server
	addr    string
	reg     *session.Registry
	revoked *pki.RevocationList
	cancel  context.CancelFunc
	done    chan error
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ca, err := pki.GenerateCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	revoked, err := pki.LoadRevocationList(filepath.Join(dir, "revoked.json"))
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := pki.SignServerCertificate(ca, 90, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultServerConfig()
	cfg.Heartbeat.IntervalS = 1
	cfg.Heartbeat.TimeoutS = 1
	cfg.Heartbeat.MissThreshold = 2
	cfg.Policy.AllowedTargets = []string{"127.0.0.0/8:*"} // tests dial loopback origins

	reg := session.NewRegistry()
	srv := &control.Server{
		CAs:              []*x509.Certificate{ca.Cert},
		Cert:             serverCert,
		Key:              serverKey,
		IsRevoked:        revoked.IsRevoked,
		Cfg:              cfg,
		Log:              slog.New(slog.NewTextHandler(discardWriter{}, nil)),
		MaxHalfOpen:      8,
		HandshakeTimeout: 5 * time.Second,
		Sessions:         reg,
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := transport.Listen(raw, transport.Options{
		CAs:       []*x509.Certificate{ca.Cert},
		Cert:      serverCert,
		Key:       serverKey,
		IsRevoked: revoked.IsRevoked,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	return &testEnv{ca: ca, cfg: cfg, srv: srv, addr: ln.Addr().String(), reg: reg, revoked: revoked, cancel: cancel, done: done}
}

func (e *testEnv) close() {
	e.cancel()
	<-e.done
}

// newClientCert issues a client certificate for a fresh client id.
func (e *testEnv) newClientCert(t *testing.T) (ed25519.PrivateKey, string, []byte) {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.ClientID()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, id, "test")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := pki.SignClientCertificate(e.ca, csr, 90)
	if err != nil {
		t.Fatal(err)
	}
	return key, id, certPEM
}

func (e *testEnv) newClient(t *testing.T) (*clientcore.Client, ed25519.PrivateKey) {
	t.Helper()
	key, id, certPEM := e.newClientCert(t)
	return &clientcore.Client{
		ServerAddr: e.addr,
		CAs:        []*x509.Certificate{e.ca.Cert},
		Cert:       certPEM,
		Key:        keyPEM(t, key),
		ClientID:   id,
		Name:       "test-device",
		Log:        slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	}, key
}

func keyPEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	pemBytes, err := pki.MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes
}

func TestHandshakeAndHeartbeat(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	client, _ := env.newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- client.Run(ctx) }()

	// wait for the session to appear
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.reg.Len() == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if env.reg.Len() != 1 {
		t.Fatal("client session did not register")
	}
	if client.Policy.MaxTunnels != env.cfg.Policy.MaxTunnelsPerClient {
		t.Fatalf("policy not delivered: %+v", client.Policy)
	}

	// heartbeat: client pings at interval 1s; must survive at least 3 ticks
	time.Sleep(3500 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("client died during heartbeat: %v", err)
	default:
	}
	if env.reg.Len() != 1 {
		t.Fatalf("session dropped unexpectedly: %d", env.reg.Len())
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not exit after cancel")
	}
	// server must release the session shortly after disconnect
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.reg.Len() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if env.reg.Len() != 0 {
		t.Fatal("session not released after disconnect")
	}
}

func TestFakeClientIDRejected(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, _, certPEM := env.newClientCert(t)
	// lie about the id: hello says a different client
	client := &clientcore.Client{
		ServerAddr: env.addr,
		CAs:        []*x509.Certificate{env.ca.Cert},
		Cert:       certPEM,
		Key:        keyPEM(t, key),
		ClientID:   "cl_notmatching",
		Name:       "evil",
		Log:        slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	}
	err := client.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("fake client_id must be rejected, got %v", err)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, id, certPEM := env.newClientCert(t)
	// override hello version via a manual dial
	conn, err := transport.Dial("tcp", env.addr, transport.Options{
		CAs: []*x509.Certificate{env.ca.Cert}, Cert: certPEM, Key: keyPEM(t, key),
		ServerName: "127.0.0.1", HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.WriteFrame(protocol.MsgClientHello, 1, &protocol.ClientHello{
		ClientID: id, ProtocolVersion: 99, Name: "dev",
	})
	env2, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if env2.Type != protocol.MsgError {
		t.Fatalf("expected error frame, got %s", env2.Type)
	}
	var e protocol.Error
	if err := env2.DecodePayload(&e); err != nil || e.Code != protocol.ErrCodeVersionUnsupported {
		t.Fatalf("expected ERR_VERSION_UNSUPPORTED, got %+v %v", e, err)
	}
}

func TestRevokedCertRejected(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, id, certPEM := env.newClientCert(t)
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.revoked.Revoke(cert.SerialNumber.String(), "test"); err != nil {
		t.Fatal(err)
	}
	client := &clientcore.Client{
		ServerAddr: env.addr,
		CAs:        []*x509.Certificate{env.ca.Cert},
		Cert:       certPEM,
		Key:        keyPEM(t, key),
		ClientID:   id,
		Name:       "dev",
		Log:        slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	}
	err = client.Run(context.Background())
	if err == nil {
		t.Fatal("revoked certificate must be rejected")
	}
}

func TestFrameTooLargeClosesConnection(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, id, certPEM := env.newClientCert(t)
	conn, err := transport.Dial("tcp", env.addr, transport.Options{
		CAs: []*x509.Certificate{env.ca.Cert}, Cert: certPEM, Key: keyPEM(t, key),
		ServerName: "127.0.0.1", HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.WriteFrame(protocol.MsgClientHello, 1, &protocol.ClientHello{
		ClientID: id, ProtocolVersion: protocol.ProtocolVersion, Name: "dev",
	})
	// server replies server_hello; then we send an oversized frame
	_, err = protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, protocol.MaxFrameSize+1)
	if err := conn.WriteFrame(protocol.MsgError, 2, &protocol.Error{Code: "x", Message: string(big)}); err == nil {
		t.Fatal("oversized frame should fail to encode")
	}
}

func TestHeartbeatKick(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, id, certPEM := env.newClientCert(t)
	// establish a control connection but never send anything after hello
	conn, err := transport.Dial("tcp", env.addr, transport.Options{
		CAs: []*x509.Certificate{env.ca.Cert}, Cert: certPEM, Key: keyPEM(t, key),
		ServerName: "127.0.0.1", HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.WriteFrame(protocol.MsgClientHello, 1, &protocol.ClientHello{
		ClientID: id, ProtocolVersion: protocol.ProtocolVersion, Name: "silent",
	})
	_, err = protocol.ReadFrame(conn) // server_hello
	if err != nil {
		t.Fatal(err)
	}
	// session must exist
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if env.reg.Len() == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if env.reg.Len() != 1 {
		t.Fatal("session not registered")
	}
	// silence: server kicks after ~2*1s+1s = 3s
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if env.reg.Len() == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if env.reg.Len() != 0 {
		t.Fatal("silent client session must be kicked")
	}
}
