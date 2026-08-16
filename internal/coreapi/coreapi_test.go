package coreapi_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/control"
	"github.com/hidxt/qoqtun/internal/coreapi"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/hidxt/qoqtun/internal/platform/keystore"
	"github.com/hidxt/qoqtun/internal/session"
	"github.com/hidxt/qoqtun/internal/transport"
	"github.com/pelletier/go-toml/v2"
)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func silentLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

// makeIdentity provisions a keystore-backed client identity + state file,
// using exactly the same pki helpers as the mainline integration tests.
func makeIdentity(t *testing.T, dir, serverAddr string, ca *pki.CA) (string, string) {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.ClientID()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, id, "coreapi-test")
	if err != nil {
		t.Fatal(err)
	}
	clientCertPEM, err := pki.SignClientCertificate(ca, csr, 90)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := pki.ParseCertificate(clientCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	spool := x509.NewCertPool()
	spool.AddCert(ca.Cert)
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     spool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert chain: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "client.crt")
	if err := os.WriteFile(certPath, clientCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	store, _, err := keystore.OpenWithPref(keystore.KeyringConfig{ServiceName: "qoqtun"}, filepath.Join(dir, "secrets"), keystore.BackendFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := pki.MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("client-key", keyPEM); err != nil {
		t.Fatal(err)
	}
	state := map[string]string{
		"client_id":   id,
		"server_addr": serverAddr,
		"cert_path":   certPath,
		"expires_at":  time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339),
	}
	data, _ := json.Marshal(state)
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return statePath, certPath
}

func newAPI(t *testing.T, dir, serverAddr, statePath string, ca *pki.CA) *coreapi.API {
	t.Helper()
	cfgPath := filepath.Join(dir, "client.toml")
	cfg := config.DefaultClientConfig()
	cfg.ServerAddr = serverAddr
	cfg.Tunnels = []config.TunnelConfig{
		{Name: "echo", Type: "tcp", RemotePort: 20090, LocalIP: "127.0.0.1", LocalPort: 1, Enabled: true},
	}
	data, err := tomlMarshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := coreapi.New(coreapi.Options{
		ConfigPath: cfgPath,
		StatePath:  statePath,
		SecretsDir: filepath.Join(dir, "secrets"),
		Backend:    keystore.BackendFile,
		Log:        silentLog(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func tomlMarshal(v any) ([]byte, error) {
	return toml.Marshal(v)
}

func TestCoreAPIConfigOps(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.toml")
	base := config.DefaultClientConfig()
	base.ServerAddr = "x:7000"
	data, _ := tomlMarshal(base)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := coreapi.New(coreapi.Options{ConfigPath: cfgPath, StatePath: filepath.Join(dir, "state.json"), Backend: keystore.BackendFile, Log: silentLog()})
	if err != nil {
		t.Fatal(err)
	}
	if api.Status().Running {
		t.Fatal("must start stopped")
	}
	// upsert a valid tunnel
	if err := api.UpsertTunnel(config.TunnelConfig{Name: "web", Type: "tcp", RemotePort: 20001, LocalIP: "127.0.0.1", LocalPort: 8080, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// upsert an invalid tunnel (bad name) must fail
	if err := api.UpsertTunnel(config.TunnelConfig{Name: "bad name!", Type: "tcp", RemotePort: 20002, LocalIP: "127.0.0.1", LocalPort: 8080}); err == nil {
		t.Fatal("invalid tunnel must be rejected")
	}
	// delete
	if err := api.DeleteTunnel("web"); err != nil {
		t.Fatal(err)
	}
	if err := api.DeleteTunnel("web"); err == nil {
		t.Fatal("double delete must fail")
	}
	// update config with bad server_addr
	if err := api.UpdateConfig(map[string]any{"server_addr": ""}); err == nil {
		t.Fatal("empty server_addr must fail validation")
	}
	// update config valid
	if err := api.UpdateConfig(map[string]any{"server_addr": "y:7000"}); err != nil {
		t.Fatal(err)
	}
}

func TestCoreAPILifecycle(t *testing.T) {
	dir := t.TempDir()
	clientCA, err := pki.GenerateCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv2, addr2, stop2 := startTestServerSingleCA(t, clientCA)
	defer stop2()
	_ = srv2

	statePath, _ := makeIdentity(t, dir, addr2, clientCA)
	api := newAPI(t, dir, addr2, statePath, clientCA)
	if err := api.Start(""); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer api.Stop()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if api.Status().Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !api.Status().Running {
		t.Fatal("client did not come online")
	}
	// the configured tunnel auto-registers (async)
	deadline2 := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline2) {
		if len(api.ListTunnels()) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got := api.ListTunnels(); len(got) != 1 {
		t.Fatalf("tunnels = %d, want 1", len(got))
	}
	id := api.GetIdentity()
	if !id.Enrolled || id.ClientID == "" {
		t.Fatalf("identity wrong: %+v", id)
	}
	if id.Keystore == "" {
		t.Fatal("keystore label missing")
	}
	_ = api.GetStats()
}

// startTestServerTrusting trusts the given client CA.
func startTestServerSingleCA(t *testing.T, ca *pki.CA) (*control.Server, string, func()) {
	t.Helper()
	revoked, err := pki.LoadRevocationList(filepath.Join(t.TempDir(), "revoked.json"))
	if err != nil {
		t.Fatal(err)
	}
	// the SAME CA signs both the server certificate and the test client
	// (single trust root, like the mainline integration tests)
	serverCert, serverKey, err := pki.SignServerCertificate(ca, 90, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultServerConfig()
	cfg.Policy.AllowedTargets = []string{"127.0.0.0/8:*"}
	srv := &control.Server{
		CAs:              []*x509.Certificate{ca.Cert},
		Cert:             serverCert,
		Key:              serverKey,
		IsRevoked:        revoked.IsRevoked,
		Cfg:              cfg,
		Log:              silentLog(),
		MaxHalfOpen:      8,
		HandshakeTimeout: 5 * time.Second,
		Sessions:         session.NewRegistry(),
		IPGateMaxConns:   4096,
		IPGateRatePerSec: 100000,
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
	return srv, ln.Addr().String(), func() { cancel(); _ = ln.Close() }
}
