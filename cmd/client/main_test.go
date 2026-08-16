package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidxt/qoqtun/internal/platform/keystore"
)

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var buf strings.Builder
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestCheckConfigWithExample(t *testing.T) {
	out, err := runRoot(t, "check-config", "--config", "../../examples/client.example.toml")
	if err != nil {
		t.Fatalf("check-config on example should pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "client configuration OK") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestTunnelHelp(t *testing.T) {
	out, err := runRoot(t, "tunnel", "--help")
	if err != nil {
		t.Fatalf("tunnel help must not error: %v", err)
	}
	for _, marker := range []string{"list", "start", "stop", "127.0.0.1"} {
		if !strings.Contains(out, marker) {
			t.Fatalf("tunnel help missing %q: %s", marker, out)
		}
	}
}

func TestCertInit(t *testing.T) {
	dir := t.TempDir()
	csrOut := filepath.Join(dir, "client.csr")
	secretsDir := filepath.Join(dir, "secrets")
	out, err := runRoot(t, "cert", "init",
		"--name", "test-device",
		"--csr-out", csrOut,
		"--secrets-dir", secretsDir,
		"--keystore-backend", "file")
	if err != nil {
		t.Fatalf("cert init failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "client_id: cl_") {
		t.Fatalf("output missing client_id: %s", out)
	}
	if !strings.Contains(out, "keystore:  file") {
		t.Fatalf("output missing keystore backend: %s", out)
	}
	// CSR file exists and is a valid PEM CSR
	csrData, err := os.ReadFile(csrOut)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csrData), "CERTIFICATE REQUEST") {
		t.Fatal("CSR output is not a valid PEM request")
	}
	// private key stored in the file keystore
	if _, err := os.Stat(filepath.Join(secretsDir, "client-key.key")); err != nil {
		t.Fatalf("keystore entry missing: %v", err)
	}
}

func TestCertInitStoresKeyInKeystore(t *testing.T) {
	dir := t.TempDir()
	csrOut := filepath.Join(dir, "c.csr")
	secretsDir := filepath.Join(dir, "secrets")
	if _, err := runRoot(t, "cert", "init", "--csr-out", csrOut, "--secrets-dir", secretsDir,
		"--keystore-backend", "file"); err != nil {
		t.Fatal(err)
	}
	store, err := keystore.NewFileStore(secretsDir)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := store.Get("client-key")
	if err != nil {
		t.Fatalf("client-key not in keystore: %v", err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("stored key is not PEM")
	}
}

// TestRunRequiresIdentity: `client run` needs an enrolled identity.
func TestRunRequiresIdentity(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/client.toml"
	content := "server_addr = \"tunnel.example.com:7000\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRoot(t, "run", "--config", path, "--state", filepath.Join(dir, "state.json"))
	if err == nil {
		t.Fatal("run without identity must fail")
	}
}
