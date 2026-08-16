package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	dir := t.TempDir()
	content, err := os.ReadFile("../../examples/server.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	// patch the example's Linux state_dir to a platform absolute path
	patched := strings.Replace(string(content),
		`state_dir = "/var/lib/qoqtun"`,
		"state_dir = "+tomlStr(filepath.ToSlash(dir)), 1)
	path := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, "check-config", "--config", path)
	if err != nil {
		t.Fatalf("check-config on example should pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "server configuration OK") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func tomlStr(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}

func TestCheckConfigWithMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	content := "state_dir = \"/tmp/x\"\n[listen]\ncontrol_addr = \"not-an-address\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRoot(t, "check-config", "--config", path)
	if err == nil {
		t.Fatal("malformed config must fail check-config")
	}
}

func TestCheckConfigWithUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.toml")
	content := "state_dir = \"/tmp/x\"\ntypo_field = true\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRoot(t, "check-config", "--config", path)
	if err == nil {
		t.Fatal("unknown field must fail strict check-config")
	}
}

func TestCheckConfigWithoutConfigUsesDefaults(t *testing.T) {
	_, err := runRoot(t, "check-config")
	if err == nil {
		t.Fatal("defaults lack required state_dir; check-config must fail")
	}
}

// TestRunRequiresCA: `server run` needs initialized PKI materials.
func TestRunRequiresCA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	content := "state_dir = " + tomlStr(filepath.ToSlash(dir)) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRoot(t, "run", "--config", path)
	if err == nil {
		t.Fatal("run without CA must fail")
	}
}

func TestCAInit(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(t.TempDir(), "server.toml")
	content := "state_dir = " + tomlStr(filepath.ToSlash(stateDir)) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runRoot(t, "ca", "init", "--config", path, "--san", "127.0.0.1")
	if err != nil {
		t.Fatalf("ca init failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "CA fingerprint") {
		t.Fatalf("output missing fingerprint: %s", out)
	}
	for _, f := range []string{"ca/ca.key", "ca/ca.crt", "server/server.key", "server/server.crt"} {
		if _, err := os.Stat(filepath.Join(stateDir, f)); err != nil {
			t.Fatalf("expected %s: %v", f, err)
		}
	}
	// idempotency: second init must fail without --force
	_, err = runRoot(t, "ca", "init", "--config", path, "--san", "127.0.0.1")
	if err == nil {
		t.Fatal("ca init must refuse to overwrite existing CA without --force")
	}
	// --force overwrites
	if _, err := runRoot(t, "ca", "init", "--config", path, "--force", "--san", "127.0.0.1"); err != nil {
		t.Fatalf("ca init --force failed: %v", err)
	}
}

// stateConfig writes a minimal server.toml with a temp state_dir and runs
// `ca init`, returning the config path.
func stateConfig(t *testing.T) (configPath, stateDir string) {
	t.Helper()
	stateDir = filepath.Join(t.TempDir(), "state")
	configPath = filepath.Join(t.TempDir(), "server.toml")
	content := "state_dir = " + tomlStr(filepath.ToSlash(stateDir)) + "\n"
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, "ca", "init", "--config", configPath, "--san", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	return configPath, stateDir
}

func TestCreateTokenCmd(t *testing.T) {
	cfg, stateDir := stateConfig(t)
	out, err := runRoot(t, "client", "create-token", "--config", cfg)
	if err != nil {
		t.Fatalf("create-token: %v\n%s", err, out)
	}
	if !strings.Contains(out, "qen_") {
		t.Fatalf("token missing from output: %s", out)
	}
	// token persisted as hash only
	data, err := os.ReadFile(filepath.Join(stateDir, "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "qen_") {
		t.Fatal("tokens.json must never contain the plaintext token")
	}
}

func TestRevokeTokenCmd(t *testing.T) {
	cfg, stateDir := stateConfig(t)
	_, err := runRoot(t, "client", "create-token", "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	// token_id is not printed by create-token; read from the store file
	data, _ := os.ReadFile(filepath.Join(stateDir, "tokens.json"))
	tokID := tokenIDFromJSON(t, string(data))
	_, err = runRoot(t, "client", "revoke-token", tokID, "--config", cfg)
	if err != nil {
		t.Fatalf("revoke-token: %v", err)
	}
}

func tokenIDFromJSON(t *testing.T, json string) string {
	t.Helper()
	idx := strings.Index(json, `"token_id": "`)
	if idx < 0 {
		t.Fatalf("token_id not found in %s", json)
	}
	rest := json[idx+len(`"token_id": "`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("unterminated token_id")
	}
	return rest[:end]
}
