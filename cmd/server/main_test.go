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

func TestRunPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	content := "state_dir = " + tomlStr(filepath.ToSlash(dir)) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRoot(t, "run", "--config", path)
	if err != nil {
		t.Fatalf("run placeholder should succeed: %v", err)
	}
}
