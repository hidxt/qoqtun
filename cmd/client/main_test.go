package main

import (
	"os"
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
	out, err := runRoot(t, "check-config", "--config", "../../examples/client.example.toml")
	if err != nil {
		t.Fatalf("check-config on example should pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "client configuration OK") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestPlaceholderSubcommands(t *testing.T) {
	for _, sub := range []string{"cert", "enroll", "tunnel"} {
		out, err := runRoot(t, sub)
		if err != nil {
			t.Fatalf("%s placeholder must not error: %v", sub, err)
		}
		if !strings.Contains(out, "not implemented yet") {
			t.Fatalf("%s placeholder output missing marker: %s", sub, out)
		}
	}
}

func TestRunPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/client.toml"
	content := "server_addr = \"tunnel.example.com:7000\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := runRoot(t, "run", "--config", path)
	if err != nil {
		t.Fatalf("run placeholder should succeed: %v", err)
	}
}
