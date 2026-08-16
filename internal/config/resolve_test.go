package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hidxt/qoqtun/internal/config"
)

func TestResolveServerPrecedence(t *testing.T) {
	env := func(string) string { return "" }
	stateDir := t.TempDir()
	// file sets state_dir, control_addr and level; other fields stay default
	fileOverlays := []config.Overlay{
		{Path: "state_dir", Value: stateDir},
		{Path: "listen.control_addr", Value: "0.0.0.0:8000"},
		{Path: "logging.level", Value: "warn"},
	}

	// file only
	got, err := config.ResolveServer(config.DefaultServerConfig(), fileOverlays, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.StateDir != stateDir || got.Listen.ControlAddr != "0.0.0.0:8000" || got.Logging.Level != "warn" {
		t.Fatalf("file merge wrong: %+v", got)
	}
	// fields not in the file must keep defaults
	if got.Heartbeat.IntervalS != 15 || got.Policy.MaxTunnelsPerClient != 16 {
		t.Fatalf("defaults must fill unset fields: %+v", got)
	}

	// env overrides file
	env = func(k string) string {
		if k == "QOQTUN_LOGGING_LEVEL" {
			return "error"
		}
		return ""
	}
	got, err = config.ResolveServer(config.DefaultServerConfig(), fileOverlays, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Logging.Level != "error" {
		t.Fatalf("env should override file: got level %q", got.Logging.Level)
	}

	// overlay (CLI) overrides env
	got, err = config.ResolveServer(config.DefaultServerConfig(), fileOverlays,
		[]config.Overlay{{Path: "logging.level", Value: "debug"}}, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Logging.Level != "debug" {
		t.Fatalf("overlay should override env: got %q", got.Logging.Level)
	}
}

// Partial files must merge onto defaults field-by-field (regression: a
// partial file used to replace all defaults wholesale and fail validation).
func TestResolveServerPartialFileKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	content := "state_dir = " + tomlString(filepath.ToSlash(dir)) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	overlays, err := config.LoadServerOverlays(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.ResolveServer(config.DefaultServerConfig(), overlays, nil, func(string) string { return "" })
	if err != nil {
		t.Fatalf("partial file must validate: %v", err)
	}
	if got.Listen.ControlAddr != "0.0.0.0:7000" || got.PKI.TokenTTL != "1h" {
		t.Fatalf("defaults must fill unset fields: %+v", got)
	}
}

// Explicit zero values in the file must survive the merge (e.g. disabling
// the enroll listener by setting enroll_addr = "").
func TestResolveServerPreservesExplicitZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	content := "state_dir = " + tomlString(filepath.ToSlash(dir)) + "\n" +
		"[listen]\nenroll_addr = \"\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	overlays, err := config.LoadServerOverlays(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.ResolveServer(config.DefaultServerConfig(), overlays, nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen.EnrollAddr != "" {
		t.Fatalf("explicit empty enroll_addr must be preserved, got %q", got.Listen.EnrollAddr)
	}
}

func TestResolveServerNoFileUsesDefaults(t *testing.T) {
	got, err := config.ResolveServer(config.DefaultServerConfig(), nil, nil, func(string) string { return "" })
	if err == nil {
		t.Fatalf("expected error: state_dir is required and not set")
	}
	_ = got
	// with state_dir overlay it must pass
	stateDir := t.TempDir()
	got, err = config.ResolveServer(config.DefaultServerConfig(), nil,
		[]config.Overlay{{Path: "state_dir", Value: stateDir}}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("state_dir overlay should make config valid: %v", err)
	}
	if got.StateDir != stateDir || got.Listen.ControlAddr != "0.0.0.0:7000" {
		t.Fatalf("unexpected resolved config: %+v", got)
	}
}

func TestEnvMappingClient(t *testing.T) {
	env := func(k string) string {
		switch k {
		case "QOQTUN_SERVER_ADDR":
			return "env.example.com:9000"
		case "QOQTUN_LOGGING_LEVEL":
			return "debug"
		case "QOQTUN_RECONNECT_JITTER":
			return "0.5"
		}
		return ""
	}
	got, err := config.ResolveClient(config.DefaultClientConfig(), nil, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServerAddr != "env.example.com:9000" || got.Logging.Level != "debug" || got.Reconnect.Jitter != 0.5 {
		t.Fatalf("env mapping wrong: %+v", got)
	}
}

// Array fields are NOT supported via ENV (05-config-schema.md §3).
func TestEnvArraysNotMapped(t *testing.T) {
	env := func(k string) string {
		if k == "QOQTUN_POLICY_ALLOWED_PORTS" {
			return "1000-2000"
		}
		return ""
	}
	got, err := config.ResolveServer(config.DefaultServerConfig(), nil,
		[]config.Overlay{{Path: "state_dir", Value: t.TempDir()}}, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Policy.AllowedPorts) != 1 || got.Policy.AllowedPorts[0] != "20000-29999" {
		t.Fatalf("array field must not be overridden by env: %v", got.Policy.AllowedPorts)
	}
}

func TestApplyOverlaysErrors(t *testing.T) {
	base := config.DefaultServerConfig()
	cases := []struct {
		name string
		ov   config.Overlay
	}{
		{"unknown path", config.Overlay{Path: "no.such.field", Value: "x"}},
		{"bad int", config.Overlay{Path: "heartbeat.interval_s", Value: "abc"}},
		{"bad bool", config.Overlay{Path: "listen.enroll_enabled", Value: "maybe"}},
		{"slice non-string", config.Overlay{Path: "policy.allowed_ports", Value: 42}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := config.ApplyOverlays(base, []config.Overlay{tc.ov}); err == nil {
				t.Fatalf("expected error for %q", tc.name)
			}
		})
	}
}

func TestApplyOverlaysSliceOfStructRejected(t *testing.T) {
	base := config.DefaultClientConfig()
	if err := config.ApplyOverlays(base, []config.Overlay{
		{Path: "tunnels", Value: []string{"a"}},
	}); err == nil {
		t.Fatal("slice-of-struct overlay must be rejected (unsupported element type)")
	}
}

func TestLoadServerStrictUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.toml")
	content := "state_dir = " + tomlString(filepath.ToSlash(dir)) + "\nunknown_field = 1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadServer(path); err == nil {
		t.Fatal("strict mode must reject unknown fields")
	}
}

func TestLoadClientStrictUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.toml")
	content := "server_addr = \"x.example.com:7000\"\n[no_such]\nx = 1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadClient(path); err == nil {
		t.Fatal("strict mode must reject unknown fields")
	}
}

func TestCheckServerExampleFile(t *testing.T) {
	dir := t.TempDir()
	content, err := os.ReadFile("../../examples/server.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	// state_dir in the example is a Linux path; patch it to a platform
	// absolute path so the full example validates on every OS.
	patched := strings.Replace(string(content),
		`state_dir = "/var/lib/qoqtun"`,
		"state_dir = "+tomlString(filepath.ToSlash(dir)), 1)
	path := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	err = config.CheckServer(path, nil, &buf)
	if err != nil {
		t.Fatalf("example server config should pass check-config: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "server configuration OK") || !strings.Contains(out, "state_dir") {
		t.Fatalf("unexpected output: %s", out)
	}
}

// tomlString quotes s as a TOML basic string (forward slashes are fine).
func tomlString(s string) string {
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}

func TestCheckClientExampleFileRedactsFingerprint(t *testing.T) {
	var buf strings.Builder
	err := config.CheckClient("../../examples/client.example.toml",
		[]config.Overlay{{Path: "ca_fingerprint", Value: strings.Repeat("ab", 32)}}, &buf)
	if err != nil {
		t.Fatalf("example client config should pass check-config: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, strings.Repeat("ab", 32)) {
		t.Fatal("ca_fingerprint must be redacted in output")
	}
	if !strings.Contains(out, "***") {
		t.Fatalf("expected redacted marker in output: %s", out)
	}
}
