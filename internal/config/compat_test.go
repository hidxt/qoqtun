package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLegacyClientConfig: config files written by earlier phases (without
// newer fields) must load cleanly and get defaults filled.
func TestLegacyClientConfig(t *testing.T) {
	dir := t.TempDir()
	// a Phase 1/5-era client.toml: server_addr + tunnels, no reconnect
	// block, no heartbeat block, no logging section
	legacy := `server_addr = "tunnel.example.com:7000"

[[tunnels]]
name = "web"
type = "tcp"
remote_port = 22000
local_ip = "127.0.0.1"
local_port = 8080
enabled = true
`
	path := filepath.Join(dir, "client.toml")
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClient(path)
	if err != nil {
		t.Fatalf("legacy client config must load: %v", err)
	}
	if cfg.ServerAddr != "tunnel.example.com:7000" {
		t.Fatalf("server_addr lost: %q", cfg.ServerAddr)
	}
	if len(cfg.Tunnels) != 1 || cfg.Tunnels[0].Name != "web" {
		t.Fatalf("tunnels lost: %+v", cfg.Tunnels)
	}
	if err := ValidateClient(cfg); err != nil {
		t.Fatalf("legacy config must validate: %v", err)
	}
	// defaults applied during validation
	if cfg.Reconnect.InitialBackoff != "1s" || !cfg.Heartbeat.Enabled {
		t.Fatalf("defaults not applied after validate: %+v", cfg)
	}
}

// TestLegacyServerConfig: old server.toml without http_vhost_port / policy
// extras must load and validate with defaults.
func TestLegacyServerConfig(t *testing.T) {
	dir := t.TempDir()
	legacy := `state_dir = "` + filepath.ToSlash(dir) + `/state"

[listen]
control_addr = "0.0.0.0:7000"
enroll_addr = "0.0.0.0:7001"
`
	path := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatalf("legacy server config must load: %v", err)
	}
	if err := ValidateServer(cfg); err != nil {
		t.Fatalf("legacy server config must validate: %v", err)
	}
}
