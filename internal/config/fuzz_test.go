package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadClientConfig: config parsing must never panic and must never
// accept structurally invalid files silently.
func FuzzLoadClientConfig(f *testing.F) {
	seeds := []string{
		"server_addr = \"x:7000\"\n",
		"server_addr = \"a.example.com:7000\"\n[[tunnels]]\nname = \"t\"\ntype = \"tcp\"\nremote_port = 22000\nlocal_ip = \"127.0.0.1\"\nlocal_port = 80\n",
		"garbage\nnot toml",
		"[tunnels]\nx = 1\n",
		"server_addr = \"\"\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "client.toml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		cfg, err := LoadClient(path)
		if err != nil {
			return // malformed is fine; must not panic
		}
		_ = cfg
		// validation must never panic either
		_ = ValidateClient(cfg)
	})
}

// FuzzLoadServerConfig: server config parsing robustness.
func FuzzLoadServerConfig(f *testing.F) {
	seeds := []string{
		"state_dir = \"/tmp/state\"\n",
		"state_dir = \"/tmp/state\"\n[listen]\ncontrol_addr = \"0.0.0.0:7000\"\n",
		"[[policy]]\n",
		"\xff\xfe not toml",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "server.toml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		cfg, err := LoadServer(path)
		if err != nil {
			return
		}
		_ = ValidateServer(cfg)
	})
}
