package config

// ClientConfig mirrors client.toml (05-config-schema.md §2).
type ClientConfig struct {
	// ServerAddr is required: hostname or IP + port.
	ServerAddr string `toml:"server_addr"`
	// CAFingerprint optionally pins the server CA SHA-256 (64 hex chars).
	CAFingerprint string `toml:"ca_fingerprint"`

	Reconnect struct {
		InitialBackoff string  `toml:"initial_backoff"`
		MaxBackoff     string  `toml:"max_backoff"`
		Jitter         float64 `toml:"jitter"`
	} `toml:"reconnect"`

	Heartbeat struct {
		Enabled bool `toml:"enabled"`
	} `toml:"heartbeat"`

	Logging struct {
		Level  string `toml:"level"`
		Format string `toml:"format"`
		File   string `toml:"file"`
	} `toml:"logging"`

	Tunnels []TunnelConfig `toml:"tunnels"`
}

// TunnelConfig is one client tunnel definition.
type TunnelConfig struct {
	Name        string `toml:"name"`
	Type        string `toml:"type"` // tcp|udp|http|https
	RemotePort  int    `toml:"remote_port"`
	LocalIP     string `toml:"local_ip"`
	LocalPort   int    `toml:"local_port"`
	HTTPHost    string `toml:"http_host"`
	Enabled     bool   `toml:"enabled"`
	IdleTimeout string `toml:"idle_timeout"`
}

// DefaultClientConfig returns the built-in defaults (05-config-schema.md §2).
// ServerAddr and the tunnels list are intentionally empty: both are required
// from the user and have no defaults.
func DefaultClientConfig() *ClientConfig {
	c := &ClientConfig{}
	c.CAFingerprint = ""
	c.Reconnect.InitialBackoff = "1s"
	c.Reconnect.MaxBackoff = "60s"
	c.Reconnect.Jitter = 0.2
	c.Heartbeat.Enabled = true
	c.Logging.Level = "info"
	c.Logging.Format = "text"
	c.Logging.File = ""
	return c
}
