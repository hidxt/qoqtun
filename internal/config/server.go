// Package config implements the qoqtun configuration schema
// (docs/plan/05-config-schema.md): strict TOML parsing, validation,
// and the CLI > ENV > Config > Default merge.
package config

// ServerConfig mirrors server.toml (05-config-schema.md §1).
// Field order follows the document.
type ServerConfig struct {
	// StateDir is required (no default): CA/certs/revocation/tokens
	// and client registry directory. Absolute path.
	StateDir string `toml:"state_dir"`

	Listen struct {
		ControlAddr   string `toml:"control_addr"`
		EnrollAddr    string `toml:"enroll_addr"`
		EnrollEnabled bool   `toml:"enroll_enabled"`
		HTTPVhostPort int    `toml:"http_vhost_port"`
	} `toml:"listen"`

	Policy struct {
		AllowedPorts            []string `toml:"allowed_ports"`
		MaxTunnelsPerClient     int      `toml:"max_tunnels_per_client"`
		MaxConnsPerClient       int      `toml:"max_conns_per_client"`
		MaxConnsPerTunnel       int      `toml:"max_conns_per_tunnel"`
		BandwidthBpsPerClient   int64    `toml:"bandwidth_bps_per_client"`
		BandwidthBpsPerTunnel   int64    `toml:"bandwidth_bps_per_tunnel"`
		AllowedTargets          []string `toml:"allowed_targets"`
		UDPMaxSessionsPerTunnel int      `toml:"udp_max_sessions_per_tunnel"`
		UDPMaxPacket            int      `toml:"udp_max_packet"`
		UDPSessionIdleTimeout   string   `toml:"udp_session_idle_timeout"`
	} `toml:"policy"`

	Heartbeat struct {
		IntervalS     int `toml:"interval_s"`
		TimeoutS      int `toml:"timeout_s"`
		MissThreshold int `toml:"miss_threshold"`
	} `toml:"heartbeat"`

	PKI struct {
		CAValidityYears        int    `toml:"ca_validity_years"`
		ClientCertValidityDays int    `toml:"client_cert_validity_days"`
		TokenTTL               string `toml:"token_ttl"`
	} `toml:"pki"`

	Logging struct {
		Level  string `toml:"level"`
		Format string `toml:"format"`
		File   string `toml:"file"`
	} `toml:"logging"`
}

// DefaultServerConfig returns the built-in defaults (05-config-schema.md §1).
// StateDir is intentionally left empty: it is required and has no default.
func DefaultServerConfig() *ServerConfig {
	c := &ServerConfig{}
	c.Listen.ControlAddr = "0.0.0.0:7000"
	c.Listen.EnrollAddr = "0.0.0.0:7001"
	c.Listen.EnrollEnabled = true
	c.Listen.HTTPVhostPort = 0

	c.Policy.AllowedPorts = []string{"20000-29999"}
	c.Policy.MaxTunnelsPerClient = 16
	c.Policy.MaxConnsPerClient = 256
	c.Policy.MaxConnsPerTunnel = 128
	c.Policy.BandwidthBpsPerClient = 0
	c.Policy.BandwidthBpsPerTunnel = 0
	c.Policy.AllowedTargets = []string{"10.0.0.0/8:*"}
	c.Policy.UDPMaxSessionsPerTunnel = 256
	c.Policy.UDPMaxPacket = 1500
	c.Policy.UDPSessionIdleTimeout = "60s"

	c.Heartbeat.IntervalS = 15
	c.Heartbeat.TimeoutS = 10
	c.Heartbeat.MissThreshold = 2

	c.PKI.CAValidityYears = 10
	c.PKI.ClientCertValidityDays = 90
	c.PKI.TokenTTL = "1h"

	c.Logging.Level = "info"
	c.Logging.Format = "json"
	c.Logging.File = ""
	return c
}
