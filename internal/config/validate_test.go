package config_test

import (
	"strings"
	"testing"

	"github.com/hidxt/qoqtun/internal/config"
)

func validServer(dir string) *config.ServerConfig {
	c := config.DefaultServerConfig()
	c.StateDir = dir
	return c
}

func validClient() *config.ClientConfig {
	c := config.DefaultClientConfig()
	c.ServerAddr = "tunnel.example.com:7000"
	c.Tunnels = []config.TunnelConfig{
		{Name: "ssh", Type: "tcp", RemotePort: 22000, LocalIP: "127.0.0.1", LocalPort: 22, Enabled: true, IdleTimeout: "5m"},
	}
	return c
}

func TestValidateServerValid(t *testing.T) {
	if err := config.ValidateServer(validServer(t.TempDir())); err != nil {
		t.Fatalf("default-with-state_dir config should be valid: %v", err)
	}
}

func TestValidateServerInvalid(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.ServerConfig)
	}{
		{"state_dir required", func(c *config.ServerConfig) { c.StateDir = "" }},
		{"state_dir relative", func(c *config.ServerConfig) { c.StateDir = "rel/path" }},
		{"state_dir dotdot", func(c *config.ServerConfig) { c.StateDir = "/var/../lib/qoqtun" }},
		{"control_addr no port", func(c *config.ServerConfig) { c.Listen.ControlAddr = "0.0.0.0" }},
		{"control_addr bad port", func(c *config.ServerConfig) { c.Listen.ControlAddr = "0.0.0.0:0" }},
		{"control_addr bad host", func(c *config.ServerConfig) { c.Listen.ControlAddr = "bad host!:7000" }},
		{"enroll_addr bad host", func(c *config.ServerConfig) { c.Listen.EnrollAddr = "x_y:7001" }},
		{"http_vhost_port too big", func(c *config.ServerConfig) { c.Listen.HTTPVhostPort = 70000 }},
		{"allowed_ports invalid", func(c *config.ServerConfig) { c.Policy.AllowedPorts = []string{"abc"} }},
		{"allowed_ports overlaps control", func(c *config.ServerConfig) { c.Policy.AllowedPorts = []string{"6990-7010"} }},
		{"allowed_ports overlaps enroll", func(c *config.ServerConfig) {
			c.Policy.AllowedPorts = []string{"6990-7010"}
			c.Listen.EnrollAddr = "0.0.0.0:7005"
		}},
		{"max_tunnels too low", func(c *config.ServerConfig) { c.Policy.MaxTunnelsPerClient = 0 }},
		{"max_tunnels too high", func(c *config.ServerConfig) { c.Policy.MaxTunnelsPerClient = 1025 }},
		{"max_conns_per_client zero", func(c *config.ServerConfig) { c.Policy.MaxConnsPerClient = 0 }},
		{"max_conns_per_tunnel too high", func(c *config.ServerConfig) { c.Policy.MaxConnsPerTunnel = 100001 }},
		{"bandwidth negative", func(c *config.ServerConfig) { c.Policy.BandwidthBpsPerClient = -1 }},
		{"allowed_targets bad cidr", func(c *config.ServerConfig) { c.Policy.AllowedTargets = []string{"999.1.1.0/8:80"} }},
		{"allowed_targets bad port", func(c *config.ServerConfig) { c.Policy.AllowedTargets = []string{"10.0.0.0/8:abc"} }},
		{"allowed_targets empty", func(c *config.ServerConfig) { c.Policy.AllowedTargets = nil }},
		{"udp_max_sessions zero", func(c *config.ServerConfig) { c.Policy.UDPMaxSessionsPerTunnel = 0 }},
		{"udp_max_packet too big", func(c *config.ServerConfig) { c.Policy.UDPMaxPacket = 65508 }},
		{"udp idle timeout invalid", func(c *config.ServerConfig) { c.Policy.UDPSessionIdleTimeout = "xyz" }},
		{"heartbeat interval too low", func(c *config.ServerConfig) { c.Heartbeat.IntervalS = 4 }},
		{"heartbeat interval too high", func(c *config.ServerConfig) { c.Heartbeat.IntervalS = 301 }},
		{"heartbeat timeout zero", func(c *config.ServerConfig) { c.Heartbeat.TimeoutS = 0 }},
		{"heartbeat miss zero", func(c *config.ServerConfig) { c.Heartbeat.MissThreshold = 0 }},
		{"ca_validity too low", func(c *config.ServerConfig) { c.PKI.CAValidityYears = 0 }},
		{"cert validity zero", func(c *config.ServerConfig) { c.PKI.ClientCertValidityDays = 0 }},
		{"cert validity too high", func(c *config.ServerConfig) { c.PKI.ClientCertValidityDays = 826 }},
		{"token_ttl invalid", func(c *config.ServerConfig) { c.PKI.TokenTTL = "abc" }},
		{"token_ttl too long", func(c *config.ServerConfig) { c.PKI.TokenTTL = "25h" }},
		{"token_ttl negative", func(c *config.ServerConfig) { c.PKI.TokenTTL = "-1h" }},
		{"log level invalid", func(c *config.ServerConfig) { c.Logging.Level = "trace" }},
		{"log format invalid", func(c *config.ServerConfig) { c.Logging.Format = "xml" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validServer(t.TempDir())
			tc.mut(c)
			if err := config.ValidateServer(c); err == nil {
				t.Fatalf("expected validation error for %q, got nil", tc.name)
			}
		})
	}
}

func TestValidateClientValid(t *testing.T) {
	if err := config.ValidateClient(validClient()); err != nil {
		t.Fatalf("valid client config rejected: %v", err)
	}
	// http tunnel via vhost: remote_port 0 is allowed when http_host set
	c := validClient()
	c.Tunnels = append(c.Tunnels, config.TunnelConfig{
		Name: "web", Type: "http", RemotePort: 0, HTTPHost: "blog.example.com",
		LocalIP: "127.0.0.1", LocalPort: 8080, Enabled: true,
	})
	if err := config.ValidateClient(c); err != nil {
		t.Fatalf("http vhost tunnel rejected: %v", err)
	}
}

func TestValidateClientInvalid(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.ClientConfig)
	}{
		{"server_addr required", func(c *config.ClientConfig) { c.ServerAddr = "" }},
		{"server_addr invalid host", func(c *config.ClientConfig) { c.ServerAddr = "bad host:7000" }},
		{"server_addr port zero", func(c *config.ClientConfig) { c.ServerAddr = "example.com:0" }},
		{"server_addr port too big", func(c *config.ClientConfig) { c.ServerAddr = "example.com:65536" }},
		{"ca_fingerprint wrong len", func(c *config.ClientConfig) { c.CAFingerprint = "abc123" }},
		{"max_backoff too long", func(c *config.ClientConfig) { c.Reconnect.MaxBackoff = "11m" }},
		{"initial_backoff invalid", func(c *config.ClientConfig) { c.Reconnect.InitialBackoff = "soon" }},
		{"jitter too high", func(c *config.ClientConfig) { c.Reconnect.Jitter = 1.5 }},
		{"jitter negative", func(c *config.ClientConfig) { c.Reconnect.Jitter = -0.1 }},
		{"tunnel name invalid", func(c *config.ClientConfig) { c.Tunnels[0].Name = "bad name!" }},
		{"tunnel name too long", func(c *config.ClientConfig) { c.Tunnels[0].Name = strings.Repeat("x", 65) }},
		{"tunnel name duplicate", func(c *config.ClientConfig) {
			c.Tunnels = append(c.Tunnels, c.Tunnels[0])
		}},
		{"tunnel type invalid", func(c *config.ClientConfig) { c.Tunnels[0].Type = "quic" }},
		{"tcp remote_port zero", func(c *config.ClientConfig) { c.Tunnels[0].RemotePort = 0 }},
		{"tcp remote_port too big", func(c *config.ClientConfig) { c.Tunnels[0].RemotePort = 65536 }},
		{"local_ip wildcard", func(c *config.ClientConfig) { c.Tunnels[0].LocalIP = "0.0.0.0" }},
		{"local_ip multicast", func(c *config.ClientConfig) { c.Tunnels[0].LocalIP = "224.0.0.1" }},
		{"local_ip link-local", func(c *config.ClientConfig) { c.Tunnels[0].LocalIP = "169.254.1.1" }},
		{"local_ip garbage", func(c *config.ClientConfig) { c.Tunnels[0].LocalIP = "not an ip!" }},
		{"local_port zero", func(c *config.ClientConfig) { c.Tunnels[0].LocalPort = 0 }},
		{"http no host no port", func(c *config.ClientConfig) {
			c.Tunnels[0] = config.TunnelConfig{Name: "web", Type: "http", RemotePort: 0, LocalIP: "127.0.0.1", LocalPort: 8080, Enabled: true}
		}},
		{"http_host invalid", func(c *config.ClientConfig) {
			c.Tunnels[0] = config.TunnelConfig{Name: "web", Type: "http", HTTPHost: "bad_host!", RemotePort: 80, LocalIP: "127.0.0.1", LocalPort: 8080, Enabled: true}
		}},
		{"idle_timeout invalid", func(c *config.ClientConfig) { c.Tunnels[0].IdleTimeout = "nope" }},
		{"log level invalid", func(c *config.ClientConfig) { c.Logging.Level = "verbose" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validClient()
			tc.mut(c)
			if err := config.ValidateClient(c); err == nil {
				t.Fatalf("expected validation error for %q, got nil", tc.name)
			}
		})
	}
}
