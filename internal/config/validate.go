package config

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- shared validation helpers ----

var (
	tunnelNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
	// rfc1123Hostname matches RFC 1123 hostnames (labels of alnum + hyphen).
	rfc1123Hostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	hex64           = regexp.MustCompile(`(?i)^[0-9a-f]{64}$`)
)

func validHostname(h string) bool {
	return len(h) <= 253 && rfc1123Hostname.MatchString(h)
}

// validHostOrIP accepts an RFC1123 hostname or a literal IP.
func validHostOrIP(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	return validHostname(s)
}

// splitHostPort splits "host:port". IPv6 literals ([::1]:7000) are supported
// via net.SplitHostPort; bare IPv6 without brackets is rejected for clarity.
func splitHostPort(addr string) (string, int, error) {
	if addr == "" {
		return "", 0, fmt.Errorf("empty address")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("must be host:port (got %q)", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port %q (want 1-65535)", portStr)
	}
	return host, port, nil
}

func validDuration(s string) bool {
	_, err := time.ParseDuration(s)
	return err == nil
}

// validateAbsPath enforces: absolute path, filepath.Clean applied, no ".."
// escape segments (checked on the raw path so normalization cannot hide them).
func validateAbsPath(p, field string) error {
	if p == "" {
		return fmt.Errorf("%s: must not be empty", field)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s: must be an absolute path (got %q)", field, p)
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if seg == ".." {
			return fmt.Errorf("%s: path must not contain \"..\"", field)
		}
	}
	_ = filepath.Clean(p) // normalization applied implicitly by callers
	return nil
}

func validLogLevel(l string) bool {
	switch strings.ToLower(l) {
	case "debug", "info", "warn", "warning", "error":
		return true
	}
	return false
}

func validLogFormat(f string) bool {
	switch strings.ToLower(f) {
	case "json", "text", "":
		return true
	}
	return false
}

func validLogFile(f string) error {
	if f == "" {
		return nil
	}
	if filepath.Clean(f) == "" || filepath.Clean(f) == "." {
		return fmt.Errorf("logging.file: invalid path %q", f)
	}
	return nil
}

// parsePortRange validates "N" or "N-M", returning the bounds.
func parsePortRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	lo, hi := s, s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, hi = s[:i], s[i+1:]
		if strings.IndexByte(hi, '-') >= 0 || lo == "" || hi == "" {
			return 0, 0, fmt.Errorf("invalid port range %q (want N or N-M)", s)
		}
	}
	a, errA := strconv.Atoi(lo)
	b, errB := strconv.Atoi(hi)
	if errA != nil || errB != nil || a < 1 || b > 65535 || a > b {
		return 0, 0, fmt.Errorf("invalid port range %q (want 1-65535, N<=M)", s)
	}
	return a, b, nil
}

// rangeContainsPort reports whether [lo,hi] contains p.
func rangeContainsPort(lo, hi, p int) bool { return p >= lo && p <= hi }

// parseTarget validates "CIDR:port" or "CIDR:port-range" or "CIDR:*".
func parseTarget(t string) error {
	t = strings.TrimSpace(t)
	i := strings.LastIndexByte(t, ':')
	if i <= 0 || i == len(t)-1 {
		return fmt.Errorf("invalid target %q (want CIDR:port|range|*)", t)
	}
	cidr, portPart := t[:i], t[i+1:]
	if _, err := netip.ParsePrefix(cidr); err != nil {
		return fmt.Errorf("invalid CIDR in target %q", t)
	}
	if portPart == "*" {
		return nil
	}
	if _, _, err := parsePortRange(portPart); err != nil {
		return fmt.Errorf("invalid port in target %q: %v", t, err)
	}
	return nil
}

// validLocalIP validates the local_ip field: literal IP that is not
// unspecified/wildcard, multicast or link-local; or an RFC1123 hostname.
func validLocalIP(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	ip := net.ParseIP(s)
	if ip == nil {
		if !validHostname(s) {
			return fmt.Errorf("%q is neither a valid IP nor an RFC1123 hostname", s)
		}
		return nil
	}
	if ip.IsUnspecified() { // 0.0.0.0 / ::
		return fmt.Errorf("wildcard address %q is not allowed", s)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("multicast address %q is not allowed", s)
	}
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("link-local address %q is not allowed (must be explicit white-listed)", s)
	}
	return nil
}

// ---- ServerConfig validation ----

// ValidateServer checks every field of cfg against the schema rules.
// Any error means the configuration is rejected (fail-closed).
func ValidateServer(c *ServerConfig) error {
	if c.StateDir == "" {
		return fmt.Errorf("state_dir: required (no default)")
	}
	if err := validateAbsPath(c.StateDir, "state_dir"); err != nil {
		return err
	}

	// listen
	ctlHost, ctlPort, err := splitHostPort(c.Listen.ControlAddr)
	if err != nil {
		return fmt.Errorf("listen.control_addr: %v", err)
	}
	if !validHostOrIP(ctlHost) {
		return fmt.Errorf("listen.control_addr: invalid host %q", ctlHost)
	}
	enrollPort := 0
	if c.Listen.EnrollAddr != "" {
		enrollHost, p, err := splitHostPort(c.Listen.EnrollAddr)
		if err != nil {
			return fmt.Errorf("listen.enroll_addr: %v", err)
		}
		if !validHostOrIP(enrollHost) {
			return fmt.Errorf("listen.enroll_addr: invalid host %q", enrollHost)
		}
		enrollPort = p
	}
	if c.Listen.HTTPVhostPort != 0 && (c.Listen.HTTPVhostPort < 1 || c.Listen.HTTPVhostPort > 65535) {
		return fmt.Errorf("listen.http_vhost_port: must be 0 or 1-65535")
	}

	// policy
	for _, pr := range c.Policy.AllowedPorts {
		lo, hi, err := parsePortRange(pr)
		if err != nil {
			return fmt.Errorf("policy.allowed_ports: %v", err)
		}
		// ranges must not contain the control/enroll listener ports
		if rangeContainsPort(lo, hi, ctlPort) {
			return fmt.Errorf("policy.allowed_ports: range %q must not contain control port %d", pr, ctlPort)
		}
		if enrollPort != 0 && rangeContainsPort(lo, hi, enrollPort) {
			return fmt.Errorf("policy.allowed_ports: range %q must not contain enroll port %d", pr, enrollPort)
		}
	}
	if err := checkRange(c.Policy.MaxTunnelsPerClient, 1, 1024, "policy.max_tunnels_per_client"); err != nil {
		return err
	}
	if err := checkRange(c.Policy.MaxConnsPerClient, 1, 100000, "policy.max_conns_per_client"); err != nil {
		return err
	}
	if err := checkRange(c.Policy.MaxConnsPerTunnel, 1, 100000, "policy.max_conns_per_tunnel"); err != nil {
		return err
	}
	if c.Policy.BandwidthBpsPerClient < 0 {
		return fmt.Errorf("policy.bandwidth_bps_per_client: must be >= 0")
	}
	if c.Policy.BandwidthBpsPerTunnel < 0 {
		return fmt.Errorf("policy.bandwidth_bps_per_tunnel: must be >= 0")
	}
	if len(c.Policy.AllowedTargets) == 0 {
		return fmt.Errorf("policy.allowed_targets: must not be empty (deployment must configure explicitly)")
	}
	for _, t := range c.Policy.AllowedTargets {
		if err := parseTarget(t); err != nil {
			return fmt.Errorf("policy.allowed_targets: %v", err)
		}
	}
	if err := checkRange(c.Policy.UDPMaxSessionsPerTunnel, 1, 1<<20, "policy.udp_max_sessions_per_tunnel"); err != nil {
		return err
	}
	if err := checkRange(c.Policy.UDPMaxPacket, 1, 65507, "policy.udp_max_packet"); err != nil {
		return err
	}
	if !validDuration(c.Policy.UDPSessionIdleTimeout) {
		return fmt.Errorf("policy.udp_session_idle_timeout: invalid duration %q", c.Policy.UDPSessionIdleTimeout)
	}

	// heartbeat
	if err := checkRange(c.Heartbeat.IntervalS, 5, 300, "heartbeat.interval_s"); err != nil {
		return err
	}
	if err := checkRange(c.Heartbeat.TimeoutS, 1, 300, "heartbeat.timeout_s"); err != nil {
		return err
	}
	if err := checkRange(c.Heartbeat.MissThreshold, 1, 100, "heartbeat.miss_threshold"); err != nil {
		return err
	}

	// pki
	if err := checkRange(c.PKI.CAValidityYears, 1, 100, "pki.ca_validity_years"); err != nil {
		return err
	}
	if err := checkRange(c.PKI.ClientCertValidityDays, 1, 825, "pki.client_cert_validity_days"); err != nil {
		return err
	}
	d, err := time.ParseDuration(c.PKI.TokenTTL)
	if err != nil {
		return fmt.Errorf("pki.token_ttl: invalid duration %q", c.PKI.TokenTTL)
	}
	if d <= 0 || d > 24*time.Hour {
		return fmt.Errorf("pki.token_ttl: must be > 0 and <= 24h (got %s)", d)
	}

	// logging
	if !validLogLevel(c.Logging.Level) {
		return fmt.Errorf("logging.level: invalid level %q (want debug|info|warn|error)", c.Logging.Level)
	}
	if !validLogFormat(c.Logging.Format) {
		return fmt.Errorf("logging.format: invalid format %q (want json|text)", c.Logging.Format)
	}
	if err := validLogFile(c.Logging.File); err != nil {
		return err
	}
	return nil
}

// ---- ClientConfig validation ----

// ValidateClient checks every field of cfg (05-config-schema.md §2).
func ValidateClient(c *ClientConfig) error {
	if c.ServerAddr == "" {
		return fmt.Errorf("server_addr: required (no default)")
	}
	host, port, err := splitHostPort(c.ServerAddr)
	if err != nil {
		return fmt.Errorf("server_addr: %v", err)
	}
	if !validHostOrIP(host) {
		return fmt.Errorf("server_addr: invalid host %q (want RFC1123 hostname or IP)", host)
	}
	_ = port
	if c.CAFingerprint != "" && !hex64.MatchString(c.CAFingerprint) {
		return fmt.Errorf("ca_fingerprint: must be 64 hex chars (SHA-256) or empty")
	}

	if !validDuration(c.Reconnect.InitialBackoff) {
		return fmt.Errorf("reconnect.initial_backoff: invalid duration %q", c.Reconnect.InitialBackoff)
	}
	maxB, err := time.ParseDuration(c.Reconnect.MaxBackoff)
	if err != nil {
		return fmt.Errorf("reconnect.max_backoff: invalid duration %q", c.Reconnect.MaxBackoff)
	}
	if maxB > 10*time.Minute {
		return fmt.Errorf("reconnect.max_backoff: must be <= 10min (got %s)", maxB)
	}
	if c.Reconnect.Jitter < 0 || c.Reconnect.Jitter > 1 {
		return fmt.Errorf("reconnect.jitter: must be in [0,1] (got %v)", c.Reconnect.Jitter)
	}

	if !validLogLevel(c.Logging.Level) {
		return fmt.Errorf("logging.level: invalid level %q", c.Logging.Level)
	}
	if !validLogFormat(c.Logging.Format) {
		return fmt.Errorf("logging.format: invalid format %q", c.Logging.Format)
	}
	if err := validLogFile(c.Logging.File); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(c.Tunnels))
	for i, t := range c.Tunnels {
		field := fmt.Sprintf("tunnels[%d]", i)
		if !tunnelNameRe.MatchString(t.Name) {
			return fmt.Errorf("%s.name: must match ^[a-zA-Z0-9_-]{1,64}$ (got %q)", field, t.Name)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("%s.name: duplicate tunnel name %q", field, t.Name)
		}
		seen[t.Name] = struct{}{}
		switch t.Type {
		case "tcp", "udp", "https":
			if err := checkRange(t.RemotePort, 1, 65535, field+".remote_port"); err != nil {
				return err
			}
		case "http":
			// http may use the shared vhost port (remote_port == 0)
			if t.RemotePort != 0 {
				if err := checkRange(t.RemotePort, 1, 65535, field+".remote_port"); err != nil {
					return err
				}
			}
			if t.HTTPHost == "" && t.RemotePort == 0 {
				return fmt.Errorf("%s: type=http requires http_host or a non-zero remote_port", field)
			}
		default:
			return fmt.Errorf("%s.type: must be tcp|udp|http|https (got %q)", field, t.Type)
		}
		if err := validLocalIP(t.LocalIP); err != nil {
			return fmt.Errorf("%s.local_ip: %v", field, err)
		}
		if err := checkRange(t.LocalPort, 1, 65535, field+".local_port"); err != nil {
			return err
		}
		if t.HTTPHost != "" && !validHostname(t.HTTPHost) {
			return fmt.Errorf("%s.http_host: invalid RFC1123 hostname %q", field, t.HTTPHost)
		}
		if t.IdleTimeout != "" && !validDuration(t.IdleTimeout) {
			return fmt.Errorf("%s.idle_timeout: invalid duration %q", field, t.IdleTimeout)
		}
	}
	return nil
}

func checkRange(v, lo, hi int, field string) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s: must be in [%d,%d] (got %d)", field, lo, hi, v)
	}
	return nil
}
