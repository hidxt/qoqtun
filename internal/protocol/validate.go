package protocol

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Field validators per 05-config-schema.md and 04-protocol-v1.md.
// Missing required fields or invalid values = ERR_PROTOCOL (fail-closed).

var tunnelNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

const maxNameLen = 64

// ValidateClientHello checks the handshake message. clientID must match the
// mTLS certificate CN (checked by the caller with the transport identity);
// here we validate shape only.
func ValidateClientHello(h *ClientHello) error {
	if h == nil {
		return ProtocolError("missing client_hello")
	}
	if h.ClientID == "" {
		return ProtocolError("client_hello: missing client_id")
	}
	if len(h.ClientID) > 128 {
		return ProtocolError("client_hello: client_id too long")
	}
	if h.ProtocolVersion != ProtocolVersion {
		return VersionUnsupportedError()
	}
	if len(h.Name) > maxNameLen {
		return ProtocolError("client_hello: name too long")
	}
	for _, cap := range h.Capabilities {
		if len(cap) > 64 {
			return ProtocolError("client_hello: capability too long")
		}
	}
	return nil
}

// ValidateServerHello checks the server handshake response shape.
func ValidateServerHello(h *ServerHello) error {
	if h == nil {
		return ProtocolError("missing server_hello")
	}
	if h.SessionID == "" {
		return ProtocolError("server_hello: missing session_id")
	}
	if err := ValidatePolicy(&h.Policy); err != nil {
		return err
	}
	return validateHeartbeat(&h.Heartbeat)
}

// ValidatePolicy checks bounds on the per-client policy.
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return ProtocolError("missing policy")
	}
	if p.MaxTunnels <= 0 || p.MaxTunnels > 1024 {
		return ProtocolError(fmt.Sprintf("policy: max_tunnels out of range %d", p.MaxTunnels))
	}
	if p.MaxConns <= 0 || p.MaxConns > 100000 {
		return ProtocolError(fmt.Sprintf("policy: max_conns out of range %d", p.MaxConns))
	}
	if p.BandwidthBPS < 0 {
		return ProtocolError("policy: negative bandwidth")
	}
	if p.UDP.MaxSessions < 0 || p.UDP.MaxSessions > 65536 {
		return ProtocolError(fmt.Sprintf("policy: udp.max_sessions out of range %d", p.UDP.MaxSessions))
	}
	if p.UDP.MaxPacket < 0 || p.UDP.MaxPacket > 65507 {
		return ProtocolError(fmt.Sprintf("policy: udp.max_packet out of range %d", p.UDP.MaxPacket))
	}
	for _, t := range p.AllowedTargets {
		if !validTarget(t) {
			return ProtocolError("policy: invalid allowed_targets entry " + t)
		}
	}
	return nil
}

// ValidateRegisterTunnel checks a tunnel registration request.
func ValidateRegisterTunnel(r *RegisterTunnel) error {
	if r == nil {
		return ProtocolError("missing register_tunnel")
	}
	if !tunnelNameRe.MatchString(r.Name) {
		return ProtocolError("register_tunnel: invalid name")
	}
	switch r.Type {
	case "tcp", "udp", "http", "https":
	default:
		return ProtocolError("register_tunnel: invalid type " + r.Type)
	}
	if r.RemotePort < 0 || r.RemotePort > 65535 {
		return ProtocolError("register_tunnel: remote_port out of range")
	}
	if r.Type == "http" && r.RemotePort == 0 && (r.HTTP == nil || r.HTTP.Host == "") {
		return ProtocolError("register_tunnel: http tunnel needs http.host when remote_port=0")
	}
	if err := validateLocalTarget(&r.Local); err != nil {
		return err
	}
	if r.HTTP != nil && len(r.HTTP.Host) > 255 {
		return ProtocolError("register_tunnel: http.host too long")
	}
	return nil
}

// ValidateOpenData checks the data-connection first frame.
func ValidateOpenData(d *OpenData) error {
	if d == nil {
		return ProtocolError("missing open_data")
	}
	if d.ConnID == "" {
		return ProtocolError("open_data: missing conn_id")
	}
	if d.TunnelID == "" {
		return ProtocolError("open_data: missing tunnel_id")
	}
	return nil
}

func validateLocalTarget(t *LocalTarget) error {
	if t == nil {
		return ProtocolError("register_tunnel: missing local")
	}
	if t.Port < 1 || t.Port > 65535 {
		return ProtocolError("register_tunnel: local.port out of range")
	}
	ip := net.ParseIP(t.IP)
	if ip == nil {
		if !validHostname(t.IP) {
			return ProtocolError("register_tunnel: local.ip invalid")
		}
		return nil
	}
	// 05-config-schema: no wildcard/multicast/link-local unless allow-listed
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ProtocolError("register_tunnel: local.ip must not be wildcard/multicast/link-local")
	}
	return nil
}

func validateHeartbeat(h *Heartbeat) error {
	if h == nil {
		return ProtocolError("missing heartbeat")
	}
	if h.IntervalS < 1 || h.IntervalS > 300 {
		return ProtocolError(fmt.Sprintf("heartbeat: interval_s out of range %d", h.IntervalS))
	}
	if h.TimeoutS < 1 || h.TimeoutS > 60 {
		return ProtocolError(fmt.Sprintf("heartbeat: timeout_s out of range %d", h.TimeoutS))
	}
	if h.MissThreshold < 1 || h.MissThreshold > 10 {
		return ProtocolError(fmt.Sprintf("heartbeat: miss_threshold out of range %d", h.MissThreshold))
	}
	return nil
}

// validTarget checks "CIDR:port-or-range" syntax (e.g. "10.0.0.0/8:*").
func validTarget(t string) bool {
	idx := strings.LastIndexByte(t, ':')
	if idx <= 0 || idx == len(t)-1 {
		return false
	}
	cidr := t[:idx]
	portSpec := t[idx+1:]
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return false
	}
	if portSpec == "*" {
		return true
	}
	if _, _, err := parsePortRange(portSpec); err != nil {
		return false
	}
	return true
}

// parsePortRange accepts "N" or "N-M" within [1,65535].
func parsePortRange(s string) (int, int, error) {
	var lo, hi int
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		if _, err := fmt.Sscanf(parts[0], "%d", &lo); err != nil {
			return 0, 0, fmt.Errorf("bad range")
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &hi); err != nil {
			return 0, 0, fmt.Errorf("bad range")
		}
	} else {
		if _, err := fmt.Sscanf(s, "%d", &lo); err != nil {
			return 0, 0, fmt.Errorf("bad range")
		}
		hi = lo
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("bad range")
	}
	return lo, hi, nil
}

// ParsePortRange is exported for server-side ACL checks (Phase 5).
func ParsePortRange(s string) (lo, hi int, err error) {
	return parsePortRange(s)
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' && i > 0 && i < len(label)-1) {
				return false
			}
		}
	}
	return true
}
