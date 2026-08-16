package protocol

// Message payloads per 04-protocol-v1.md §2. Unknown JSON fields are
// ignored (forward compatibility); required-field validation lives in
// validate.go (missing required fields = ERR_PROTOCOL).

// ClientHello is the first control message from the client (C→S).
type ClientHello struct {
	ClientID        string   `json:"client_id"` // must equal the mTLS cert CN
	ProtocolVersion int      `json:"protocol_version"`
	Name            string   `json:"name"`
	Note            string   `json:"note,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"` // extension point
}

// ServerHello carries the session id and the full policy (S→C).
type ServerHello struct {
	SessionID string    `json:"session_id"`
	Policy    Policy    `json:"policy"`
	Heartbeat Heartbeat `json:"heartbeat"`
}

// Policy is the server-side per-client policy.
type Policy struct {
	AllowedPorts   []string  `json:"allowed_ports"`
	MaxTunnels     int       `json:"max_tunnels"`
	MaxConns       int       `json:"max_conns"`
	BandwidthBPS   int64     `json:"bandwidth_bps"`
	UDP            UDPPolicy `json:"udp"`
	AllowedTargets []string  `json:"allowed_targets"`
}

// UDPPolicy bounds the per-tunnel UDP data channel (v1: UDP-in-TCP).
type UDPPolicy struct {
	MaxSessions        int    `json:"max_sessions"`
	MaxPacket          int    `json:"max_packet"`
	SessionIdleTimeout string `json:"session_idle_timeout"`
}

// Heartbeat parameters (04-protocol-v1.md §4).
type Heartbeat struct {
	IntervalS     int `json:"interval_s"`
	TimeoutS      int `json:"timeout_s"`
	MissThreshold int `json:"miss_threshold"`
}

// RegisterTunnel requests a tunnel registration (C→S).
type RegisterTunnel struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"` // tcp|udp|http|https
	RemotePort int         `json:"remote_port"`
	Local      LocalTarget `json:"local"`
	HTTP       *HTTPConfig `json:"http,omitempty"`
}

// LocalTarget is the client-side origin (IP literal or allow-listed host).
type LocalTarget struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// HTTPConfig carries vhost routing for type=http.
type HTTPConfig struct {
	Host string `json:"host,omitempty"`
}

// RegisterTunnelResp acknowledges registration (S→C).
type RegisterTunnelResp struct {
	TunnelID  string     `json:"tunnel_id"`
	OK        bool       `json:"ok"`
	Error     *Error     `json:"error,omitempty"`
	Effective *Effective `json:"effective,omitempty"`
}

// Effective reports the resolved public port and limits.
type Effective struct {
	RemotePort int `json:"remote_port"`
}

// UnregisterTunnel removes a tunnel (C→S).
type UnregisterTunnel struct {
	TunnelID string `json:"tunnel_id"`
}

// OpenConnection notifies the client to establish a data connection (S→C).
type OpenConnection struct {
	ConnID     string `json:"conn_id"` // 128-bit hex
	TunnelID   string `json:"tunnel_id"`
	SrcAddr    string `json:"src_addr"`
	DeadlineMS int    `json:"deadline_ms"`
	Transport  string `json:"transport,omitempty"` // extension point (tcp_mux/quic/p2p)
}

// CloseConnection is the accounting point when a data conn ends (both ways).
type CloseConnection struct {
	ConnID   string `json:"conn_id"`
	Reason   string `json:"reason"`
	BytesIn  int64  `json:"bytes_in,omitempty"`
	BytesOut int64  `json:"bytes_out,omitempty"`
}

// Ping / Pong heartbeat payloads (§4).
type Ping struct {
	Echo string `json:"echo"`
}

// Pong mirrors the ping echo.
type Pong struct {
	Echo string `json:"echo"`
}

// PolicyUpdate is a runtime policy change (S→C); V1 may honor it on reconnect.
type PolicyUpdate struct {
	Policy Policy `json:"policy"`
}

// Shutdown negotiates graceful close (both ways).
type Shutdown struct {
	Reason         string `json:"reason"`
	DrainTimeoutMS int    `json:"drain_timeout_ms"`
}

// Error is the unified error message (§5). Messages never contain internal
// paths, stack traces or key material.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

// OpenData is the first frame on a data connection (length-prefixed JSON);
// the stream becomes raw bytes afterwards.
type OpenData struct {
	ConnID   string `json:"conn_id"`
	TunnelID string `json:"tunnel_id"`
}
