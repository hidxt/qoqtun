package tunnel

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
)

// Client is the client-side tunnel registry and data-connection dialer.
type Client struct {
	ServerAddr string
	CAs        []*x509.Certificate
	Cert, Key  []byte
	// AllowedTargets is the server-delivered policy (回源 ACL).
	AllowedTargets []string
	// DialLocal overrides the origin dial (tests).
	DialLocal func(ctx context.Context, ip string, port int) (net.Conn, error)
	Log       *slog.Logger

	mu        sync.Mutex
	tunnels   map[string]*TunnelConfig // tunnel_id
	dataConns map[*transport.Conn]struct{}
	rules     []targetRule
}

// TunnelConfig is a locally registered tunnel.
type TunnelConfig struct {
	ID         string
	Name       string
	Type       string
	RemotePort int
	LocalIP    string
	LocalPort  int
}

// NewClient creates the client-side tunnel manager.
func NewClient(serverAddr string, cas []*x509.Certificate, cert, key []byte, allowedTargets []string, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}
	rules, err := ParseTargets(allowedTargets)
	if err != nil {
		return nil, err
	}
	return &Client{
		ServerAddr:     serverAddr,
		CAs:            cas,
		Cert:           cert,
		Key:            key,
		AllowedTargets: allowedTargets,
		rules:          rules,
		Log:            log,
		tunnels:        make(map[string]*TunnelConfig),
		dataConns:      make(map[*transport.Conn]struct{}),
	}, nil
}

// RegisterLocal records a tunnel acknowledged by the server.
func (c *Client) RegisterLocal(tc *TunnelConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tunnels[tc.ID] = tc
}

// UnregisterLocal removes a tunnel.
func (c *Client) UnregisterLocal(tunnelID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tunnels, tunnelID)
}

// Get returns the tunnel config.
func (c *Client) Get(tunnelID string) (*TunnelConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tc, ok := c.tunnels[tunnelID]
	return tc, ok
}

// Count returns the number of registered tunnels.
func (c *Client) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.tunnels)
}

// HandleOpenConnection is invoked when the server sends open_connection:
// validate the tunnel, ACL-check the origin, dial it (10s), open the mTLS
// data connection and send the open_data first frame; then splice.
func (c *Client) HandleOpenConnection(ctx context.Context, oc *protocol.OpenConnection) error {
	if oc.Transport == "udp" {
		return c.HandleUDPOpenConnection(ctx, oc)
	}
	tc, ok := c.Get(oc.TunnelID)
	if !ok {
		return fmt.Errorf("unknown tunnel %s", oc.TunnelID)
	}
	if err := c.checkACL(tc.LocalIP, tc.LocalPort); err != nil {
		return err
	}
	// resolve once, dial the same IP (DNS-rebinding guard)
	origin, err := c.dialLocal(ctx, tc.LocalIP, tc.LocalPort)
	if err != nil {
		return fmt.Errorf("dial local %s:%d: %w", tc.LocalIP, tc.LocalPort, err)
	}
	host, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		origin.Close()
		return fmt.Errorf("invalid server addr: %w", err)
	}
	dataConn, err := transport.Dial("tcp", c.ServerAddr, transport.Options{
		CAs:              c.CAs,
		Cert:             c.Cert,
		Key:              c.Key,
		ServerName:       host,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		origin.Close()
		return fmt.Errorf("dial server data channel: %w", err)
	}
	if err := dataConn.WriteFrame(protocol.MsgOpenData, 0, &protocol.OpenData{
		ConnID:   oc.ConnID,
		TunnelID: oc.TunnelID,
	}); err != nil {
		origin.Close()
		dataConn.Close()
		return err
	}
	c.trackData(dataConn)
	defer c.untrackData(dataConn)
	c.Log.Info("data connection established", "conn_id", oc.ConnID[:8], "tunnel", tc.Name)
	<-Splice(origin, dataConn, 32*1024)
	return nil
}

// trackData registers an active data connection so it can be torn down when
// the control session ends.
func (c *Client) trackData(conn *transport.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dataConns[conn] = struct{}{}
}

func (c *Client) untrackData(conn *transport.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.dataConns, conn)
}

// CloseAllDataConns forcibly closes every active data connection (invoked
// when the control session drops).
func (c *Client) CloseAllDataConns() {
	c.mu.Lock()
	conns := make([]*transport.Conn, 0, len(c.dataConns))
	for conn := range c.dataConns {
		conns = append(conns, conn)
	}
	c.dataConns = make(map[*transport.Conn]struct{})
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// checkACL enforces the server-delivered allowed_targets on the origin.
func (c *Client) checkACL(ip string, port int) error {
	c.mu.Lock()
	rules := c.rules
	c.mu.Unlock()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("origin ip %q invalid", ip)
	}
	if !Allows(rules, parsed, port) {
		return fmt.Errorf("origin %s:%d not allowed by policy", ip, port)
	}
	return nil
}

// dialLocal dials the origin with a 10s timeout. IP literals are dialed
// directly; hostnames are resolved exactly once and dialed via that IP.
func (c *Client) dialLocal(ctx context.Context, target string, port int) (net.Conn, error) {
	if c.DialLocal != nil {
		return c.DialLocal(ctx, target, port)
	}
	host := target
	if ip := net.ParseIP(target); ip == nil {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, target)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %w", target, err)
		}
		host = ips[0].IP.String() // single resolution; dial the same IP
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}
