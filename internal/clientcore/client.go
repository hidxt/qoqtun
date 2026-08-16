// Package clientcore implements the client-side control session
// (04-protocol-v1.md §1/§2/§4): dial, handshake, policy reception and the
// heartbeat loop. Reconnection arrives in Phase 6; for now a dropped
// control connection terminates with an error.
package clientcore

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hidxt/qoqtun/internal/metrics"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
	"github.com/hidxt/qoqtun/internal/tunnel"
)

// Client drives one control session.
type Client struct {
	ServerAddr string
	// mTLS materials.
	CAs       []*x509.Certificate
	Cert, Key []byte
	// Identity (cert CN) and hello metadata.
	ClientID string
	Name     string
	Note     string
	Log      *slog.Logger

	// Tunnels to register after handshake (from client.toml).
	Tunnels []TunnelSpec

	// Heartbeat is the negotiated parameters (filled after handshake).
	Heartbeat protocol.Heartbeat
	// Policy is the server-assigned policy (filled after handshake).
	Policy protocol.Policy

	// Backoff controls reconnect timing (default: 1s x2 max 60s +-20%).
	Backoff BackoffConfig

	// Metrics collects local traffic statistics (client status); lazily
	// created on first use.
	metrics *metrics.Registry

	tunnelClient *tunnel.Client
	manager      *Manager
	seq          uint64
	missed       atomic.Int32
	mu           sync.Mutex
	pendingMu    sync.Mutex
	pending      map[uint64]chan *protocol.Envelope
	conn         *transport.Conn
	closeOnce    sync.Once
}

// TunnelInfo is the runtime view of one tunnel (`client tunnel list`).
type TunnelInfo struct {
	Name       string
	Type       string
	LocalIP    string
	LocalPort  int
	RemotePort int
	TunnelID   string
}

// TunnelSpec is one tunnel to register (mirrors config.TunnelConfig).
type TunnelSpec struct {
	Name       string
	Type       string
	RemotePort int
	LocalIP    string
	LocalPort  int
	HTTPHost   string
	Enabled    bool
}

// setupTunnels builds the client-side tunnel manager after the policy is
// received (allowed_targets is required for the origin ACL).
func (c *Client) setupTunnels() error {
	tc, err := tunnel.NewClient(c.ServerAddr, c.CAs, c.Cert, c.Key, c.Policy.AllowedTargets, c.Log)
	if err != nil {
		return err
	}
	c.tunnelClient = tc
	c.tunnelClient.Metrics = c.Metrics()
	c.tunnelClient.ClientID = c.ClientID
	return nil
}

// Status returns the client's local statistics snapshot.
func (c *Client) Status() metrics.Snapshot {
	if c.metrics == nil {
		return metrics.Snapshot{}
	}
	return c.metrics.Snapshot()
}

// Metrics returns (creating if needed) the local registry.
func (c *Client) Metrics() *metrics.Registry {
	if c.metrics == nil {
		c.metrics = metrics.NewRegistry()
	}
	return c.metrics
}

// Run drives the connection manager: it repeatedly establishes sessions,
// reconnecting with backoff on temporary errors, and returns a non-nil
// error only for permanent failures (authentication, revocation, protocol).
func (c *Client) Run(ctx context.Context) error {
	backoff := c.Backoff
	if backoff.Initial <= 0 {
		backoff = DefaultBackoff()
	}
	m := &Manager{
		Session: c.runSession,
		Backoff: backoff,
		Log:     c.Log,
	}
	c.manager = m
	return m.Run(ctx)
}

// runSession establishes one control session: dial, handshake, tunnel
// registration, heartbeat loop. Any error is classified by the manager.
func (c *Client) runSession(ctx context.Context) error {
	host, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		return fmt.Errorf("clientcore: invalid server addr: %w", err)
	}
	conn, err := transport.Dial("tcp", c.ServerAddr, transport.Options{
		CAs:              c.CAs,
		Cert:             c.Cert,
		Key:              c.Key,
		ServerName:       host,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		return Classify(fmt.Errorf("clientcore: dial: %w", err))
	}
	defer conn.Close()
	c.conn = conn
	c.pendingMu.Lock()
	c.pending = make(map[uint64]chan *protocol.Envelope)
	c.pendingMu.Unlock()
	defer func() {
		c.closeOnce.Do(func() {
			if c.tunnelClient != nil {
				c.tunnelClient.CloseAllDataConns()
			}
		})
	}()

	// handshake: client_hello
	if err := conn.WriteFrame(protocol.MsgClientHello, c.nextSeq(),
		&protocol.ClientHello{
			ClientID:        c.ClientID,
			ProtocolVersion: protocol.ProtocolVersion,
			Name:            c.Name,
			Note:            c.Note,
		}); err != nil {
		return fmt.Errorf("clientcore: send hello: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	env, err := protocol.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("clientcore: read hello response: %w", err)
	}
	if env.Type == protocol.MsgError {
		var e protocol.Error
		if derr := env.DecodePayload(&e); derr == nil {
			return fmt.Errorf("clientcore: server rejected: %s", e.Message)
		}
		return fmt.Errorf("clientcore: server rejected")
	}
	if env.Type != protocol.MsgServerHello {
		return fmt.Errorf("clientcore: unexpected %s during handshake", env.Type)
	}
	var sh protocol.ServerHello
	if err := env.DecodePayload(&sh); err != nil {
		return fmt.Errorf("clientcore: parse server_hello: %w", err)
	}
	if err := protocol.ValidateServerHello(&sh); err != nil {
		return fmt.Errorf("clientcore: invalid server_hello: %w", err)
	}
	c.Policy = sh.Policy
	c.Heartbeat = sh.Heartbeat
	// handshake done: clear the deadline; heartbeat miss counting takes over
	_ = conn.SetDeadline(time.Time{})
	if c.Heartbeat.IntervalS <= 0 {
		c.Heartbeat.IntervalS = 15
	}
	if c.Heartbeat.TimeoutS <= 0 {
		c.Heartbeat.TimeoutS = 10
	}
	c.Log.Info("control session established", "server", c.ServerAddr,
		"session", sh.SessionID, "max_tunnels", sh.Policy.MaxTunnels)

	// read loop: process server frames — MUST be running before the
	// synchronous register RPCs so their responses are dispatched
	readErr := make(chan error, 1)
	go func() {
		readErr <- c.readLoop()
	}()

	if err := c.setupTunnels(); err != nil {
		return fmt.Errorf("clientcore: tunnel setup: %w", err)
	}
	if err := c.registerConfiguredTunnels(ctx); err != nil {
		return fmt.Errorf("clientcore: register tunnels: %w", err)
	}

	// heartbeat loop (client pings at interval)
	ticker := time.NewTicker(time.Duration(c.Heartbeat.IntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// graceful client shutdown: notify the server so it removes the
			// public listeners and drains (04 §2 shutdown negotiation)
			_ = conn.WriteFrame(protocol.MsgShutdown, c.nextSeq(), &protocol.Shutdown{
				Reason:         "client shutdown",
				DrainTimeoutMS: 5000,
			})
			return nil
		case err := <-readErr:
			return fmt.Errorf("clientcore: control connection lost: %w", err)
		case <-ticker.C:
			if err := conn.WriteFrame(protocol.MsgPing, c.nextSeq(), &protocol.Ping{Echo: "hb"}); err != nil {
				return fmt.Errorf("clientcore: ping failed: %w", err)
			}
			if c.missed.Add(1) > int32(c.Heartbeat.MissThreshold) {
				return fmt.Errorf("clientcore: heartbeat missed %d times", c.missed.Load())
			}
		}
	}
}

// registerConfiguredTunnels sends register_tunnel for every enabled tunnel
// in the config and records the server-assigned ids.
func (c *Client) registerConfiguredTunnels(ctx context.Context) error {
	if c.tunnelClient == nil {
		return fmt.Errorf("clientcore: tunnel client not initialized")
	}
	for _, t := range c.Tunnels {
		if !t.Enabled {
			continue
		}
		if err := c.RegisterTunnel(ctx, t); err != nil {
			c.Log.Warn("tunnel registration failed", "name", t.Name, "error", err)
		}
	}
	return nil
}

// RegisterTunnel registers one tunnel with the server and the local
// registry (used at startup for enabled tunnels and at runtime by
// `client tunnel start`).
func (c *Client) RegisterTunnel(ctx context.Context, t TunnelSpec) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("clientcore: not connected")
	}
	if c.tunnelClient == nil {
		return fmt.Errorf("clientcore: tunnel client not initialized")
	}
	if _, _, ok := c.tunnelClient.FindByName(t.Name); ok {
		return fmt.Errorf("tunnel %q already running", t.Name)
	}
	req := &protocol.RegisterTunnel{
		Name:       t.Name,
		Type:       t.Type,
		RemotePort: t.RemotePort,
		Local:      protocol.LocalTarget{IP: t.LocalIP, Port: t.LocalPort},
	}
	if t.Type == "http" && t.HTTPHost != "" {
		req.HTTP = &protocol.HTTPConfig{Host: t.HTTPHost}
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	env, err := c.rpc(ctx, protocol.MsgRegisterTunnel, req)
	if err != nil {
		return err
	}
	if env.Type != protocol.MsgRegisterTunnelResp {
		return fmt.Errorf("clientcore: unexpected %s during tunnel registration", env.Type)
	}
	var rr protocol.RegisterTunnelResp
	if err := env.DecodePayload(&rr); err != nil {
		return err
	}
	if !rr.OK {
		return fmt.Errorf("tunnel %q rejected: %s: %s", t.Name, errCode(rr.Error), errMsg(rr.Error))
	}
	c.tunnelClient.RegisterLocal(&tunnel.TunnelConfig{
		ID: rr.TunnelID, Name: t.Name, Type: t.Type,
		RemotePort: t.RemotePort, LocalIP: t.LocalIP, LocalPort: t.LocalPort,
	})
	c.Log.Info("tunnel registered", "name", t.Name, "tunnel_id", rr.TunnelID, "port", rr.Effective.RemotePort)
	return nil
}

// UnregisterTunnel stops one tunnel (server unregister + local removal).
func (c *Client) UnregisterTunnel(ctx context.Context, name string) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("clientcore: not connected")
	}
	if c.tunnelClient == nil {
		return fmt.Errorf("clientcore: tunnel client not initialized")
	}
	tc, tid, ok := c.tunnelClient.FindByName(name)
	if !ok {
		return fmt.Errorf("tunnel %q not running", name)
	}
	_ = tc
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	env, err := c.rpc(ctx, protocol.MsgUnregisterTunnel, &protocol.UnregisterTunnel{TunnelID: tid})
	if err != nil {
		return err
	}
	var rr protocol.RegisterTunnelResp
	if err := env.DecodePayload(&rr); err != nil {
		return err
	}
	if !rr.OK {
		return fmt.Errorf("tunnel %q stop rejected: %s", name, errCode(rr.Error))
	}
	c.tunnelClient.UnregisterLocal(tid)
	c.Log.Info("tunnel stopped", "name", name, "tunnel_id", tid)
	return nil
}

// TunnelList returns the runtime tunnel states for `client tunnel list`.
func (c *Client) TunnelList() []TunnelInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]TunnelInfo, 0)
	if c.tunnelClient == nil {
		return out
	}
	for _, tc := range c.tunnelClient.LocalSnapshot() {
		out = append(out, TunnelInfo{
			Name: tc.Name, Type: tc.Type,
			LocalIP: tc.LocalIP, LocalPort: tc.LocalPort,
			RemotePort: tc.RemotePort, TunnelID: tc.ID,
		})
	}
	return out
}

func errMsg(e *protocol.Error) string {
	if e == nil {
		return ""
	}
	return e.Message
}

func errCode(e *protocol.Error) string {
	if e == nil {
		return ""
	}
	return e.Code
}

// readLoop consumes server frames until the connection dies.
func (c *Client) readLoop() error {
	for {
		env, err := protocol.ReadFrame(c.conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case protocol.MsgPong:
			var p protocol.Pong
			if err := env.DecodePayload(&p); err == nil {
				c.missed.Store(0)
			}
		case protocol.MsgError:
			var e protocol.Error
			if err := env.DecodePayload(&e); err == nil && e.Fatal {
				return fmt.Errorf("server fatal error: %s: %s", e.Code, e.Message)
			}
		case protocol.MsgPolicyUpdate:
			var pu protocol.PolicyUpdate
			if err := env.DecodePayload(&pu); err == nil {
				c.Policy = pu.Policy
				c.Log.Info("policy updated", "max_tunnels", pu.Policy.MaxTunnels)
			}
		case protocol.MsgOpenConnection:
			c.handleOpenConnection(env)
		case protocol.MsgRegisterTunnelResp:
			// synchronous register/unregister replies are dispatched to the
			// pending waiter (tunnel start/stop via IPC)
			if ch := c.takePending(env.Seq); ch != nil {
				select {
				case ch <- env:
				default:
				}
			}
		case protocol.MsgShutdown:
			return ErrGracefulShutdown
		default:
			// unknown types are ignored (recoverable, §8)
			c.Log.Warn("clientcore: ignoring message", "type", env.Type)
		}
	}
}

// handleOpenConnection establishes a data connection for a public-side
// connection; runs in its own goroutine (splice is long-lived).
func (c *Client) handleOpenConnection(env *protocol.Envelope) {
	var oc protocol.OpenConnection
	if err := env.DecodePayload(&oc); err != nil {
		c.Log.Warn("clientcore: bad open_connection", "error", err)
		return
	}
	go func() {
		if err := c.tunnelClient.HandleOpenConnection(context.Background(), &oc); err != nil {
			c.Log.Warn("clientcore: data connection failed", "conn_id", oc.ConnID[:min(8, len(oc.ConnID))], "error", err)
		}
	}()
}

func (c *Client) takePending(seq uint64) chan *protocol.Envelope {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	ch := c.pending[seq]
	delete(c.pending, seq)
	return ch
}

// rpc sends a request frame and waits for the matching response (used by
// tunnel start/stop from the local control endpoint; the read loop owns
// the connection, so replies flow through the pending table).
func (c *Client) rpc(ctx context.Context, msgType string, req any) (*protocol.Envelope, error) {
	seq := c.nextSeq()
	ch := make(chan *protocol.Envelope, 1)
	c.pendingMu.Lock()
	c.pending[seq] = ch
	c.pendingMu.Unlock()
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		c.takePending(seq)
		return nil, fmt.Errorf("clientcore: not connected")
	}
	if err := conn.WriteFrame(msgType, seq, req); err != nil {
		c.takePending(seq)
		return nil, err
	}
	select {
	case env := <-ch:
		return env, nil
	case <-ctx.Done():
		c.takePending(seq)
		return nil, ctx.Err()
	}
}

func (c *Client) nextSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	return c.seq
}
