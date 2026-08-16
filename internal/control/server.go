// Package control implements the server-side control plane
// (04-protocol-v1.md §1/§2/§4): accept loop, handshake validation, policy
// delivery and heartbeat-driven session cleanup.
package control

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/session"
	"github.com/hidxt/qoqtun/internal/transport"
	"github.com/hidxt/qoqtun/internal/tunnel"
)

// Server is the control-plane listener.
type Server struct {
	Addr string
	// Transport options for the mTLS listener.
	CAs       []*x509.Certificate
	Cert, Key []byte
	IsRevoked func(serial string) bool

	// Cfg carries the resolved server config (policy + heartbeat).
	Cfg *config.ServerConfig
	Log *slog.Logger

	// MaxHalfOpen per IP caps unauthenticated connections (T5).
	MaxHalfOpen int
	// HandshakeTimeout bounds the whole hello exchange.
	HandshakeTimeout time.Duration

	Sessions *session.Registry

	// per-client tunnel managers (data-plane pairing).
	managersMu sync.Mutex
	managers   map[string]*tunnel.Manager

	halfOpen *halfOpenTracker
}

// halfOpenTracker caps simultaneous unauthenticated connections per IP.
type halfOpenTracker struct {
	mu    sync.Mutex
	perIP map[string]int
}

func newHalfOpen() *halfOpenTracker {
	return &halfOpenTracker{perIP: make(map[string]int)}
}

func (h *halfOpenTracker) tryAcquire(ip string, max int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := h.perIP[ip]; n >= max {
		return false
	}
	h.perIP[ip]++
	return true
}

func (h *halfOpenTracker) release(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := h.perIP[ip]; n <= 1 {
		delete(h.perIP, ip)
	} else {
		h.perIP[ip] = n - 1
	}
}

// Serve runs the accept loop until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln *transport.Listener) error {
	if s.MaxHalfOpen <= 0 {
		s.MaxHalfOpen = 8
	}
	if s.HandshakeTimeout <= 0 {
		s.HandshakeTimeout = 10 * time.Second
	}
	if s.halfOpen == nil {
		s.halfOpen = newHalfOpen()
	}
	if s.Sessions == nil {
		s.Sessions = session.NewRegistry()
	}
	if s.managers == nil {
		s.managers = make(map[string]*tunnel.Manager)
	}
	s.Log.Info("control listener started", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("control: accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// handleConn dispatches on the first frame:
//   - client_hello: control connection lifecycle (Phase 4);
//   - open_data:    a data connection claiming a conn_id (Phase 5).
func (s *Server) handleConn(ctx context.Context, conn *transport.Conn) {
	defer conn.Close()

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	if !s.halfOpen.tryAcquire(host, s.MaxHalfOpen) {
		s.Log.Warn("control: half-open limit exceeded", "ip", host)
		return
	}
	defer s.halfOpen.release(host)

	peerID := conn.PeerID()
	if peerID == "" {
		s.Log.Warn("control: connection without identity", "ip", host)
		return
	}
	if s.IsRevoked != nil && s.IsRevoked(peerID) {
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.NewError(protocol.ErrCodeAuthFailed, "client revoked", true))
		return
	}

	_ = conn.SetDeadline(time.Now().Add(s.HandshakeTimeout))
	env, err := protocol.ReadFrame(conn)
	if err != nil {
		s.Log.Warn("control: first frame read failed", "ip", host, "error", err)
		return
	}
	switch env.Type {
	case protocol.MsgOpenData:
		s.handleDataConn(ctx, conn, peerID, env)
	case protocol.MsgClientHello:
		s.handleControlConn(ctx, conn, host, peerID, env)
	default:
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.ProtocolError("expected client_hello or open_data"))
	}
}

// handleDataConn claims a pending public connection and splices it with the
// mTLS data connection. The data connection identity must equal the
// tunnel-owning client (data conn mTLS CN == control CN, §1).
func (s *Server) handleDataConn(ctx context.Context, conn *transport.Conn, peerID string, env *protocol.Envelope) {
	var od protocol.OpenData
	if err := env.DecodePayload(&od); err != nil {
		return
	}
	if err := protocol.ValidateOpenData(&od); err != nil {
		return
	}
	m := s.managerFor(peerID)
	if m == nil {
		_ = conn.Close()
		return
	}
	publicConn, _, err := m.ClaimData(od.ConnID)
	if err != nil {
		s.Log.Warn("control: data claim failed", "client_id", peerID, "error", err)
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	res := <-tunnel.Splice(publicConn, conn, 32*1024)
	s.Log.Info("data connection closed", "conn_id", od.ConnID[:min(8, len(od.ConnID))],
		"rx", res.BytesToA, "tx", res.BytesToB)
	// close_connection accounting hook (Phase 9 metrics wire here)
}

// handleControlConn is the original Phase 4 control lifecycle.
func (s *Server) handleControlConn(ctx context.Context, conn *transport.Conn, host, peerID string, env *protocol.Envelope) {
	if env.Type != protocol.MsgClientHello {
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.ProtocolError("expected client_hello"))
		return
	}
	var hello protocol.ClientHello
	if err := env.DecodePayload(&hello); err != nil {
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.ProtocolError(err.Error()))
		return
	}
	if err := protocol.ValidateClientHello(&hello); err != nil {
		_ = conn.WriteFrame(protocol.MsgError, 0, err)
		return
	}
	// identity is the certificate CN; the self-reported id must match
	if hello.ClientID != peerID {
		_ = conn.WriteFrame(protocol.MsgError, 0,
			protocol.NewError(protocol.ErrCodeAuthFailed, "client_id does not match certificate", true))
		return
	}
	if hello.ProtocolVersion != protocol.ProtocolVersion {
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.VersionUnsupportedError())
		return
	}

	// single control connection per client
	sess := &session.Session{ClientID: peerID, Conn: conn}
	if err := s.Sessions.Register(sess); err != nil {
		_ = conn.WriteFrame(protocol.MsgError, 0,
			protocol.NewError(protocol.ErrCodeAuthFailed, "client already connected", true))
		return
	}
	defer s.Sessions.Unregister(peerID)
	sess.Touch() // heartbeat supervisor starts from "now"
	// handshake done: clear the deadline; the heartbeat supervisor and
	// read-loop errors take over liveness detection
	_ = conn.SetDeadline(time.Time{})

	// per-client tunnel manager; cleaned up on disconnect
	m := s.managerFor(peerID)
	defer m.UnregisterAll()

	// server_hello with the full policy
	sh := protocol.ServerHello{
		SessionID: peerID + "-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		Policy:    policyFromConfig(s.Cfg),
		Heartbeat: heartbeatFromConfig(s.Cfg),
	}
	if err := conn.WriteFrame(protocol.MsgServerHello, 1, sh); err != nil {
		return
	}
	s.Log.Info("control: client online", "client_id", peerID, "ip", host, "name", hello.Name)

	// keep-alive: server kicks the session when no message arrives for
	// 2*interval + timeout (04-protocol-v1.md §4)
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go superviseHeartbeat(heartbeatCtx, s, conn, sess, sh.Heartbeat)

	_ = conn.SetDeadline(time.Time{})
	readLoop(ctx, s, conn, sess, m)
}

// superviseHeartbeat closes the connection when the client goes silent.
func superviseHeartbeat(ctx context.Context, s *Server, conn *transport.Conn, sess *session.Session, hb protocol.Heartbeat) {
	timeout := time.Duration(2*hb.IntervalS+hb.TimeoutS) * time.Second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(sess.LastActive()) > timeout {
				s.Log.Warn("control: heartbeat timeout, kicking session",
					"client_id", sess.ClientID, "idle", time.Since(sess.LastActive()).Round(time.Second))
				_ = conn.Close()
				return
			}
		}
	}
}

// readLoop consumes control messages and manages tunnels.
func readLoop(ctx context.Context, s *Server, conn *transport.Conn, sess *session.Session, m *tunnel.Manager) {
	for {
		env, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		sess.Touch()
		switch env.Type {
		case protocol.MsgPing:
			var p protocol.Ping
			if err := env.DecodePayload(&p); err == nil {
				_ = conn.WriteFrame(protocol.MsgPong, env.Seq, protocol.Pong{Echo: p.Echo})
			}
		case protocol.MsgRegisterTunnel:
			s.handleRegisterTunnel(ctx, conn, sess, m, env)
		case protocol.MsgUnregisterTunnel:
			s.handleUnregisterTunnel(conn, m, env)
		case protocol.MsgCloseConnection:
			// accounting handled at the splice owner; ignore here
		case protocol.MsgShutdown:
			return
		default:
			// unknown message type: ERR_PROTOCOL (recoverable per §8)
			_ = conn.WriteFrame(protocol.MsgError, env.Seq, protocol.ProtocolError("unknown message type"))
		}
	}
}

// handleRegisterTunnel validates and registers a tunnel, replying with the
// assigned tunnel id and effective port.
func (s *Server) handleRegisterTunnel(ctx context.Context, conn *transport.Conn, sess *session.Session, m *tunnel.Manager, env *protocol.Envelope) {
	var req protocol.RegisterTunnel
	if err := env.DecodePayload(&req); err != nil {
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: protocol.ProtocolError(err.Error()),
		})
		return
	}
	if err := protocol.ValidateRegisterTunnel(&req); err != nil {
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: protocolErrToMsg(err),
		})
		return
	}
	policy := policyFromConfig(s.Cfg)
	onOpen := func(t *tunnel.Tunnel, publicConn net.Conn) {
		connID, err := m.OpenConnection(t, publicConn, 10*time.Second)
		if err != nil {
			_ = publicConn.Close()
			return
		}
		host, _, _ := net.SplitHostPort(publicConn.RemoteAddr().String())
		_ = conn.WriteFrame(protocol.MsgOpenConnection, 0, &protocol.OpenConnection{
			ConnID:     connID,
			TunnelID:   t.ID,
			SrcAddr:    host,
			DeadlineMS: 10000,
		})
	}
	t, err := m.Register(ctx, req.Name, req.Type, req.RemotePort,
		policy.AllowedPorts, policy.MaxTunnels, onOpen)
	resp := &protocol.RegisterTunnelResp{}
	if err != nil {
		resp.Error = &protocol.Error{Code: mapRegisterErr(err), Message: err.Error()}
	} else {
		resp.TunnelID = t.ID
		resp.OK = true
		resp.Effective = &protocol.Effective{RemotePort: t.RemotePort}
	}
	_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, resp)
}

func (s *Server) handleUnregisterTunnel(conn *transport.Conn, m *tunnel.Manager, env *protocol.Envelope) {
	var req protocol.UnregisterTunnel
	if err := env.DecodePayload(&req); err != nil {
		return
	}
	m.Unregister(req.TunnelID)
	_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
		TunnelID: req.TunnelID,
		OK:       true,
	})
}

// managerFor returns (creating if needed) the per-client tunnel manager.
func (s *Server) managerFor(clientID string) *tunnel.Manager {
	s.managersMu.Lock()
	defer s.managersMu.Unlock()
	m, ok := s.managers[clientID]
	if !ok {
		m = tunnel.NewManager(s.Log)
		s.managers[clientID] = m
	}
	return m
}

// Managers returns a snapshot of the per-client tunnel managers
// (diagnostics/tests).
func (s *Server) Managers() []*tunnel.Manager {
	s.managersMu.Lock()
	defer s.managersMu.Unlock()
	out := make([]*tunnel.Manager, 0, len(s.managers))
	for _, m := range s.managers {
		out = append(out, m)
	}
	return out
}

// protocolErrToMsg converts a validator *protocol.Error (which may be an
// *Error) into a message payload.
func protocolErrToMsg(err error) *protocol.Error {
	if pe, ok := err.(*protocol.Error); ok {
		return pe
	}
	return protocol.NewError(protocol.ErrCodeProtocol, err.Error(), true)
}

// mapRegisterErr translates tunnel registration errors to protocol codes.
func mapRegisterErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not allowed"):
		return protocol.ErrCodePortNotAllowed
	case strings.Contains(msg, "already in use"):
		return protocol.ErrCodePortInUse
	case strings.Contains(msg, "tunnel limit"):
		return protocol.ErrCodeTunnelLimit
	case strings.Contains(msg, "invalid"):
		return protocol.ErrCodeNameInvalid
	default:
		return protocol.ErrCodeInternal
	}
}

func policyFromConfig(cfg *config.ServerConfig) protocol.Policy {
	if cfg == nil {
		return protocol.Policy{}
	}
	return protocol.Policy{
		AllowedPorts:   cfg.Policy.AllowedPorts,
		MaxTunnels:     cfg.Policy.MaxTunnelsPerClient,
		MaxConns:       cfg.Policy.MaxConnsPerClient,
		BandwidthBPS:   cfg.Policy.BandwidthBpsPerClient,
		AllowedTargets: cfg.Policy.AllowedTargets,
		UDP: protocol.UDPPolicy{
			MaxSessions:        cfg.Policy.UDPMaxSessionsPerTunnel,
			MaxPacket:          cfg.Policy.UDPMaxPacket,
			SessionIdleTimeout: cfg.Policy.UDPSessionIdleTimeout,
		},
	}
}

func heartbeatFromConfig(cfg *config.ServerConfig) protocol.Heartbeat {
	if cfg == nil {
		return protocol.Heartbeat{IntervalS: 15, TimeoutS: 10, MissThreshold: 2}
	}
	return protocol.Heartbeat{IntervalS: cfg.Heartbeat.IntervalS, TimeoutS: cfg.Heartbeat.TimeoutS, MissThreshold: cfg.Heartbeat.MissThreshold}
}
