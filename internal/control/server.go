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
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/session"
	"github.com/hidxt/qoqtun/internal/transport"
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

// handleConn drives one control connection through its lifecycle.
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
		// revocation is enforced at TLS handshake by serial; identity-level
		// guard here is defense in depth
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.NewError(protocol.ErrCodeAuthFailed, "client revoked", true))
		return
	}

	// handshake: read client_hello within the timeout
	_ = conn.SetDeadline(time.Now().Add(s.HandshakeTimeout))
	env, err := protocol.ReadFrame(conn)
	if err != nil {
		s.Log.Warn("control: handshake read failed", "ip", host, "error", err)
		return
	}
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
	readLoop(ctx, s, conn, sess)
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

// readLoop consumes control messages; Phase 5 wires tunnel/conn handling.
func readLoop(ctx context.Context, s *Server, conn *transport.Conn, sess *session.Session) {
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
		case protocol.MsgShutdown:
			return
		case protocol.MsgRegisterTunnel, protocol.MsgUnregisterTunnel, protocol.MsgCloseConnection:
			// Phase 5: tunnel registration and data connection management
			s.Log.Warn("control: message type not yet handled", "type", env.Type, "client_id", sess.ClientID)
		default:
			// unknown message type: ERR_PROTOCOL (recoverable per §8)
			_ = conn.WriteFrame(protocol.MsgError, env.Seq, protocol.ProtocolError("unknown message type"))
		}
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
