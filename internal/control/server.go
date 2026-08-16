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
	"github.com/hidxt/qoqtun/internal/metrics"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/security"
	"github.com/hidxt/qoqtun/internal/session"
	"github.com/hidxt/qoqtun/internal/transport"
	"github.com/hidxt/qoqtun/internal/tunnel"
	"golang.org/x/time/rate"
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

	// UDP limits applied to per-client tunnel managers (tests shrink).
	UDPIdleTimeout time.Duration
	UDPMaxSessions int
	UDPMaxPacket   int

	// VhostPort is the shared HTTP Host-routing port (0 = disabled; http
	// tunnels then degrade to dedicated ports).
	VhostPort int
	vhost     *tunnel.VhostTable
	vhostLn   net.Listener
	vhostMu   sync.Mutex
	vhostRefs int

	// security machinery (Phase 9, T6/T7/T9/T10).
	policy    protocol.Policy // resolved policy (from Cfg at Serve start)
	polMu     sync.Mutex
	clientSem map[string]*security.Semaphore   // per-client conn quota
	tunnelSem map[string]*security.Semaphore   // per-tunnel conn quota
	clientBW  map[string]*security.TokenBucket // per-client bandwidth
	tunnelBW  map[string]*security.TokenBucket // per-tunnel bandwidth
	regLim    map[string]*rate.Limiter         // per-client register rate
	ipGate    *security.IPGate                 // per public-IP conn gate

	// IP gate tunables (defaults suit production; tests raise them).
	IPGateMaxConns   int
	IPGateRatePerSec float64

	// Metrics collects local traffic statistics (Phase 10); nil disables.
	Metrics *metrics.Registry

	Sessions *session.Registry

	// per-client tunnel managers (data-plane pairing).
	managersMu sync.Mutex
	managers   map[string]*tunnel.Manager

	// dataConns tracks in-flight data connections for drain accounting.
	dataConns *dataConnTracker

	// port reservations (port -> clientID) so a reconnecting client can
	// reclaim its ports within a short window (Phase 6; 60s TTL).
	reserveMu    sync.Mutex
	reservations map[int]reservation

	halfOpen *halfOpenTracker
}

// reservation is a temporary port hold for a disconnected client.
type reservation struct {
	clientID string
	until    time.Time
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
	if s.dataConns == nil {
		s.dataConns = newDataConnTracker()
	}
	if s.reservations == nil {
		s.reservations = make(map[int]reservation)
	}
	if s.vhost == nil {
		s.vhost = tunnel.NewVhostTable()
	}
	if s.policy.AllowedPorts == nil {
		s.policy = policyFromConfig(s.Cfg)
	}
	if s.clientSem == nil {
		s.clientSem = make(map[string]*security.Semaphore)
	}
	if s.tunnelSem == nil {
		s.tunnelSem = make(map[string]*security.Semaphore)
	}
	if s.clientBW == nil {
		s.clientBW = make(map[string]*security.TokenBucket)
	}
	if s.tunnelBW == nil {
		s.tunnelBW = make(map[string]*security.TokenBucket)
	}
	if s.regLim == nil {
		s.regLim = make(map[string]*rate.Limiter)
	}
	if s.Metrics == nil {
		s.Metrics = metrics.NewRegistry()
	}
	if s.ipGate == nil {
		maxConns := s.IPGateMaxConns
		if maxConns <= 0 {
			maxConns = 16
		}
		ratePerSec := s.IPGateRatePerSec
		if ratePerSec <= 0 {
			ratePerSec = 20
		}
		s.ipGate = security.NewIPGate(maxConns, ratePerSec)
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
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}

	peerID := conn.PeerID()
	if peerID == "" {
		s.Log.Warn("control: connection without identity", "ip", host)
		_ = conn.Close()
		return
	}
	if s.IsRevoked != nil && s.IsRevoked(peerID) {
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.NewError(protocol.ErrCodeAuthFailed, "client revoked", true))
		_ = conn.Close()
		return
	}

	_ = conn.SetDeadline(time.Now().Add(s.HandshakeTimeout))
	env, err := protocol.ReadFrame(conn)
	if err != nil {
		s.Log.Warn("control: first frame read failed", "ip", host, "error", err)
		_ = conn.Close()
		return
	}
	switch env.Type {
	case protocol.MsgOpenData:
		// data connections own their lifecycle (splice closeBoth / UDP
		// channel ownership); handleConn must not close them here.
		// The half-open cap bounds only control-plane hello floods (T9);
		// data connections are already mTLS-authenticated and must never
		// be throttled by it.
		s.handleDataConn(ctx, conn, peerID, env)
	case protocol.MsgClientHello:
		// control-plane half-open cap: bounds concurrent hello floods
		// (authenticated but not yet validated) per source IP
		if !s.halfOpen.tryAcquire(host, s.MaxHalfOpen) {
			s.Log.Warn("control: half-open limit exceeded", "ip", host)
			_ = conn.Close()
			return
		}
		defer s.halfOpen.release(host)
		defer conn.Close() // control connection owned by this goroutine
		s.handleControlConn(ctx, conn, host, peerID, env)
	default:
		_ = conn.WriteFrame(protocol.MsgError, 0, protocol.ProtocolError("expected client_hello or open_data"))
		_ = conn.Close()
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
	publicConn, t, err := m.ClaimData(od.ConnID)
	if err != nil {
		s.Log.Warn("control: data claim failed", "client_id", peerID, "error", err)
		_ = conn.Close()
		return
	}
	// UDP tunnels use the connection as a persistent channel, not a splice.
	if t.Type == "udp" {
		if publicConn != nil {
			_ = publicConn.Close() // not used for UDP (session table only)
		}
		_ = conn.SetDeadline(time.Time{})
		if !s.acquireDataQuota(peerID, t.ID) {
			s.Log.Warn("udp channel quota exceeded", "client_id", peerID, "tunnel", t.ID)
			_ = conn.Close()
			return
		}
		if s.Metrics != nil {
			s.Metrics.ConnOpened(peerID, t.ID)
		}
		m := s.managerFor(peerID)
		m.SetUDPChannel(ctx, t, security.NewRateLimitedConn(conn,
			s.clientBucket(peerID), s.tunnelBucket(t.ID)))
		return
	}
	s.dataConns.add(od.ConnID)
	defer s.dataConns.done(od.ConnID)
	// release the per-client/per-tunnel quota held by the public side
	// (acquired in onOpen / handleVhostConn)
	defer s.releaseDataQuota(peerID, t.ID)
	_ = conn.SetDeadline(time.Time{})
	// the public side may carry a claim deadline (vhost replay conns got a
	// 10s claim timeout in OpenConnection); the splice owns liveness now
	if publicConn != nil {
		_ = publicConn.SetDeadline(time.Time{})
	}
	res := <-tunnel.Splice(publicConn, conn, 32*1024)
	s.Log.Info("data connection closed", "conn_id", od.ConnID[:min(8, len(od.ConnID))],
		"rx", res.BytesToA, "tx", res.BytesToB)
	// metrics: rx = bytes to public side (client read), tx = bytes from
	// public side; the vhost replay prefix is counted by the splice too
	if s.Metrics != nil {
		s.Metrics.RecordConn(peerID, t.ID, res.BytesToB, res.BytesToA)
	}
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

	// single control connection per client: a duplicate client_id kicks the
	// old session (new session wins, audit logged; 04 §1 one control conn).
	sess := &session.Session{ClientID: peerID, Conn: conn}
	if err := s.Sessions.Register(sess); err != nil {
		if old, ok := s.Sessions.Get(peerID); ok {
			s.Log.Warn("duplicate client_id: kicking old session", "client_id", peerID)
			// send a fatal error first so the old client stops reconnecting
			// (prevents kick ping-pong between two live processes)
			if old.Conn != nil {
				_ = old.Conn.WriteFrame(protocol.MsgError, 0,
					protocol.NewError(protocol.ErrCodeAuthFailed, "replaced by a newer session", true))
				_ = old.Conn.Close()
			}
			s.Sessions.Unregister(peerID)
			if err2 := s.Sessions.Register(sess); err2 != nil {
				_ = conn.WriteFrame(protocol.MsgError, 0,
					protocol.NewError(protocol.ErrCodeAuthFailed, "client already connected", true))
				return
			}
		} else {
			_ = conn.WriteFrame(protocol.MsgError, 0,
				protocol.NewError(protocol.ErrCodeAuthFailed, "client already connected", true))
			return
		}
	}
	defer s.Sessions.Unregister(peerID)
	sess.Touch() // heartbeat supervisor starts from "now"
	// handshake done: clear the deadline; the heartbeat supervisor and
	// read-loop errors take over liveness detection
	_ = conn.SetDeadline(time.Time{})

	// per-client tunnel manager; cleaned up on disconnect with port
	// reservations so a reconnecting client can reclaim its ports.
	m := s.managerFor(peerID)
	defer func() {
		for _, port := range m.Ports() {
			s.reservePort(port, peerID, 60*time.Second)
		}
		// release every vhost host this client held (unregister goes
		// through the same path on clean teardown)
		for _, t := range m.Tunnels() {
			if t.VhostHost != "" {
				s.vhost.UnregisterTunnel(t.ID)
			}
			s.tunnelTeardown(t.ID)
		}
		s.stopVhost()
		s.cleanupSecurity(peerID)
		m.UnregisterAll()
	}()

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
	msgLim := newCtrlMsgLimiter()
	for {
		env, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		sess.Touch()
		// per-connection control-message flood guard (T9): over the cap the
		// connection is dropped with ERR_RATE_LIMITED
		if !msgLim.Allow() {
			s.Log.Warn("control message rate exceeded", "client_id", sess.ClientID)
			_ = conn.WriteFrame(protocol.MsgError, env.Seq,
				protocol.NewError(protocol.ErrCodeRateLimited, "control message rate exceeded", true))
			return
		}
		switch env.Type {
		case protocol.MsgPing:
			var p protocol.Ping
			if err := env.DecodePayload(&p); err == nil {
				_ = conn.WriteFrame(protocol.MsgPong, env.Seq, protocol.Pong{Echo: p.Echo})
			}
		case protocol.MsgRegisterTunnel:
			s.handleRegisterTunnel(ctx, conn, sess, m, env)
		case protocol.MsgUnregisterTunnel:
			s.handleUnregisterTunnel(conn, m, sess, env)
		case protocol.MsgCloseConnection:
			// accounting handled at the splice owner; ignore here
		case protocol.MsgShutdown:
			s.handleShutdownFromClient(conn, m, env)
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
	// per-client register/unregister frequency (T9)
	if !s.checkRegisterRate(sess.ClientID) {
		s.Log.Warn("register rate limited", "client_id", sess.ClientID, "name", req.Name)
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodeRateLimited, Message: "register frequency exceeded"},
		})
		return
	}
	// server-side allowed_targets enforcement at registration (T6):
	// the client-declared local origin must be inside the policy allow-list
	if err := s.checkTargetAllowed(req.Local); err != nil {
		s.Log.Warn("target not allowed", "client_id", sess.ClientID, "name", req.Name, "error", err)
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodeTargetNotAllowed, Message: err.Error()},
		})
		return
	}
	// HTTP vhost mode: shared port + Host routing (remote_port == 0).
	if req.Type == "http" && req.RemotePort == 0 && req.HTTP != nil && req.HTTP.Host != "" {
		s.handleRegisterVhost(ctx, conn, sess, m, env, &req)
		return
	}
	if err := s.checkPortArbitration(req.RemotePort, sess.ClientID); err != nil {
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodePortInUse, Message: err.Error()},
		})
		return
	}
	policy := policyFromConfig(s.Cfg)
	onOpen := func(t *tunnel.Tunnel, publicConn net.Conn) {
		// per public-IP front-line gate (T9): rate + concurrency
		ip, _, _ := net.SplitHostPort(publicConn.RemoteAddr().String())
		if !s.ipGate.Allow(ip) {
			s.Log.Warn("public conn per-IP limit", "ip", ip, "tunnel", t.ID)
			_ = publicConn.Close()
			return
		}
		defer s.ipGate.Release(ip)
		// per-client + per-tunnel concurrency quotas (T9): fail-fast
		if !s.acquireDataQuota(sess.ClientID, t.ID) {
			s.Log.Warn("connection quota exceeded", "client_id", sess.ClientID, "tunnel", t.ID)
			_ = publicConn.Close()
			return
		}
		if s.Metrics != nil {
			s.Metrics.ConnOpened(sess.ClientID, t.ID)
		}
		// bandwidth shaping: per-client + per-tunnel token buckets
		// (release happens at the splice owner, handleDataConn)
		wrapped := security.NewRateLimitedConn(publicConn,
			s.clientBucket(sess.ClientID), s.tunnelBucket(t.ID))
		connID, err := m.OpenConnection(t, wrapped, 10*time.Second)
		if err != nil {
			s.releaseDataQuota(sess.ClientID, t.ID)
			_ = wrapped.Close()
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
	// UDP tunnels need a persistent data channel: pre-open it AFTER the
	// register response (the client's registration is synchronous; an early
	// open_connection would be misread as the response).
	if resp.OK && req.Type == "udp" {
		connID, oerr := m.OpenConnection(t, nil, 10*time.Second)
		if oerr == nil {
			_ = conn.WriteFrame(protocol.MsgOpenConnection, 0, &protocol.OpenConnection{
				ConnID: connID, TunnelID: t.ID, Transport: "udp", DeadlineMS: 10000,
			})
		}
	}
}

// handleRegisterVhost registers an HTTP tunnel on the shared vhost port:
// normalize + conflict-check the host, register the routing entry, then
// start the shared listener (refcounted). The response carries the shared
// port as the effective public port.
func (s *Server) handleRegisterVhost(ctx context.Context, conn *transport.Conn, sess *session.Session, m *tunnel.Manager, env *protocol.Envelope, req *protocol.RegisterTunnel) {
	host, err := tunnel.NormalizeHostName(req.HTTP.Host)
	if err != nil {
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodeNameInvalid, Message: "invalid http.host: " + err.Error()},
		})
		return
	}
	policy := policyFromConfig(s.Cfg)
	t, err := m.AddVhostTunnel(ctx, req.Name, host, policy.MaxTunnels)
	if err != nil {
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: mapRegisterErr(err), Message: err.Error()},
		})
		return
	}
	if err := s.vhost.Register(host, t.ID, sess.ClientID); err != nil {
		m.Unregister(t.ID)
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodeNameConflict, Message: "http.host already registered: " + host},
		})
		return
	}
	if err := s.startVhost(ctx); err != nil {
		s.vhost.UnregisterTunnel(t.ID)
		m.Unregister(t.ID)
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodeInternal, Message: err.Error()},
		})
		return
	}
	_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
		TunnelID:  t.ID,
		OK:        true,
		Effective: &protocol.Effective{RemotePort: s.VhostPort},
	})
}

func (s *Server) handleUnregisterTunnel(conn *transport.Conn, m *tunnel.Manager, sess *session.Session, env *protocol.Envelope) {
	var req protocol.UnregisterTunnel
	if err := env.DecodePayload(&req); err != nil {
		return
	}
	if !s.checkRegisterRate(sess.ClientID) {
		_ = conn.WriteFrame(protocol.MsgRegisterTunnelResp, env.Seq, &protocol.RegisterTunnelResp{
			Error: &protocol.Error{Code: protocol.ErrCodeRateLimited, Message: "unregister frequency exceeded"},
		})
		return
	}
	if t, ok := m.TunnelByID(req.TunnelID); ok && t.VhostHost != "" {
		s.vhost.UnregisterTunnel(req.TunnelID)
		s.stopVhost()
	}
	s.tunnelTeardown(req.TunnelID)
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
		m.UDPIdleTimeout = s.UDPIdleTimeout
		m.UDPMaxSessions = s.UDPMaxSessions
		m.UDPMaxPacket = s.UDPMaxPacket
		m.OnUDPStats = func(tunnelID string, rx, tx int64) {
			if s.Metrics != nil {
				s.Metrics.RecordUDP(clientID, tunnelID, rx, tx)
			}
		}
		m.OnUDPChannelClosed = func(t *tunnel.Tunnel) {
			// release the quota held for this channel, then pre-open a
			// replacement (Phase 6 reconnect path)
			s.releaseDataQuota(clientID, t.ID)
			sess, ok := s.Sessions.Get(clientID)
			if !ok || sess.Conn == nil {
				return
			}
			connID, err := m.OpenConnection(t, nil, 10*time.Second)
			if err != nil {
				return
			}
			_ = sess.Conn.WriteFrame(protocol.MsgOpenConnection, 0, &protocol.OpenConnection{
				ConnID: connID, TunnelID: t.ID, Transport: "udp", DeadlineMS: 10000,
			})
		}
		s.managers[clientID] = m
	}
	return m
}

// reservePort holds a port for a disconnected client for ttl.
func (s *Server) reservePort(port int, clientID string, ttl time.Duration) {
	s.reserveMu.Lock()
	defer s.reserveMu.Unlock()
	s.reservations[port] = reservation{clientID: clientID, until: time.Now().Add(ttl)}
}

// checkPortArbitration rejects a port held by another client's reservation
// (the owning client may reclaim it). Expired reservations are dropped.
func (s *Server) checkPortArbitration(port int, clientID string) error {
	s.reserveMu.Lock()
	defer s.reserveMu.Unlock()
	now := time.Now()
	for p, r := range s.reservations {
		if now.After(r.until) {
			delete(s.reservations, p)
		}
	}
	if r, ok := s.reservations[port]; ok {
		if r.clientID != clientID {
			return fmt.Errorf("remote port %d reserved by another client", port)
		}
		// own reservation: reclaim and clear
		delete(s.reservations, port)
	}
	return nil
}

// StatusSnapshot is a point-in-time view for `server status`.
type StatusSnapshot struct {
	Sessions    int
	TunnelCount int
	VhostHosts  int
	ActiveConns int64
	Metrics     metrics.Snapshot
}

// Status returns a copy of the server's local state (V1: local query only).
func (s *Server) Status() StatusSnapshot {
	conns := int64(0)
	if s.Metrics != nil {
		conns = s.Metrics.Snapshot().GlobalConns
	}
	sn := StatusSnapshot{
		Sessions:    s.Sessions.Len(),
		VhostHosts:  s.VhostCount(),
		ActiveConns: conns,
	}
	for _, m := range s.Managers() {
		sn.TunnelCount += m.TunnelCount()
	}
	if s.Metrics != nil {
		sn.Metrics = s.Metrics.Snapshot()
	}
	return sn
}

// SetPolicyForTests overrides the resolved policy (integration tests only;
// production resolves it from the config at Serve start).
func (s *Server) SetPolicyForTests(p protocol.Policy) {
	s.policy = p
}

// VhostCount returns the number of hosts in the vhost routing table
// (diagnostics/tests).
func (s *Server) VhostCount() int {
	if s.vhost == nil {
		return 0
	}
	return s.vhost.Count()
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
