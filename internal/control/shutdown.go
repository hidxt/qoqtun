package control

import (
	"context"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
	"github.com/hidxt/qoqtun/internal/tunnel"
)

// DefaultDrainTimeout bounds graceful drain of in-flight data connections
// (04-protocol-v1.md §3.8: 30s default).
const DefaultDrainTimeout = 30 * time.Second

// dataConnTracker tracks in-flight data connections for drain accounting.
type dataConnTracker struct {
	mu    sync.Mutex
	conns map[string]struct{} // conn_id
}

func newDataConnTracker() *dataConnTracker {
	return &dataConnTracker{conns: make(map[string]struct{})}
}

func (t *dataConnTracker) add(connID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[connID] = struct{}{}
}

func (t *dataConnTracker) done(connID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, connID)
}

func (t *dataConnTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// handleShutdownFromClient implements the graceful-close negotiation: the
// client initiates; the server removes its public listeners and lets the
// in-flight data connections drain (bounded), then closes the control conn.
func (s *Server) handleShutdownFromClient(conn *transport.Conn, m *tunnel.Manager, env *protocol.Envelope) {
	var req protocol.Shutdown
	if err := env.DecodePayload(&req); err != nil {
		req.DrainTimeoutMS = int(DefaultDrainTimeout / time.Millisecond)
	}
	s.Log.Info("shutdown requested by client", "client_id", conn.PeerID(), "reason", req.Reason)
	// 1. remove public listeners (no new connections)
	m.UnregisterAll()
	// 2. drain in-flight data connections (bounded)
	s.drainDataConns(time.Duration(req.DrainTimeoutMS) * time.Millisecond)
	s.Log.Info("shutdown complete", "client_id", conn.PeerID())
}

// drainDataConns waits for in-flight data connections up to the timeout and
// reports how many were force-closed (the control connection close in
// handleConn tears the rest down via the splice owners).
func (s *Server) drainDataConns(timeout time.Duration) {
	if timeout <= 0 {
		timeout = DefaultDrainTimeout
	}
	deadline := time.Now().Add(timeout)
	for s.dataConns.count() > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := s.dataConns.count(); n > 0 {
		s.Log.Warn("drain timeout, force-closing data connections", "remaining", n)
	}
}

// BroadcastShutdown asks every connected client to shut down gracefully and
// waits up to the drain timeout for their control connections to close.
// Used on server SIGINT/SIGTERM.
func (s *Server) BroadcastShutdown(ctx context.Context, reason string, drainTimeout time.Duration) {
	if drainTimeout <= 0 {
		drainTimeout = DefaultDrainTimeout
	}
	sh := &protocol.Shutdown{
		Reason:         reason,
		DrainTimeoutMS: int(drainTimeout / time.Millisecond),
	}
	for _, sess := range s.Sessions.All() {
		if sess.Conn != nil {
			if err := sess.Conn.WriteFrame(protocol.MsgShutdown, 0, sh); err != nil {
				s.Log.Warn("shutdown notify failed", "client_id", sess.ClientID, "error", err)
			}
		}
	}
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		if s.Sessions.Len() == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := s.Sessions.Len(); n > 0 {
		s.Log.Warn("shutdown drain timeout, force-closing remaining sessions", "count", n)
		for _, sess := range s.Sessions.All() {
			if sess.Conn != nil {
				_ = sess.Conn.Close()
			}
		}
	}
}
