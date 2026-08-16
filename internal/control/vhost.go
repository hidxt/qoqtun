package control

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/security"
	"github.com/hidxt/qoqtun/internal/tunnel"
)

// vhost listener lifecycle: refcounted. The shared http_vhost_port listener
// starts with the first vhost tunnel registration and stops when the last
// vhost tunnel goes away (04 §7: one shared port, Host-routed).

func (s *Server) startVhost(ctx context.Context) error {
	s.vhostMu.Lock()
	defer s.vhostMu.Unlock()
	s.vhostRefs++
	if s.vhostLn != nil {
		return nil
	}
	if s.VhostPort <= 0 {
		s.vhostRefs--
		return fmt.Errorf("control: http_vhost_port not configured")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.VhostPort))
	if err != nil {
		s.vhostRefs--
		return fmt.Errorf("control: vhost listen on %d: %w", s.VhostPort, err)
	}
	s.vhostLn = ln
	s.Log.Info("http vhost listener started", "port", s.VhostPort)
	go s.vhostAcceptLoop(ctx, ln)
	return nil
}

func (s *Server) stopVhost() {
	s.vhostMu.Lock()
	defer s.vhostMu.Unlock()
	if s.vhostRefs > 0 {
		s.vhostRefs--
	}
	if s.vhostRefs <= 0 && s.vhostLn != nil {
		_ = s.vhostLn.Close()
		s.vhostLn = nil
		s.Log.Info("http vhost listener stopped")
	}
}

func (s *Server) vhostAcceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// listener closed (stopVhost) or fatal; nothing to recover
			return
		}
		go s.handleVhostConn(ctx, conn)
	}
}

// handleVhostConn sniffs the Host of an incoming vhost request, routes it to
// the owning tunnel, and hands the replay-wrapped connection to the pending
// table. Ownership of the connection transfers to the data path (splice);
// this goroutine never closes it.
func (s *Server) handleVhostConn(ctx context.Context, raw net.Conn) {
	_ = raw.SetReadDeadline(time.Now().Add(tunnel.SniffTimeout))
	res, err := tunnel.SniffHost(raw, tunnel.MaxSniffBytes)
	if err != nil {
		tunnel.WriteHTTPError(raw, 400, "Bad Request")
		_ = raw.Close()
		return
	}
	tunnelID, clientID, ok := s.vhost.Lookup(res.Host)
	if !ok {
		tunnel.WriteHTTPError(raw, 421, "Misdirected Request")
		_ = raw.Close()
		return
	}
	m := s.managerFor(clientID)
	t, ok := m.TunnelByID(tunnelID)
	if !ok || t == nil {
		tunnel.WriteHTTPError(raw, 503, "Tunnel Unavailable")
		_ = raw.Close()
		return
	}
	_ = raw.SetReadDeadline(time.Time{}) // sniff done; splice owns liveness
	// replay the consumed head verbatim, then pure byte passthrough
	replay := tunnel.NewReplayConn(raw, res.Prefix, bufio.NewReader(res.Rest))
	// per-client + per-tunnel quotas and bandwidth shaping (T9)
	if !s.acquireDataQuota(clientID, t.ID) {
		s.Log.Warn("vhost connection quota exceeded", "client_id", clientID, "tunnel", t.ID)
		tunnel.WriteHTTPError(raw, 503, "Tunnel Busy")
		_ = replay.Close()
		return
	}
	wrapped := security.NewRateLimitedConn(replay, s.clientBucket(clientID), s.tunnelBucket(t.ID))
	connID, err := m.OpenConnection(t, wrapped, 10*time.Second)
	if err != nil {
		s.releaseDataQuota(clientID, t.ID)
		tunnel.WriteHTTPError(raw, 503, "Tunnel Busy")
		_ = wrapped.Close()
		return
	}
	sess, ok := s.Sessions.Get(clientID)
	if !ok || sess.Conn == nil {
		_ = replay.Close()
		return
	}
	_ = sess.Conn.WriteFrame(protocol.MsgOpenConnection, 0, &protocol.OpenConnection{
		ConnID:     connID,
		TunnelID:   tunnelID,
		SrcAddr:    "http",
		DeadlineMS: 10000,
	})
	// pending table owns the connection now; the client's open_data will
	// claim it and splice (or the 10s claim deadline closes it).
}
