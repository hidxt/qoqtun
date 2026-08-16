package control

import (
	"fmt"
	"net"

	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/security"
	"github.com/hidxt/qoqtun/internal/tunnel"
	"golang.org/x/time/rate"
)

// security wiring: per-client / per-tunnel connection quotas, bandwidth
// buckets, registration-frequency limiters and the per-IP gate for public
// listeners. All maps are keyed by clientID / tunnelID, created on first
// use and dropped on disconnect (no unbounded growth).

// rate limits (control plane)
const (
	registerRatePerSec = 5.0   // register/unregister per client
	registerBurst      = 32    // a reconnect re-registers all tunnels at once
	ctrlMsgRatePerSec  = 200.0 // per control connection
	ctrlMsgBurst       = 400
)

func (s *Server) clientSemaphore(clientID string) *security.Semaphore {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	sem, ok := s.clientSem[clientID]
	if !ok {
		sem = security.NewSemaphore(s.policy.MaxConns)
		s.clientSem[clientID] = sem
	}
	return sem
}

func (s *Server) tunnelSemaphore(tunnelID string) *security.Semaphore {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	sem, ok := s.tunnelSem[tunnelID]
	if !ok {
		sem = security.NewSemaphore(s.policy.MaxConnsTunnel)
		s.tunnelSem[tunnelID] = sem
	}
	return sem
}

func (s *Server) clientBucket(clientID string) *security.TokenBucket {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	b, ok := s.clientBW[clientID]
	if !ok {
		b = security.NewTokenBucket(s.policy.BandwidthBPS)
		s.clientBW[clientID] = b
	}
	return b
}

func (s *Server) tunnelBucket(tunnelID string) *security.TokenBucket {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	b, ok := s.tunnelBW[tunnelID]
	if !ok {
		b = security.NewTokenBucket(s.policy.BandwidthTunnelBPS)
		s.tunnelBW[tunnelID] = b
	}
	return b
}

func (s *Server) registerLimiter(clientID string) *rate.Limiter {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	l, ok := s.regLim[clientID]
	if !ok {
		l = rate.NewLimiter(registerRatePerSec, registerBurst)
		s.regLim[clientID] = l
	}
	return l
}

// acquireDataQuota grabs the per-client and per-tunnel connection slots;
// false when either is exhausted (fail-fast, no queuing).
func (s *Server) acquireDataQuota(clientID, tunnelID string) bool {
	if !s.clientSemaphore(clientID).TryAcquire() {
		return false
	}
	if !s.tunnelSemaphore(tunnelID).TryAcquire() {
		s.clientSemaphore(clientID).Release()
		return false
	}
	return true
}

// releaseDataQuota returns the slots for a finished data connection.
func (s *Server) releaseDataQuota(clientID, tunnelID string) {
	s.tunnelSemaphore(tunnelID).Release()
	s.clientSemaphore(clientID).Release()
}

// checkRegisterRate enforces the per-client register/unregister frequency.
func (s *Server) checkRegisterRate(clientID string) bool {
	return s.registerLimiter(clientID).Allow()
}

// checkTargetAllowed enforces allowed_targets server-side at registration:
// the client-declared local origin must be in the policy allow-list
// (fail-closed: unparsable entries deny). The client dials the same check
// before connecting (defense in depth, T6).
func (s *Server) checkTargetAllowed(local protocol.LocalTarget) error {
	if len(s.policy.AllowedTargets) == 0 {
		return fmt.Errorf("local target not allowed by policy")
	}
	ip := net.ParseIP(local.IP)
	if ip == nil {
		// hostnames are resolved client-side and the resolved IP is what
		// the client dials; the ACL only admits IP literals/CIDRs, so a
		// hostname declaration is denied — the client re-checks the
		// resolved address before dialing (defense in depth, T6).
		return fmt.Errorf("local target hostname not allowed: %s", local.IP)
	}
	if !tunnel.TargetsAllow(s.policy.AllowedTargets, ip, local.Port) {
		return fmt.Errorf("local target %s:%d not allowed by policy", local.IP, local.Port)
	}
	return nil
}

// cleanupSecurity drops all per-client state on disconnect.
func (s *Server) cleanupSecurity(clientID string) {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	delete(s.clientSem, clientID)
	delete(s.clientBW, clientID)
	delete(s.regLim, clientID)
	// tunnel-semaphores/buckets are owned by the manager; they are removed
	// when the manager is dropped by the disconnect path (tunnelTeardown).
}

// tunnelTeardown removes per-tunnel security state (invoked on unregister
// and on manager teardown).
func (s *Server) tunnelTeardown(tunnelID string) {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	delete(s.tunnelSem, tunnelID)
	delete(s.tunnelBW, tunnelID)
}

// newCtrlMsgLimiter bounds the control-message rate of one connection
// (flood of messages is answered with ERR_RATE_LIMITED and a disconnect).
func newCtrlMsgLimiter() *rate.Limiter {
	return rate.NewLimiter(ctrlMsgRatePerSec, ctrlMsgBurst)
}
