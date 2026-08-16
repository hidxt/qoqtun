package clientcore

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"sync/atomic"
	"time"
)

// State is the connection manager state (docs/conn-manager-state.md).
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateOnline       State = "online"
	StateDraining     State = "draining"
	StateStopped      State = "stopped"
)

// BackoffConfig controls reconnect timing (05-config-schema [reconnect]).
type BackoffConfig struct {
	Initial time.Duration
	Max     time.Duration
	Jitter  float64 // 0..1, applied as ±
}

// DefaultBackoff returns the documented defaults (1s, ×2 up to 60s, ±20%).
func DefaultBackoff() BackoffConfig {
	return BackoffConfig{Initial: time.Second, Max: 60 * time.Second, Jitter: 0.2}
}

// Manager drives the client connection lifecycle: it repeatedly establishes
// a session, classifies failures, and reconnects with backoff for temporary
// errors while permanent errors stop the loop (non-zero exit by the caller).
type Manager struct {
	// Session builds one control session (injected; the production one is
	// clientcore.Client.RunSession).
	Session func(ctx context.Context) error
	// Backoff is the reconnect schedule (injectable for tests).
	Backoff BackoffConfig
	// Now injects the clock (tests).
	Now func() time.Time
	Log *slog.Logger

	// OnStateChange is called on every state transition (tests/diagnostics).
	OnStateChange func(State)
	// OnReconnect is called after a successful reconnect (tests).
	OnReconnect func(attempt int)

	state atomic.Value // State
	// attempt counters
	attempts atomic.Int64

	// stop requests a graceful stop (e.g. from signal handling).
	stopCtx context.Context
	stop    context.CancelFunc
}

// State returns the current manager state.
func (m *Manager) State() State {
	v := m.state.Load()
	if v == nil {
		return StateDisconnected
	}
	return v.(State)
}

func (m *Manager) setState(s State) {
	m.state.Store(s)
	if m.OnStateChange != nil {
		m.OnStateChange(s)
	}
	if m.Log != nil {
		m.Log.Debug("conn manager state", "state", s)
	}
}

// Run executes the connection loop until ctx is cancelled or a permanent
// error occurs. It returns nil on graceful stop, or the permanent error.
func (m *Manager) Run(ctx context.Context) error {
	if m.Now == nil {
		m.Now = time.Now
	}
	if m.Backoff.Initial <= 0 {
		m.Backoff = DefaultBackoff()
	}
	m.stopCtx, m.stop = context.WithCancel(ctx)

	attempt := 0
	for {
		select {
		case <-m.stopCtx.Done():
			m.setState(StateStopped)
			return nil
		default:
		}
		attempt++
		m.attempts.Store(int64(attempt))
		m.setState(StateConnecting)

		err := Classify(m.Session(m.stopCtx))
		if err == nil || errors.Is(err, ErrGracefulShutdown) {
			// clean session end (graceful): stop without reconnecting
			m.setState(StateStopped)
			return nil
		}
		if IsPermanent(err) {
			m.setState(StateStopped)
			return err
		}
		m.setState(StateDisconnected)
		if m.OnReconnect != nil {
			m.OnReconnect(attempt)
		}
		// temporary: back off and retry (log sampling: every 5th attempt or
		// first, to avoid log storms during sustained outages)
		delay := m.backoffFor(attempt)
		if m.Log != nil && (attempt == 1 || attempt%5 == 0) {
			m.Log.Warn("reconnecting", "attempt", attempt, "delay", delay.Round(time.Millisecond), "error", err)
		}
		select {
		case <-m.stopCtx.Done():
			m.setState(StateStopped)
			return nil
		case <-time.After(delay):
		}
	}
}

// backoffFor computes initial*2^(n-1) capped at max, with ±jitter.
func (m *Manager) backoffFor(attempt int) time.Duration {
	base := m.Backoff.Initial
	for i := 1; i < attempt && base < m.Backoff.Max; i++ {
		base *= 2
		if base > m.Backoff.Max {
			base = m.Backoff.Max
		}
	}
	if base > m.Backoff.Max {
		base = m.Backoff.Max
	}
	jitter := m.Backoff.Jitter
	if jitter <= 0 {
		jitter = 0.2
	}
	delta := time.Duration(float64(base) * jitter * rand.Float64())
	// ± jitter, then re-clamp so the jitter never exceeds the max
	if rand.Intn(2) == 0 {
		base -= delta
	} else {
		base += delta
	}
	if base < time.Millisecond {
		base = time.Millisecond
	}
	if base > m.Backoff.Max {
		base = m.Backoff.Max
	}
	return base
}

// Stop requests a graceful stop (returns once the loop exits).
func (m *Manager) Stop() {
	if m.stop != nil {
		m.stop()
	}
}

// StopContext returns the manager stop context (for shutdown coordination).
func (m *Manager) StopContext() context.Context { return m.stopCtx }

// String renders the state for logs.
func (s State) String() string { return string(s) }
