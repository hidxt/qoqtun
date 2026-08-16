// Package session maintains the server-side connection registry:
// client_id -> Session with thread-safe register/unregister/enumerate and
// resource-count hooks reserved for Phase 9 limits.
package session

import (
	"errors"
	"sync"
	"time"
)

// ErrExists is returned when a client_id is already registered.
var ErrExists = errors.New("session: client already connected")

// ControlConn is the minimal control-connection surface a session needs
// (duck-typed; *transport.Conn satisfies it without an import).
type ControlConn interface {
	PeerID() string
	WriteFrame(msgType string, seq uint64, payload any) error
	Close() error
}

// Session tracks one connected client.
type Session struct {
	ClientID string
	Conn     ControlConn

	mu         sync.Mutex
	tunnels    int
	conns      int
	lastActive int64 // unix nanoseconds, updated on any activity
}

// Touch records client activity (called on every received control message).
func (s *Session) Touch() {
	now := time.Now().UnixNano()
	s.mu.Lock()
	s.lastActive = now
	s.mu.Unlock()
}

// LastActive returns the last activity timestamp.
func (s *Session) LastActive() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Unix(0, s.lastActive)
}

// SetTunnels / SetConns update resource counts (reserved for Phase 9).
func (s *Session) SetTunnels(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnels = n
}

func (s *Session) SetConns(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = n
}

// Tunnels / Conns return the current resource counts.
func (s *Session) Tunnels() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tunnels
}

func (s *Session) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// Registry maps client_id -> Session.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]*Session
}

// NewRegistry creates a registry.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]*Session)}
}

// Register inserts a session for clientID. Returns ErrExists if the id is
// already present (one control connection per client).
func (r *Registry) Register(s *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[s.ClientID]; ok {
		return ErrExists
	}
	r.byID[s.ClientID] = s
	return nil
}

// Unregister removes the session and returns it (nil if absent).
func (r *Registry) Unregister(clientID string) *Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byID[clientID]
	delete(r.byID, clientID)
	return s
}

// Get returns the session for clientID.
func (r *Registry) Get(clientID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byID[clientID]
	return s, ok
}

// Len returns the number of active sessions.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// All returns a snapshot of all sessions.
func (r *Registry) All() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s)
	}
	return out
}
