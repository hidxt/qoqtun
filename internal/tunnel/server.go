package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager is the server-side tunnel manager (04-protocol-v1.md §3):
// registration with port arbitration, public listeners, conn_id generation
// and pending pairing, data-connection claiming, and cleanup of unclaimed
// conn_ids after the 10s deadline.
type Manager struct {
	Log *slog.Logger

	mu      sync.Mutex
	seq     uint64
	tunnels map[string]*Tunnel      // tunnel_id
	ports   map[int]string          // remote_port -> tunnel_id
	pending map[string]*pendingConn // conn_id -> pending pairing
}

// Tunnel is one registered tunnel on the server.
type Tunnel struct {
	ID         string
	Name       string
	Type       string
	RemotePort int
	LocalIP    string
	LocalPort  int

	ln net.Listener
}

// pendingConn is a public-side connection awaiting the client's data conn.
type pendingConn struct {
	conn     net.Conn
	tunnelID string
	deadline time.Time
}

// NewManager creates a tunnel manager.
func NewManager(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		Log:     log,
		tunnels: make(map[string]*Tunnel),
		ports:   make(map[int]string),
		pending: make(map[string]*pendingConn),
	}
}

// Register validates the port, starts the public listener and returns the
// tunnel. onOpen is invoked for every accepted public connection with the
// tunnel and the raw conn (the control plane notifies the client).
func (m *Manager) Register(ctx context.Context, name, typ string, remotePort int,
	allowedPorts []string, maxTunnels int, onOpen func(t *Tunnel, conn net.Conn)) (*Tunnel, error) {
	if maxTunnels > 0 && m.TunnelCount() >= maxTunnels {
		return nil, fmt.Errorf("tunnel limit reached (%d)", maxTunnels)
	}
	if remotePort < 1 || remotePort > 65535 {
		return nil, fmt.Errorf("invalid remote port %d", remotePort)
	}
	if !portAllowed(allowedPorts, remotePort) {
		return nil, fmt.Errorf("remote port %d not allowed by policy", remotePort)
	}
	m.mu.Lock()
	if owner, ok := m.ports[remotePort]; ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("remote port %d already in use by %s", remotePort, owner)
	}
	m.mu.Unlock()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", remotePort))
	if err != nil {
		return nil, fmt.Errorf("listen on %d: %w", remotePort, err)
	}
	t := &Tunnel{
		ID:         fmt.Sprintf("t_%d", m.nextSeq()),
		Name:       name,
		Type:       typ,
		RemotePort: remotePort,
		ln:         ln,
	}
	m.mu.Lock()
	m.tunnels[t.ID] = t
	m.ports[remotePort] = t.ID
	m.mu.Unlock()

	go m.acceptLoop(ctx, t, onOpen)
	m.Log.Info("tunnel registered", "tunnel_id", t.ID, "name", name, "port", remotePort)
	return t, nil
}

func (m *Manager) nextSeq() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return m.seq
}

// portAllowed checks a port against "N" / "N-M" / "*" entries.
func portAllowed(entries []string, port int) bool {
	for _, e := range entries {
		if e == "*" {
			return true
		}
		if strings.Contains(e, "-") {
			parts := strings.SplitN(e, "-", 2)
			lo, err1 := strconv.Atoi(parts[0])
			hi, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil && port >= lo && port <= hi {
				return true
			}
		} else {
			p, err := strconv.Atoi(e)
			if err == nil && p == port {
				return true
			}
		}
	}
	return false
}

// Unregister stops the public listener and drops its pending connections.
func (m *Manager) Unregister(tunnelID string) {
	m.mu.Lock()
	t := m.tunnels[tunnelID]
	if t == nil {
		m.mu.Unlock()
		return
	}
	delete(m.tunnels, tunnelID)
	delete(m.ports, t.RemotePort)
	for id, pc := range m.pending {
		if pc.tunnelID == tunnelID {
			_ = pc.conn.Close()
			delete(m.pending, id)
		}
	}
	m.mu.Unlock()
	if t.ln != nil {
		_ = t.ln.Close()
	}
	m.Log.Info("tunnel unregistered", "tunnel_id", tunnelID)
}

// UnregisterAll removes all tunnels (client disconnect cleanup).
func (m *Manager) UnregisterAll() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.tunnels))
	for id := range m.tunnels {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Unregister(id)
	}
}

// acceptLoop accepts public connections and hands them to onOpen.
func (m *Manager) acceptLoop(ctx context.Context, t *Tunnel, onOpen func(*Tunnel, net.Conn)) {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// listener closed (unregister) or fatal error: stop accepting
			return
		}
		if onOpen != nil {
			onOpen(t, conn)
		} else {
			_ = conn.Close()
		}
	}
}

// NewConnID generates a CSPRNG 128-bit conn id (hex).
func NewConnID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tunnel: conn id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// OpenConnection reserves a pairing for a fresh public connection and
// returns the conn id (the control plane notifies the client).
func (m *Manager) OpenConnection(t *Tunnel, publicConn net.Conn, claimTimeout time.Duration) (string, error) {
	connID, err := NewConnID()
	if err != nil {
		return "", err
	}
	if claimTimeout <= 0 {
		claimTimeout = 10 * time.Second
	}
	_ = publicConn.SetDeadline(time.Now().Add(claimTimeout))
	m.mu.Lock()
	m.pending[connID] = &pendingConn{conn: publicConn, tunnelID: t.ID, deadline: time.Now().Add(claimTimeout)}
	m.mu.Unlock()
	return connID, nil
}

// ClaimData pairs an incoming data connection (identified by conn_id in its
// open_data frame) with the pending public connection. The caller must have
// verified the data connection's mTLS identity matches the tunnel's client.
func (m *Manager) ClaimData(connID string) (net.Conn, *Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pc, ok := m.pending[connID]
	if !ok {
		return nil, nil, fmt.Errorf("unknown or expired conn_id")
	}
	if time.Now().After(pc.deadline) {
		_ = pc.conn.Close()
		delete(m.pending, connID)
		return nil, nil, fmt.Errorf("conn_id claim timeout")
	}
	delete(m.pending, connID)
	t := m.tunnels[pc.tunnelID]
	if t == nil {
		_ = pc.conn.Close()
		return nil, nil, fmt.Errorf("tunnel gone")
	}
	return pc.conn, t, nil
}

// CleanupExpired drops pending conns past their claim deadline.
func (m *Manager) CleanupExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, pc := range m.pending {
		if now.After(pc.deadline) {
			_ = pc.conn.Close()
			delete(m.pending, id)
			m.Log.Warn("tunnel: conn_id claim timeout", "conn_id", id)
		}
	}
}

// TunnelCount returns the number of registered tunnels.
func (m *Manager) TunnelCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tunnels)
}

// Ports returns the remote ports currently registered by this manager
// (used for port reservations on disconnect).
func (m *Manager) Ports() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int, 0, len(m.ports))
	for port := range m.ports {
		out = append(out, port)
	}
	return out
}
