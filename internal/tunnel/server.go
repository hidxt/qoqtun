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

	// UDP limits (defaults per 04 §6; tests shrink these).
	UDPIdleTimeout time.Duration
	UDPMaxSessions int
	UDPMaxPacket   int

	// OnUDPChannelClosed is invoked when a UDP data channel drops so the
	// control plane can pre-open a replacement (Phase 6 reconnect semantics).
	OnUDPChannelClosed func(t *Tunnel)

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

	ln        net.Listener // tcp/http/https
	VhostHost string       // normalized vhost host (type=http vhost mode)
	udp       *udpServerState
	chMu      sync.Mutex
	ch        net.Conn // active UDP data channel (type=udp)
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
		Log:            log,
		UDPIdleTimeout: 60 * time.Second,
		UDPMaxSessions: 256,
		UDPMaxPacket:   1500,
		tunnels:        make(map[string]*Tunnel),
		ports:          make(map[int]string),
		pending:        make(map[string]*pendingConn),
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

	t := &Tunnel{
		ID:         fmt.Sprintf("t_%d", m.nextSeq()),
		Name:       name,
		Type:       typ,
		RemotePort: remotePort,
	}
	if typ == "udp" {
		// UDP public listener + session table (04 §6)
		us, err := newUDPServerState(t.ID, remotePort, m.UDPMaxSessions, m.UDPMaxPacket, m.UDPIdleTimeout)
		if err != nil {
			return nil, fmt.Errorf("udp listen on %d: %w", remotePort, err)
		}
		t.udp = us
		go us.cleanupLoop(ctx, m.Log)
	} else {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", remotePort))
		if err != nil {
			return nil, fmt.Errorf("listen on %d: %w", remotePort, err)
		}
		t.ln = ln
	}
	m.mu.Lock()
	m.tunnels[t.ID] = t
	m.ports[remotePort] = t.ID
	m.mu.Unlock()

	if t.ln != nil {
		go m.acceptLoop(ctx, t, onOpen)
	}
	if t.udp != nil {
		m.StartUDPServer(ctx, t)
	}
	m.Log.Info("tunnel registered", "tunnel_id", t.ID, "name", name, "type", typ, "port", remotePort)
	return t, nil
}

// HandleUDPPacket processes a public UDP datagram: rate-limit, map/create
// the session and forward a channel frame to the client (drop if no
// channel). The public UDP read loop drives this.
func (m *Manager) HandleUDPPacket(t *Tunnel, peer *net.UDPAddr, payload []byte) {
	if t.udp == nil {
		return
	}
	if len(payload) > t.udp.maxPacket {
		m.Log.Warn("udp: oversized packet dropped", "tunnel", t.ID, "size", len(payload))
		return
	}
	ip, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		ip = peer.String()
	}
	if !t.udp.rateAllow(ip) {
		m.Log.Debug("udp: rate limited", "tunnel", t.ID, "ip", ip)
		return
	}
	sess := t.udp.sessionFor(peer, time.Now())
	if sess == nil {
		return
	}
	frame, err := udpFrame(sess.id, payload)
	if err != nil {
		return
	}
	t.chMu.Lock()
	ch := t.ch
	t.chMu.Unlock()
	if ch == nil {
		m.Log.Debug("udp: no channel, dropping", "tunnel", t.ID)
		return
	}
	if _, err := ch.Write(frame); err != nil {
		m.Log.Warn("udp: channel write failed", "tunnel", t.ID, "error", err)
	}
}

// SetUDPChannel binds the client's UDP data channel and starts the return
// path (frames -> original peers).
func (m *Manager) SetUDPChannel(ctx context.Context, t *Tunnel, ch net.Conn) {
	t.chMu.Lock()
	old := t.ch
	t.ch = ch
	t.chMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	go m.udpChannelReadLoop(ctx, t, ch)
	m.Log.Info("udp channel established", "tunnel", t.ID)
}

func (m *Manager) udpChannelReadLoop(ctx context.Context, t *Tunnel, ch net.Conn) {
	defer ch.Close()
	for {
		sessID, payload, err := readUDPFrame(ch, t.udp.maxPacket)
		if err != nil {
			break // channel dropped: fall through to cleanup + notify
		}
		sess := t.udp.sessionByID(sessID)
		if sess == nil {
			continue
		}
		if _, err := t.udp.conn.WriteToUDP(payload, sess.peer); err != nil {
			m.Log.Debug("udp: write to peer failed", "tunnel", t.ID, "error", err)
		}
	}
	// channel dropped: clear it and let the control plane rebuild it
	t.chMu.Lock()
	if t.ch == ch {
		t.ch = nil
	}
	t.chMu.Unlock()
	if m.OnUDPChannelClosed != nil {
		m.OnUDPChannelClosed(t)
	}
}

// StartUDPServer starts the public UDP read loop for a registered tunnel.
func (m *Manager) StartUDPServer(ctx context.Context, t *Tunnel) {
	if t.udp == nil {
		return
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := t.udp.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
				default:
				}
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			m.HandleUDPPacket(t, peer, payload)
		}
	}()
}

// UDPSessions returns the active session count for a tunnel (tests).
func (m *Manager) UDPSessions(t *Tunnel) int {
	if t == nil || t.udp == nil {
		return 0
	}
	return t.udp.count()
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
			closePendingConn(pc)
			delete(m.pending, id)
		}
	}
	m.mu.Unlock()
	if t.ln != nil {
		_ = t.ln.Close()
	}
	if t.udp != nil {
		t.udp.close()
	}
	t.chMu.Lock()
	if t.ch != nil {
		_ = t.ch.Close()
	}
	t.chMu.Unlock()
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

// closePendingConn closes a pending public conn if present (UDP channel
// pre-openings have none).
func closePendingConn(pc *pendingConn) {
	if pc != nil && pc.conn != nil {
		_ = pc.conn.Close()
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
	// UDP channel pre-openings have no public connection yet (nil).
	if publicConn != nil {
		_ = publicConn.SetDeadline(time.Now().Add(claimTimeout))
	}
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
		closePendingConn(pc)
		delete(m.pending, connID)
		return nil, nil, fmt.Errorf("conn_id claim timeout")
	}
	delete(m.pending, connID)
	t := m.tunnels[pc.tunnelID]
	if t == nil {
		closePendingConn(pc)
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
			closePendingConn(pc)
			delete(m.pending, id)
			m.Log.Warn("tunnel: conn_id claim timeout", "conn_id", id)
		}
	}
}

// AddVhostTunnel registers an HTTP vhost tunnel: it occupies a slot in the
// manager (for data-connection routing) but no public port — the shared
// http_vhost_port listener on the Server routes by Host (04 §7).
func (m *Manager) AddVhostTunnel(ctx context.Context, name, host string, maxTunnels int) (*Tunnel, error) {
	if maxTunnels > 0 && m.TunnelCount() >= maxTunnels {
		return nil, fmt.Errorf("tunnel limit reached (%d)", maxTunnels)
	}
	t := &Tunnel{
		ID:         fmt.Sprintf("t_%d", m.nextSeq()),
		Name:       name,
		Type:       "http",
		RemotePort: 0, // no dedicated port in vhost mode
		VhostHost:  host,
	}
	m.mu.Lock()
	m.tunnels[t.ID] = t
	m.mu.Unlock()
	m.Log.Info("vhost tunnel registered", "tunnel_id", t.ID, "name", name, "host", host)
	return t, nil
}

// Tunnels returns a snapshot of all registered tunnels.
func (m *Manager) Tunnels() []*Tunnel {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		out = append(out, t)
	}
	return out
}

// TunnelByID returns the registered tunnel by id.
func (m *Manager) TunnelByID(tunnelID string) (*Tunnel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[tunnelID]
	return t, ok
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
