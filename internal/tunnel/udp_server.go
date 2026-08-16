package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// udpSession maps one public-side peer to a session id.
type udpSession struct {
	id         []byte
	peer       *net.UDPAddr
	lastActive time.Time
}

// udpServerState is the per-tunnel UDP listener and session table.
type udpServerState struct {
	mu       sync.Mutex
	tunnelID string
	conn     *net.UDPConn
	byPeer   map[string]*udpSession // key: peer addr string
	byID     map[string]*udpSession // key: session id hex
	// LRU order for eviction (most recent last).
	order []string

	// limits (from policy)
	maxSessions int
	maxPacket   int
	sessionIdle time.Duration

	// per-peer packet rate limiters (公网 IP pps 防滥用, Server 强制).
	rateMu sync.Mutex
	rates  map[string]*rate.Limiter
	// drop counters (metrics hook; Phase 10 wires atomics).
	dropped uint64
}

// newUDPServerState binds a UDP listener and prepares limits.
func newUDPServerState(tunnelID string, port int, maxSessions, maxPacket int, idle time.Duration) (*udpServerState, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	if maxSessions <= 0 {
		maxSessions = 256
	}
	if maxPacket <= 0 || maxPacket > udpMaxPacket {
		maxPacket = 1500
	}
	if idle <= 0 {
		idle = 60 * time.Second
	}
	return &udpServerState{
		tunnelID:    tunnelID,
		conn:        conn,
		byPeer:      make(map[string]*udpSession),
		byID:        make(map[string]*udpSession),
		maxSessions: maxSessions,
		maxPacket:   maxPacket,
		sessionIdle: idle,
		rates:       make(map[string]*rate.Limiter),
	}, nil
}

// LocalAddr returns the bound public UDP address.
func (u *udpServerState) LocalAddr() net.Addr { return u.conn.LocalAddr() }

// PeerAddrString renders the peer for keying.
func peerKey(addr *net.UDPAddr) string { return addr.String() }

// rateAllow checks the per-peer packet budget (5 pps burst 10).
func (u *udpServerState) rateAllow(peerIP string) bool {
	u.rateMu.Lock()
	l, ok := u.rates[peerIP]
	if !ok {
		l = rate.NewLimiter(5, 10)
		u.rates[peerIP] = l
	}
	u.rateMu.Unlock()
	return l.Allow()
}

// sessionFor returns the session for a peer, creating it if needed (with
// LRU eviction when full). A nil return means the packet must be dropped.
func (u *udpServerState) sessionFor(peer *net.UDPAddr, now time.Time) *udpSession {
	key := peerKey(peer)
	u.mu.Lock()
	defer u.mu.Unlock()
	if s, ok := u.byPeer[key]; ok {
		s.lastActive = now
		u.touchLocked(key)
		return s
	}
	// capacity: evict the least-recently-used session
	if len(u.byPeer) >= u.maxSessions {
		u.evictLRULocked(now)
	}
	id, err := NewSessionID()
	if err != nil {
		return nil
	}
	s := &udpSession{id: id, peer: peer, lastActive: now}
	u.byPeer[key] = s
	u.byID[hexID(id)] = s
	u.order = append(u.order, key)
	return s
}

// sessionByID resolves a session id for a return packet.
func (u *udpServerState) sessionByID(id []byte) *udpSession {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.byID[hexID(id)]
}

func (u *udpServerState) touchLocked(key string) {
	for i, k := range u.order {
		if k == key {
			u.order = append(u.order[:i], u.order[i+1:]...)
			u.order = append(u.order, key)
			return
		}
	}
}

func (u *udpServerState) evictLRULocked(now time.Time) {
	if len(u.order) == 0 {
		return
	}
	oldestKey := u.order[0]
	u.order = u.order[1:]
	if s, ok := u.byPeer[oldestKey]; ok {
		delete(u.byPeer, oldestKey)
		delete(u.byID, hexID(s.id))
	}
}

// expireIdle removes sessions idle longer than the timeout; returns count.
func (u *udpServerState) expireIdle(now time.Time) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	var expired []string
	for key, s := range u.byPeer {
		if now.Sub(s.lastActive) > u.sessionIdle {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		if s, ok := u.byPeer[key]; ok {
			delete(u.byPeer, key)
			delete(u.byID, hexID(s.id))
			u.removeOrderLocked(key)
		}
	}
	return len(expired)
}

func (u *udpServerState) removeOrderLocked(key string) {
	for i, k := range u.order {
		if k == key {
			u.order = append(u.order[:i], u.order[i+1:]...)
			return
		}
	}
}

// count returns the current session count.
func (u *udpServerState) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.byPeer)
}

// close stops the listener and clears all sessions.
func (u *udpServerState) close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	_ = u.conn.Close()
	u.byPeer = make(map[string]*udpSession)
	u.byID = make(map[string]*udpSession)
	u.order = nil
}

// cleanupLoop periodically expires idle sessions.
func (u *udpServerState) cleanupLoop(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n := u.expireIdle(time.Now()); n > 0 {
				log.Debug("udp: expired idle sessions", "tunnel", u.tunnelID, "count", n)
			}
		}
	}
}

func hexID(id []byte) string {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, len(id)*2)
	for i, c := range id {
		b[i*2] = hexDigits[c>>4]
		b[i*2+1] = hexDigits[c&0xf]
	}
	return string(b)
}
