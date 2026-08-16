// Package metrics implements the local-only statistics for qoqtun
// (01-architecture §2 / §4): per-client and per-tunnel byte/connection
// counters plus a sliding-window rate estimator. It contains metadata
// only — never payload content — and is never reported off-device.
package metrics

import (
	"sync"
	"sync/atomic"
)

// Counter is a lock-free monotonic counter (except Active which moves both
// ways). Reads use Load; writes use Add.
type Counter struct{ v atomic.Int64 }

func (c *Counter) Add(n int64)  { c.v.Add(n) }
func (c *Counter) Value() int64 { return c.v.Load() }

// TunnelStats is the per-tunnel view.
type TunnelStats struct {
	TunnelID string

	RxBytes, TxBytes *Counter
	ActiveConns      *Counter // currently open data connections
	TotalConns       *Counter // cumulative accepted data connections
	UDPRxPackets     *Counter
	UDPTxPackets     *Counter
}

// ClientStats is the per-client view.
type ClientStats struct {
	ClientID string

	RxBytes, TxBytes *Counter
	ActiveConns      *Counter
	TotalConns       *Counter

	tunnels map[string]*TunnelStats
}

// Registry owns every counter and the global roll-up.
type Registry struct {
	mu      sync.RWMutex
	clients map[string]*ClientStats

	globalRx, globalTx *Counter
	globalConns        *Counter
	globalRate         *RateWindow
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		clients:     make(map[string]*ClientStats),
		globalRx:    &Counter{},
		globalTx:    &Counter{},
		globalConns: &Counter{},
		globalRate:  NewRateWindow(),
	}
}

// Client returns (creating if needed) the stats for clientID.
func (r *Registry) Client(clientID string) *ClientStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[clientID]
	if !ok {
		c = &ClientStats{
			ClientID:    clientID,
			RxBytes:     &Counter{},
			TxBytes:     &Counter{},
			ActiveConns: &Counter{},
			TotalConns:  &Counter{},
			tunnels:     make(map[string]*TunnelStats),
		}
		r.clients[clientID] = c
	}
	return c
}

// Tunnel returns (creating if needed) the stats for a tunnel under clientID.
func (r *Registry) Tunnel(clientID, tunnelID string) *TunnelStats {
	c := r.Client(clientID)
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := c.tunnels[tunnelID]
	if !ok {
		t = &TunnelStats{
			TunnelID:     tunnelID,
			RxBytes:      &Counter{},
			TxBytes:      &Counter{},
			ActiveConns:  &Counter{},
			TotalConns:   &Counter{},
			UDPRxPackets: &Counter{},
			UDPTxPackets: &Counter{},
		}
		c.tunnels[tunnelID] = t
	}
	return t
}

// RemoveClient drops all state for a disconnected client.
func (r *Registry) RemoveClient(clientID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.clients, clientID)
}

// RemoveTunnel drops a tunnel's counters.
func (r *Registry) RemoveTunnel(clientID, tunnelID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[clientID]; ok {
		delete(c.tunnels, tunnelID)
	}
}

// RecordConn accounts one finished data connection (TCP/HTTP): rx is bytes
// received from the public side, tx is bytes sent to the public side.
func (r *Registry) RecordConn(clientID, tunnelID string, rx, tx int64) {
	c := r.Client(clientID)
	t := r.Tunnel(clientID, tunnelID)
	t.RxBytes.Add(rx)
	t.TxBytes.Add(tx)
	t.ActiveConns.Add(-1)
	c.RxBytes.Add(rx)
	c.TxBytes.Add(tx)
	c.ActiveConns.Add(-1)
	r.globalRx.Add(rx)
	r.globalTx.Add(tx)
	r.globalRate.Add(rx + tx)
}

// ConnOpened accounts a data connection opening (quota acquire).
func (r *Registry) ConnOpened(clientID, tunnelID string) {
	c := r.Client(clientID)
	t := r.Tunnel(clientID, tunnelID)
	t.ActiveConns.Add(1)
	t.TotalConns.Add(1)
	c.ActiveConns.Add(1)
	c.TotalConns.Add(1)
	r.globalConns.Add(1)
}

// RecordUDP accounts one UDP packet in each direction (0 for the idle side).
func (r *Registry) RecordUDP(clientID, tunnelID string, rx, tx int64) {
	t := r.Tunnel(clientID, tunnelID)
	if rx > 0 {
		t.UDPRxPackets.Add(rx)
	}
	if tx > 0 {
		t.UDPTxPackets.Add(tx)
	}
}

// Snapshot returns a deep copy safe for concurrent readers.
func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rateBPS, avg60 := r.globalRate.Rate()
	snap := Snapshot{
		GlobalRxBytes: r.globalRx.Value(),
		GlobalTxBytes: r.globalTx.Value(),
		GlobalConns:   r.globalConns.Value(),
		RateBPS:       rateBPS,
		AvgRateBPS:    avg60,
		Clients:       make([]ClientSnapshot, 0, len(r.clients)),
	}
	for id, c := range r.clients {
		cs := ClientSnapshot{
			ClientID:    id,
			RxBytes:     c.RxBytes.Value(),
			TxBytes:     c.TxBytes.Value(),
			ActiveConns: c.ActiveConns.Value(),
			TotalConns:  c.TotalConns.Value(),
			Tunnels:     make([]TunnelSnapshot, 0, len(c.tunnels)),
		}
		for tid, t := range c.tunnels {
			cs.Tunnels = append(cs.Tunnels, TunnelSnapshot{
				TunnelID:     tid,
				RxBytes:      t.RxBytes.Value(),
				TxBytes:      t.TxBytes.Value(),
				ActiveConns:  t.ActiveConns.Value(),
				TotalConns:   t.TotalConns.Value(),
				UDPRxPackets: t.UDPRxPackets.Value(),
				UDPTxPackets: t.UDPTxPackets.Value(),
			})
		}
		snap.Clients = append(snap.Clients, cs)
	}
	return snap
}

// Snapshot is the immutable, copy-out view of the registry.
type Snapshot struct {
	GlobalRxBytes int64
	GlobalTxBytes int64
	GlobalConns   int64
	RateBPS       int64 // instantaneous (last 1s)
	AvgRateBPS    int64 // 60s average
	Clients       []ClientSnapshot
}

// ClientSnapshot is one client's counters.
type ClientSnapshot struct {
	ClientID    string
	RxBytes     int64
	TxBytes     int64
	ActiveConns int64
	TotalConns  int64
	Tunnels     []TunnelSnapshot
}

// TunnelSnapshot is one tunnel's counters.
type TunnelSnapshot struct {
	TunnelID     string
	RxBytes      int64
	TxBytes      int64
	ActiveConns  int64
	TotalConns   int64
	UDPRxPackets int64
	UDPTxPackets int64
}
