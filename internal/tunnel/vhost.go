package tunnel

import (
	"strings"
	"sync"
)

// vhostEntry binds a normalized Host to a registered tunnel.
type vhostEntry struct {
	tunnelID string
	clientID string
}

// VhostTable maps Host -> tunnel for HTTP vhost routing (04 §7). Rules are
// exact-or-suffix: a rule "example.com" matches requests for "example.com"
// and "*.example.com" (longest suffix wins). Updates are atomic.
type VhostTable struct {
	mu    sync.RWMutex
	hosts map[string]*vhostEntry
}

// NewVhostTable returns an empty routing table.
func NewVhostTable() *VhostTable {
	return &VhostTable{hosts: make(map[string]*vhostEntry)}
}

// Register binds host (already normalized) to a tunnel; a duplicate host is
// rejected with ErrNameConflict (the later registration loses).
func (vt *VhostTable) Register(host, tunnelID, clientID string) error {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	if _, ok := vt.hosts[host]; ok {
		return ErrNameConflict
	}
	vt.hosts[host] = &vhostEntry{tunnelID: tunnelID, clientID: clientID}
	return nil
}

// UnregisterTunnel removes every host bound to tunnelID (tunnel teardown).
func (vt *VhostTable) UnregisterTunnel(tunnelID string) {
	vt.mu.Lock()
	defer vt.mu.Unlock()
	for h, e := range vt.hosts {
		if e.tunnelID == tunnelID {
			delete(vt.hosts, h)
		}
	}
}

// Count returns the number of registered hosts (tests/diagnostics).
func (vt *VhostTable) Count() int {
	vt.mu.RLock()
	defer vt.mu.RUnlock()
	return len(vt.hosts)
}

// Lookup routes a normalized request host: exact match first, then the
// longest suffix rule (so the most specific rule wins).
func (vt *VhostTable) Lookup(host string) (tunnelID, clientID string, ok bool) {
	vt.mu.RLock()
	defer vt.mu.RUnlock()
	if e, found := vt.hosts[host]; found {
		return e.tunnelID, e.clientID, true
	}
	bestLen := 0
	for rule, e := range vt.hosts {
		if len(rule) > bestLen && strings.HasSuffix(host, "."+rule) {
			bestLen = len(rule)
			tunnelID, clientID, ok = e.tunnelID, e.clientID, true
		}
	}
	return tunnelID, clientID, ok
}
