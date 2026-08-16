package security

import (
	"sync"

	"golang.org/x/time/rate"
)

// IPGate enforces per-source-IP connection limits on public listeners
// (T9): a connection rate cap and a concurrent-connection cap. It is the
// first line of defense before any mTLS/application work.
type IPGate struct {
	mu       sync.Mutex
	conns    map[string]int
	rates    map[string]*rate.Limiter
	maxPerIP int
	rateBPS  rate.Limit
	burst    int
}

// NewIPGate builds a gate: maxConnsPerIP concurrent connections and
// connRatePerSec connections per second per source IP. Zero values disable
// the respective cap (fail-closed callers set explicit values).
func NewIPGate(maxConnsPerIP int, connRatePerSec float64) *IPGate {
	g := &IPGate{
		conns:    make(map[string]int),
		rates:    make(map[string]*rate.Limiter),
		maxPerIP: maxConnsPerIP,
	}
	if connRatePerSec > 0 {
		g.rateBPS = rate.Limit(connRatePerSec)
		g.burst = int(connRatePerSec) * 2
		if g.burst < 8 {
			g.burst = 8
		}
	}
	return g
}

// Allow checks the connection rate and the concurrency cap for ip. Callers
// must call Release(ip) exactly once for every successful Allow.
func (g *IPGate) Allow(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.rateBPS > 0 {
		l, ok := g.rates[ip]
		if !ok {
			l = rate.NewLimiter(g.rateBPS, g.burst)
			g.rates[ip] = l
		}
		if !l.Allow() {
			return false
		}
	}
	if g.maxPerIP > 0 && g.conns[ip] >= g.maxPerIP {
		return false
	}
	g.conns[ip]++
	return true
}

// Release returns one concurrent slot for ip.
func (g *IPGate) Release(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.conns[ip] > 0 {
		g.conns[ip]--
		if g.conns[ip] == 0 {
			delete(g.conns, ip)
		}
	}
}

// Active returns the current concurrent connections for ip (tests).
func (g *IPGate) Active(ip string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conns[ip]
}
