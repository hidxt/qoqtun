package enroll

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPLimiter rate-limits the enroll endpoint per source IP (03-pki-enrollment
// §4): a token bucket of 5 requests/minute with exponential ban escalation
// after repeated failures (token brute-force mitigation, T17).
type IPLimiter struct {
	mu    sync.Mutex
	now   func() time.Time
	perIP map[string]*ipState
}

type ipState struct {
	limiter  *rate.Limiter
	fails    int
	banUntil time.Time
}

// NewIPLimiter builds a limiter with 5 req/min, burst 5. now injects the
// clock (nil => time.Now) for tests.
func NewIPLimiter(now func() time.Time) *IPLimiter {
	if now == nil {
		now = time.Now
	}
	return &IPLimiter{now: now, perIP: make(map[string]*ipState)}
}

// Allow reports whether a request from ip may proceed right now.
func (l *IPLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.perIP[ip]
	if st == nil {
		st = &ipState{limiter: rate.NewLimiter(rate.Limit(5.0/60.0), 5)} // 5 req/min, burst 5
		l.perIP[ip] = st
	}
	if l.now().Before(st.banUntil) {
		return false
	}
	return st.limiter.Allow()
}

// Report records the outcome of a request: a failure increments the ban
// backoff (2^fails * 5s capped at 24h), a success resets the counter.
func (l *IPLimiter) Report(ip string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.perIP[ip]
	if st == nil {
		return
	}
	if ok {
		st.fails = 0
		return
	}
	st.fails++
	if st.fails < 2 {
		return
	}
	// exponential: 5s, 10s, 20s ... capped at 24h
	backoff := time.Duration(1<<(st.fails-1)) * 5 * time.Second
	if backoff > 24*time.Hour {
		backoff = 24 * time.Hour
	}
	st.banUntil = l.now().Add(backoff)
}
