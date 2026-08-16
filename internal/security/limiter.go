// Package security implements the server-enforced policy machinery for
// threat model T6/T7/T9/T10: connection quotas, bandwidth rate limiting,
// registration frequency caps and resource guards. The server is the ONLY
// enforcement point; anything that cannot be judged is denied (fail-closed).
package security

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// TokenBucket is a bandwidth limiter (bytes/sec). A nil bucket means
// unlimited; the zero value is unlimited too.
type TokenBucket struct {
	lim *rate.Limiter
	ctx context.Context
}

// NewTokenBucket returns a bucket that allows bps bytes per second with a
// burst sized to absorb one I/O chunk (>= 32KiB). bps <= 0 means unlimited.
func NewTokenBucket(bps int64) *TokenBucket {
	if bps <= 0 {
		return &TokenBucket{}
	}
	burst := bps / 10
	if burst < 32*1024 {
		burst = 32 * 1024
	}
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // cancel is invoked via RateLimitedConn.Close
	tb := &TokenBucket{
		lim: rate.NewLimiter(rate.Limit(bps), int(burst)),
		ctx: ctx,
	}
	return tb
}

// AllowN reports whether n tokens can be consumed without blocking.
func (b *TokenBucket) AllowN(n int) bool {
	if b == nil || b.lim == nil {
		return true
	}
	return b.lim.AllowN(time.Now(), n)
}

// WaitN blocks until n tokens are available or the bucket's context is
// cancelled (connection teardown unblocks waiters).
func (b *TokenBucket) WaitN(n int) error {
	if b == nil || b.lim == nil {
		return nil
	}
	return b.lim.WaitN(b.ctx, n)
}

// RateLimitedConn wraps a net.Conn so every byte consumed or produced
// passes the chained token buckets (per-client + per-tunnel). Close cancels
// the buckets' wait context so blocked writers unblock immediately.
type RateLimitedConn struct {
	net.Conn
	buckets []*TokenBucket
	cancel  context.CancelFunc
	once    sync.Once
}

// NewRateLimitedConn chains the given buckets around c (nil entries are
// skipped). Returns c unchanged when every bucket is unlimited.
func NewRateLimitedConn(c net.Conn, buckets ...*TokenBucket) net.Conn {
	active := make([]*TokenBucket, 0, len(buckets))
	for _, b := range buckets {
		if b != nil && b.lim != nil {
			active = append(active, b)
		}
	}
	if len(active) == 0 {
		return c
	}
	ctx, cancel := context.WithCancel(context.Background())
	for _, b := range active {
		b.ctx = ctx
	}
	return &RateLimitedConn{Conn: c, buckets: active, cancel: cancel}
}

// Read consumes tokens for the bytes read (read-side shaping).
func (c *RateLimitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		for _, b := range c.buckets {
			if err := b.WaitN(n); err != nil {
				return n, err
			}
		}
	}
	return n, err
}

// Write reserves tokens before writing (send-side shaping).
func (c *RateLimitedConn) Write(p []byte) (int, error) {
	for _, b := range c.buckets {
		if err := b.WaitN(len(p)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}

// Close releases the waiters and closes the underlying connection.
func (c *RateLimitedConn) Close() error {
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
	})
	return c.Conn.Close()
}
