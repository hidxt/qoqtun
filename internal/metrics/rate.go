package metrics

import (
	"sync"
	"time"
)

// RateWindow estimates bytes/sec over a sliding window (1s buckets, 60s
// depth). The client polls Snapshot() to derive instantaneous rates.
type RateWindow struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets [60]int64 // 1s buckets
	lastIdx int
	lastTs  int64 // unix seconds of the newest bucket
}

// NewRateWindow returns a rate estimator using time.Now.
func NewRateWindow() *RateWindow {
	return &RateWindow{now: time.Now}
}

// Add credits n bytes to the current second.
func (w *RateWindow) Add(n int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.advance(time.Now().Unix())
	w.buckets[w.lastIdx] += n
}

// advance moves the ring to ts (second granularity), zeroing skipped slots.
func (w *RateWindow) advance(ts int64) {
	if w.lastTs == 0 {
		w.lastTs = ts
		w.lastIdx = 0
		return
	}
	for ts > w.lastTs {
		w.lastTs++
		w.lastIdx = (w.lastIdx + 1) % len(w.buckets)
		w.buckets[w.lastIdx] = 0
	}
}

// Rate returns the bytes/sec estimate over the last second (instantaneous)
// and over the last 60s (average). Advance is idempotent for reads.
func (w *RateWindow) Rate() (perSec int64, avg60 int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now().Unix()
	if now > w.lastTs {
		w.advance(now) // zero out stale slots so recent history is accurate
	}
	perSec = w.buckets[w.lastIdx]
	var sum int64
	for _, b := range w.buckets {
		sum += b
	}
	return perSec, sum / 60
}

// SnapshotRate pairs a byte total with its current rate (for CLI display).
type SnapshotRate struct {
	TotalBytes int64
	RateBPS    int64 // instantaneous (last 1s)
}
