package security

import "sync"

// Semaphore is a non-blocking concurrency quota (T9/T10). TryAcquire fails
// immediately when the quota is exhausted — no queuing, so a flood of
// connections never piles up goroutines or memory.
type Semaphore struct {
	mu     sync.Mutex
	limit  int
	active int
}

// NewSemaphore returns a semaphore with limit slots. limit <= 0 means
// unlimited (never blocks, never counts).
func NewSemaphore(limit int) *Semaphore {
	return &Semaphore{limit: limit}
}

// TryAcquire grabs a slot without blocking; false when exhausted.
func (s *Semaphore) TryAcquire() bool {
	if s == nil || s.limit <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= s.limit {
		return false
	}
	s.active++
	return true
}

// Release returns a slot. Releasing beyond acquires is a programming error;
// we clamp so the counter can never go negative (fail-closed).
func (s *Semaphore) Release() {
	if s == nil || s.limit <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active > 0 {
		s.active--
	}
}

// Active reports the number of held slots (diagnostics/tests).
func (s *Semaphore) Active() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Limit returns the configured limit (diagnostics/tests).
func (s *Semaphore) Limit() int {
	if s == nil {
		return 0
	}
	return s.limit
}
