package security

import (
	"net"
	"testing"
	"time"
)

func TestSemaphore(t *testing.T) {
	s := NewSemaphore(2)
	if !s.TryAcquire() || !s.TryAcquire() {
		t.Fatal("first two acquires must succeed")
	}
	if s.TryAcquire() {
		t.Fatal("third acquire must fail (quota exhausted)")
	}
	if s.Active() != 2 {
		t.Fatalf("active = %d, want 2", s.Active())
	}
	s.Release()
	s.Release()
	s.Release() // over-release must clamp, never go negative
	if s.Active() != 0 {
		t.Fatalf("active after release = %d, want 0", s.Active())
	}
	if !s.TryAcquire() {
		t.Fatal("slot must be reusable after release")
	}
}

func TestSemaphoreUnlimited(t *testing.T) {
	u := NewSemaphore(0)
	for i := 0; i < 1000; i++ {
		if !u.TryAcquire() {
			t.Fatal("unlimited semaphore must never deny")
		}
	}
}

func TestTokenBucketBasic(t *testing.T) {
	b := NewTokenBucket(1000) // 1000 B/s
	// burst absorbs the first chunk
	if !b.AllowN(1000) {
		t.Fatal("burst must allow the first chunk")
	}
	// after burst, AllowN must eventually deny
	time.Sleep(1100 * time.Millisecond)
	if !b.AllowN(1000) {
		t.Fatal("refilled bucket must allow")
	}
	if b.AllowN(1_000_000) {
		t.Fatal("oversized request must be denied")
	}
}

func TestTokenBucketUnlimited(t *testing.T) {
	u := NewTokenBucket(0)
	if !u.AllowN(1 << 30) {
		t.Fatal("unlimited bucket must allow everything")
	}
	if u.WaitN(1<<30) != nil {
		t.Fatal("unlimited WaitN must not block")
	}
}

func TestRateLimitedConnPassthrough(t *testing.T) {
	// unlimited buckets: wrapper returns the original conn
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	wrapped := NewRateLimitedConn(a)
	if wrapped != net.Conn(a) {
		t.Fatal("no active buckets must return the conn unchanged")
	}
}

func TestIPGate(t *testing.T) {
	g := NewIPGate(2, 1000) // 2 concurrent, 1000/s
	if !g.Allow("1.2.3.4") || !g.Allow("1.2.3.4") {
		t.Fatal("first two conns must pass")
	}
	if g.Allow("1.2.3.4") {
		t.Fatal("third concurrent conn must be denied")
	}
	if g.Active("1.2.3.4") != 2 {
		t.Fatalf("active = %d", g.Active("1.2.3.4"))
	}
	g.Release("1.2.3.4")
	if !g.Allow("1.2.3.4") {
		t.Fatal("slot must be reusable")
	}
	// different IP is independent
	if !g.Allow("5.6.7.8") {
		t.Fatal("other IP must not share the cap")
	}
}

func TestIPGateRate(t *testing.T) {
	g := NewIPGate(0, 10) // 10/s, no concurrency cap
	allowed := 0
	for i := 0; i < 50; i++ {
		if g.Allow("9.9.9.9") {
			allowed++
		}
	}
	if allowed < 5 || allowed > 30 {
		t.Fatalf("rate cap not applied: allowed %d of 50 (burst ~20)", allowed)
	}
}

func TestGuardInjectable(t *testing.T) {
	// restore originals
	defer SetCheckFDLimit(nil)
	defer SetIsRoot(nil)

	// fd check below recommended
	SetCheckFDLimit(func(est uint64) FDCheck {
		return FDCheck{Current: 100, Recommended: est, BelowLimit: true}
	})
	chk := CheckFDLimit(1000)
	if !chk.BelowLimit {
		t.Fatal("must report below limit")
	}
	if ErrInsufficientFD(chk) == nil {
		t.Fatal("must produce an error")
	}

	// ok case
	SetCheckFDLimit(func(est uint64) FDCheck {
		return FDCheck{Current: 999999, Recommended: est}
	})
	if CheckFDLimit(1000).BelowLimit {
		t.Fatal("must pass with ample limit")
	}

	// root detection
	SetIsRoot(func() bool { return true })
	if !IsRoot() {
		t.Fatal("injected root must be detected")
	}
	if ErrRootDenied() == nil {
		t.Fatal("root denial error missing")
	}
	SetIsRoot(func() bool { return false })
	if IsRoot() {
		t.Fatal("injected non-root must pass")
	}
}

func TestEstimatedFDLimit(t *testing.T) {
	est := EstimatedFDLimit(256, 128, 64)
	if est < 64*256 {
		t.Fatalf("estimate %d too small for 64 clients x 256 conns", est)
	}
}
