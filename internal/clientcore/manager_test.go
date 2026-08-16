package clientcore

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

// TestManagerReconnectsWithBackoff: temporary failures trigger reconnect
// with growing delays; a success transitions to online and stops the loop.
func TestManagerReconnectsWithBackoff(t *testing.T) {
	var sessions atomic.Int64
	var reconnectAttempts atomic.Int64
	m := &Manager{
		Session: func(ctx context.Context) error {
			n := sessions.Add(1)
			if n < 3 {
				return &ErrTemporary{Err: errors.New("boom")}
			}
			return nil // session succeeds
		},
		Backoff: BackoffConfig{Initial: 5 * time.Millisecond, Max: 20 * time.Millisecond, Jitter: 0},
		Log:     discardSlog(),
		OnReconnect: func(attempt int) {
			reconnectAttempts.Store(int64(attempt))
		},
	}
	if err := m.Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if sessions.Load() != 3 {
		t.Fatalf("expected 3 sessions, got %d", sessions.Load())
	}
	if reconnectAttempts.Load() < 2 {
		t.Fatalf("expected reconnect callbacks, got %d", reconnectAttempts.Load())
	}
	if m.State() != StateStopped {
		t.Fatalf("final state = %s, want stopped", m.State())
	}
}

// TestManagerPermanentErrorStops: a permanent error exits Run with the error
// (no reconnect, non-zero exit semantics).
func TestManagerPermanentErrorStops(t *testing.T) {
	var sessions atomic.Int64
	m := &Manager{
		Session: func(ctx context.Context) error {
			sessions.Add(1)
			return &ErrPermanent{Err: errors.New("certificate revoked")}
		},
		Backoff: BackoffConfig{Initial: time.Millisecond, Max: time.Millisecond, Jitter: 0},
		Log:     discardSlog(),
	}
	err := m.Run(context.Background())
	if err == nil {
		t.Fatal("permanent error must stop Run with an error")
	}
	if sessions.Load() != 1 {
		t.Fatalf("must not reconnect after permanent error, sessions=%d", sessions.Load())
	}
}

// TestManagerGracefulCancel: cancelling the context stops cleanly (nil).
func TestManagerGracefulCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		Session: func(ctx context.Context) error {
			<-ctx.Done()
			return &ErrTemporary{Err: ctx.Err()}
		},
		Backoff: BackoffConfig{Initial: time.Millisecond, Max: time.Millisecond, Jitter: 0},
		Log:     discardSlog(),
	}
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful cancel must return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manager did not stop after cancel")
	}
}

// TestBackoffGrows: delay increases with attempt count (bounded by max).
func TestBackoffGrows(t *testing.T) {
	m := &Manager{Backoff: BackoffConfig{Initial: 10 * time.Millisecond, Max: 80 * time.Millisecond, Jitter: 0}}
	d1 := m.backoffFor(1)
	d3 := m.backoffFor(3)
	d10 := m.backoffFor(10)
	if d3 <= d1 {
		t.Fatalf("backoff must grow: %v then %v", d1, d3)
	}
	if d10 > 80*time.Millisecond {
		t.Fatalf("backoff must cap at max: %v", d10)
	}
}

// TestClassify: network errors are temporary; auth errors are permanent.
func TestClassify(t *testing.T) {
	if IsTemporary(Classify(errors.New("read: connection reset"))) {
	} else {
		t.Fatal("network error must be temporary")
	}
	if !IsPermanent(Classify(&ErrPermanent{Err: errors.New("x")})) {
		t.Fatal("wrapped permanent must stay permanent")
	}
	if !IsPermanent(Classify(errors.New("tls: bad certificate"))) {
		t.Fatal("tls cert error must be permanent")
	}
	if !IsPermanent(Classify(errors.New("server rejected: ERR_AUTH_FAILED: nope"))) {
		t.Fatal("auth code must be permanent")
	}
	if !IsTemporary(Classify(errors.New("i/o timeout"))) {
		t.Fatal("timeout must be temporary")
	}
}
