package control_test

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
)

// TestSoakReconnectLoop simulates a sustained outage: the session keeps
// failing temporarily and the manager keeps reconnecting. It asserts the
// loop stays bounded (no goroutine growth) and the manager survives.
func TestSoakReconnectLoop(t *testing.T) {
	var sessions atomic.Int64
	var attempts atomic.Int64
	m := &clientcore.Manager{
		Session: func(ctx context.Context) error {
			n := sessions.Add(1)
			if n >= 20 { // after 20 failures, succeed to end the loop
				return nil
			}
			return &clientcore.ErrTemporary{Err: ctx.Err()}
		},
		Backoff: clientcore.BackoffConfig{Initial: time.Millisecond, Max: 5 * time.Millisecond, Jitter: 0},
		Log:     discardLogger(),
		OnReconnect: func(attempt int) {
			attempts.Store(int64(attempt))
		},
	}
	before := runtime.NumGoroutine()
	if err := m.Run(context.Background()); err != nil {
		t.Fatalf("soak run: %v", err)
	}
	if sessions.Load() != 20 {
		t.Fatalf("expected 20 sessions, got %d", sessions.Load())
	}
	if attempts.Load() != 19 {
		t.Fatalf("expected 19 reconnects, got %d", attempts.Load())
	}
	// allow goroutines to settle
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before+4 {
		t.Fatalf("goroutine leak in soak: before=%d after=%d", before, runtime.NumGoroutine())
	}
}

// TestClientShutdownRemovesListeners: a client-initiated graceful shutdown
// removes the server's public listeners (drain path).
func TestClientShutdownRemovesListeners(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	client := fastClient(t, env, []clientcore.TunnelSpec{
		{Name: "sd", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { errCh <- client.Run(ctx) }()
	waitTunnelCount(t, env, 1, 5*time.Second)

	// graceful shutdown: cancel -> client sends shutdown -> server removes
	// the public listener
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not exit after graceful shutdown")
	}
	waitTunnelCount(t, env, 0, 5*time.Second)
}

// TestSoakClientDataConnections: repeated connect/disconnect of a real
// client with data transfers must not leak goroutines (reduced soak).
func TestSoakClientDataConnections(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	before := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		client := fastClient(t, env, []clientcore.TunnelSpec{
			{Name: "soak", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
		})
		ctx, cancel := context.WithCancel(context.Background())
		errCh := make(chan error, 1)
		go func() { errCh <- client.Run(ctx) }()
		waitTunnelCount(t, env, 1, 5*time.Second)
		roundTrip(t, port, []byte("soak round"))
		cancel()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("client %d did not exit", i)
		}
		waitTunnelCount(t, env, 0, 5*time.Second)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+10 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before+10 {
		t.Fatalf("goroutine leak after soak cycles: before=%d after=%d", before, runtime.NumGoroutine())
	}
}
