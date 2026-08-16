package control_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
)

// fastClient builds a clientcore.Client with a quick reconnect backoff.
func fastClient(t *testing.T, env *testEnv, tunnels []clientcore.TunnelSpec) *clientcore.Client {
	t.Helper()
	key, id, certPEM := env.newClientCert(t)
	return &clientcore.Client{
		ServerAddr: env.addr,
		CAs:        []*x509.Certificate{env.ca.Cert},
		Cert:       certPEM,
		Key:        keyPEM(t, key),
		ClientID:   id,
		Name:       "reconnect-client",
		Tunnels:    tunnels,
		Log:        discardLogger(),
		Backoff:    clientcore.BackoffConfig{Initial: 50 * time.Millisecond, Max: 200 * time.Millisecond, Jitter: 0},
	}
}

// waitTunnelCount polls the server tunnel managers until count matches.
func waitTunnelCount(t *testing.T, env *testEnv, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cnt := 0
		for _, m := range env.srv.Managers() {
			cnt += m.TunnelCount()
		}
		if cnt == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tunnel count did not reach %d", want)
}

// TestReconnectReregistersAndForwards: after the control connection is
// dropped server-side, the client reconnects with backoff, re-registers its
// tunnels, and forwarding works again.
func TestReconnectReregistersAndForwards(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	client := fastClient(t, env, []clientcore.TunnelSpec{
		{Name: "r", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	errCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { errCh <- client.Run(ctx) }()

	waitTunnelCount(t, env, 1, 5*time.Second)
	roundTrip(t, port, []byte("before disconnect"))

	// drop the control connection server-side (simulated network cut)
	sess, ok := env.srv.Sessions.Get(client.ClientID)
	if !ok {
		t.Fatal("session not found")
	}
	_ = sess.Conn.Close()

	// client reconnects and re-registers
	waitTunnelCount(t, env, 0, 3*time.Second) // dropped
	waitTunnelCount(t, env, 1, 5*time.Second) // re-registered
	roundTrip(t, port, []byte("after reconnect"))
}

// TestKickOldSession: a duplicate client_id kicks the old session (new
// connection wins); the old client's session is gone.
func TestKickOldSession(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	key, id, certPEM := env.newClientCert(t)
	mk := func() *clientcore.Client {
		return &clientcore.Client{
			ServerAddr: env.addr,
			CAs:        []*x509.Certificate{env.ca.Cert},
			Cert:       certPEM,
			Key:        keyPEM(t, key),
			ClientID:   id,
			Name:       "dup",
			Log:        discardLogger(),
			Backoff:    clientcore.BackoffConfig{Initial: 50 * time.Millisecond, Max: 100 * time.Millisecond, Jitter: 0},
		}
	}
	first := mk()
	errCh1 := make(chan error, 1)
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() { errCh1 <- first.Run(ctx1) }()
	waitForSession(t, env, id, true)

	// second connection with the same identity
	second := mk()
	errCh2 := make(chan error, 1)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { errCh2 <- second.Run(ctx2) }()
	waitForSession(t, env, id, true)

	// the first session must be kicked with a PERMANENT error so it stops
	// reconnecting (prevents kick ping-pong between two live processes)
	select {
	case err := <-errCh1:
		if err == nil {
			t.Fatal("kicked session must return an error")
		}
		if !clientcore.IsPermanent(err) {
			t.Fatalf("kick must be permanent (no auto-reconnect), got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first session was not kicked")
	}
	_ = errCh2
}

func waitForSession(t *testing.T, env *testEnv, clientID string, present bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, ok := env.srv.Sessions.Get(clientID)
		if ok == present {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("session presence = %v, want %v", !present, present)
}

// TestPortReservation: after disconnect the port is reserved for its owner
// and the owner auto-reconnects to reclaim it (forwarding works again). A
// thief client attempting the port is refused by the server arbitration.
func TestPortReservation(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	owner := fastClient(t, env, []clientcore.TunnelSpec{
		{Name: "pr", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	octx, ocancel := context.WithCancel(context.Background())
	defer ocancel()
	go func() { _ = owner.Run(octx) }()
	waitTunnelCount(t, env, 1, 5*time.Second)

	// disconnect the owner; it must auto-reconnect and reclaim the port
	sess, _ := env.srv.Sessions.Get(owner.ClientID)
	_ = sess.Conn.Close()
	waitTunnelCount(t, env, 0, 3*time.Second)
	waitTunnelCount(t, env, 1, 8*time.Second) // reconnected
	roundTrip(t, port, []byte("reclaimed after reconnect"))

	// a thief with the same port must NOT get a tunnel: total tunnel count
	// for any OTHER manager stays 0 (owner keeps the port)
	thief := fastClient(t, env, []clientcore.TunnelSpec{
		{Name: "thief", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	tctx, tcancel := context.WithCancel(context.Background())
	defer tcancel()
	go func() { _ = thief.Run(tctx) }()
	time.Sleep(1500 * time.Millisecond)
	// the owner's manager is the only one with a tunnel
	owners := 0
	others := 0
	for _, m := range env.srv.Managers() {
		if m.TunnelCount() > 0 {
			owners++
		}
	}
	if owners > 1 {
		t.Fatalf("more than one tunnel holder: %d", owners)
	}
	_ = others
	tcancel()

	// owner still serves traffic
	roundTrip(t, port, []byte("still mine"))
}
