package control_test

import (
	"context"
	crand "crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/hidxt/qoqtun/internal/clientcore"
	"github.com/hidxt/qoqtun/internal/protocol"
)

// freePort grabs an ephemeral port by listening and closing it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// freePortInRange returns a free port inside the policy range (20000-29999).
// Windows ephemeral ports start at 49152, so we probe the range directly.
func freePortInRange(t *testing.T) int {
	t.Helper()
	start := 20000 + rand.Intn(8000)
	for p := start; p < 29999; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			port := ln.Addr().(*net.TCPAddr).Port
			ln.Close()
			return port
		}
	}
	t.Fatal("no free port in allowed range")
	return 0
}

// udpPortInRange returns a free port probed in the UDP space (UDP tunnels
// bind UDP, and a TCP probe does not guarantee a UDP port is free — a
// freshly closed UDP socket may still hold the port on Windows).
func udpPortInRange(t *testing.T) int {
	t.Helper()
	start := 20000 + rand.Intn(8000)
	for p := start; p < 29999; p++ {
		// probe with the same wildcard bind the server uses (:port), so a
		// busy 0.0.0.0:port is detected too
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: p})
		if err == nil {
			port := conn.LocalAddr().(*net.UDPAddr).Port
			conn.Close()
			return port
		}
	}
	t.Fatal("no free udp port in allowed range")
	return 0
}

// startEchoServer runs an echo service on 127.0.0.1.
func startEchoServer(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close(); <-done }
}

// startClient runs a clientcore.Client in the background. The returned
// cancel must be invoked before env.close() so the control connection is
// torn down cleanly (the server wait-group waits for its read loop).
func startClient(t *testing.T, env *testEnv, tunnels []clientcore.TunnelSpec) (*clientcore.Client, context.CancelFunc, chan error) {
	t.Helper()
	key, id, certPEM := env.newClientCert(t)
	client := &clientcore.Client{
		ServerAddr: env.addr,
		CAs:        []*x509.Certificate{env.ca.Cert},
		Cert:       certPEM,
		Key:        keyPEM(t, key),
		ClientID:   id,
		Name:       "tunnel-client",
		Tunnels:    tunnels,
		Log:        discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- client.Run(ctx) }()
	// wait until the tunnels are registered server-side
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cnt := 0
		for _, m := range env.srv.Managers() {
			cnt += m.TunnelCount()
		}
		if cnt >= len(tunnels) {
			return client, cancel, errCh
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatal("tunnel registration timed out")
	return nil, nil, nil
}

// waitClientExit cancels the client context and waits for the control
// session to tear down (must finish before env.close() so the server
// wait-group is not left waiting on the control read loop).
func waitClientExit(cancel context.CancelFunc, errCh chan error) {
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
	}
}

// discardLogger silences slog in tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

// roundTrip sends payload through the public port and expects the echo.
func roundTrip(t *testing.T, publicPort int, payload []byte) {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort))
	if err != nil {
		t.Fatalf("dial public port: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(buf), len(payload))
	}
}

func TestTCPTunnelEcho(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "echo", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)

	roundTrip(t, port, []byte("hello qoqtun"))
	roundTrip(t, port, []byte("second message"))
}

func TestTCPTunnelLargeTransfer(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "big", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})

	// 64 MiB of pseudo-random data, verified byte-for-byte
	const size = 64 << 20
	payload := make([]byte, size)
	if _, err := crand.Read(payload); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))

	// send in chunks
	written := 0
	for written < size {
		n, err := conn.Write(payload[written:])
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		written += n
	}
	// read back and compare
	got := make([]byte, size)
	read := 0
	for read < size {
		n, err := conn.Read(got[read:])
		if err != nil {
			t.Fatalf("read: %v (read %d)", err, read)
		}
		read += n
	}
	if string(got) != string(payload) {
		t.Fatal("64MiB transfer corrupted")
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not exit after cancel")
	}
}

func TestTCPTunnelConcurrent100(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "conc", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("conn-%d", i))
			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err := conn.Write(msg); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errs <- err
				return
			}
			if string(buf) != string(msg) {
				errs <- fmt.Errorf("mismatch: %s", buf)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent connection failed: %v", err)
		}
	}
}

func TestHalfClose(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	// origin: reads request, closes its write side, client still reads
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("reply"))
		_ = conn.(*net.TCPConn).CloseWrite()
		// keep reading until the peer also half-closes / closes
		_, _ = io.Copy(io.Discard, conn)
		close(done)
	}()
	originPort := ln.Addr().(*net.TCPAddr).Port

	port := freePortInRange(t)
	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "half", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: originPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("request-data")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(buf) != "reply" {
		t.Fatalf("got %q", buf)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not observe half-close")
	}
}

func TestOriginUnreachable(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	// a port nobody listens on
	deadPort := freePortInRange(t)
	port := freePortInRange(t)
	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "dead", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: deadPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		// acceptable: server closes on origin dial failure
		return
	}
	// server should close the public side shortly
	buf := make([]byte, 1)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatal("public connection must be closed when origin is unreachable")
	}
}

func TestTunnelGoroutineReclaim(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	port := freePortInRange(t)
	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "gr", Type: "tcp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)

	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		roundTrip(t, port, []byte(fmt.Sprintf("m%d", i)))
	}
	// allow splices to unwind
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+8 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before+8 {
		t.Fatalf("goroutines not reclaimed: before=%d after=%d", before, runtime.NumGoroutine())
	}
}

// TestACLRejection verifies a tunnel whose origin is outside the policy
// allowed_targets is refused client-side (fail-closed).
func TestACLRejection(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	// server policy allows 127.0.0.0/8 (testEnv). Since Phase 9 the
	// server enforces allowed_targets at registration (T6): a tunnel to
	// an out-of-ACL origin is refused with ERR_TARGET_NOT_ALLOWED.
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	conn, _ := dialControl(t, env)
	defer conn.Close()
	resp := registerRaw(t, conn, "bad", "tcp", freePortInRange(t),
		protocol.LocalTarget{IP: "192.0.2.1", Port: echoPort}, "")
	if resp.OK || resp.Error == nil || resp.Error.Code != protocol.ErrCodeTargetNotAllowed {
		t.Fatalf("out-of-ACL origin must be refused at registration, got %+v", resp)
	}
}
