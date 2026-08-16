package control_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
)

// startUDPEchoServer runs a UDP echo service on 127.0.0.1.
func startUDPEchoServer(t *testing.T) (port int, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { conn.Close(); <-done }
}

// udpRoundTrip sends a datagram and waits for the echo (retried while the
// UDP data channel is being established).
func udpRoundTrip(t *testing.T, port int, payload []byte, retries int) []byte {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < retries; i++ {
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err == nil {
			return buf[:n]
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("udp round trip timed out for %d-byte payload", len(payload))
	return nil
}

// startUDPClient runs a client with a udp tunnel and waits for it.
func startUDPClient(t *testing.T, env *testEnv, port, localPort int) (*clientcore.Client, context.CancelFunc, chan error) {
	t.Helper()
	client := fastClient(t, env, []clientcore.TunnelSpec{
		{Name: "udp1", Type: "udp", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: localPort, Enabled: true},
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- client.Run(ctx) }()
	waitTunnelCount(t, env, 1, 5*time.Second)
	return client, cancel, errCh
}

func TestUDPEchoEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	port := udpPortInRange(t)
	_, cancel, errCh := startUDPClient(t, env, port, echoPort)
	defer waitClientExit(cancel, errCh)

	// small packet
	got := udpRoundTrip(t, port, []byte("dns-like-query"), 25)
	if string(got) != "dns-like-query" {
		t.Fatalf("udp echo mismatch: %q", got)
	}
	// large packet (>512B, under max_packet)
	big := make([]byte, 1200)
	for i := range big {
		big[i] = byte(i)
	}
	got2 := udpRoundTrip(t, port, big, 25)
	if len(got2) != len(big) {
		t.Fatalf("large echo length mismatch: %d vs %d", len(got2), len(big))
	}
}

func TestUDPMultiPeerConcurrent(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	port := udpPortInRange(t)
	_, cancel, errCh := startUDPClient(t, env, port, echoPort)
	defer waitClientExit(cancel, errCh)

	// wait for the UDP channel to be fully established before hammering
	// with 20 peers (the channel is pre-opened asynchronously)
	udpRoundTrip(t, port, []byte("warm"), 60)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("peer-%d", i))
			got, err := udpRoundTripErr(port, msg, 60)
			if err != nil {
				errs <- err
				return
			}
			if string(got) != string(msg) {
				errs <- fmt.Errorf("peer %d mismatch: %q", i, got)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// udpRoundTripErr is udpRoundTrip without t.Fatal (safe for goroutines):
// returns the echoed payload or an error.
func udpRoundTripErr(port int, payload []byte, retries int) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	for i := 0; i < retries; i++ {
		_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err == nil {
			return buf[:n], nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("udp round trip timed out for %d-byte payload", len(payload))
}

// TestUDPControlDisconnectClearsSessions: dropping the control connection
// removes the tunnel and all UDP sessions.
func TestUDPControlDisconnectClearsSessions(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	port := udpPortInRange(t)
	client, cancel, errCh := startUDPClient(t, env, port, echoPort)
	defer waitClientExit(cancel, errCh)
	udpRoundTrip(t, port, []byte("warmup"), 60)

	// drop the control connection; the tunnel (and its UDP listener) go away
	sess, ok := env.srv.Sessions.Get(client.ClientID)
	if !ok {
		t.Fatal("session not found")
	}
	_ = sess.Conn.Close()
	waitTunnelCount(t, env, 0, 5*time.Second)

	// no echo must be possible anymore
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Skip("listener already gone")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte("x"))
	buf := make([]byte, 10)
	if _, rerr := conn.Read(buf); rerr == nil {
		t.Fatal("udp must not respond after control disconnect")
	}
}
