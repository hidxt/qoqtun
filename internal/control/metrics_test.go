package control_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
	"github.com/hidxt/qoqtun/internal/metrics"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
)

// TestMetricsAccuracy: forwarding an exact byte count must be reflected in
// the server metrics with ZERO error (rx = bytes read from the public side,
// tx = bytes written to the public side).
func TestMetricsAccuracy(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "acc", Type: "tcp", RemotePort: 20080, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	const size = 10 << 20 // 10 MiB
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	conn, err := net.Dial("tcp", "127.0.0.1:20080")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, size)
	if _, err := readFull(conn, got); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// give the splice a moment to record both directions
	deadline := time.Now().Add(5 * time.Second)
	var snap metrics.Snapshot
	for time.Now().Before(deadline) {
		snap = env.srv.Metrics.Snapshot()
		if snap.GlobalRxBytes >= size && snap.GlobalTxBytes >= size {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if snap.GlobalRxBytes != size {
		t.Fatalf("rx = %d, want exactly %d (error %d)", snap.GlobalRxBytes, size, size-snap.GlobalRxBytes)
	}
	if snap.GlobalTxBytes != size {
		t.Fatalf("tx = %d, want exactly %d (error %d)", snap.GlobalTxBytes, size, size-snap.GlobalTxBytes)
	}
}

// TestMetricsUDPPackets: UDP packets are counted per direction.
func TestMetricsUDPPackets(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	udpPort, stopUDP := startUDPEchoServer(t)
	defer stopUDP()

	port := freePortInRange(t)
	_, cancel, errCh := startUDPClient(t, env, port, udpPort)
	defer waitClientExit(cancel, errCh)

	const rounds = 5
	for i := 0; i < rounds; i++ {
		udpRoundTrip(t, port, []byte(fmt.Sprintf("m%d", i)), 3)
	}
	deadline := time.Now().Add(3 * time.Second)
	var snap metrics.Snapshot
	for time.Now().Before(deadline) {
		snap = env.srv.Metrics.Snapshot()
		if len(snap.Clients) > 0 && len(snap.Clients[0].Tunnels) > 0 &&
			snap.Clients[0].Tunnels[0].UDPRxPackets >= rounds &&
			snap.Clients[0].Tunnels[0].UDPTxPackets >= rounds {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(snap.Clients) == 0 || len(snap.Clients[0].Tunnels) == 0 {
		t.Fatal("no tunnel stats recorded")
	}
	ts := snap.Clients[0].Tunnels[0]
	if ts.UDPRxPackets < rounds || ts.UDPTxPackets < rounds {
		t.Fatalf("udp packets rx/tx = %d/%d, want >= %d", ts.UDPRxPackets, ts.UDPTxPackets, rounds)
	}
}

// TestMetricsVhostReplayCounted: the vhost sniff prefix (replayed bytes)
// must be counted in the tunnel metrics (no bypass).
func TestMetricsVhostReplayCounted(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	p, stop := startHTTPEchoService(t)
	defer stop()

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "vr", Type: "http", RemotePort: 0, HTTPHost: "vr.example.com", LocalIP: "127.0.0.1", LocalPort: p, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	resp := httpGetText(t, env.srv.VhostPort, "vr.example.com", "/x")
	if !strings.Contains(resp, "echo host=vr.example.com") {
		t.Fatalf("vhost routing failed: %q", resp)
	}
	// the request head (incl. Host header, the sniffed+replayed prefix) and
	// the response must both be counted
	deadline := time.Now().Add(3 * time.Second)
	var snap metrics.Snapshot
	for time.Now().Before(deadline) {
		snap = env.srv.Metrics.Snapshot()
		if snap.GlobalRxBytes > 0 && snap.GlobalTxBytes > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if snap.GlobalRxBytes == 0 || snap.GlobalTxBytes == 0 {
		t.Fatalf("vhost bytes not counted: rx=%d tx=%d", snap.GlobalRxBytes, snap.GlobalTxBytes)
	}
}

// TestMetricsConnLifecycle: active connections go up and back to zero.
func TestMetricsConnLifecycle(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "cl", Type: "tcp", RemotePort: 20081, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	conn, err := net.Dial("tcp", "127.0.0.1:20081")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("hi"))
	buf := make([]byte, 2)
	_, _ = conn.Read(buf)
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := env.srv.Metrics.Snapshot()
		if snap.GlobalConns == 1 && snap.Clients[0].ActiveConns == 0 {
			return // opened once, closed again
		}
		time.Sleep(100 * time.Millisecond)
	}
	snap := env.srv.Metrics.Snapshot()
	t.Fatalf("conn lifecycle wrong: global=%d clients=%+v", snap.GlobalConns, snap.Clients)
}

// ---- raw helpers reused from policy_test ----

var _ = context.Background
var _ = x509.NewCertPool
var _ = transport.Dial
var _ = protocol.MsgPing
