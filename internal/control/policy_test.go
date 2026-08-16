package control_test

import (
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
)

// dialControl opens a manual mTLS control connection and completes the
// hello handshake, returning the raw conn (for protocol-level assertions).
func dialControl(t *testing.T, env *testEnv) (*transport.Conn, string) {
	t.Helper()
	key, id, certPEM := env.newClientCert(t)
	conn, err := transport.Dial("tcp", env.addr, transport.Options{
		CAs: []*x509.Certificate{env.ca.Cert}, Cert: certPEM, Key: keyPEM(t, key),
		ServerName: "127.0.0.1", HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.WriteFrame(protocol.MsgClientHello, 1, &protocol.ClientHello{
		ClientID: id, ProtocolVersion: protocol.ProtocolVersion, Name: "policy-test",
	})
	env2, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if env2.Type != protocol.MsgServerHello {
		t.Fatalf("expected server_hello, got %s", env2.Type)
	}
	return conn, id
}

func registerRaw(t *testing.T, conn *transport.Conn, name, typ string, port int, local protocol.LocalTarget, host string) protocol.RegisterTunnelResp {
	t.Helper()
	req := &protocol.RegisterTunnel{Name: name, Type: typ, RemotePort: port, Local: local}
	if host != "" {
		req.HTTP = &protocol.HTTPConfig{Host: host}
	}
	_ = conn.WriteFrame(protocol.MsgRegisterTunnel, 7, req)
	env, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var resp protocol.RegisterTunnelResp
	if err := env.DecodePayload(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestPolicyTargetNotAllowed: server-side allowed_targets enforcement at
// registration (T6) — an origin outside the allow-list is refused.
func TestPolicyTargetNotAllowed(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.SetPolicyForTests(protocol.Policy{AllowedPorts: []string{"20000-29999"}, AllowedTargets: []string{"10.0.0.0/8:*"}})

	conn, _ := dialControl(t, env)
	defer conn.Close()
	resp := registerRaw(t, conn, "out", "tcp", 20001,
		protocol.LocalTarget{IP: "127.0.0.1", Port: 80}, "")
	if resp.OK || resp.Error == nil || resp.Error.Code != protocol.ErrCodeTargetNotAllowed {
		t.Fatalf("target outside allow-list must be refused with ERR_TARGET_NOT_ALLOWED, got %+v", resp)
	}
	// inside the allow-list passes
	env.srv.SetPolicyForTests(protocol.Policy{AllowedPorts: []string{"20000-29999"}, MaxConns: 100, MaxConnsTunnel: 100, AllowedTargets: []string{"127.0.0.0/8:*"}})
	resp = registerRaw(t, conn, "in", "tcp", 20002,
		protocol.LocalTarget{IP: "127.0.0.1", Port: 80}, "")
	if !resp.OK {
		t.Fatalf("target inside allow-list must pass, got %+v", resp)
	}
}

// TestPolicyConnLimitPerTunnel: exceeding the per-tunnel concurrency quota
// is rejected immediately (no queuing, T9).
func TestPolicyConnLimitPerTunnel(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.SetPolicyForTests(protocol.Policy{
		AllowedPorts:   []string{"20000-29999"},
		MaxConns:       100,
		MaxConnsTunnel: 2,
		AllowedTargets: []string{"127.0.0.0/8:*"},
	})
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "lim", Type: "tcp", RemotePort: 20001, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	var success, rejected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", "127.0.0.1:20001")
			if err != nil {
				rejected.Add(1)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ping")); err != nil {
				rejected.Add(1)
				return
			}
			buf := make([]byte, 4)
			if _, err := conn.Read(buf); err == nil && string(buf) == "ping" {
				success.Add(1)
			} else {
				rejected.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 2 {
		t.Fatalf("exactly 2 connections must succeed, got %d (rejected %d)", success.Load(), rejected.Load())
	}
	if rejected.Load() != 3 {
		t.Fatalf("3 connections must be rejected, got %d", rejected.Load())
	}
}

// TestPolicyBandwidthLimit: sustained traffic is shaped within ±10% of the
// per-client rate limit (read-side shaping on the public conn).
func TestPolicyBandwidthLimit(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	const bps = int64(50_000) // 50 KB/s
	env.srv.SetPolicyForTests(protocol.Policy{
		AllowedPorts:   []string{"20000-29999"},
		MaxConns:       100,
		MaxConnsTunnel: 100,
		BandwidthBPS:   bps,
		AllowedTargets: []string{"127.0.0.0/8:*"},
	})
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "bw", Type: "tcp", RemotePort: 20010, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	// 200 KB echoed through the shaped public conn: ~4s per direction
	const size = 200 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	conn, err := net.Dial("tcp", "127.0.0.1:20010")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, size)
	if _, err := readFull(conn, got); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// two directions at bps => total ~2*size/bps = 8s
	want := 2 * float64(size) / float64(bps)
	if elapsed < time.Duration(want*0.9*float64(time.Second)) || elapsed > time.Duration(want*1.1*float64(time.Second)) {
		t.Fatalf("rate not shaped within ±10%%: elapsed %.2fs, want ~%.2fs", elapsed.Seconds(), want)
	}
	if string(got) != string(payload) {
		t.Fatal("data corrupted by shaping wrapper")
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := conn.Read(buf[n:])
		if err != nil {
			return n, err
		}
		n += m
	}
	return n, nil
}

// TestPolicyRegisterRateLimit: a flood of register/unregister is refused
// with ERR_RATE_LIMITED (T9).
func TestPolicyRegisterRateLimit(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	conn, _ := dialControl(t, env)
	defer conn.Close()
	rateLimited := 0
	ok := 0
	for i := 0; i < 60; i++ {
		resp := registerRaw(t, conn, fmt.Sprintf("r%d", i), "tcp", 20050+i,
			protocol.LocalTarget{IP: "127.0.0.1", Port: 80}, "")
		if resp.Error != nil && resp.Error.Code == protocol.ErrCodeRateLimited {
			rateLimited++
		} else if resp.OK {
			ok++
		}
	}
	if rateLimited == 0 {
		t.Fatalf("register flood must trigger ERR_RATE_LIMITED (ok=%d)", ok)
	}
}

// TestPolicyFloodAvailability: half-open connections occupying the public
// listener must not starve established tunnels — legitimate traffic keeps
// forwarding (availability, T9).
func TestPolicyFloodAvailability(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "fl", Type: "tcp", RemotePort: 20060, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	// hold 8 half-open connections (under the 16/IP gate cap): they occupy
	// concurrency slots but send nothing
	var flood []net.Conn
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:20060", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		flood = append(flood, c)
	}
	defer func() {
		for _, c := range flood {
			_ = c.Close()
		}
	}()

	// legitimate traffic must keep working under the pressure
	for i := 0; i < 5; i++ {
		roundTrip(t, 20060, []byte(fmt.Sprintf("legit-%d", i)))
		time.Sleep(100 * time.Millisecond)
	}
}

// TestPolicyConnLimitReleases: the quota is released when connections end,
// so the tunnel accepts new connections after a burst (no leak, T10).
func TestPolicyConnLimitReleases(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.SetPolicyForTests(protocol.Policy{
		AllowedPorts:   []string{"20000-29999"},
		MaxConns:       100,
		MaxConnsTunnel: 2,
		AllowedTargets: []string{"127.0.0.0/8:*"},
	})
	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	_, cancel, errCh := startClient(t, env, []clientcore.TunnelSpec{
		{Name: "rel", Type: "tcp", RemotePort: 20070, LocalIP: "127.0.0.1", LocalPort: echoPort, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	for round := 0; round < 3; round++ {
		// two connections complete and close
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := net.Dial("tcp", "127.0.0.1:20070")
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = c.Write([]byte("hi"))
				buf := make([]byte, 2)
				_, _ = c.Read(buf)
			}()
		}
		wg.Wait()
		// the next connection must succeed once the splice releases the
		// quota (teardown is asynchronous: retry briefly)
		roundTripRetry(t, 20070, []byte("again"), 10, 300*time.Millisecond)
	}
}

// roundTripRetry retries roundTrip until it succeeds or the budget is spent.
func roundTripRetry(t *testing.T, publicPort int, payload []byte, tries int, gap time.Duration) {
	t.Helper()
	for i := 0; i < tries; i++ {
		if roundTripNoFatal(publicPort, payload) {
			return
		}
		time.Sleep(gap)
	}
	t.Fatalf("round trip %q failed after %d tries", payload, tries)
}

// roundTripNoFatal performs one round trip; returns success without failing.
func roundTripNoFatal(publicPort int, payload []byte) bool {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	got := make([]byte, len(payload))
	n := 0
	for n < len(payload) {
		m, err := conn.Read(got[n:])
		if err != nil {
			return false
		}
		n += m
	}
	return string(got) == string(payload)
}
