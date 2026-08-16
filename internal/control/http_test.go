package control_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
	"github.com/hidxt/qoqtun/internal/pki"
)

// ---- local HTTP echo service ----

// startHTTPEchoService serves a single GET request and replies with a body
// echoing the received Host header and request path.
func startHTTPEchoService(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				reqLine, err := br.ReadString('\n')
				if err != nil {
					return
				}
				host := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						host = strings.TrimSpace(line[len("host:"):])
					}
				}
				path := ""
				parts := strings.Fields(reqLine)
				if len(parts) >= 2 {
					path = parts[1]
				}
				body := fmt.Sprintf("echo host=%s path=%s", host, path)
				_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

// httpGetText dials port with a plain HTTP GET and returns the raw response.
func httpGetText(t *testing.T, port int, host, path string) string {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	all, _ := io.ReadAll(conn)
	return string(all)
}

func vhostClient(t *testing.T, env *testEnv, tunnels []clientcore.TunnelSpec) (*clientcore.Client, context.CancelFunc, chan error) {
	t.Helper()
	key, id, certPEM := env.newClientCert(t)
	client := &clientcore.Client{
		ServerAddr: env.addr,
		CAs:        []*x509.Certificate{env.ca.Cert},
		Cert:       certPEM,
		Key:        keyPEM(t, key),
		ClientID:   id,
		Name:       "http-client",
		Tunnels:    tunnels,
		Log:        discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- client.Run(ctx) }()
	return client, cancel, errCh
}

func waitVhostCount(t *testing.T, env *testEnv, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if env.srv.VhostCount() == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("vhost count = %d, want %d", env.srv.VhostCount(), want)
}

// TestHTTPVhostMultiHost routes two Hosts to two different local services
// on the single shared vhost port.
func TestHTTPVhostMultiHost(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	pA, stopA := startHTTPEchoService(t)
	defer stopA()
	pB, stopB := startHTTPEchoService(t)
	defer stopB()

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "siteA", Type: "http", RemotePort: 0, HTTPHost: "a.example.com", LocalIP: "127.0.0.1", LocalPort: pA, Enabled: true},
		{Name: "siteB", Type: "http", RemotePort: 0, HTTPHost: "b.example.com", LocalIP: "127.0.0.1", LocalPort: pB, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 2, 5*time.Second)

	resp := httpGetText(t, env.srv.VhostPort, "a.example.com", "/index.html")
	if !strings.Contains(resp, "echo host=a.example.com path=/index.html") {
		t.Fatalf("site A routing wrong: %q", resp)
	}
	resp = httpGetText(t, env.srv.VhostPort, "b.example.com", "/api")
	if !strings.Contains(resp, "echo host=b.example.com path=/api") {
		t.Fatalf("site B routing wrong: %q", resp)
	}
}

// TestHTTPVhostNormalization: registration and lookup both normalize case,
// ports and trailing dots.
func TestHTTPVhostNormalization(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	p, stop := startHTTPEchoService(t)
	defer stop()

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "site", Type: "http", RemotePort: 0, HTTPHost: "API.Example.COM.", LocalIP: "127.0.0.1", LocalPort: p, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	// request with mixed case, explicit port and trailing dot
	resp := httpGetText(t, env.srv.VhostPort, "api.example.com.:8080", "/x")
	if !strings.Contains(resp, "echo host=api.example.com.:8080 path=/x") {
		t.Fatalf("normalized routing failed: %q", resp)
	}
}

// TestHTTPVhostUnknownHost returns 421 for an unregistered host.
func TestHTTPVhostUnknownHost(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "site", Type: "http", RemotePort: 0, HTTPHost: "known.example.com", LocalIP: "127.0.0.1", LocalPort: freePortInRange(t), Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	resp := httpGetText(t, env.srv.VhostPort, "unknown.example.com", "/")
	if !strings.HasPrefix(resp, "HTTP/1.1 421") {
		t.Fatalf("unknown host: got %q, want 421", resp)
	}
}

// TestHTTPVhostConflict: the second registration of the same host loses
// (ERR_NAME_CONFLICT server-side; the vhost table keeps one entry).
func TestHTTPVhostConflict(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "site", Type: "http", RemotePort: 0, HTTPHost: "dup.example.com", LocalIP: "127.0.0.1", LocalPort: freePortInRange(t), Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	// a second client claims the same host: it must lose
	_, cancel2, errCh2 := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "impostor", Type: "http", RemotePort: 0, HTTPHost: "dup.example.com", LocalIP: "127.0.0.1", LocalPort: freePortInRange(t), Enabled: true},
	})
	defer waitClientExit(cancel2, errCh2)
	time.Sleep(800 * time.Millisecond)
	if got := env.srv.VhostCount(); got != 1 {
		t.Fatalf("vhost count after conflict = %d, want 1", got)
	}
}

// TestHTTPVhostWebSocketUpgrade: an Upgrade request (WebSocket handshake)
// is passed through verbatim and frames flow bidirectionally.
func TestHTTPVhostWebSocketUpgrade(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	// local "upgrade echo": replies 101 then echoes raw bytes
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var head []byte
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head = append(head, []byte(line)...)
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				if !strings.Contains(strings.ToLower(string(head)), "upgrade: websocket") {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "ws", Type: "http", RemotePort: 0, HTTPHost: "ws.example.com", LocalIP: "127.0.0.1", LocalPort: ln.Addr().(*net.TCPAddr).Port, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.srv.VhostPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade rejected: %q", status)
	}
	// drain the remaining 101 headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	// bidirectional frames (raw bytes echoed)
	frame := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(frame) {
		t.Fatalf("echoed frame mismatch: %x vs %x", got, frame)
	}
}

// TestHTTPVhostSSEKeepAlive: a long-lived streaming response survives far
// beyond the heartbeat window (heartbeat interval is 1s; the stream must
// stay open for 12s, proving no premature teardown).
func TestHTTPVhostSSEKeepAlive(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n")
				tick := time.NewTicker(300 * time.Millisecond)
				defer tick.Stop()
				for i := 0; ; i++ {
					select {
					case <-tick.C:
						_, _ = fmt.Fprintf(c, "data: event-%d\n\n", i)
					case <-time.After(2 * time.Second):
						return
					}
				}
			}(c)
		}
	}()

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "sse", Type: "http", RemotePort: 0, HTTPHost: "sse.example.com", LocalIP: "127.0.0.1", LocalPort: ln.Addr().(*net.TCPAddr).Port, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.srv.VhostPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.WriteString(conn, "GET /stream HTTP/1.1\r\nHost: sse.example.com\r\nConnection: keep-alive\r\n\r\n")
	br := bufio.NewReader(conn)
	if !strings.HasPrefix(mustReadLine(t, br), "HTTP/1.1 200") {
		t.Fatal("SSE not accepted")
	}
	for i := 0; i < 4; i++ { // drain headers
		if mustReadLine(t, br) == "" {
			break
		}
	}
	// collect events for 12s (12x beyond the 1s heartbeat window)
	events := 0
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("SSE stream broke after %d events: %v", events, err)
		}
		if strings.HasPrefix(line, "data: event-") {
			events++
		}
	}
	if events < 10 {
		t.Fatalf("too few events over 12s: %d", events)
	}
}

func mustReadLine(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
}

// TestHTTPVhostLargeHeader: a request head exceeding 8KiB is rejected.
func TestHTTPVhostLargeHeader(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "site", Type: "http", RemotePort: 0, HTTPHost: "big.example.com", LocalIP: "127.0.0.1", LocalPort: freePortInRange(t), Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.srv.VhostPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: big.example.com\r\nX-Pad: "+strings.Repeat("z", 9*1024)+"\r\n\r\n")
	all, _ := io.ReadAll(conn)
	if strings.Contains(string(all), "200 OK") {
		t.Fatalf("oversized header must be rejected, got: %.80s", all)
	}
}

// TestHTTPVhostSlowloris: 100 half-open slow connections must not starve
// the vhost port — legitimate requests keep succeeding, and every slow
// connection is reaped within the 5s sniff deadline.
func TestHTTPVhostSlowloris(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()
	env.srv.VhostPort = freePortInRange(t)

	p, stop := startHTTPEchoService(t)
	defer stop()

	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "site", Type: "http", RemotePort: 0, HTTPHost: "ok.example.com", LocalIP: "127.0.0.1", LocalPort: p, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitVhostCount(t, env, 1, 5*time.Second)

	// open 100 slow connections that trickle an incomplete request head
	var slowConns []net.Conn
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", env.srv.VhostPort))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nX-Slow: "+strings.Repeat("s", 32))
		// deliberately no CRLF terminator and no Host: the sniff blocks
		mu.Lock()
		slowConns = append(slowConns, conn)
		mu.Unlock()
	}
	defer func() {
		mu.Lock()
		for _, c := range slowConns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	// legitimate traffic stays healthy while the slithers are in flight
	for i := 0; i < 3; i++ {
		time.Sleep(1500 * time.Millisecond)
		resp := httpGetText(t, env.srv.VhostPort, "ok.example.com", "/alive")
		if !strings.Contains(resp, "echo host=ok.example.com path=/alive") {
			t.Fatalf("legitimate request starved by slowloris: %q", resp)
		}
	}

	// every slow connection must be reaped (deadline) — the 400 response
	// drains first, then EOF proves the server closed it
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		allDead := true
		for _, c := range slowConns {
			if !connReaped(c) {
				allDead = false
			}
		}
		mu.Unlock()
		if allDead {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("slow connections were not reaped")
}

// connReaped reports whether the peer closed the connection (EOF/reset);
// a read timeout means the connection is still alive.
func connReaped(c net.Conn) bool {
	buf := make([]byte, 256)
	for {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := c.Read(buf)
		if err == nil {
			continue // drain any buffered response bytes
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false // still alive
		}
		return true // EOF or reset: reaped
	}
}

// TestHTTPVhostHTTPSPassthrough: type=https is pure L4 — the peer
// certificate observed through the tunnel is the origin's own cert (the
// server never terminates TLS).
func TestHTTPVhostHTTPSPassthrough(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	// origin TLS server with its own self-signed CA
	originCA, err := pki.GenerateCA(365 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	originCert, originKey, err := pki.SignServerCertificate(originCA, 90, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	originPair, err := tls.X509KeyPair(originCert, originKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{originPair}})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsLn.Close()
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()

	publicPort := freePortInRange(t)
	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "tls", Type: "https", RemotePort: publicPort, LocalIP: "127.0.0.1", LocalPort: tlsLn.Addr().(*net.TCPAddr).Port, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	// TLS handshake against the public port, trusting ONLY the origin CA:
	// success proves the tunnel carries the origin's cert end-to-end.
	pool := x509.NewCertPool()
	pool.AddCert(originCA.Cert)
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort), &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("TLS handshake through tunnel failed: %v", err)
	}
	peer := conn.ConnectionState().PeerCertificates[0]
	if !bytes.Equal(peer.Raw, originPair.Leaf.Raw) {
		t.Fatal("TLS was terminated: peer cert differs from the origin cert")
	}
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("tunneled TLS echo failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	_ = conn.Close()
}

// TestHTTPDegradedDedicatedPort: type=http with remote_port>0 behaves like
// a plain TCP tunnel on its own port.
func TestHTTPDegradedDedicatedPort(t *testing.T) {
	env := newTestEnv(t)
	defer env.close()

	p, stop := startHTTPEchoService(t)
	defer stop()

	port := freePortInRange(t)
	_, cancel, errCh := vhostClient(t, env, []clientcore.TunnelSpec{
		{Name: "degraded", Type: "http", RemotePort: port, LocalIP: "127.0.0.1", LocalPort: p, Enabled: true},
	})
	defer waitClientExit(cancel, errCh)
	waitTunnelCount(t, env, 1, 5*time.Second)

	resp := httpGetText(t, port, "anything.example.com", "/via-dedicated-port")
	if !strings.Contains(resp, "echo host=anything.example.com path=/via-dedicated-port") {
		t.Fatalf("degraded http tunnel failed: %q", resp)
	}
}
