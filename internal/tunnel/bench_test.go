package tunnel

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

// BenchmarkHostSniff: request-head parsing throughput.
func BenchmarkHostSniff(b *testing.B) {
	head := []byte("GET /index.html HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SniffHost(bytes.NewReader(head), 0); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHostSniffNoHost: worst-case full-header scan (rejected).
func BenchmarkHostSniffNoHost(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 20; i++ {
		sb.WriteString("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	}
	sb.WriteString("\r\n")
	head := []byte(sb.String())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SniffHost(bytes.NewReader(head), 0)
	}
}

// BenchmarkUDPServerThroughput: datagrams through the server state path
// (session map + rate limiter, no channel).
func BenchmarkUDPServerThroughput(b *testing.B) {
	us, err := newUDPServerState("t1", 39990, 256, 1500, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer us.close()
	peer, _ := net.ResolveUDPAddr("udp", "127.0.0.1:39999")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sess := us.sessionFor(peer, time.Now())
		if sess == nil {
			b.Fatal("session nil")
		}
		us.sessionByID(sess.id)
	}
}
