package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestUDPFrameRoundTrip(t *testing.T) {
	id, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 16 {
		t.Fatalf("session id must be 16 bytes, got %d", len(id))
	}
	payload := []byte("hello udp")
	frame, err := udpFrame(id, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotID, gotPayload, err := readUDPFrame(bytes.NewReader(frame), 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotID, id) || !bytes.Equal(gotPayload, payload) {
		t.Fatal("frame round trip mismatch")
	}
}

func TestUDPFrameTooLarge(t *testing.T) {
	id, _ := NewSessionID()
	if _, err := udpFrame(id, make([]byte, udpMaxPacket+1)); err == nil {
		t.Fatal("oversized frame must be rejected")
	}
	// frame payload larger than the read cap is rejected
	frame, _ := udpFrame(id, make([]byte, 2000))
	if _, _, err := readUDPFrame(bytes.NewReader(frame), 1500); err == nil {
		t.Fatal("frame beyond read cap must be rejected")
	}
}

func newTestUDPServer(t *testing.T, maxSessions, maxPacket int, idle time.Duration) *udpServerState {
	t.Helper()
	us, err := newUDPServerState("t_1", 0, maxSessions, maxPacket, idle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(us.close)
	return us
}

func TestSessionMappingAndTouch(t *testing.T) {
	us := newTestUDPServer(t, 4, 1500, time.Hour)
	peer := mustUDPAddr(t, "127.0.0.1:10001")
	now := time.Now()
	s1 := us.sessionFor(peer, now)
	if s1 == nil || len(s1.id) != 16 {
		t.Fatal("session creation failed")
	}
	// same peer -> same session
	s2 := us.sessionFor(peer, now.Add(time.Second))
	if !bytes.Equal(s1.id, s2.id) {
		t.Fatal("same peer must reuse the session")
	}
	// by-id lookup works for return packets
	if us.sessionByID(s1.id) == nil {
		t.Fatal("sessionByID must find the session")
	}
	if us.count() != 1 {
		t.Fatalf("expected 1 session, got %d", us.count())
	}
}

func TestLRUEviction(t *testing.T) {
	us := newTestUDPServer(t, 3, 1500, time.Hour)
	now := time.Now()
	// fill to capacity
	for i := 0; i < 3; i++ {
		us.sessionFor(mustUDPAddr(t, fmt.Sprintf("127.0.0.1:%d", 10000+i)), now)
	}
	// touch the first session (make it most recent)
	first := mustUDPAddr(t, "127.0.0.1:10000")
	us.sessionFor(first, now.Add(time.Second))
	// add a fourth: the least-recently-used (10001) must be evicted
	fourth := mustUDPAddr(t, "127.0.0.1:19999")
	us.sessionFor(fourth, now.Add(2*time.Second))
	if us.count() != 3 {
		t.Fatalf("expected 3 sessions after eviction, got %d", us.count())
	}
	// 10001 evicted: a new packet from it gets a fresh session
	s := us.sessionFor(mustUDPAddr(t, "127.0.0.1:10001"), now.Add(3*time.Second))
	if s == nil {
		t.Fatal("evicted peer must get a new session")
	}
}

func TestIdleExpiry(t *testing.T) {
	us := newTestUDPServer(t, 4, 1500, time.Second)
	now := time.Now()
	us.sessionFor(mustUDPAddr(t, "127.0.0.1:10001"), now)
	us.sessionFor(mustUDPAddr(t, "127.0.0.1:10002"), now)
	// idle timeout passes
	if n := us.expireIdle(now.Add(2 * time.Second)); n != 2 {
		t.Fatalf("expected 2 expired, got %d", n)
	}
	if us.count() != 0 {
		t.Fatalf("sessions must be cleared, got %d", us.count())
	}
}

func TestRateLimit(t *testing.T) {
	us := newTestUDPServer(t, 4, 1500, time.Hour)
	// burst 10 allows the first 10 fast packets
	allowed := 0
	for i := 0; i < 30; i++ {
		if us.rateAllow("192.0.2.1") {
			allowed++
		}
	}
	if allowed == 30 {
		t.Fatal("rate limiter must throttle bursts")
	}
	if allowed < 5 {
		t.Fatalf("burst should allow several packets, got %d", allowed)
	}
}

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
