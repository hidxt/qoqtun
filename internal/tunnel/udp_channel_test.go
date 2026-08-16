package tunnel

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestUDPChannelRebuild: when the UDP data channel drops, the channel is
// cleared and OnUDPChannelClosed fires so the control plane rebuilds it.
func TestUDPChannelRebuild(t *testing.T) {
	m := NewManager(slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rebuildCalled := make(chan *Tunnel, 1)
	m.OnUDPChannelClosed = func(t *Tunnel) {
		rebuildCalled <- t
	}

	// ephemeral udp port
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	tun, err := m.Register(ctx, "udp1", "udp", port, []string{"*"}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Unregister(tun.ID) })

	// channel over a real TCP pair (server side feeds the read loop)
	lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lst.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := lst.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()
	clientEnd, err := net.Dial("tcp", lst.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverEnd := <-accepted
	m.SetUDPChannel(ctx, tun, serverEnd)

	// drop the channel from the client side
	_ = clientEnd.Close()
	_ = serverEnd.SetReadDeadline(time.Now().Add(time.Second))
	probeBuf := make([]byte, 4)
	if _, rerr := serverEnd.Read(probeBuf); rerr == nil {
		t.Log("serverEnd read returned nil after close (unexpected)")
	} else {
		t.Logf("serverEnd read after close: %v", rerr)
	}

	select {
	case rebuilt := <-rebuildCalled:
		if rebuilt != tun {
			t.Fatal("callback got wrong tunnel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnUDPChannelClosed not called after channel drop")
	}
	tun.chMu.Lock()
	cleared := tun.ch == nil
	tun.chMu.Unlock()
	if !cleared {
		t.Fatal("channel must be cleared after drop")
	}
}

// TestUDPChannelCarriesFrames: a frame written by the manager's channel
// read loop is delivered to the peer (return path).
func TestUDPChannelCarriesFrames(t *testing.T) {
	m := NewManager(slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	tun, err := m.Register(ctx, "udp2", "udp", port, []string{"*"}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Unregister(tun.ID) })

	serverEnd, clientEnd := net.Pipe()
	m.SetUDPChannel(ctx, tun, serverEnd)
	defer clientEnd.Close()

	// a public peer sends a datagram through the public UDP listener
	peerConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	if _, err := peerConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	// the frame must arrive on the client side of the channel
	buf := make([]byte, 64)
	_ = clientEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := clientEnd.Read(buf)
	if err != nil {
		t.Fatalf("channel frame not received: %v", err)
	}
	sessID, payload, err := readUDPFrame(bytes.NewReader(buf[:n]), 1500)
	if err != nil {
		t.Fatalf("bad frame: %v", err)
	}
	if len(sessID) != 16 || string(payload) != "ping" {
		t.Fatalf("frame mismatch: payload=%q", payload)
	}
}
