// Package clientcore implements the client-side control session
// (04-protocol-v1.md §1/§2/§4): dial, handshake, policy reception and the
// heartbeat loop. Reconnection arrives in Phase 6; for now a dropped
// control connection terminates with an error.
package clientcore

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
)

// Client drives one control session.
type Client struct {
	ServerAddr string
	// mTLS materials.
	CAs       []*x509.Certificate
	Cert, Key []byte
	// Identity (cert CN) and hello metadata.
	ClientID string
	Name     string
	Note     string
	Log      *slog.Logger

	// Heartbeat is the negotiated parameters (filled after handshake).
	Heartbeat protocol.Heartbeat
	// Policy is the server-assigned policy (filled after handshake).
	Policy protocol.Policy

	seq       uint64
	missed    atomic.Int32
	mu        sync.Mutex
	conn      *transport.Conn
	closeOnce sync.Once
}

// Run connects, handshakes and maintains the control session until ctx is
// cancelled or the connection fails (reconnect in Phase 6).
func (c *Client) Run(ctx context.Context) error {
	host, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		return fmt.Errorf("clientcore: invalid server addr: %w", err)
	}
	conn, err := transport.Dial("tcp", c.ServerAddr, transport.Options{
		CAs:              c.CAs,
		Cert:             c.Cert,
		Key:              c.Key,
		ServerName:       host,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("clientcore: dial: %w", err)
	}
	defer conn.Close()
	c.conn = conn
	defer func() {
		c.closeOnce.Do(func() {})
	}()

	// handshake: client_hello
	if err := conn.WriteFrame(protocol.MsgClientHello, c.nextSeq(),
		&protocol.ClientHello{
			ClientID:        c.ClientID,
			ProtocolVersion: protocol.ProtocolVersion,
			Name:            c.Name,
			Note:            c.Note,
		}); err != nil {
		return fmt.Errorf("clientcore: send hello: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	env, err := protocol.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("clientcore: read hello response: %w", err)
	}
	if env.Type == protocol.MsgError {
		var e protocol.Error
		if derr := env.DecodePayload(&e); derr == nil {
			return fmt.Errorf("clientcore: server rejected: %s", e.Message)
		}
		return fmt.Errorf("clientcore: server rejected")
	}
	if env.Type != protocol.MsgServerHello {
		return fmt.Errorf("clientcore: unexpected %s during handshake", env.Type)
	}
	var sh protocol.ServerHello
	if err := env.DecodePayload(&sh); err != nil {
		return fmt.Errorf("clientcore: parse server_hello: %w", err)
	}
	if err := protocol.ValidateServerHello(&sh); err != nil {
		return fmt.Errorf("clientcore: invalid server_hello: %w", err)
	}
	c.Policy = sh.Policy
	c.Heartbeat = sh.Heartbeat
	if c.Heartbeat.IntervalS <= 0 {
		c.Heartbeat.IntervalS = 15
	}
	if c.Heartbeat.TimeoutS <= 0 {
		c.Heartbeat.TimeoutS = 10
	}
	c.Log.Info("control session established", "server", c.ServerAddr,
		"session", sh.SessionID, "max_tunnels", sh.Policy.MaxTunnels)

	// heartbeat loop (client pings at interval)
	ticker := time.NewTicker(time.Duration(c.Heartbeat.IntervalS) * time.Second)
	defer ticker.Stop()

	// read loop: process server frames
	readErr := make(chan error, 1)
	go func() {
		readErr <- c.readLoop()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-readErr:
			return fmt.Errorf("clientcore: control connection lost: %w", err)
		case <-ticker.C:
			if err := conn.WriteFrame(protocol.MsgPing, c.nextSeq(), &protocol.Ping{Echo: "hb"}); err != nil {
				return fmt.Errorf("clientcore: ping failed: %w", err)
			}
			if c.missed.Add(1) > int32(c.Heartbeat.MissThreshold) {
				return fmt.Errorf("clientcore: heartbeat missed %d times", c.missed.Load())
			}
		}
	}
}

// readLoop consumes server frames until the connection dies.
func (c *Client) readLoop() error {
	for {
		env, err := protocol.ReadFrame(c.conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case protocol.MsgPong:
			var p protocol.Pong
			if err := env.DecodePayload(&p); err == nil {
				c.missed.Store(0)
			}
		case protocol.MsgError:
			var e protocol.Error
			if err := env.DecodePayload(&e); err == nil && e.Fatal {
				return fmt.Errorf("server fatal error: %s: %s", e.Code, e.Message)
			}
		case protocol.MsgPolicyUpdate:
			var pu protocol.PolicyUpdate
			if err := env.DecodePayload(&pu); err == nil {
				c.Policy = pu.Policy
				c.Log.Info("policy updated", "max_tunnels", pu.Policy.MaxTunnels)
			}
		case protocol.MsgShutdown:
			return fmt.Errorf("server shutdown")
		default:
			// unknown types are ignored (recoverable, §8)
			c.Log.Warn("clientcore: ignoring message", "type", env.Type)
		}
	}
}

func (c *Client) nextSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	return c.seq
}
