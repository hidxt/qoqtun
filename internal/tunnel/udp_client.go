package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/protocol"
	"github.com/hidxt/qoqtun/internal/transport"
)

// udpLocalConn is one client-side UDP socket to the local service for a
// session (UDP-in-TCP data channel, 04 §6).
type udpLocalConn struct {
	conn *net.UDPConn
	// responses are read by a per-conn goroutine that frames them back.
	done chan struct{}
}

// HandleUDPOpenConnection establishes the persistent mTLS UDP data channel
// for a tunnel: after the open_data first frame, the channel carries
// [4B len][session_id 16B][payload] frames in both directions.
func (c *Client) HandleUDPOpenConnection(ctx context.Context, oc *protocol.OpenConnection) error {
	tc, ok := c.Get(oc.TunnelID)
	if !ok {
		return fmt.Errorf("unknown tunnel %s", oc.TunnelID)
	}
	if err := c.checkACL(tc.LocalIP, tc.LocalPort); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		return fmt.Errorf("invalid server addr: %w", err)
	}
	ch, err := transport.Dial("tcp", c.ServerAddr, transport.Options{
		CAs:              c.CAs,
		Cert:             c.Cert,
		Key:              c.Key,
		ServerName:       host,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("dial udp channel: %w", err)
	}
	c.trackData(ch)
	defer c.untrackData(ch)
	if err := ch.WriteFrame(protocol.MsgOpenData, 0, &protocol.OpenData{
		ConnID: oc.ConnID, TunnelID: oc.TunnelID,
	}); err != nil {
		ch.Close()
		return err
	}
	c.Log.Info("udp channel established", "tunnel", tc.Name, "conn_id", oc.ConnID[:8])

	local, err := net.ResolveUDPAddr("udp", net.JoinHostPort(tc.LocalIP, fmt.Sprintf("%d", tc.LocalPort)))
	if err != nil {
		ch.Close()
		return fmt.Errorf("resolve local udp: %w", err)
	}

	var (
		mu    sync.Mutex
		conns = make(map[string]*udpLocalConn) // session id hex -> socket
	)
	// local response goroutine: any local UDP response is framed back.
	readLocal := func(sessHex string, lc *udpLocalConn) {
		defer func() {
			mu.Lock()
			delete(conns, sessHex)
			mu.Unlock()
			_ = lc.conn.Close()
			close(lc.done)
		}()
		buf := make([]byte, 65535)
		for {
			n, err := lc.conn.Read(buf)
			if err != nil {
				return
			}
			if n > c.maxUDPMaxPacket() {
				continue // oversized: drop (matches server max_packet)
			}
			frame, ferr := udpFrame([]byte(sessHex), buf[:n])
			if ferr != nil {
				continue
			}
			if _, werr := ch.Write(frame); werr != nil {
				return
			}
		}
	}

	// channel -> local: dispatch frames by session id
	for {
		sessID, payload, err := readUDPFrame(ch, c.maxUDPMaxPacket())
		if err != nil {
			break
		}
		hex := string(sessID)
		mu.Lock()
		lc := conns[hex]
		mu.Unlock()
		if lc == nil {
			// new session: connected UDP socket to the local service
			uc, err := net.DialUDP("udp", nil, local)
			if err != nil {
				continue
			}
			lc = &udpLocalConn{conn: uc, done: make(chan struct{})}
			mu.Lock()
			conns[hex] = lc
			mu.Unlock()
			go readLocal(hex, lc)
		}
		if _, err := lc.conn.Write(payload); err != nil {
			// local unreachable: session dies with the socket
			continue
		}
	}

	// channel closed: close every local socket
	mu.Lock()
	for _, lc := range conns {
		_ = lc.conn.Close()
	}
	conns = make(map[string]*udpLocalConn)
	mu.Unlock()
	return nil
}

// maxUDPMaxPacket is the channel frame payload cap (matches the server's
// default policy; Phase 9 wires the negotiated policy value).
func (c *Client) maxUDPMaxPacket() int {
	return 1500
}
