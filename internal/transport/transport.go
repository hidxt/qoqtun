// Package transport provides the mTLS Listener/Dialer used by every qoqtun
// connection (04-protocol-v1.md §1): TLS 1.3, mandatory client certificates,
// CA-pool verification with revocation checking, and peer-identity
// extraction (client_id == certificate CN).
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/protocol"
)

// Options configures both listeners and dialers.
type Options struct {
	// CAs is the trusted CA pool (multiple roots allowed for CA rotation).
	CAs []*x509.Certificate
	// Cert is this peer's certificate (PEM cert chain + private key).
	Cert []byte
	Key  []byte
	// IsRevoked checks a certificate serial against the revocation list
	// (nil disables the check).
	IsRevoked func(serial string) bool
	// ServerName is used by the dialer for SNI (not verified: trust is
	// the CA pool + fingerprint-less private PKI).
	ServerName string
	// HandshakeTimeout bounds the TLS handshake.
	HandshakeTimeout time.Duration
}

// Config builds a *tls.Config from Options.
func Config(o Options) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(o.Cert, o.Key)
	if err != nil {
		return nil, fmt.Errorf("transport: load keypair: %w", err)
	}
	pool := x509.NewCertPool()
	for _, ca := range o.CAs {
		if ca != nil {
			pool.AddCert(ca)
		}
	}
	ht := o.HandshakeTimeout
	if ht == 0 {
		ht = 10 * time.Second
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		RootCAs:      pool,
		ServerName:   o.ServerName,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeer(rawCerts, pool, o.IsRevoked)
		},
	}, nil
}

// verifyPeer enforces chain-to-pool and revocation for a peer certificate.
func verifyPeer(rawCerts [][]byte, pool *x509.CertPool, isRevoked func(string) bool) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("transport: peer presented no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("transport: parse peer cert: %w", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("transport: peer cert chain: %w", err)
	}
	if isRevoked != nil && isRevoked(cert.SerialNumber.String()) {
		return fmt.Errorf("transport: peer certificate revoked")
	}
	return nil
}

// Listener is an mTLS listener that also records the accepted peer.
type Listener struct {
	ln     net.Listener
	tlsCfg *tls.Config
}

// Listen wraps a raw listener with TLS 1.3 + mTLS.
func Listen(raw net.Listener, o Options) (*Listener, error) {
	cfg, err := Config(o)
	if err != nil {
		return nil, err
	}
	ln := tls.NewListener(raw, cfg)
	return &Listener{ln: ln, tlsCfg: cfg}, nil
}

// Accept accepts the next mTLS connection and completes the handshake.
func (l *Listener) Accept() (*Conn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		raw.Close()
		return nil, fmt.Errorf("transport: unexpected connection type")
	}
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("transport: handshake: %w", err)
	}
	return &Conn{Conn: tlsConn, peerCN: peerCN(tlsConn)}, nil
}

// Addr returns the underlying listener address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener.
func (l *Listener) Close() error { return l.ln.Close() }

// Dial establishes an mTLS connection to addr.
func Dial(network, addr string, o Options) (*Conn, error) {
	cfg, err := Config(o)
	if err != nil {
		return nil, err
	}
	raw, err := net.DialTimeout(network, addr, o.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return &Conn{Conn: conn, peerCN: peerCN(conn)}, nil
}

// peerCN extracts the peer client_id from the certificate CN.
func peerCN(conn *tls.Conn) string {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// Conn wraps a TLS connection with write serialization and peer identity.
type Conn struct {
	*tls.Conn
	writeMu sync.Mutex
	peerID  string
	peerCN  string
}

// PeerID returns the peer client_id (certificate CN).
func (c *Conn) PeerID() string { return c.peerCN }

// Write serializes writes (control messages are low frequency; a single
// write mutex keeps the reader and heartbeats race-free).
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.Write(p)
}

// WriteFrame writes a length-prefixed JSON control frame under the lock.
func (c *Conn) WriteFrame(msgType string, seq uint64, payload any) error {
	frame, err := protocol.Encode(msgType, seq, payload)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err = c.Conn.Write(frame)
	return err
}

// SetDeadline applies a deadline to all future IO (04: no unbounded waits).
func (c *Conn) SetDeadline(t time.Time) error { return c.Conn.SetDeadline(t) }

// ReadAll limits a single read to n bytes (oversized frames are protocol
// errors handled by the caller).
func (c *Conn) ReadAll(n int64) ([]byte, error) {
	if n > 64*1024 {
		return nil, fmt.Errorf("transport: read limit exceeds maximum")
	}
	data, err := io.ReadAll(io.LimitReader(c.Conn, n))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > n {
		return nil, fmt.Errorf("transport: read exceeds limit")
	}
	return data, nil
}
