package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hidxt/qoqtun/internal/pki"
)

// Client performs enrollment / renewal against an enroll server.
type Client struct {
	ServerAddr string
	// Dial is injectable for tests (nil => net.Dialer with timeout).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Result carries the enrolled identity.
type Result struct {
	ClientID  string
	CertPath  string
	CAPath    string
	ExpiresAt time.Time
	// ClientCertPEM / CACertPEM are the raw response payloads.
	ClientCertPEM []byte
	CACertPEM     []byte
	// CAFingerprint is the observed server CA fingerprint (for pinning).
	CAFingerprint string
}

// EnrollOptions configure a single enroll call.
type EnrollOptions struct {
	Token string
	CSR   []byte
	Meta  Meta
	// CAFingerprint pins the server CA (64 hex chars). When empty, TOFU is
	// applied and the observed fingerprint is returned for the caller to
	// persist; callers MUST record it and verify on subsequent connections.
	CAFingerprint string
	// ClientCert is the existing client certificate for renew (mTLS).
	ClientCert []byte
	ClientKey  ed25519.PrivateKey
	// Timeout bounds the whole exchange.
	Timeout time.Duration
}

// Enroll sends the CSR with a one-time token and verifies the returned
// certificate chain (03-pki-enrollment.md §4): chains to the received CA,
// CN == our client id, public key matches our local private key.
func (c *Client) Enroll(ctx context.Context, opts EnrollOptions) (*Result, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dial := c.Dial
	if dial == nil {
		d := net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}

	serverName, _, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("enroll: invalid server addr: %w", err)
	}
	var observedServerFP string
	tlsCfg, err := c.tlsConfig(serverName, opts, &observedServerFP)
	if err != nil {
		return nil, err
	}
	rawConn, err := dial(ctx, "tcp", c.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("enroll: dial %s: %w", c.ServerAddr, err)
	}
	conn := tls.Client(rawConn, tlsCfg)
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("enroll: TLS handshake: %w", err)
	}

	req := Request{Type: "enroll", Token: opts.Token, CSR: string(opts.CSR), Meta: opts.Meta}
	if len(opts.ClientCert) > 0 {
		req.Type = "renew"
	}
	if err := writeFrame(conn, &req); err != nil {
		return nil, err
	}
	var resp Response
	if err := readFrame(conn, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error != nil {
			return nil, fmt.Errorf("enroll: server refused: %s: %s", resp.Error.Code, resp.Error.Message)
		}
		return nil, fmt.Errorf("enroll: server refused")
	}

	// verify the returned chain
	clientCert, err := pki.ParseCertificate([]byte(resp.ClientCert))
	if err != nil {
		return nil, fmt.Errorf("enroll: bad client cert in response: %w", err)
	}
	caCert, err := pki.ParseCertificate([]byte(resp.CACert))
	if err != nil {
		return nil, fmt.Errorf("enroll: bad CA cert in response: %w", err)
	}
	if err := pki.VerifyChain(clientCert, caCert); err != nil {
		return nil, fmt.Errorf("enroll: returned chain does not verify: %w", err)
	}
	if clientCert.Subject.CommonName == "" {
		return nil, fmt.Errorf("enroll: certificate missing client id")
	}
	if len(opts.ClientKey) > 0 {
		pub := opts.ClientKey.Public().(ed25519.PublicKey)
		certPub, ok := clientCert.PublicKey.(ed25519.PublicKey)
		if !ok || !pub.Equal(certPub) {
			return nil, fmt.Errorf("enroll: certificate public key does not match local private key")
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		expiresAt = clientCert.NotAfter
	}
	return &Result{
		ClientID:      clientCert.Subject.CommonName,
		ExpiresAt:     expiresAt,
		ClientCertPEM: []byte(resp.ClientCert),
		CACertPEM:     []byte(resp.CACert),
		CAFingerprint: observedServerFP,
	}, nil
}

// tlsConfig builds the client TLS config. The trust anchor is the server
// certificate fingerprint (pinned or TOFU): qoqtun runs a private PKI, so
// the fingerprint is the identity and no SAN/hostname configuration burden
// is imposed on the operator. With a pinned fingerprint, mismatches are
// rejected; without one (TOFU), the observed fingerprint is captured for
// the caller to persist and pin on the next connection.
func (c *Client) tlsConfig(serverName string, opts EnrollOptions, observedFP *string) (*tls.Config, error) {
	expectedFP := opts.CAFingerprint
	var clientCert *tls.Certificate
	if len(opts.ClientCert) > 0 && len(opts.ClientKey) > 0 {
		keyDER, err := x509.MarshalPKCS8PrivateKey(opts.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("enroll: marshal client key: %w", err)
		}
		cert, err := tls.X509KeyPair(opts.ClientCert, pemEncodeKey(keyDER))
		if err != nil {
			return nil, fmt.Errorf("enroll: build client keypair: %w", err)
		}
		clientCert = &cert
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		Certificates: func() []tls.Certificate {
			if clientCert != nil {
				return []tls.Certificate{*clientCert}
			}
			return nil
		}(),
		// Custom verification (below) is mandatory; never system roots.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("enroll: server presented no certificate")
			}
			serverCert := cs.PeerCertificates[0]
			fp := pki.Fingerprint(serverCert)
			if observedFP != nil {
				*observedFP = fp
			}
			if expectedFP != "" && fp != expectedFP {
				return fmt.Errorf("enroll: server fingerprint mismatch (pinned %s, got %s)", expectedFP, fp)
			}
			return nil
		},
	}, nil
}

// pemEncodeKey wraps PKCS#8 DER as PEM.
func pemEncodeKey(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Save writes the enrolled certificate, the CA certificate and the identity
// state file. certPath/caPath are 0644; statePath is 0600.
func (r *Result) Save(clientCertPEM, caCertPEM []byte, certPath, caPath, statePath string, state any) error {
	if err := writeFile(certPath, clientCertPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(caPath, caCertPEM, 0o644); err != nil {
		return err
	}
	if state != nil {
		data, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return fmt.Errorf("enroll: marshal state: %w", err)
		}
		if err := writeFile(statePath, append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("enroll: create dir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("enroll: write %s: %w", path, err)
	}
	return nil
}

// FingerprintPEM computes the SHA-256 fingerprint of a PEM certificate,
// normalizing to the colon format (used for pinning comparisons).
func FingerprintPEM(certPEM []byte) (string, error) {
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return "", err
	}
	return pki.Fingerprint(cert), nil
}
