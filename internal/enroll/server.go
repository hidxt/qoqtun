package enroll

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/auth"
	"github.com/hidxt/qoqtun/internal/pki"
)

// Server is the server-side enrollment/renewal endpoint.
type Server struct {
	Addr            string
	Cert            *x509.Certificate
	CertPEM, KeyPEM []byte

	CA       *pki.CA
	Tokens   *auth.TokenStore
	Registry *pki.ClientRegistry
	Revoked  *pki.RevocationList

	ClientCertValidityDays int
	Limiter                *IPLimiter
	Log                    *slog.Logger
}

// handlerTimeout bounds an unauthenticated enroll connection (T9).
const handlerTimeout = 15 * time.Second

// TLSConfig builds the server TLS config (TLS 1.3, request client certs,
// verify chain + revocation when present).
func (s *Server) TLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(s.CertPEM, s.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("enroll: load server keypair: %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(s.CA.Cert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// VerifyClientCertIfGiven: enroll works without a client certificate;
		// renew REQUIRES one and, when presented, it is verified against the
		// CA and the revocation list (below).
		ClientAuth:            tls.VerifyClientCertIfGiven,
		ClientCAs:             caPool,
		VerifyPeerCertificate: s.verifyPeerCertificate,
	}, nil
}

// ListenAndServe starts the TLS listener until ctx is cancelled or a fatal
// error occurs.
func (s *Server) ListenAndServe(ctx context.Context) error {
	tlsCfg, err := s.TLSConfig()
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", s.Addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("enroll: listen on %s: %w", s.Addr, err)
	}
	defer ln.Close()
	return s.Serve(ctx, ln)
}

// Serve accepts connections on an already-created listener (tests bind an
// ephemeral port and call Serve directly).
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.Log.Info("enroll listener started", "addr", ln.Addr().String())
	var wg sync.WaitGroup
	// Closing the listener unblocks Accept when ctx is cancelled.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("enroll: accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// verifyPeerCertificate enforces chain-to-CA and revocation for any client
// certificate presented during the TLS handshake.
func (s *Server) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	s.Log.Debug("enroll: verifyPeerCertificate", "raw_certs", len(rawCerts))
	if len(rawCerts) == 0 {
		return nil // no client cert: enroll path, validated in the handler
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("enroll: parse client cert: %w", err)
	}
	if err := pki.VerifyClientCertificate(cert, s.CA.Cert); err != nil {
		return err
	}
	serial := cert.SerialNumber.String()
	s.Log.Debug("enroll: verifyPeerCertificate check", "serial", serial, "revoked", s.Revoked.IsRevoked(serial))
	if s.Revoked.IsRevoked(serial) {
		return fmt.Errorf("enroll: client certificate revoked")
	}
	return nil
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handlerTimeout))

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	if !s.Limiter.Allow(host) {
		s.writeResponse(conn, errResponse(ErrCodeRateLimited, "too many requests, try again later"))
		return
	}

	var req Request
	if err := readFrame(conn, &req); err != nil {
		s.Limiter.Report(host, false)
		return
	}

	var resp *Response
	switch req.Type {
	case "enroll":
		resp = s.handleEnroll(host, &req)
	case "renew":
		resp = s.handleRenew(conn, &req)
	default:
		resp = errResponse(ErrCodeBadRequest, "unknown request type")
		s.Limiter.Report(host, false)
	}
	if resp == nil {
		resp = errResponse(ErrCodeInternal, "internal error")
	}
	s.Limiter.Report(host, resp.OK)
	s.writeResponse(conn, resp)
}

func (s *Server) writeResponse(conn net.Conn, resp *Response) {
	if err := writeFrame(conn, resp); err != nil {
		s.Log.Warn("enroll: write response", "error", err)
	}
}

func (s *Server) handleEnroll(host string, req *Request) *Response {
	// 1. token: atomic consume (first caller wins, no double-spend)
	if _, err := s.Tokens.Consume(req.Token); err != nil {
		switch {
		case errors.Is(err, auth.ErrTokenInvalid):
			return errResponse(ErrCodeTokenInvalid, "invalid token")
		case errors.Is(err, auth.ErrTokenExpired):
			return errResponse(ErrCodeTokenExpired, "token expired")
		case errors.Is(err, auth.ErrTokenUsed):
			return errResponse(ErrCodeTokenUsed, "token already used")
		case errors.Is(err, auth.ErrTokenRevoked):
			return errResponse(ErrCodeTokenInvalid, "invalid token")
		default:
			s.Log.Error("enroll: token store error", "error", err, "ip", host)
			return errResponse(ErrCodeInternal, "internal error")
		}
	}

	// 2. CSR: parse, POP, algorithm, CN
	certPEM, expiresAt, clientID, err := s.signFromCSR(req.CSR)
	if err != nil {
		return errResponse(ErrCodeBadRequest, err.Error())
	}

	// 3. client_id conflict
	if s.Registry.Exists(clientID) {
		return errResponse(ErrCodeNameConflict, "client id already registered")
	}

	// 4. persist registry
	rec := pki.ClientRecord{
		ClientID:   clientID,
		Name:       req.Meta.Name,
		Note:       req.Meta.Note,
		CertSerial: certSerial(clientID, certPEM),
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.Registry.Add(rec); err != nil {
		s.Log.Error("enroll: registry add", "error", err)
		return errResponse(ErrCodeInternal, "internal error")
	}

	return &Response{
		OK:         true,
		ClientCert: string(certPEM),
		CACert:     string(pkiCertPEM(s.CA)),
		ExpiresAt:  expiresAt,
	}
}

// handleRenew requires a valid mTLS client certificate (verified at
// handshake); the old certificate's identity is reused.
func (s *Server) handleRenew(conn net.Conn, req *Request) *Response {
	tlsState, ok := conn.(*tls.Conn)
	if !ok || len(tlsState.ConnectionState().PeerCertificates) == 0 {
		return errResponse(ErrCodeAuthFailed, "client certificate required for renewal")
	}
	oldCert := tlsState.ConnectionState().PeerCertificates[0]
	clientID := oldCert.Subject.CommonName
	if s.Revoked.IsRevoked(oldCert.SerialNumber.String()) {
		return errResponse(ErrCodeCertRevoked, "certificate revoked")
	}

	certPEM, expiresAt, cn, err := s.signFromCSR(req.CSR)
	if err != nil {
		return errResponse(ErrCodeBadRequest, err.Error())
	}
	if cn != clientID {
		return errResponse(ErrCodeBadRequest, "CSR identity does not match the authenticated client")
	}
	// keep the registry in sync with the new serial
	if rec, ok := s.Registry.Get(clientID); ok {
		rec.CertSerial = certSerial(clientID, certPEM)
		_ = s.Registry.Add(rec) // best-effort: cert issuance already succeeded
	}
	return &Response{
		OK:         true,
		ClientCert: string(certPEM),
		CACert:     string(pkiCertPEM(s.CA)),
		ExpiresAt:  expiresAt,
	}
}

// signFromCSR validates a CSR (parse, POP, Ed25519, CN format) and signs a
// client certificate. Returns the cert PEM, RFC3339 expiry and the client id.
func (s *Server) signFromCSR(csrPEM string) ([]byte, string, string, error) {
	certPEM, err := pki.SignClientCertificate(s.CA, []byte(csrPEM), s.ClientCertValidityDays)
	if err != nil {
		return nil, "", "", err
	}
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return nil, "", "", fmt.Errorf("internal: %w", err)
	}
	return certPEM, cert.NotAfter.UTC().Format(time.RFC3339), cert.Subject.CommonName, nil
}

func certSerial(_ string, certPEM []byte) string {
	cert, err := pki.ParseCertificate(certPEM)
	if err != nil {
		return ""
	}
	return cert.SerialNumber.String()
}

func pkiCertPEM(ca *pki.CA) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}
