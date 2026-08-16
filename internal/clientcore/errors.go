package clientcore

import (
	"errors"
	"strings"

	"github.com/hidxt/qoqtun/internal/protocol"
)

// ErrGracefulShutdown signals a peer-requested or local graceful stop: the
// manager exits cleanly (nil) without reconnecting.
var ErrGracefulShutdown = errors.New("graceful shutdown")

// ErrPermanent marks errors that must NOT be retried: authentication
// failures, revoked/expired certificates, protocol violations. The caller
// stops reconnecting and exits non-zero (04-protocol-v1.md §4).
type ErrPermanent struct{ Err error }

func (e *ErrPermanent) Error() string { return "permanent error: " + e.Err.Error() }
func (e *ErrPermanent) Unwrap() error { return e.Err }

// ErrTemporary marks transient errors (network, EOF, heartbeat): back off
// and reconnect.
type ErrTemporary struct{ Err error }

func (e *ErrTemporary) Error() string { return "temporary error: " + e.Err.Error() }
func (e *ErrTemporary) Unwrap() error { return e.Err }

// IsPermanent reports whether err (possibly wrapped) is permanent.
func IsPermanent(err error) bool {
	var p *ErrPermanent
	return errors.As(err, &p)
}

// IsTemporary reports whether err (possibly wrapped) is temporary.
func IsTemporary(err error) bool {
	var t *ErrTemporary
	return errors.As(err, &t)
}

// Classify maps an error from a session to permanent or temporary. Network
// errors are temporary; TLS verification / auth / revocation / version /
// protocol errors are permanent.
func Classify(err error) error {
	if err == nil {
		return nil
	}
	if IsPermanent(err) || IsTemporary(err) {
		return err
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	// permanent markers from TLS and the protocol error surface
	permanentMarkers := []string{
		"certificate", "x509", "unknown authority", "bad certificate",
		"permanent", "server rejected", "server fatal error",
		"not allowed", "revoked", "expired", "unsupported protocol version",
	}
	for _, m := range permanentMarkers {
		if strings.Contains(lower, m) {
			return &ErrPermanent{Err: err}
		}
	}
	// protocol error codes that are fatal
	if strings.Contains(msg, protocol.ErrCodeAuthFailed) ||
		strings.Contains(msg, protocol.ErrCodeCertRevoked) ||
		strings.Contains(msg, protocol.ErrCodeCertExpired) ||
		strings.Contains(msg, protocol.ErrCodeVersionUnsupported) {
		return &ErrPermanent{Err: err}
	}
	// everything else (network IO, EOF, timeout, heartbeat) is temporary
	return &ErrTemporary{Err: err}
}
