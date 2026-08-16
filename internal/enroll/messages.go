// Package enroll implements the online certificate enrollment flow
// (03-pki-enrollment.md §4): a TLS 1.3 endpoint issuing client certificates
// in exchange for one-time tokens, plus the client-side enrollment and
// renewal. Framing is 4-byte length prefix + JSON (04-protocol-v1.md).
package enroll

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// maxFrameSize caps control/enroll frames (T9: oversized frames rejected).
const maxFrameSize = 64 * 1024

// Meta carries client-reported metadata at enrollment.
type Meta struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
}

// Request is the wire envelope for both enroll and renew.
type Request struct {
	Type  string `json:"type"` // "enroll" | "renew"
	Token string `json:"token,omitempty"`
	CSR   string `json:"csr"` // PEM-encoded PKCS#10
	Meta  Meta   `json:"meta,omitempty"`
}

// Error is a machine-readable protocol error (04-protocol-v1.md §5).
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is the wire response for enroll and renew.
type Response struct {
	OK         bool   `json:"ok"`
	ClientCert string `json:"client_cert,omitempty"` // PEM
	CACert     string `json:"ca_cert,omitempty"`     // PEM
	ExpiresAt  string `json:"expires_at,omitempty"`  // RFC3339
	Error      *Error `json:"error,omitempty"`
}

// Protocol error codes (04-protocol-v1.md §5).
const (
	ErrCodeTokenInvalid = "ERR_TOKEN_INVALID"
	ErrCodeTokenExpired = "ERR_TOKEN_EXPIRED"
	ErrCodeTokenUsed    = "ERR_TOKEN_USED"
	ErrCodeNameConflict = "ERR_NAME_CONFLICT"
	ErrCodeRateLimited  = "ERR_RATE_LIMITED"
	ErrCodeBadRequest   = "ERR_PROTOCOL"
	ErrCodeAuthFailed   = "ERR_AUTH_FAILED"
	ErrCodeCertRevoked  = "ERR_CERT_REVOKED"
	ErrCodeInternal     = "ERR_INTERNAL"
)

// errResponse builds a failure response. Messages never contain internal
// paths, stack traces or key material.
func errResponse(code, message string) *Response {
	return &Response{OK: false, Error: &Error{Code: code, Message: message}}
}

// writeFrame encodes v as JSON with a 4-byte big-endian length prefix.
func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("enroll: marshal frame: %w", err)
	}
	if len(data) > maxFrameSize {
		return fmt.Errorf("enroll: frame too large (%d bytes)", len(data))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("enroll: write frame header: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("enroll: write frame body: %w", err)
	}
	return nil
}

// readFrame reads a length-prefixed JSON frame into v.
func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("enroll: read frame header: %w", err)
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > maxFrameSize {
		return fmt.Errorf("enroll: invalid frame size %d", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("enroll: read frame body: %w", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("enroll: parse frame: %w", err)
	}
	return nil
}
