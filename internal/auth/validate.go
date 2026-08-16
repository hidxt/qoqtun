package auth

import "errors"

// Token consumption / management errors (mapped to protocol error codes in
// internal/enroll; 04-protocol-v1.md §5).
var (
	// ErrTokenInvalid: token not found (wrong or unknown token).
	ErrTokenInvalid = errors.New("auth: token invalid")
	// ErrTokenExpired: token past its TTL.
	ErrTokenExpired = errors.New("auth: token expired")
	// ErrTokenUsed: token already consumed (replay).
	ErrTokenUsed = errors.New("auth: token already used")
	// ErrTokenRevoked: token revoked by an administrator.
	ErrTokenRevoked = errors.New("auth: token revoked")
)
