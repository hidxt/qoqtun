// Package auth implements enrollment-token lifecycle (03-pki-enrollment.md
// §3): high-entropy one-time short-lived tokens. The server stores only
// SHA-256 hashes; the plaintext token is printed exactly once at creation.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// tokenIDLen is the length of the 8-byte random token id (hex encoded = 16).
const tokenIDLen = 8

// CreateToken generates a new enrollment token.
//
// Display format: "qen_" + base62(32 random bytes), ~43 chars. The returned
// plaintext must be printed exactly once by the caller; only Token.Hash
// (SHA-256) is persisted.
func CreateToken() (plaintext, tokenID, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("auth: generate token: %w", err)
	}
	plaintext = "qen_" + base62Encode(raw)

	idBytes := make([]byte, tokenIDLen)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", "", fmt.Errorf("auth: generate token id: %w", err)
	}
	tokenID = hex.EncodeToString(idBytes)

	hash = HashToken(plaintext)
	return plaintext, tokenID, hash, nil
}

// HashToken returns the SHA-256 hex digest of a plaintext token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// base62Encode encodes raw bytes as base62 (0-9A-Za-z). This is a display
// encoding only — not cryptography.
func base62Encode(raw []byte) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	n := new(big.Int).SetBytes(raw)
	base := big.NewInt(62)
	mod := new(big.Int)
	var sb strings.Builder
	sb.Grow(44)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		sb.WriteByte(alphabet[mod.Int64()])
	}
	// left-pad with '0' to a fixed width (32 bytes -> 43 base62 chars)
	for sb.Len() < 43 {
		sb.WriteByte('0')
	}
	// reverse
	s := sb.String()
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
