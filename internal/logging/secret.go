// Package logging provides structured logging with mandatory secret
// redaction. All qoqtun components must log through this package so that
// private keys, tokens and credentials never reach log output.
package logging

// Secret wraps a sensitive value. Its String method always returns "***",
// so passing a Secret to any logger can never leak the underlying value.
type Secret struct {
	value string
}

// NewSecret wraps v as a redacted value.
func NewSecret(v string) Secret { return Secret{value: v} }

// String always returns "***" (redacted). It satisfies fmt.Stringer so
// Secret is safe to log.
func (s Secret) String() string { return redacted }

// Value returns the underlying value. Use sparingly and never for logging.
func (s Secret) Value() string { return s.value }
