package logging

import (
	"log/slog"
	"regexp"
	"strings"
)

const redacted = "***"

// sensitiveKeys is the attribute-name blacklist (matched case-insensitively
// on the final key segment). Any attribute whose key contains one of these
// substrings is redacted entirely.
var sensitiveKeys = []string{
	"key", "token", "secret", "password", "passwd", "pwd",
	"cert", "private", "privkey", "api_key", "apikey", "credential",
	"authorization", "cookie", "signature", "fingerprint",
}

var (
	// longHex matches strings that are entirely 32+ hex characters
	// (e.g. SHA-256 fingerprints, hex-encoded keys).
	longHex = regexp.MustCompile(`(?i)^[0-9a-f]{32,}$`)
	// longB64 matches base64-looking strings of 44+ characters with
	// optional padding (e.g. PEM bodies without headers, JWTs, API tokens).
	longB64 = regexp.MustCompile(`^[A-Za-z0-9+/_-]{44,}={0,2}$`)
)

// RedactAttr is a slog.HandlerOptions.ReplaceAttr function that redacts
// sensitive attributes by key blacklist and by value pattern.
func RedactAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Value.Kind() != slog.KindString {
		return a
	}
	key := strings.ToLower(a.Key)
	for _, frag := range sensitiveKeys {
		if strings.Contains(key, frag) {
			return slog.String(a.Key, redacted)
		}
	}
	if isSensitiveValue(a.Value.String()) {
		return slog.String(a.Key, redacted)
	}
	return a
}

// isSensitiveValue reports whether v looks like a secret: a long pure-hex
// string or a long base64-looking string. Short or mixed strings (URLs,
// sentences) are left untouched to avoid over-redaction.
func isSensitiveValue(v string) bool {
	if len(v) < 16 {
		return false
	}
	return longHex.MatchString(v) || longB64.MatchString(v)
}
