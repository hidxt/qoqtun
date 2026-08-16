package logging

import (
	"context"
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
	// optional padding (e.g. PEM bodies without headers, API tokens).
	longB64 = regexp.MustCompile(`^[A-Za-z0-9+/_-]{44,}={0,2}$`)
	// jwtLike matches compact JWTs (three base64url segments).
	jwtLike = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
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

// RedactWrap returns a handler that applies RedactAttr to every record
// before delegating to h (used to retrofit redaction onto arbitrary
// handlers; the package loggers already install it via ReplaceAttr).
func RedactWrap(h slog.Handler) slog.Handler {
	if h == nil {
		return nil
	}
	return &redactHandler{h: h}
}

type redactHandler struct{ h slog.Handler }

func (r *redactHandler) Enabled(ctx context.Context, l slog.Level) bool { return r.h.Enabled(ctx, l) }

func (r *redactHandler) Handle(ctx context.Context, rec slog.Record) error {
	attrs := make([]slog.Attr, 0, rec.NumAttrs())
	rec.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, RedactAttr(nil, a))
		return true
	})
	rec2 := slog.NewRecord(rec.Time, rec.Level, rec.Message, rec.PC)
	for _, a := range attrs {
		rec2.AddAttrs(a)
	}
	return r.h.Handle(ctx, rec2)
}

func (r *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &redactHandler{h: r.h.WithAttrs(attrs)}
}

func (r *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{h: r.h.WithGroup(name)}
}

// isSensitiveValue reports whether v looks like a secret: a long pure-hex
// string or a long base64-looking string. Short or mixed strings (URLs,
// sentences) are left untouched to avoid over-redaction.
func isSensitiveValue(v string) bool {
	if len(v) < 16 {
		return false
	}
	if longHex.MatchString(v) || longB64.MatchString(v) {
		return true
	}
	// compact JWT: three base64url segments, overall length >= 40
	return len(v) >= 40 && jwtLike.MatchString(v)
}
