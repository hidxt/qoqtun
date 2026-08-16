package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactAttrByKey(t *testing.T) {
	cases := []struct {
		key      string
		val      string
		redacted bool
	}{
		{"token", "abc", true},
		{"access_token", "abc", true},
		{"client_secret", "abc", true},
		{"password", "hunter2", true},
		{"private_key_pem", "---", true},
		{"api_key", "xyz", true},
		{"ca_fingerprint", strings.Repeat("ab", 32), true},
		{"message", "hello world", false},
		{"error", "connection refused", false},
	}
	for _, tc := range cases {
		got := RedactAttr(nil, slog.String(tc.key, tc.val))
		if tc.redacted && got.Value.String() != redacted {
			t.Errorf("key %q should be redacted, got %q", tc.key, got.Value.String())
		}
		if !tc.redacted && got.Value.String() != tc.val {
			t.Errorf("key %q should not be redacted, got %q", tc.key, got.Value.String())
		}
	}
}

func TestRedactAttrByValuePattern(t *testing.T) {
	longHex := strings.Repeat("a1", 32) // 64 hex chars
	b64 := "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
	cases := []struct {
		name     string
		val      string
		redacted bool
	}{
		{"long hex", longHex, true},
		{"long base64", b64, true},
		{"url not redacted", "https://example.com/path/with/segments", false},
		{"short hex ok", "deadbeef", false},
		{"short value ok", "hello", false},
		{"sentence not redacted", "the quick brown fox jumps over the lazy dog", false},
	}
	for _, tc := range cases {
		got := RedactAttr(nil, slog.String("value", tc.val))
		if tc.redacted && got.Value.String() != redacted {
			t.Errorf("%s: should be redacted, got %q", tc.name, got.Value.String())
		}
		if !tc.redacted && got.Value.String() != tc.val {
			t.Errorf("%s: should not be redacted, got %q", tc.name, got.Value.String())
		}
	}
}

// End-to-end: a logger built by New must never emit a Secret's value.
func TestLoggerNeverLeaksSecret(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: RedactAttr}))
	secret := NewSecret("super-secret-value-42")
	logger.Info("test", "client_secret", secret, "token", "t0ken-value")
	out := buf.String()
	if strings.Contains(out, "super-secret-value-42") || strings.Contains(out, "t0ken-value") {
		t.Fatalf("logger leaked secret: %s", out)
	}
	if !strings.Contains(out, "***") {
		t.Fatalf("expected redaction marker: %s", out)
	}
}

func TestNewLoggerValidation(t *testing.T) {
	if _, err := New("info", "json", ""); err != nil {
		t.Fatalf("valid logger params rejected: %v", err)
	}
	if _, err := New("verbose", "json", ""); err == nil {
		t.Fatal("invalid level must error")
	}
	if _, err := New("info", "xml", ""); err == nil {
		t.Fatal("invalid format must error")
	}
	if _, err := New("info", "text", t.TempDir()+"/missing-dir/x.log"); err == nil {
		t.Fatal("log file in missing directory must error")
	}
}
