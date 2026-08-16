package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureHandler collects formatted output for assertions.
type captureHandler struct {
	mu  sync.Mutex
	buf bytes.Buffer
	h   slog.Handler
}

func (c *captureHandler) Enabled(ctx context.Context, l slog.Level) bool { return true }
func (c *captureHandler) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.h.Handle(ctx, r)
}
func (c *captureHandler) WithAttrs(a []slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(n string) slog.Handler      { return c }
func (c *captureHandler) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func newCapture() *captureHandler {
	c := &captureHandler{}
	c.h = slog.NewTextHandler(&c.buf, &slog.HandlerOptions{ReplaceAttr: RedactAttr})
	return c
}

// redactedLogger returns a logger whose output is redacted then captured.
func redactedLogger(c *captureHandler) *slog.Logger {
	return slog.New(RedactWrap(c))
}

func TestRedactionByKey(t *testing.T) {
	c := newCapture()
	logger := redactedLogger(c)
	logger.Info("handshake", "client_token", "qen_abcdefghijklmnopqrstuvwxyz123456", "key_pem", "-----BEGIN PRIVATE KEY-----")
	out := c.String()
	if strings.Contains(out, "qen_") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("sensitive values leaked: %s", out)
	}
	if !strings.Contains(out, "***") {
		t.Fatalf("redaction marker missing: %s", out)
	}
}

func TestRedactionByValuePattern(t *testing.T) {
	c := newCapture()
	logger := redactedLogger(c)
	// long hex (fingerprint) and long base64 (token-like)
	logger.Info("identity", "fingerprint", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
	out := c.String()
	if strings.Contains(out, "0123456789abcdef") || strings.Contains(out, "eyJhbGciOi") {
		t.Fatalf("value-pattern redaction failed: %s", out)
	}
}

func TestRedactionLeavesSafeValues(t *testing.T) {
	c := newCapture()
	logger := redactedLogger(c)
	logger.Info("tunnel registered", "name", "my-tunnel", "port", 8080, "client_id", "cl_abcdef12")
	out := c.String()
	if !strings.Contains(out, "my-tunnel") || !strings.Contains(out, "cl_abcdef12") {
		t.Fatalf("safe values must not be redacted: %s", out)
	}
}

func TestFloodGuardSampling(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	guarded := SamplingHandler(h, time.Minute, 3, 0) // no summary lines
	logger := slog.New(guarded)
	for i := 0; i < 50; i++ {
		logger.Error("dial failed", "addr", "x")
	}
	out := buf.String()
	lines := strings.Count(out, "dial failed")
	if lines != 3 {
		t.Fatalf("sampled lines = %d, want 3 (flood guard)", lines)
	}
	if strings.Contains(out, "log flood suppressed") {
		t.Fatalf("summary must be disabled with dropEvery=0:\n%s", out)
	}
}

func TestFloodGuardSummary(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	guarded := SamplingHandler(h, time.Minute, 3, 10)
	logger := slog.New(guarded)
	for i := 0; i < 100; i++ {
		logger.Error("dup error", "i", i)
	}
	out := buf.String()
	if !strings.Contains(out, "log flood suppressed") {
		t.Fatalf("suppression summary missing:\n%s", out)
	}
}

func TestFloodGuardDifferentMessages(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, nil)
	guarded := SamplingHandler(h, time.Minute, 3, 0)
	logger := slog.New(guarded)
	for i := 0; i < 10; i++ {
		logger.Error("msg one", "i", i)
		logger.Error("msg two", "i", i)
	}
	out := buf.String()
	if strings.Count(out, "msg one") != 3 || strings.Count(out, "msg two") != 3 {
		t.Fatalf("different messages must be sampled independently:\n%s", out)
	}
}
