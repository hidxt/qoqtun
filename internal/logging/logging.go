package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// NewFloodGuarded is like New but also wraps the handler with the default
// anti-flood sampler (at most 5 identical messages per minute).
func NewFloodGuarded(level, format, file string) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: RedactAttr}
	var out io.Writer = os.Stderr
	if file != "" {
		f, err := openLogFile(file)
		if err != nil {
			return nil, err
		}
		out = f
	}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "json":
		h = slog.NewJSONHandler(out, opts)
	case "text", "":
		h = slog.NewTextHandler(out, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q (want json|text)", format)
	}
	return slog.New(DefaultFloodGuard(h)), nil
}

func New(level, format, file string) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: RedactAttr}

	var out io.Writer = os.Stderr
	if file != "" {
		f, err := openLogFile(file)
		if err != nil {
			return nil, err
		}
		out = f
	}

	var h slog.Handler
	switch strings.ToLower(format) {
	case "json":
		h = slog.NewJSONHandler(out, opts)
	case "text", "":
		h = slog.NewTextHandler(out, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q (want json|text)", format)
	}
	return slog.New(h), nil
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want debug|info|warn|error)", level)
	}
}

// openLogFile opens (creating if needed) a log file with 0640 permissions.
// The path is cleaned; the parent directory must exist.
func openLogFile(path string) (*os.File, error) {
	p := filepath.Clean(path)
	if p == "" || filepath.IsAbs(p) && p == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid log file path %q", path)
	}
	dir := filepath.Dir(p)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("log directory %q does not exist", dir)
	}
	return os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
}
