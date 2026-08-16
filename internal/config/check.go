package config

import (
	"fmt"
	"io"

	"github.com/pelletier/go-toml/v2"
)

// CheckServer implements the server check-config flow: load (if path given),
// merge with env/overlays, validate, and print the effective configuration.
// Returns an error (exit 1) on any failure; sensitive values are never
// printed.
func CheckServer(path string, overlays []Overlay, out io.Writer) error {
	var fileOverlays []Overlay
	var err error
	if path != "" {
		fileOverlays, err = LoadServerOverlays(path)
		if err != nil {
			return err
		}
	}
	effective, err := ResolveServer(DefaultServerConfig(), fileOverlays, overlays, nil)
	if err != nil {
		return fmt.Errorf("invalid server configuration: %w", err)
	}
	data, err := toml.Marshal(effective)
	if err != nil {
		return fmt.Errorf("marshal effective config: %w", err)
	}
	fmt.Fprintln(out, "server configuration OK:")
	fmt.Fprint(out, string(data))
	return nil
}

// CheckClient implements the client check-config flow. The ca_fingerprint
// (a credential) is redacted before printing.
func CheckClient(path string, overlays []Overlay, out io.Writer) error {
	var fileOverlays []Overlay
	var err error
	if path != "" {
		fileOverlays, err = LoadClientOverlays(path)
		if err != nil {
			return err
		}
	}
	effective, err := ResolveClient(DefaultClientConfig(), fileOverlays, overlays, nil)
	if err != nil {
		return fmt.Errorf("invalid client configuration: %w", err)
	}
	redacted := *effective
	if redacted.CAFingerprint != "" {
		redacted.CAFingerprint = "***"
	}
	data, err := toml.Marshal(&redacted)
	if err != nil {
		return fmt.Errorf("marshal effective config: %w", err)
	}
	fmt.Fprintln(out, "client configuration OK:")
	fmt.Fprint(out, string(data))
	return nil
}
