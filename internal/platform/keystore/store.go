// Package keystore stores private keys securely per platform
// (docs/plan/03-pki-enrollment.md §7): system keyring preferred
// (wincred / Keychain / Secret Service), falling back to a hardened
// file backend (0700 dir, 0600 files, owner check, no symlinks, atomic
// writes). A memory backend exists for tests.
package keystore

import (
	"fmt"
	"runtime"
)

// Store is the private-key storage interface.
type Store interface {
	// Get returns the stored data for id. ErrNotFound when absent.
	Get(id string) ([]byte, error)
	// Set stores data under id.
	Set(id string, data []byte) error
	// Delete removes id. Missing entries are not an error.
	Delete(id string) error
	// List returns all stored ids.
	List() ([]string, error)
}

// ErrNotFound is returned by Get for missing entries.
var ErrNotFound = fmt.Errorf("keystore: entry not found")

// KeyringConfig configures the system-keyring backend.
type KeyringConfig struct {
	ServiceName string
}

// BackendPref controls backend selection (user-facing, e.g. --keystore-backend).
type BackendPref int

const (
	// BackendAuto prefers the system keyring and falls back to the file backend.
	BackendAuto BackendPref = iota
	// BackendKeyring forces the system keyring (fails if unavailable).
	BackendKeyring
	// BackendFile forces the hardened file backend.
	BackendFile
)

// ParseBackendPref parses "auto", "keyring" or "file".
func ParseBackendPref(s string) (BackendPref, error) {
	switch s {
	case "", "auto":
		return BackendAuto, nil
	case "keyring":
		return BackendKeyring, nil
	case "file":
		return BackendFile, nil
	default:
		return 0, fmt.Errorf("invalid keystore backend %q (want auto|keyring|file)", s)
	}
}

func (p BackendPref) String() string {
	switch p {
	case BackendKeyring:
		return "keyring"
	case BackendFile:
		return "file"
	default:
		return "auto"
	}
}

// openKeyringFn is injectable for tests (exercises the file-backend
// fallback path deterministically).
var openKeyringFn = openKeyring

// Open selects the best available backend for the platform: the system
// keyring first; if it cannot be initialized (e.g. Linux without a
// Secret Service / dbus), it falls back to the hardened file backend at
// fileDir (created 0700 if missing). warn, when non-nil, receives a
// non-sensitive message describing the fallback.
func Open(cfg KeyringConfig, fileDir string, warn func(string)) (Store, error) {
	s, _, err := OpenWithPref(cfg, fileDir, BackendAuto, warn)
	return s, err
}

// OpenWithBackend is like Open but also returns the selected backend name
// ("keyring" or "file") for user-facing diagnostics.
func OpenWithBackend(cfg KeyringConfig, fileDir string, warn func(string)) (Store, string, error) {
	return OpenWithPref(cfg, fileDir, BackendAuto, warn)
}

// OpenWithPref is Open with an explicit backend preference.
func OpenWithPref(cfg KeyringConfig, fileDir string, pref BackendPref, warn func(string)) (Store, string, error) {
	switch pref {
	case BackendFile:
		fs, err := NewFileStore(fileDir)
		if err != nil {
			return nil, "", err
		}
		return fs, "file", nil
	case BackendKeyring:
		ks, err := openKeyringFn(cfg)
		if err != nil {
			return nil, "", fmt.Errorf("keystore: keyring unavailable: %w", err)
		}
		return ks, "keyring", nil
	}
	if ks, err := openKeyringFn(cfg); err == nil {
		return ks, "keyring", nil
	}
	fs, err := NewFileStore(fileDir)
	if err != nil {
		return nil, "", fmt.Errorf("keystore: keyring unavailable and file backend failed: %w", err)
	}
	if warn != nil {
		warn(fmt.Sprintf("system keyring unavailable (%s), using secure file backend at %s", runtime.GOOS, fileDir))
	}
	return fs, "file", nil
}
