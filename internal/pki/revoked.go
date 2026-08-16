package pki

import (
	"encoding/json"
	"fmt"
	"github.com/hidxt/qoqtun/internal/platform/atomicfile"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RevokedEntry records one revoked certificate.
type RevokedEntry struct {
	Serial    string    `json:"serial"` // decimal serial number
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}

// RevocationList is a thread-safe, JSON-persisted set of revoked serials
// (03-pki-enrollment.md §6). Writes are atomic (tmp+fsync+rename) and the
// in-memory map is the source of truth at runtime; the file is a snapshot.
type RevocationList struct {
	mu   sync.RWMutex
	path string
	byID map[string]RevokedEntry // key: decimal serial
}

// LoadRevocationList loads the list from path; a missing file yields an
// empty list (the caller decides whether that is acceptable).
func LoadRevocationList(path string) (*RevocationList, error) {
	rl := &RevocationList{path: path, byID: make(map[string]RevokedEntry)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rl, nil
		}
		return nil, fmt.Errorf("read revocation list %q: %w", path, err)
	}
	var entries []RevokedEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse revocation list %q: %w", path, err)
	}
	for _, e := range entries {
		if e.Serial == "" {
			continue
		}
		rl.byID[e.Serial] = e
	}
	return rl, nil
}

// Revoke marks a serial as revoked and persists atomically.
func (rl *RevocationList) Revoke(serial, reason string) error {
	if serial == "" {
		return fmt.Errorf("serial must not be empty")
	}
	rl.mu.Lock()
	rl.byID[serial] = RevokedEntry{Serial: serial, RevokedAt: time.Now().UTC(), Reason: reason}
	rl.mu.Unlock()
	return rl.save()
}

// IsRevoked reports whether the given decimal serial is revoked.
func (rl *RevocationList) IsRevoked(serial string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	_, ok := rl.byID[serial]
	return ok
}

// Revoked returns a snapshot of all revoked entries (sorted by serial).
func (rl *RevocationList) Revoked() []RevokedEntry {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	out := make([]RevokedEntry, 0, len(rl.byID))
	for _, e := range rl.byID {
		out = append(out, e)
	}
	// stable order by serial
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Serial < out[j-1].Serial; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (rl *RevocationList) save() error {
	rl.mu.RLock()
	entries := make([]RevokedEntry, 0, len(rl.byID))
	for _, e := range rl.byID {
		entries = append(entries, e)
	}
	rl.mu.RUnlock()
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal revocation list: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(rl.path), 0o700); err != nil {
		return fmt.Errorf("create revocation dir: %w", err)
	}
	if err := atomicfile.Write(rl.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("save revocation list: %w", err)
	}
	return nil
}
