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

// ClientRecord is the server-side registry entry for one enrolled client.
type ClientRecord struct {
	ClientID   string    `json:"client_id"`
	Name       string    `json:"name"`
	Note       string    `json:"note,omitempty"`
	CertSerial string    `json:"cert_serial"`
	CreatedAt  time.Time `json:"created_at"`
}

// ClientRegistry persists the client_id -> record mapping
// (03-pki-enrollment.md §1 storage layout: clients.json, 0600).
type ClientRegistry struct {
	mu   sync.RWMutex
	path string
	byID map[string]ClientRecord
}

// LoadClientRegistry loads the registry from path; a missing file yields an
// empty registry.
func LoadClientRegistry(path string) (*ClientRegistry, error) {
	r := &ClientRegistry{path: path, byID: make(map[string]ClientRecord)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("read client registry %q: %w", path, err)
	}
	var records []ClientRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse client registry %q: %w", path, err)
	}
	for _, rec := range records {
		if rec.ClientID == "" {
			continue
		}
		r.byID[rec.ClientID] = rec
	}
	return r, nil
}

// Add inserts or updates a record and persists atomically.
func (r *ClientRegistry) Add(rec ClientRecord) error {
	if err := ValidateClientID(rec.ClientID); err != nil {
		return err
	}
	r.mu.Lock()
	r.byID[rec.ClientID] = rec
	r.mu.Unlock()
	return r.save()
}

// Get returns the record for clientID.
func (r *ClientRegistry) Get(clientID string) (ClientRecord, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.byID[clientID]
	return rec, ok
}

// Exists reports whether clientID is already registered.
func (r *ClientRegistry) Exists(clientID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.byID[clientID]
	return ok
}

// All returns a snapshot of all records (sorted by client id).
func (r *ClientRegistry) All() []ClientRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ClientRecord, 0, len(r.byID))
	for _, rec := range r.byID {
		out = append(out, rec)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].ClientID < out[j-1].ClientID; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func (r *ClientRegistry) save() error {
	r.mu.RLock()
	records := make([]ClientRecord, 0, len(r.byID))
	for _, rec := range r.byID {
		records = append(records, rec)
	}
	r.mu.RUnlock()
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal client registry: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}
	if err := atomicfile.Write(r.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("save client registry: %w", err)
	}
	return nil
}
