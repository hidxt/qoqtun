package keystore

import (
	"sync"
)

// MemStore is an in-memory Store for tests only.
type MemStore struct {
	mu sync.RWMutex
	m  map[string][]byte
}

// NewMemStore creates an empty memory store.
func NewMemStore() *MemStore {
	return &MemStore{m: make(map[string][]byte)}
}

func (m *MemStore) Get(id string) ([]byte, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte{}, data...), nil
}

func (m *MemStore) Set(id string, data []byte) error {
	if err := validID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[id] = append([]byte{}, data...)
	return nil
}

func (m *MemStore) Delete(id string) error {
	if err := validID(id); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, id)
	return nil
}

func (m *MemStore) List() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.m))
	for id := range m.m {
		out = append(out, id)
	}
	return out, nil
}
