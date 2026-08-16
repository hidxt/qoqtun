package keystore

import (
	"fmt"
	"runtime"

	"github.com/99designs/keyring"
)

// openKeyring initializes the platform system keyring backend
// (wincred on Windows, Keychain on macOS, Secret Service on Linux).
func openKeyring(cfg KeyringConfig) (Store, error) {
	backends := allowedBackends()
	if len(backends) == 0 {
		return nil, fmt.Errorf("no keyring backend available on %s", runtime.GOOS)
	}
	kr, err := keyring.Open(keyring.Config{
		ServiceName:     cfg.ServiceName,
		AllowedBackends: backends,
	})
	if err != nil {
		return nil, err
	}
	return &keyringStore{kr: kr}, nil
}

func allowedBackends() []keyring.BackendType {
	switch runtime.GOOS {
	case "windows":
		return []keyring.BackendType{keyring.WinCredBackend}
	case "darwin":
		return []keyring.BackendType{keyring.KeychainBackend}
	case "linux":
		return []keyring.BackendType{keyring.SecretServiceBackend}
	}
	return nil
}

type keyringStore struct {
	kr keyring.Keyring
}

func (k *keyringStore) Get(id string) ([]byte, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	item, err := k.kr.Get(id)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return item.Data, nil
}

func (k *keyringStore) Set(id string, data []byte) error {
	if err := validID(id); err != nil {
		return err
	}
	return k.kr.Set(keyring.Item{Key: id, Data: data})
}

func (k *keyringStore) Delete(id string) error {
	if err := validID(id); err != nil {
		return err
	}
	return k.kr.Remove(id)
}

// List is not supported by the keyring backends (no enumeration API).
func (k *keyringStore) List() ([]string, error) {
	return nil, fmt.Errorf("keystore: listing is not supported by the keyring backend")
}
