package pki

import (
	"fmt"
	"os"
	"path/filepath"
)

// atomicWriteFile writes data to path atomically and securely:
//   - a temp file is created in the same directory (same filesystem,
//     required for atomic rename) with 0600 permissions;
//   - data is fsynced before rename;
//   - the temp file is renamed over path (atomic on POSIX and Windows NTFS).
//
// Callers must have already validated the parent directory ownership and
// symlink safety (see internal/platform/keystore for the full story).
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName) // no-op after successful rename
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file onto %s: %w", path, err)
	}
	tmpName = "" // renamed successfully; nothing to clean up
	return nil
}
