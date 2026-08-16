// Package atomicfile provides secure atomic file writes (same-directory
// temp file, fsync, rename) used by every sensitive state file in qoqtun.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write writes data to path atomically and securely:
//   - a temp file is created in the same directory (same filesystem,
//     required for atomic rename);
//   - the temp file is chmodded to mode before writing;
//   - data is fsynced before the rename over path.
func Write(path string, data []byte, mode os.FileMode) error {
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
	tmpName = ""
	return nil
}
