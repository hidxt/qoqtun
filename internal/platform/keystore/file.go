package keystore

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// idRe restricts store ids to safe characters (no path separators,
// no ".." sequences) to prevent path traversal (T12).
var idRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func validID(id string) error {
	if !idRe.MatchString(id) || strings.Contains(id, "..") {
		return fmt.Errorf("invalid store id %q", id)
	}
	return nil
}

// ownerCheck verifies a path's owner is the current user (platform-specific).
// It is a variable so tests can exercise the rejection path (TOCTOU /
// preplaced files) without OS privileges.
var ownerCheck = checkOwner

// FileStore is the hardened file backend:
//   - base directory 0700 (created on demand, re-chmodded to 0700);
//   - files 0600, owner must be the current user;
//   - symlinks refused (Lstat check + O_NOFOLLOW on Unix);
//   - writes are atomic (same-dir tmp + fsync + rename);
//   - serialized with a mutex.
type FileStore struct {
	mu  sync.Mutex
	dir string
}

// NewFileStore validates the base directory and prepares it.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("keystore: directory must not be empty")
	}
	clean := filepath.Clean(dir)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("keystore: directory must be absolute (got %q)", dir)
	}
	for _, seg := range strings.FieldsFunc(clean, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return nil, fmt.Errorf("keystore: directory must not contain \"..\"")
		}
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: create directory: %w", err)
	}
	// enforce 0700 even if the directory pre-existed
	_ = os.Chmod(clean, 0o700)
	_ = setOwnerOnlyACL(clean) // Windows: owner-only ACL; no-op elsewhere
	if err := ownerCheck(clean); err != nil {
		return nil, err
	}
	// refuse a symlinked base directory
	if fi, err := os.Lstat(clean); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("keystore: directory %s is a symlink (refusing)", clean)
	}
	return &FileStore{dir: clean}, nil
}

// Dir returns the base directory (for diagnostics; never log secrets).
func (s *FileStore) Dir() string { return s.dir }

func (s *FileStore) pathFor(id string) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, id+".key"), nil
}

// Get reads the entry, enforcing owner and symlink safety.
func (s *FileStore) Get(id string) ([]byte, error) {
	path, err := s.pathFor(id)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ownerCheck(s.dir); err != nil {
		return nil, err
	}
	// refuse symlinks: Lstat must report a regular file
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keystore: stat %s: %w", id, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keystore: %s is not a regular file (symlink attack refused)", id)
	}
	if err := ownerCheck(path); err != nil {
		return nil, err
	}
	f, err := openNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: open %s: %w", id, err)
	}
	defer f.Close()
	return readAll(f)
}

// Set writes the entry atomically with 0600 permissions.
func (s *FileStore) Set(id string, data []byte) error {
	path, err := s.pathFor(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := ownerCheck(s.dir); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("keystore: %s is a symlink (refusing to overwrite)", id)
	}
	if err := atomicWrite(s.dir, path, data, 0o600); err != nil {
		return fmt.Errorf("keystore: set %s: %w", id, err)
	}
	if err := setOwnerOnlyACL(path); err != nil { // Windows: 0600-equivalent ACL
		return fmt.Errorf("keystore: set %s ACL: %w", id, err)
	}
	return nil
}

// Delete removes the entry.
func (s *FileStore) Delete(id string) error {
	path, err := s.pathFor(id)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("keystore: %s is a symlink (refusing to delete)", id)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("keystore: delete %s: %w", id, err)
	}
	return nil
}

// List returns the ids of all *.key files in the base directory.
func (s *FileStore) List() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("keystore: list: %w", err)
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".key") {
			continue
		}
		ids = append(ids, strings.TrimSuffix(name, ".key"))
	}
	return ids, nil
}

// atomicWrite creates a temp file in the same directory (0600), fsyncs it,
// and renames it over path.
func atomicWrite(dir, path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	return nil
}
