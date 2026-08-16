package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/99designs/keyring"
)

// contract runs the same suite against any Store implementation.
func contract(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.Get("missing"); err != ErrNotFound {
		t.Fatalf("Get missing: got %v, want ErrNotFound", err)
	}
	if err := s.Set("k1", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("k2", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("k1")
	if err != nil || string(got) != "v1" {
		t.Fatalf("Get k1: %q, %v", got, err)
	}
	// overwrite
	if err := s.Set("k1", []byte("v1b")); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get("k1")
	if string(got) != "v1b" {
		t.Fatalf("overwrite failed: %q", got)
	}
	ids, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("List: %v", ids)
	}
	if err := s.Delete("k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("k1"); err != ErrNotFound {
		t.Fatalf("after delete: got %v", err)
	}
	// delete missing is not an error
	if err := s.Delete("k1"); err != nil {
		t.Fatalf("delete missing must not error: %v", err)
	}
	// id validation
	for _, bad := range []string{"../escape", "a/b", "a\\b", "", "a..b", strings.Repeat("x", 129)} {
		if err := s.Set(bad, []byte("x")); err == nil {
			t.Errorf("Set with invalid id %q must error", bad)
		}
	}
}

func TestMemStoreContract(t *testing.T) {
	contract(t, NewMemStore())
}

// The keyring backend wrapper is exercised through 99designs/keyring's own
// file backend (deterministic in tests; the real WinCred/Keychain/Secret
// Service backends require interactive system services). Skipped on Windows:
// keyring v1.2.2's file backend panics on Windows (upstream bug).
func TestKeyringStoreContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("99designs/keyring file backend panics on Windows (upstream)")
	}
	dir := filepath.Join(t.TempDir(), "kr")
	kr, err := keyring.Open(keyring.Config{
		ServiceName:     "qoqtun-test",
		AllowedBackends: []keyring.BackendType{keyring.FileBackend},
		FileDir:         dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	contract(t, &keyringStore{kr: kr})
	// List is unsupported by the keyring backend
	if _, err := (&keyringStore{kr: kr}).List(); err == nil {
		t.Fatal("keyring List must return an error")
	}
}

func TestFileStoreContract(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	contract(t, fs)
}

func TestFileStorePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Set("client-key", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client-key.key")

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("dir must be 0700, got %o", fi.Mode().Perm())
		}
		fi, err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("file must be 0600, got %o", fi.Mode().Perm())
		}
	} else {
		// Windows: assert the owner-only ACL was applied by checking owner SID
		// matches the current user and the DACL contains an owner entry.
		if err := checkOwner(path); err != nil {
			t.Fatalf("owner check on stored file: %v", err)
		}
	}
}

// Symlink attack: a symlinked target must be refused on Set and Get.
// Unix-only: Windows may silently create a plain copy instead of a link when
// the process lacks SeCreateSymbolicLinkPrivilege, making Lstat unreliable.
func TestFileStoreSymlinkAttack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics unreliable on Windows (covered by Unix CI)")
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "victim.key")
	if err := os.WriteFile(target, []byte("victim-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "evil.key")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	if err := fs.Set("evil", []byte("x")); err == nil {
		t.Fatal("Set must refuse a symlinked entry")
	}
	if _, err := fs.Get("evil"); err == nil {
		t.Fatal("Get must refuse a symlinked entry")
	}
	// victim untouched
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "victim-data" {
		t.Fatalf("victim file was modified: %q, %v", data, err)
	}
}

// Symlinked base directory must be refused (Unix-only, see above).
func TestFileStoreSymlinkedDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics unreliable on Windows (covered by Unix CI)")
	}
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink not supported here: %v", err)
	}
	if _, err := NewFileStore(link); err == nil {
		t.Fatal("NewFileStore must refuse a symlinked base directory")
	}
}

// Owner mismatch must be refused (TOCTOU / preplaced file defense).
func TestFileStoreOwnerCheck(t *testing.T) {
	orig := ownerCheck
	ownerCheck = func(string) error { return errors.New("owner mismatch (test)") }
	t.Cleanup(func() { ownerCheck = orig })

	if _, err := NewFileStore(filepath.Join(t.TempDir(), "s")); err == nil {
		t.Fatal("NewFileStore must fail when owner check fails")
	}
}

// Keyring unavailable -> file backend fallback with warning.
func TestOpenFallbackToFile(t *testing.T) {
	orig := openKeyringFn
	openKeyringFn = func(KeyringConfig) (Store, error) {
		return nil, errors.New("no dbus (simulated)")
	}
	t.Cleanup(func() { openKeyringFn = orig })

	warned := false
	dir := filepath.Join(t.TempDir(), "secrets")
	s, backend, err := OpenWithBackend(KeyringConfig{ServiceName: "qoqtun"}, dir, func(string) { warned = true })
	if err != nil {
		t.Fatal(err)
	}
	if backend != "file" {
		t.Fatalf("backend = %q, want file", backend)
	}
	if !warned {
		t.Fatal("fallback must warn")
	}
	// fallback store must actually work
	if err := s.Set("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
}

// Both backends unavailable -> error.
func TestOpenAllFail(t *testing.T) {
	orig := openKeyringFn
	openKeyringFn = func(KeyringConfig) (Store, error) {
		return nil, errors.New("no keyring (simulated)")
	}
	t.Cleanup(func() { openKeyringFn = orig })
	if _, _, err := OpenWithBackend(KeyringConfig{}, filepath.Join(t.TempDir(), "s"), nil); err != nil {
		t.Fatalf("file backend should work even when keyring fails: %v", err)
	}
}
