package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStore(t *testing.T, now func() time.Time) *TokenStore {
	t.Helper()
	s, err := LoadTokenStore(filepath.Join(t.TempDir(), "tokens.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustCreate(t *testing.T, s *TokenStore, now time.Time, ttl time.Duration) (plain, id string) {
	t.Helper()
	plain, id, hash, err := CreateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "qen_") || len(plain) < 40 {
		t.Fatalf("token format unexpected: %q", plain)
	}
	if _, err := s.Create(plain, id, "tester", ttl); err != nil {
		t.Fatal(err)
	}
	if hash == "" || hash == plain {
		t.Fatal("hash must differ from plaintext")
	}
	return plain, id
}

func TestTokenFormatAndHashOnly(t *testing.T) {
	s := newStore(t, time.Now)
	plain, id := mustCreate(t, s, time.Now(), time.Hour)
	rec, ok := s.Get(id)
	if !ok {
		t.Fatal("token must be stored")
	}
	if rec.Hash == plain {
		t.Fatal("store must never contain the plaintext")
	}
	// persistence: reload and consume with the same plaintext
	if _, err := s.Consume(plain); err != nil {
		t.Fatalf("consume: %v", err)
	}
	// persisted file must contain the hash, never the plaintext
	data, _ := os.ReadFile(s.path)
	if !strings.Contains(string(data), rec.Hash) {
		t.Fatal("persisted file must contain the hash")
	}
}

func TestConsumeOnceOnly(t *testing.T) {
	s := newStore(t, time.Now)
	plain, _ := mustCreate(t, s, time.Now(), time.Hour)
	if _, err := s.Consume(plain); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(plain); err != ErrTokenUsed {
		t.Fatalf("second consume must be ErrTokenUsed, got %v", err)
	}
}

func TestConsumeExpired(t *testing.T) {
	now := time.Now()
	s := newStore(t, func() time.Time { return now })
	plain, _ := mustCreate(t, s, now, time.Hour)
	// advance clock past expiry
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := s.Consume(plain); err != ErrTokenExpired {
		t.Fatalf("expired consume must be ErrTokenExpired, got %v", err)
	}
}

func TestConsumeRevoked(t *testing.T) {
	s := newStore(t, time.Now)
	plain, id := mustCreate(t, s, time.Now(), time.Hour)
	if err := s.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(plain); err != ErrTokenRevoked {
		t.Fatalf("revoked consume must be ErrTokenRevoked, got %v", err)
	}
}

func TestConsumeUnknown(t *testing.T) {
	s := newStore(t, time.Now)
	if _, err := s.Consume("qen_fake"); err != ErrTokenInvalid {
		t.Fatalf("unknown token must be ErrTokenInvalid, got %v", err)
	}
}

// Concurrent consumption: exactly one goroutine wins.
func TestConsumeConcurrentSingleWinner(t *testing.T) {
	s := newStore(t, time.Now)
	plain, _ := mustCreate(t, s, time.Now(), time.Hour)
	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Consume(plain)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("exactly one consumer must win, got %d", success)
	}
}

func TestLazyExpiryPurge(t *testing.T) {
	now := time.Now()
	s := newStore(t, func() time.Time { return now })
	plain1, id1 := mustCreate(t, s, now, time.Hour)
	plain2, _ := mustCreate(t, s, now, time.Hour)
	_ = plain1
	_ = id1
	// advance clock: both expired; consuming one triggers purge of expired
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := s.Consume(plain2); err != ErrTokenExpired {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
	if len(s.All()) != 0 {
		t.Fatalf("expired tokens should be purged, got %d", len(s.All()))
	}
}

func TestCreateTTLValidation(t *testing.T) {
	s := newStore(t, time.Now)
	plain, id, _, err := CreateToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(plain, id, "x", 0); err == nil {
		t.Fatal("zero TTL must error")
	}
	if _, err := s.Create(plain, id, "x", 25*time.Hour); err == nil {
		t.Fatal("TTL > 24h must error")
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "tokens.json")
	s, err := LoadTokenStore(path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	plain, id, _, _ := CreateToken()
	if _, err := s.Create(plain, id, "x", time.Hour); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("tokens.json must be 0600, got %o", fi.Mode().Perm())
	}
}

// Cross-process sync: a token created by another process (a second store
// instance on the same file) becomes visible to the running store on the
// next Consume (standalone `enroll serve` sees `client create-token`).
func TestReloadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	now := time.Now()
	srv, err := LoadTokenStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	// another process creates a token
	other, err := LoadTokenStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	plain, id, _, err := CreateToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Create(plain, id, "cli", time.Hour); err != nil {
		t.Fatal(err)
	}
	// srv must see it after a file change
	if _, err := srv.Consume(plain); err != nil {
		t.Fatalf("reloaded store must accept the new token: %v", err)
	}
	// replay still rejected
	if _, err := srv.Consume(plain); err != ErrTokenUsed {
		t.Fatalf("replay must be ErrTokenUsed, got %v", err)
	}
}
