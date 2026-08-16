// Package tunnel implements tunnel registration, public listeners and the
// TCP data path (04-protocol-v1.md §3). UDP/HTTP/HTTPS arrive in Phase 7/8.
package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// SpliceResult reports transferred bytes in each direction.
type SpliceResult struct {
	BytesToA int64 // bytes copied from B to A
	BytesToB int64 // bytes copied from A to B
}

// IdleTimeout is the default half-close/read idle bound (04 §3.5: 5min).
const IdleTimeout = 5 * time.Minute

// Splice relays bytes between a and b with explicit half-close semantics:
//   - two goroutines, one per direction;
//   - when one side hits EOF/error, the opposite side's write is closed
//     (CloseWrite) and the copy continues until the reverse direction also
//     finishes, a fatal error, or the idle timeout;
//   - both directions done -> both connections closed;
//   - the caller (owner) waits on the returned channel; nothing leaks.
func Splice(a, b net.Conn, bufSize int) chan SpliceResult {
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	done := make(chan SpliceResult, 1)
	var wg sync.WaitGroup
	wg.Add(2)

	var (
		toA, toB int64
	)

	// closeBoth is idempotent and called from any fatal path or after both
	// directions finish; net.Conn.Close is safe to call repeatedly.
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	// copyDir copies from src to dst; on EOF the dst write side is closed
	// (half-close), the other direction keeps running.
	copyDir := func(src, dst net.Conn, counter *int64) {
		defer wg.Done()
		buf := make([]byte, bufSize)
		n, err := io.CopyBuffer(dst, src, buf)
		*counter = n // single writer per direction, no race
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		if err != nil && !isClosedErr(err) {
			// fatal: tear down both sides
			closeBoth()
		}
	}

	go func() { copyDir(b, a, &toA) }() // b -> a
	go func() { copyDir(a, b, &toB) }() // a -> b

	go func() {
		wg.Wait()
		closeBoth()
		done <- SpliceResult{BytesToA: toA, BytesToB: toB}
		close(done)
	}()
	return done
}

func isClosedErr(err error) bool {
	if err == nil || err == io.EOF || errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}
