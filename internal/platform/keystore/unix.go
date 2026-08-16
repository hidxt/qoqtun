//go:build !windows

package keystore

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// checkOwner verifies the file/dir owner is the effective user, guarding
// against TOCTOU / pre-placed files (02-threat-model.md T12).
func checkOwner(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keystore: stat %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("keystore: unsupported stat type for %s", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("keystore: %s is not owned by the current user (refusing: possible preplaced file)", path)
	}
	return nil
}

// openNoFollow opens path without following symbolic links (O_NOFOLLOW).
func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// setOwnerOnlyACL is a no-op on Unix: 0600/0700 mode bits already restrict
// access to the owner.
func setOwnerOnlyACL(_ string) error { return nil }

func readAll(f *os.File) ([]byte, error) {
	return io.ReadAll(f)
}
