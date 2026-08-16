//go:build !windows

package security

import (
	"os"

	"golang.org/x/sys/unix"
)

func platformCheckFDLimit(estimated uint64) FDCheck {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return FDCheck{Unsupported: true, Recommended: estimated}
	}
	cur := rl.Cur
	if rl.Cur == unix.RLIM_INFINITY {
		cur = ^uint64(0)
	}
	return FDCheck{
		Current:     cur,
		Recommended: estimated,
		BelowLimit:  cur < estimated,
	}
}

func platformIsRoot() bool {
	return os.Geteuid() == 0
}
