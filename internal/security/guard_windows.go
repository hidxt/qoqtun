//go:build windows

package security

func platformCheckFDLimit(estimated uint64) FDCheck {
	// Windows does not expose RLIMIT_NOFILE; the OS handles handle limits.
	return FDCheck{Unsupported: true, Recommended: estimated}
}

func platformIsRoot() bool {
	// Windows has no root concept; UAC elevation is not detectable here.
	return false
}
