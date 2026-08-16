package security

import (
	"fmt"
	"runtime"
	"strings"
)

// FDCheck is the result of the RLIMIT_NOFILE startup check.
type FDCheck struct {
	Current     uint64
	Recommended uint64
	BelowLimit  bool
	Unsupported bool // platform cannot read the limit
}

// CheckFDLimit compares the process open-file limit against the estimated
// requirement. The platform probe is injectable for tests.
func CheckFDLimit(estimated uint64) FDCheck { return checkFDLimit(estimated) }

// EstimatedFDLimit derives a safe open-file requirement from the policy
// caps: control conns + data conns per client/tunnel + listeners + headroom.
func EstimatedFDLimit(maxConnsPerClient, maxConnsPerTunnel, maxClients int) uint64 {
	est := uint64(16) // listeners, enroll, misc
	if maxClients > 0 {
		est += uint64(maxClients) * uint64(maxConnsPerClient) * 2 // control + data
	}
	est += 256 // headroom
	return est
}

// IsRoot reports root/administrator privileges (injectable).
func IsRoot() bool { return isRoot() }

// RootWarning builds the actionable hint shown when running as root.
func RootWarning() string {
	var sb strings.Builder
	sb.WriteString("running as root/administrator is not recommended for a network-facing service")
	if runtime.GOOS == "linux" {
		sb.WriteString("; grant only the required capabilities instead (e.g. setcap 'cap_net_bind_service=+ep' on the binary)")
	}
	return sb.String()
}

// ErrInsufficientFD is returned by the startup guard.
func ErrInsufficientFD(c FDCheck) error {
	return fmt.Errorf("open-file limit %d is below the recommended %d (pass --allow-low-fdlimit to override)",
		c.Current, c.Recommended)
}

// ErrRootDenied is returned when running as root without --allow-root.
func ErrRootDenied() error {
	return fmt.Errorf("%s (pass --allow-root to override)", RootWarning())
}

// platform probes (defined per OS; injectable for tests)
var (
	checkFDLimitFunc = platformCheckFDLimit
	isRootFunc       = platformIsRoot
)

func checkFDLimit(estimated uint64) FDCheck { return checkFDLimitFunc(estimated) }

func isRoot() bool { return isRootFunc() }

// SetCheckFDLimit overrides the platform probe (tests inject fixed results).
func SetCheckFDLimit(fn func(uint64) FDCheck) {
	if fn == nil {
		fn = platformCheckFDLimit
	}
	checkFDLimitFunc = fn
}

// SetIsRoot overrides the root probe (tests).
func SetIsRoot(fn func() bool) {
	if fn == nil {
		fn = platformIsRoot
	}
	isRootFunc = fn
}
