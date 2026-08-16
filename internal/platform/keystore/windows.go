//go:build windows

package keystore

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// advapi32's SetEntriesInAclW is not exported by x/sys/windows; call it via
// a lazy proc (no new dependency).
var (
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procSetEntriesInAclW = advapi32.NewProc("SetEntriesInAclW")
)

func setEntriesInAcl(count uint32, entries *windows.EXPLICIT_ACCESS, oldACL *windows.ACL, newACL **windows.ACL) error {
	r1, _, e1 := procSetEntriesInAclW.Call(
		uintptr(count),
		uintptr(unsafe.Pointer(entries)),
		uintptr(unsafe.Pointer(oldACL)),
		uintptr(unsafe.Pointer(newACL)),
	)
	if r1 != 0 { // ERROR_SUCCESS == 0
		return e1
	}
	return nil
}

// checkOwner verifies the file/dir owner SID matches the current process
// user. Windows has no O_NOFOLLOW / 0600 semantics, so ownership (plus the
// ACL set by setOwnerOnlyACL) is the security boundary.
func checkOwner(path string) error {
	owner, err := fileOwnerSID(path)
	if err != nil {
		return fmt.Errorf("keystore: query owner of %s: %w", path, err)
	}
	me, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("keystore: query current user: %w", err)
	}
	if owner != me {
		return fmt.Errorf("keystore: %s is not owned by the current user (refusing: possible preplaced file)", path)
	}
	return nil
}

// openNoFollow on Windows: symlink/reparse-point refusal is done via Lstat
// before opening (file.go); a plain open is sufficient after that check.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

// setOwnerOnlyACL restricts path to the current user only, the Windows
// equivalent of 0600: a protected DACL granting GENERIC_ALL to the owner SID.
func setOwnerOnlyACL(path string) error {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("keystore: open process token: %w", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("keystore: query token user: %w", err)
	}

	// The SID pointer referenced by the trustee must stay pinned for the
	// lifetime of the EXPLICIT_ACCESS (x/sys/windows contract).
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(tu.User.Sid)

	trustee := windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  windows.TRUSTEE_IS_USER,
		TrusteeValue: windows.TrusteeValueFromSID(tu.User.Sid),
	}
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee:           trustee,
	}
	var dacl *windows.ACL
	if err := setEntriesInAcl(1, &ea, nil, &dacl); err != nil {
		return fmt.Errorf("keystore: build DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("keystore: apply owner-only ACL to %s: %w", path, err)
	}
	return nil
}

// fileOwnerSID returns the owner SID string of the file/dir at path.
func fileOwnerSID(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	return owner.String(), nil
}

// currentUserSID returns the SID string of the current process user.
func currentUserSID() (string, error) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}

func readAll(f *os.File) ([]byte, error) {
	return io.ReadAll(f)
}
