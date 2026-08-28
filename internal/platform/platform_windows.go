//go:build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// protectPrivateDACL replaces the DACL of path with a protected DACL granting
// full access to the current user only, and breaks inheritance from the parent
// (PROTECTED_DACL_SECURITY_INFORMATION). This is the Windows analogue of
// chmod 0700 / 0600: a default inherited ACL would also grant Administrators
// and SYSTEM, which is why an explicit protected DACL is mandatory.
func protectPrivateDACL(path string) error {
	sid, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("resolve current user SID: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.ACCESS_MASK(windows.GENERIC_ALL),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		// Protected DACL: replace the DACL and block inherited ACEs.
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set protected DACL: %w", err)
	}
	return nil
}

func currentUserSID() (*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tokenUser.User.Sid, nil
}

// ensurePrivateDir creates the directory (and parents) and applies a protected
// DACL to it.
func ensurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	if err := protectPrivateDACL(path); err != nil {
		return err
	}
	return nil
}

// validatePrivateFile verifies the path is a regular file (not a reparse
// point) carrying a protected DACL owned by the current user, i.e. inheritance
// is broken and no foreign principal holds access.
func validatePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private file: %w", err)
	}
	// ModeSymlink covers symlinks and junctions (reparse points).
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("inspect private file: %w", ErrUnsafePath)
	}
	current, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("resolve current user SID: %w", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read security descriptor: %w", err)
	}
	if owner, _, err := sd.Owner(); err != nil || owner == nil || !windows.EqualSid(owner, current) {
		return fmt.Errorf("inspect private file: %w", ErrUnsafeOwner)
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || dacl == nil || defaulted {
		return fmt.Errorf("inspect private file: %w", ErrUnsafePermissions)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("inspect private file: %w", ErrUnsafePermissions)
	}
	return nil
}

// writeAtomic writes a same-directory temp file then moves it over path with
// MoveFileEx(MOVEFILE_REPLACE_EXISTING), applying a protected DACL first.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".aegis-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	// Normalize the fully-qualified temp path for the Win32 APIs.
	name := strings.TrimPrefix(tempPath, `\\?\`)
	if err := protectPrivateDACL(name); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	return nil
}
