//go:build darwin || linux

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	privateDirMode  = os.FileMode(0o700)
	privateFileMode = os.FileMode(0o600)
)

// ensurePrivateDir creates the directory (and parents) with 0700 and verifies
// mode + uid.
func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, privateDirMode); err != nil {
			return fmt.Errorf("create private directory: %w", err)
		}
		if err := os.Chmod(path, privateDirMode); err != nil {
			return fmt.Errorf("secure private directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("inspect private directory: %w", ErrUnsafePath)
	}
	if info.Mode().Perm() != privateDirMode {
		return fmt.Errorf("inspect private directory: %w", ErrUnsafePermissions)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("inspect private directory: %w", ErrUnsafeOwner)
	}
	return nil
}

// validatePrivateFile verifies an existing file has 0600 and matching uid.
func validatePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("inspect private file: %w", ErrUnsafePath)
	}
	if info.Mode().Perm() != privateFileMode {
		return fmt.Errorf("inspect private file: %w", ErrUnsafePermissions)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("inspect private file: %w", ErrUnsafeOwner)
	}
	return nil
}

// writeAtomic writes a same-directory temp file (0600, fsynced) and renames it
// over path.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".aegis-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(privateFileMode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("secure temporary file: %w", err)
	}
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
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func syncDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}
