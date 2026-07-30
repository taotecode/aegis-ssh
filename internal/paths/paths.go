package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrUnsafePath        = errors.New("unsafe private path")
	ErrUnsafePermissions = errors.New("unsafe private path permissions")
	ErrUnsafeOwner       = errors.New("unsafe private path owner")
)

type Paths struct {
	Root         string
	ConfigFile   string
	VaultFile    string
	RecoveryFile string
	AuditDir     string
	LogsDir      string
	RunDir       string
	SocketFile   string
}

func DefaultRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".aegis-ssh"), nil
}

func EnsureLayout(root string) (Paths, error) {
	result := Paths{
		Root:         root,
		ConfigFile:   filepath.Join(root, "config.yaml"),
		VaultFile:    filepath.Join(root, "vault.enc"),
		RecoveryFile: filepath.Join(root, "recovery.enc"),
		AuditDir:     filepath.Join(root, "audit"),
		LogsDir:      filepath.Join(root, "logs"),
		RunDir:       filepath.Join(root, "run"),
		SocketFile:   filepath.Join(root, "run", "aegis.sock"),
	}

	for _, dir := range []string{result.Root, result.AuditDir, result.LogsDir, result.RunDir} {
		if err := ensurePrivateDir(dir); err != nil {
			return Paths{}, err
		}
	}
	return result, nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create private directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
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
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("inspect private directory: %w", ErrUnsafePermissions)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("inspect private directory: %w", ErrUnsafeOwner)
	}
	return nil
}
