// Package platform is the single place that absorbs every difference between
// macOS / Linux / Windows for the aegis-ssh executor: root path resolution,
// private file & directory permissions, atomic writes, home expansion, and
// no-echo console reading.
//
// Constraint enforced across the rest of the module: no package outside this
// one may branch on runtime.GOOS or call syscall directly. Platform-specific
// behavior is exposed here through build-tagged files (platform_unix.go /
// platform_windows.go, console_unix.go / console_windows.go).
package platform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrUnsafePath is returned when a path is not a regular private file or dir.
	ErrUnsafePath = errors.New("unsafe aegis-ssh path")
	// ErrUnsafePermissions is returned when permissions are too permissive.
	ErrUnsafePermissions = errors.New("unsafe aegis-ssh permissions")
	// ErrUnsafeOwner is returned when a path is owned by another user.
	ErrUnsafeOwner = errors.New("unsafe aegis-ssh owner")
	// ErrNoConsole is returned when the controlling console cannot be opened.
	ErrNoConsole = errors.New("interactive console unavailable")
)

// Root returns the aegis-ssh data root for the current OS:
// $HOME/.aegis-ssh on macOS/Linux, %USERPROFILE%\.aegis-ssh on Windows.
func Root() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".aegis-ssh"), nil
}

// Paths holds the fully-resolved layout for a given root.
type Paths struct {
	Root       string
	ConfigFile string
	AuditDir   string
	AuditFile  string
}

// Layout resolves the data files under root without creating anything.
func Layout(root string) Paths {
	return Paths{
		Root:       root,
		ConfigFile: filepath.Join(root, "servers.yaml"),
		AuditDir:   filepath.Join(root, "audit"),
		AuditFile:  filepath.Join(root, "audit", "aegis.jsonl"),
	}
}

// EnsurePrivateDir creates path (and any missing parents) with private
// permissions, then verifies the result. It errors when the path already
// exists with unsafe permissions or the wrong owner.
func EnsurePrivateDir(path string) error {
	if err := ensurePrivateDir(path); err != nil {
		return err
	}
	return nil
}

// PermsOK verifies that an existing regular file at path has private
// permissions and ownership. It is used by the store loader and by doctor's
// self-check; a nil return means compliant.
func PermsOK(path string) error {
	return validatePrivateFile(path)
}

// WriteAtomic writes data to path via a same-directory temp file plus an
// atomic replace, applying private permissions. On Windows the replace uses
// MoveFileEx so an existing destination can be overwritten.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	return writeAtomic(path, data)
}

// ExpandHome expands a leading '~' (or '\') to the current user's home
// directory and normalizes separators. A non-leading '~' is left untouched.
// On Windows the separator is normalized to '\'.
func ExpandHome(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return expandHome(path, home)
}

func expandHome(path, home string) string {
	trimmed := strings.TrimSpace(path)
	if home != "" && (trimmed == "~" || strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, "~\\")) {
		return filepath.Join(home, trimmed[1:])
	}
	return path
}

// Console is the low-level controlling-terminal handle used by interactive
// user-facing commands. Password prompts are read here (no echo) rather than
// from process stdin, which an agent tool call may own.
type Console interface {
	io.Writer
	ReadPassword() ([]byte, error)
	ReadLine() (string, error)
	Close() error
}

// OpenConsole opens the controlling console for interactive input. On
// macOS/Linux this is /dev/tty; on Windows CONIN$/CONOUT$.
func OpenConsole() (Console, error) {
	return openConsole()
}
