package paths_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/chenjw/aegis-ssh/internal/paths"
)

func TestDefaultRootUsesPrivateHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got, err := paths.DefaultRoot()
	if err != nil {
		t.Fatalf("DefaultRoot() error = %v", err)
	}
	want := filepath.Join(home, ".aegis-ssh")
	if got != want {
		t.Fatalf("DefaultRoot() = %q, want %q", got, want)
	}
}

func TestEnsureLayoutCreatesPrivateDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "aegis")

	got, err := paths.EnsureLayout(root)
	if err != nil {
		t.Fatalf("EnsureLayout() error = %v", err)
	}

	want := paths.Paths{
		Root:       root,
		ConfigFile: filepath.Join(root, "config.yaml"),
		VaultFile:  filepath.Join(root, "vault.enc"),
		AuditDir:   filepath.Join(root, "audit"),
		RunDir:     filepath.Join(root, "run"),
		SocketFile: filepath.Join(root, "run", "aegis.sock"),
	}
	if got != want {
		t.Fatalf("EnsureLayout() = %#v, want %#v", got, want)
	}

	for _, dir := range []string{got.Root, got.AuditDir, got.RunDir} {
		info, statErr := os.Lstat(dir)
		if statErr != nil {
			t.Fatalf("Lstat(%q): %v", dir, statErr)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("mode for %q = %04o, want 0700", dir, info.Mode().Perm())
		}
		assertOwnedByCurrentUser(t, info)
	}
}

func TestEnsureLayoutRejectsOverPermissiveRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "aegis")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := paths.EnsureLayout(root)
	if !errors.Is(err, paths.ErrUnsafePermissions) {
		t.Fatalf("EnsureLayout() error = %v, want ErrUnsafePermissions", err)
	}
}

func TestEnsureLayoutRejectsRootSymlink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "aegis")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}

	_, err := paths.EnsureLayout(root)
	if !errors.Is(err, paths.ErrUnsafePath) {
		t.Fatalf("EnsureLayout() error = %v, want ErrUnsafePath", err)
	}
}

func TestEnsureLayoutRejectsSymlinkedChild(t *testing.T) {
	root := filepath.Join(t.TempDir(), "aegis")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "audit")); err != nil {
		t.Fatal(err)
	}

	_, err := paths.EnsureLayout(root)
	if !errors.Is(err, paths.ErrUnsafePath) {
		t.Fatalf("EnsureLayout() error = %v, want ErrUnsafePath", err)
	}
}

func assertOwnedByCurrentUser(t *testing.T, info os.FileInfo) {
	t.Helper()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ownership assertion is supported on darwin and linux")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("file info does not contain syscall.Stat_t")
	}
	if int(stat.Uid) != os.Getuid() {
		t.Errorf("owner uid = %d, want %d", stat.Uid, os.Getuid())
	}
}
