package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"

	"github.com/taotecode/aegis-ssh/internal/config"
)

func TestParseRejectsConnectionFields(t *testing.T) {
	data := []byte("version: 1\ndefaults: {}\nservers:\n  prod:\n    host: internal.example\n")

	_, err := config.Parse(data)
	if err == nil {
		t.Fatal("Parse() error = nil, want unknown-field error")
	}
}

func TestParseRejectsUnknownDefaults(t *testing.T) {
	data := []byte("version: 1\ndefaults:\n  retries: 3\nservers: {}\n")

	_, err := config.Parse(data)
	if err == nil {
		t.Fatal("Parse() error = nil, want unknown-field error")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	want := config.Config{
		Version: 1,
		Defaults: config.Defaults{
			ConnectTimeout:  "10s",
			CommandTimeout:  "2m",
			MaxOutputBytes:  1 << 20,
			AuditFailClosed: true,
		},
		Servers: map[string]config.ServerPublic{
			"prod": {Description: "Production application servers"},
		},
	}

	if err := config.Save(path, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestSaveCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	if err := config.Save(path, config.Config{Version: 1}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	assertOwnedByCurrentUser(t, info)
}

func TestSaveCreatesPrivateFileWithRestrictiveUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	previousUmask := syscall.Umask(0o777)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	if err := config.Save(path, config.Config{Version: 1}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLoadRejectsOverPermissiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load(path)
	if !errors.Is(err, config.ErrUnsafePermissions) {
		t.Fatalf("Load() error = %v, want ErrUnsafePermissions", err)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load(path)
	if !errors.Is(err, config.ErrUnsafePath) {
		t.Fatalf("Load() error = %v, want ErrUnsafePath", err)
	}
}

func TestSaveRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	err := config.Save(path, config.Config{Version: 1})
	if !errors.Is(err, config.ErrUnsafePath) {
		t.Fatalf("Save() error = %v, want ErrUnsafePath", err)
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
