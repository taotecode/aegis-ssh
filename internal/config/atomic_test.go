package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSavePreservesExistingFileWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("version: 1\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	renameErr := errors.New("rename failed")
	originalRename := renameFile
	renameFile = func(string, string) error { return renameErr }
	t.Cleanup(func() { renameFile = originalRename })

	err := Save(path, Config{Version: 2})
	if !errors.Is(err, renameErr) {
		t.Fatalf("Save() error = %v, want rename failure", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing config = %q, want %q", got, original)
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".config-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary files remain after rename failure: %v", temps)
	}
}

func TestSaveReturnsDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	syncErr := errors.New("directory sync failed")
	originalSyncDirectory := syncDirectory
	syncedPath := ""
	syncDirectory = func(path string) error {
		syncedPath = path
		return syncErr
	}
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })

	err := Save(path, Config{Version: 1})
	if !errors.Is(err, syncErr) {
		t.Fatalf("Save() error = %v, want directory sync failure", err)
	}
	if syncedPath != dir {
		t.Fatalf("synced directory = %q, want %q", syncedPath, dir)
	}
}
