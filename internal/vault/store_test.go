package vault

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStoreInitializeLoadAndSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	store := Store{Path: path}

	if err := store.Initialize([]byte("master")); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("initialized mode = %04o, want 0600", info.Mode().Perm())
	}
	initial, err := store.Load([]byte("master"))
	if err != nil {
		t.Fatalf("Load(initial) error = %v", err)
	}
	if initial.Servers == nil || len(initial.Servers) != 0 {
		t.Fatalf("Load(initial) = %#v, want empty server map", initial)
	}

	want := Data{Servers: map[string]ServerSecret{
		"prod": {
			Host:            "prod.example.com",
			Port:            22,
			User:            "root",
			Password:        []byte("server-password"),
			HostFingerprint: "SHA256:fingerprint",
		},
	}}
	if err := store.Save([]byte("master"), want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load([]byte("master"))
	if err != nil {
		t.Fatalf("Load(saved) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load(saved) = %#v, want %#v", got, want)
	}
}

func TestStoreSaveUsesInjectedAtomicWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	master := []byte("master")
	want := Data{Servers: map[string]ServerSecret{"prod": {Host: "prod.example.com"}}}
	var gotPath string
	var gotMode fs.FileMode
	var gotEnvelope []byte
	store := Store{
		Path: path,
		WriteAtomic: func(path string, data []byte, mode fs.FileMode) error {
			gotPath = path
			gotMode = mode
			gotEnvelope = append([]byte(nil), data...)
			return nil
		},
	}

	if err := store.Save(master, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if gotPath != path {
		t.Fatalf("writer path = %q, want %q", gotPath, path)
	}
	if gotMode != 0o600 {
		t.Fatalf("writer mode = %04o, want 0600", gotMode)
	}
	got, err := Open(master, gotEnvelope)
	if err != nil {
		t.Fatalf("Open(writer data) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("writer data decrypts to %#v, want %#v", got, want)
	}
}

func TestStoreInitializeDoesNotOverwriteExistingVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	original := []byte("existing vault")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err := (Store{Path: path}).Initialize([]byte("master"))
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("Initialize() error = %v, want ErrAlreadyInitialized", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing vault = %q, want %q", got, original)
	}
}

func TestStoreRejectsUnsafePathsAndPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	wide := filepath.Join(dir, "wide.json")
	if err := os.WriteFile(wide, []byte("wide"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
		want error
	}{
		{"load symlink", symlink, ErrUnsafePath},
		{"save symlink", symlink, ErrUnsafePath},
		{"load directory", dir, ErrUnsafePath},
		{"save directory", dir, ErrUnsafePath},
		{"load wide permissions", wide, ErrUnsafePermissions},
		{"save wide permissions", wide, ErrUnsafePermissions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := Store{Path: tt.path}
			var err error
			if strings.HasPrefix(tt.name, "load") {
				_, err = store.Load([]byte("master"))
			} else {
				err = store.Save([]byte("master"), Data{})
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}

	info, err := os.Lstat(wide)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("unsafe existing mode = %04o, want unchanged 0644", info.Mode().Perm())
	}
	content, err := os.ReadFile(wide)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "wide" {
		t.Fatalf("unsafe existing content = %q, want unchanged", content)
	}
}

func TestValidatePrivateFileRejectsDifferentOwner(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ownership validation uses syscall.Stat_t")
	}
	info := fakeFileInfo{
		mode: 0o600,
		sys:  &syscall.Stat_t{Uid: uint32(os.Getuid() + 1)},
	}
	if err := validatePrivateFile(info); !errors.Is(err, ErrUnsafeOwner) {
		t.Fatalf("validatePrivateFile() error = %v, want ErrUnsafeOwner", err)
	}
}

func TestDefaultAtomicWriterOrdersDurableReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	want := []byte("encrypted vault")
	var events []string
	var temporaryPaths []string

	originalCreate := createTemporaryFile
	originalRename := renameFile
	originalSyncDirectory := syncDirectory
	createTemporaryFile = func(dir, pattern string) (temporaryFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		temporaryPaths = append(temporaryPaths, file.Name())
		return &recordingTemporaryFile{File: file, events: &events}, nil
	}
	renameFile = func(oldPath, newPath string) error {
		events = append(events, "rename")
		if filepath.Dir(oldPath) != dir {
			t.Errorf("temporary directory = %q, want %q", filepath.Dir(oldPath), dir)
		}
		if newPath != path {
			t.Errorf("rename destination = %q, want %q", newPath, path)
		}
		info, err := os.Lstat(oldPath)
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("temporary mode = %04o, want 0600", info.Mode().Perm())
		}
		content, err := os.ReadFile(oldPath)
		if err != nil {
			return err
		}
		if string(content) != string(want) {
			t.Errorf("temporary content = %q, want %q", content, want)
		}
		return os.Rename(oldPath, newPath)
	}
	syncDirectory = func(got string) error {
		events = append(events, "sync directory")
		if got != dir {
			t.Errorf("synced directory = %q, want %q", got, dir)
		}
		return nil
	}
	t.Cleanup(func() {
		createTemporaryFile = originalCreate
		renameFile = originalRename
		syncDirectory = originalSyncDirectory
	})

	if err := writeAtomic(path, want, 0o600); err != nil {
		t.Fatalf("writeAtomic() error = %v", err)
	}
	wantEvents := []string{"chmod", "write", "sync file", "close", "rename", "sync directory"}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	if len(temporaryPaths) != 1 {
		t.Fatalf("temporary paths = %v, want one", temporaryPaths)
	}
	base := filepath.Base(temporaryPaths[0])
	if !strings.HasPrefix(base, ".vault-") || !strings.HasSuffix(base, ".tmp") || temporaryPaths[0] == path {
		t.Fatalf("temporary path = %q, want random .vault-*.tmp sibling", temporaryPaths[0])
	}
}

func TestStoreSavePreservesExistingVaultWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	original := []byte("old encrypted vault")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	renameErr := errors.New("rename failed")
	originalRename := renameFile
	renameFile = func(string, string) error { return renameErr }
	t.Cleanup(func() { renameFile = originalRename })

	err := (Store{Path: path}).Save([]byte("master"), Data{})
	if !errors.Is(err, renameErr) {
		t.Fatalf("Save() error = %v, want rename failure", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing vault = %q, want %q", got, original)
	}
	assertNoTemporaryVaultFiles(t, dir)
}

func TestDefaultAtomicWriterReturnsDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	syncErr := errors.New("directory sync failed")
	originalSyncDirectory := syncDirectory
	syncDirectory = func(string) error { return syncErr }
	t.Cleanup(func() { syncDirectory = originalSyncDirectory })

	err := writeAtomic(path, []byte("encrypted"), 0o600)
	if !errors.Is(err, syncErr) {
		t.Fatalf("writeAtomic() error = %v, want directory sync failure", err)
	}
}

func TestDefaultAtomicWriterCleansUpAfterWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	writeErr := errors.New("write failed")
	originalCreate := createTemporaryFile
	createTemporaryFile = func(dir, pattern string) (temporaryFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return &failingWriteTemporaryFile{File: file, err: writeErr}, nil
	}
	t.Cleanup(func() { createTemporaryFile = originalCreate })

	err := writeAtomic(path, []byte("encrypted"), 0o600)
	if !errors.Is(err, writeErr) {
		t.Fatalf("writeAtomic() error = %v, want write failure", err)
	}
	assertNoTemporaryVaultFiles(t, dir)
}

func TestStoreSaveCreatesPrivateFileWithRestrictiveUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	previousUmask := syscall.Umask(0o777)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	if err := (Store{Path: path}).Save([]byte("master"), Data{}); err != nil {
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

type recordingTemporaryFile struct {
	*os.File
	events *[]string
}

func (file *recordingTemporaryFile) Chmod(mode fs.FileMode) error {
	*file.events = append(*file.events, "chmod")
	return file.File.Chmod(mode)
}

func (file *recordingTemporaryFile) Write(data []byte) (int, error) {
	*file.events = append(*file.events, "write")
	return file.File.Write(data)
}

func (file *recordingTemporaryFile) Sync() error {
	*file.events = append(*file.events, "sync file")
	return file.File.Sync()
}

func (file *recordingTemporaryFile) Close() error {
	*file.events = append(*file.events, "close")
	return file.File.Close()
}

type failingWriteTemporaryFile struct {
	*os.File
	err error
}

func (file *failingWriteTemporaryFile) Write([]byte) (int, error) {
	return 0, file.err
}

type fakeFileInfo struct {
	mode fs.FileMode
	sys  any
}

func (info fakeFileInfo) Name() string       { return "vault.json" }
func (info fakeFileInfo) Size() int64        { return 0 }
func (info fakeFileInfo) Mode() fs.FileMode  { return info.mode }
func (info fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info fakeFileInfo) Sys() any           { return info.sys }

func assertNoTemporaryVaultFiles(t *testing.T, dir string) {
	t.Helper()
	temps, err := filepath.Glob(filepath.Join(dir, ".vault-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary vault files remain: %v", temps)
	}
}
