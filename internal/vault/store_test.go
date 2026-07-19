package vault

import (
	"errors"
	"io"
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

func TestStoreSaveRejectsOversizedDataWithoutReplacingVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	master := []byte("master")
	want := Data{Servers: map[string]ServerSecret{
		"existing": {Host: "existing.example.com", Port: 22, User: "deploy", Password: []byte("old-secret")},
	}}
	original, err := Seal(master, want, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	err = (Store{Path: path}).Save(master, dataWithPasswordSize(13<<20))
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Save() error = %v, want ErrInvalidEnvelope", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatal("Save() changed existing vault bytes after oversized input")
	}
	got, err := (Store{Path: path}).Load(master)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want existing data", got)
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

func TestStoreInitializeDoesNotOverwriteSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	original := []byte("target content")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	err := (Store{Path: path}).Initialize([]byte("master"))
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Initialize() error = %v, want ErrUnsafePath", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("symlink target = %q, want unchanged %q", got, original)
	}
}

func TestStoreInitializePublishesOnlySyncedClosedTempByLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	master := []byte("master")
	var events []string
	var temporaryPath string
	ops := fileOps{
		createTemp: func(dir, pattern string) (temporaryFile, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			temporaryPath = file.Name()
			return &recordingTemporaryFile{File: file, events: &events}, nil
		},
		link: func(oldPath, newPath string) error {
			events = append(events, "link")
			if _, err := os.Lstat(newPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("final exists before link: %v", err)
			}
			if oldPath != temporaryPath || newPath != path {
				t.Errorf("link(%q, %q), want (%q, %q)", oldPath, newPath, temporaryPath, path)
			}
			info, err := os.Lstat(oldPath)
			if err != nil {
				return err
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("temporary mode = %04o, want 0600", info.Mode().Perm())
			}
			sealed, err := os.ReadFile(oldPath)
			if err != nil {
				return err
			}
			if _, err := Open(master, sealed); err != nil {
				t.Errorf("temporary vault is not complete: %v", err)
			}
			wantBeforeLink := []string{"chmod", "write", "sync file", "close", "link"}
			if !reflect.DeepEqual(events, wantBeforeLink) {
				t.Errorf("events before link = %v, want %v", events, wantBeforeLink)
			}
			return os.Link(oldPath, newPath)
		},
		remove: func(path string) error {
			events = append(events, "remove temp")
			return os.Remove(path)
		},
		syncDir: func(got string) error {
			events = append(events, "sync directory")
			if got != dir {
				t.Errorf("synced directory = %q, want %q", got, dir)
			}
			return nil
		},
	}

	if err := (Store{Path: path, ops: ops}).Initialize(master); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	wantEvents := []string{
		"chmod", "write", "sync file", "close", "link",
		"sync directory", "remove temp", "sync directory",
	}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
	assertNoTemporaryVaultFiles(t, dir)
	if _, err := (Store{Path: path}).Load(master); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestStoreInitializeFailuresBeforePublishLeaveNoFinal(t *testing.T) {
	tests := []struct {
		name string
		err  error
		ops  func(error) fileOps
	}{
		{
			name: "write",
			err:  errors.New("write failed"),
			ops: func(failure error) fileOps {
				return fileOps{createTemp: createWrappedTemporaryFile(func(file *os.File) temporaryFile {
					return &failingWriteTemporaryFile{File: file, err: failure}
				})}
			},
		},
		{
			name: "file sync",
			err:  errors.New("file sync failed"),
			ops: func(failure error) fileOps {
				return fileOps{createTemp: createWrappedTemporaryFile(func(file *os.File) temporaryFile {
					return &failingSyncTemporaryFile{File: file, err: failure}
				})}
			},
		},
		{
			name: "close",
			err:  errors.New("close failed"),
			ops: func(failure error) fileOps {
				return fileOps{createTemp: createWrappedTemporaryFile(func(file *os.File) temporaryFile {
					return &failingCloseTemporaryFile{File: file, err: failure}
				})}
			},
		},
		{
			name: "link",
			err:  errors.New("link failed"),
			ops: func(failure error) fileOps {
				return fileOps{link: func(string, string) error { return failure }}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "vault.json")
			err := (Store{Path: path, ops: tt.ops(tt.err)}).Initialize([]byte("master"))
			if !errors.Is(err, tt.err) {
				t.Fatalf("Initialize() error = %v, want %v", err, tt.err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("final exists after %s failure: %v", tt.name, err)
			}
			assertNoTemporaryVaultFiles(t, dir)
		})
	}
}

func TestStoreInitializeRollsBackWhenFirstDirectorySyncFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	syncErr := errors.New("directory sync failed")
	syncCalls := 0
	ops := fileOps{syncDir: func(string) error {
		syncCalls++
		if syncCalls == 1 {
			return syncErr
		}
		return nil
	}}

	err := (Store{Path: path, ops: ops}).Initialize([]byte("master"))
	if !errors.Is(err, syncErr) {
		t.Fatalf("Initialize() error = %v, want directory sync failure", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final exists after directory sync rollback: %v", err)
	}
	assertNoTemporaryVaultFiles(t, dir)
	if syncCalls < 2 {
		t.Fatalf("directory sync calls = %d, want rollback sync", syncCalls)
	}
}

func TestConcurrentInitializePublishesExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	results := make(chan error, 2)
	for range 2 {
		go func() {
			results <- (Store{Path: path}).Initialize([]byte("master"))
		}()
	}

	succeeded := 0
	alreadyInitialized := 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrAlreadyInitialized):
			alreadyInitialized++
		default:
			t.Fatalf("Initialize() error = %v", err)
		}
	}
	if succeeded != 1 || alreadyInitialized != 1 {
		t.Fatalf("results: success=%d already_initialized=%d, want 1 each", succeeded, alreadyInitialized)
	}
	if _, err := (Store{Path: path}).Load([]byte("master")); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestStoreInitializeCreatesPrivateFileWithRestrictiveUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	previousUmask := syscall.Umask(0o777)
	t.Cleanup(func() { syscall.Umask(previousUmask) })

	if err := (Store{Path: path}).Initialize([]byte("master")); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
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

func TestStoreLoadRejectsOversizedSparseFileBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxEnvelopeBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = (Store{Path: path}).Load([]byte("master"))
	assertSanitizedError(t, err, ErrInvalidEnvelope, path)
}

func TestReadEnvelopeRejectsGrowthBeyondLimit(t *testing.T) {
	reader := io.LimitReader(endlessSpaceReader{}, MaxEnvelopeBytes+1)
	_, err := readEnvelope(reader)
	assertSanitizedError(t, err, ErrInvalidEnvelope)
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

	ops := fileOps{
		createTemp: func(dir, pattern string) (temporaryFile, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			temporaryPaths = append(temporaryPaths, file.Name())
			return &recordingTemporaryFile{File: file, events: &events}, nil
		},
		rename: func(oldPath, newPath string) error {
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
		},
		syncDir: func(got string) error {
			events = append(events, "sync directory")
			if got != dir {
				t.Errorf("synced directory = %q, want %q", got, dir)
			}
			return nil
		},
	}

	if err := writeAtomicWithOps(path, want, 0o600, ops); err != nil {
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

	err := (Store{
		Path: path,
		ops:  fileOps{rename: func(string, string) error { return renameErr }},
	}).Save([]byte("master"), Data{})
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

	err := writeAtomicWithOps(path, []byte("encrypted"), 0o600, fileOps{
		syncDir: func(string) error { return syncErr },
	})
	if !errors.Is(err, syncErr) {
		t.Fatalf("writeAtomic() error = %v, want directory sync failure", err)
	}
}

func TestDefaultAtomicWriterCleansUpAfterWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	writeErr := errors.New("write failed")

	err := writeAtomicWithOps(path, []byte("encrypted"), 0o600, fileOps{
		createTemp: createWrappedTemporaryFile(func(file *os.File) temporaryFile {
			return &failingWriteTemporaryFile{File: file, err: writeErr}
		}),
	})
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

type failingSyncTemporaryFile struct {
	*os.File
	err error
}

func (file *failingSyncTemporaryFile) Sync() error {
	return file.err
}

type failingCloseTemporaryFile struct {
	*os.File
	err error
}

func (file *failingCloseTemporaryFile) Close() error {
	_ = file.File.Close()
	return file.err
}

type fakeFileInfo struct {
	mode fs.FileMode
	sys  any
}

type endlessSpaceReader struct{}

func (endlessSpaceReader) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = ' '
	}
	return len(data), nil
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

func createWrappedTemporaryFile(wrap func(*os.File) temporaryFile) func(string, string) (temporaryFile, error) {
	return func(dir, pattern string) (temporaryFile, error) {
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return wrap(file), nil
	}
}
