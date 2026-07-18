package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

var (
	ErrUnsafePath         = errors.New("unsafe vault path")
	ErrUnsafePermissions  = errors.New("unsafe vault permissions")
	ErrUnsafeOwner        = errors.New("unsafe vault owner")
	ErrAlreadyInitialized = errors.New("vault already initialized")

	createTemporaryFile = createTempFile
	renameFile          = os.Rename
	syncDirectory       = syncDirectoryToDisk
)

type AtomicWriteFunc func(path string, data []byte, mode fs.FileMode) error

type Store struct {
	Path        string
	WriteAtomic AtomicWriteFunc
}

type temporaryFile interface {
	Name() string
	Chmod(fs.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func (store Store) Initialize(master []byte) error {
	if info, err := os.Lstat(store.Path); err == nil {
		if err := validatePrivateFile(info); err != nil {
			return err
		}
		return ErrAlreadyInitialized
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect vault: %w", err)
	}

	sealed, err := Seal(master, Data{Servers: make(map[string]ServerSecret)}, DefaultKDFParams())
	if err != nil {
		return err
	}
	defer Zero(sealed)

	file, err := os.OpenFile(store.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrAlreadyInitialized
		}
		return fmt.Errorf("create vault: %w", err)
	}
	created := true
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if created {
			_ = os.Remove(store.Path)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure vault: %w", err)
	}
	if err := writeAll(file, sealed); err != nil {
		return fmt.Errorf("write vault: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync vault: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close vault: %w", err)
	}
	closed = true
	if err := syncDirectory(filepath.Dir(store.Path)); err != nil {
		return fmt.Errorf("sync vault directory: %w", err)
	}
	created = false
	return nil
}

func (store Store) Load(master []byte) (Data, error) {
	file, err := os.OpenFile(store.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if isSymlink(store.Path) {
			return Data{}, ErrUnsafePath
		}
		return Data{}, fmt.Errorf("open vault: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Data{}, fmt.Errorf("inspect vault: %w", err)
	}
	if err := validatePrivateFile(info); err != nil {
		return Data{}, err
	}
	sealed, err := io.ReadAll(file)
	if err != nil {
		return Data{}, fmt.Errorf("read vault: %w", err)
	}
	defer Zero(sealed)
	return Open(master, sealed)
}

func (store Store) Save(master []byte, data Data) error {
	if info, err := os.Lstat(store.Path); err == nil {
		if err := validatePrivateFile(info); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect vault: %w", err)
	}

	sealed, err := Seal(master, data, DefaultKDFParams())
	if err != nil {
		return err
	}
	defer Zero(sealed)
	writer := store.WriteAtomic
	if writer == nil {
		writer = writeAtomic
	}
	if err := writer(store.Path, sealed, 0o600); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	temporary, err := createTemporaryFile(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary vault: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()

	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("secure temporary vault: %w", err)
	}
	if err := writeAll(temporary, data); err != nil {
		return fmt.Errorf("write temporary vault: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary vault: %w", err)
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return fmt.Errorf("close temporary vault: %w", err)
	}
	closed = true
	if err := renameFile(temporaryPath, path); err != nil {
		return fmt.Errorf("replace vault: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync vault directory: %w", err)
	}
	return nil
}

func createTempFile(dir, pattern string) (temporaryFile, error) {
	return os.CreateTemp(dir, pattern)
}

func syncDirectoryToDisk(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != 0o600 {
		return ErrUnsafePermissions
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
