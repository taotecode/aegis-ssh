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
)

type AtomicWriteFunc func(path string, data []byte, mode fs.FileMode) error

type Store struct {
	Path        string
	WriteAtomic AtomicWriteFunc
	ops         fileOps
}

type temporaryFile interface {
	Name() string
	Chmod(fs.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type fileOps struct {
	createTemp func(string, string) (temporaryFile, error)
	rename     func(string, string) error
	link       func(string, string) error
	remove     func(string) error
	syncDir    func(string) error
}

func defaultFileOps() fileOps {
	return fileOps{
		createTemp: createTempFile,
		rename:     os.Rename,
		link:       os.Link,
		remove:     os.Remove,
		syncDir:    syncDirectoryToDisk,
	}
}

func (ops fileOps) withDefaults() fileOps {
	defaults := defaultFileOps()
	if ops.createTemp == nil {
		ops.createTemp = defaults.createTemp
	}
	if ops.rename == nil {
		ops.rename = defaults.rename
	}
	if ops.link == nil {
		ops.link = defaults.link
	}
	if ops.remove == nil {
		ops.remove = defaults.remove
	}
	if ops.syncDir == nil {
		ops.syncDir = defaults.syncDir
	}
	return ops
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

	dir := filepath.Dir(store.Path)
	ops := store.ops.withDefaults()
	file, err := ops.createTemp(dir, ".vault-init-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary vault: %w", err)
	}
	temporaryPath := file.Name()
	temporaryExists := true
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if temporaryExists {
			_ = ops.remove(temporaryPath)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary vault: %w", err)
	}
	if err := writeAll(file, sealed); err != nil {
		return fmt.Errorf("write temporary vault: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary vault: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close temporary vault: %w", err)
	}
	closed = true

	if err := ops.link(temporaryPath, store.Path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrAlreadyInitialized
		}
		return fmt.Errorf("publish vault: %w", err)
	}
	if err := ops.syncDir(dir); err != nil {
		rollbackErr := removeLinkedFile(ops, temporaryPath, store.Path)
		removeTempErr := ops.remove(temporaryPath)
		if removeTempErr == nil || errors.Is(removeTempErr, fs.ErrNotExist) {
			temporaryExists = false
			removeTempErr = nil
		}
		resyncErr := ops.syncDir(dir)
		return fmt.Errorf("sync published vault directory: %w", errors.Join(err, rollbackErr, removeTempErr, resyncErr))
	}
	if err := ops.remove(temporaryPath); err != nil {
		return fmt.Errorf("remove temporary vault: %w", err)
	}
	temporaryExists = false
	if err := ops.syncDir(dir); err != nil {
		return fmt.Errorf("sync temporary vault removal: %w", err)
	}
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
	if info.Size() <= 0 || info.Size() > MaxEnvelopeBytes {
		return Data{}, ErrInvalidEnvelope
	}
	sealed, err := readEnvelope(file)
	if err != nil {
		return Data{}, err
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
	if writer != nil {
		if err := writer(store.Path, sealed, 0o600); err != nil {
			return fmt.Errorf("save vault: %w", err)
		}
		return nil
	}
	if err := writeAtomicWithOps(store.Path, sealed, 0o600, store.ops); err != nil {
		return fmt.Errorf("save vault: %w", err)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode fs.FileMode) error {
	return writeAtomicWithOps(path, data, mode, fileOps{})
}

func writeAtomicWithOps(path string, data []byte, mode fs.FileMode, ops fileOps) error {
	ops = ops.withDefaults()
	dir := filepath.Dir(path)
	temporary, err := ops.createTemp(dir, ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary vault: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = ops.remove(temporaryPath)
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
	if err := ops.rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace vault: %w", err)
	}
	if err := ops.syncDir(dir); err != nil {
		return fmt.Errorf("sync vault directory: %w", err)
	}
	return nil
}

func removeLinkedFile(ops fileOps, temporaryPath, finalPath string) error {
	temporaryInfo, err := os.Lstat(temporaryPath)
	if err != nil {
		return err
	}
	finalInfo, err := os.Lstat(finalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(temporaryInfo, finalInfo) {
		return ErrUnsafePath
	}
	return ops.remove(finalPath)
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

func readEnvelope(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxEnvelopeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read vault: %w", err)
	}
	if len(data) == 0 || len(data) > MaxEnvelopeBytes {
		Zero(data)
		return nil, ErrInvalidEnvelope
	}
	return data, nil
}
