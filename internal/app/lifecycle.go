package app

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

type lifecycleLock struct {
	file *os.File
}

func acquireLifecycleLock(root string) (*lifecycleLock, error) {
	path := filepath.Join(root, "run", "lifecycle.lock")
	if info, err := os.Lstat(path); err == nil {
		if !safeLifecycleFile(info) {
			return nil, ErrStorage
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrStorage
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ErrStorage
	}
	info, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !safeLifecycleFile(info) || !safeLifecycleFile(pathInfo) || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		return nil, ErrStorage
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrDaemonRunning
		}
		return nil, ErrStorage
	}
	return &lifecycleLock{file: file}, nil
}

func safeLifecycleFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && info.Mode().IsRegular() &&
		info.Mode().Perm() == 0o600 && info.Mode()&os.ModeSymlink == 0
}

func (lock *lifecycleLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	return errors.Join(err, lock.file.Close())
}
