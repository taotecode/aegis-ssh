package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"
)

var (
	ErrUnsafePath        = errors.New("unsafe config path")
	ErrUnsafePermissions = errors.New("unsafe config permissions")
	ErrUnsafeOwner       = errors.New("unsafe config owner")
)

type Config struct {
	Version  int                     `yaml:"version"`
	Defaults Defaults                `yaml:"defaults"`
	Servers  map[string]ServerPublic `yaml:"servers"`
}

type Defaults struct {
	ConnectTimeout  string `yaml:"connect_timeout,omitempty"`
	CommandTimeout  string `yaml:"command_timeout,omitempty"`
	MaxOutputBytes  int64  `yaml:"max_output_bytes,omitempty"`
	AuditFailClosed bool   `yaml:"audit_fail_closed"`
}

type ServerPublic struct {
	Description string `yaml:"description,omitempty"`
}

func Parse(data []byte) (Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("parse config: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func Load(path string) (Config, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if isSymlink(path) {
			return Config{}, fmt.Errorf("open config: %w", ErrUnsafePath)
		}
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("inspect config: %w", err)
	}
	if err := validatePrivateFile(info); err != nil {
		return Config{}, err
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

func Save(path string, cfg Config) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("save config: %w", ErrUnsafePath)
		}
		if err := validatePrivateFile(info); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect config: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("inspect config: %w", ErrUnsafePath)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("inspect config: %w", ErrUnsafePermissions)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("inspect config: %w", ErrUnsafeOwner)
	}
	return nil
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}
