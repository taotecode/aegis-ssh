// Package store owns the single source of truth for server connection data:
// ~/.aegis-ssh/servers.yaml. It holds the model, load/save with private
// permission enforcement, and the validation rules that doctor and the CLI
// rely on. Credentials here are plaintext (password, private-key passphrase);
// the only protection is filesystem permissions verified via platform.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/taotecode/aegis-ssh/internal/platform"
	"gopkg.in/yaml.v3"
)

// Version is the servers.yaml schema version.
const Version = 1

// LanguageAuto is the default language selector: infer from the environment.
const LanguageAuto = "auto"

var (
	// ErrInvalidDocument is returned when the YAML cannot be parsed or fails
	// structural validation.
	ErrInvalidDocument = errors.New("invalid servers.yaml")
	// ErrUnsafeFile is returned when the file violates private-permission rules.
	ErrUnsafeFile = errors.New("unsafe servers.yaml permissions")
	// ErrNotFound is returned when the file does not exist.
	ErrNotFound = errors.New("servers.yaml not found")
	// ErrVersion is returned when the schema version is unsupported.
	ErrVersion = errors.New("unsupported servers.yaml version")
)

// AuthMethod selects how the executor authenticates.
type AuthMethod string

const (
	// AuthPassword authenticates with a plaintext password.
	AuthPassword AuthMethod = "password"
	// AuthKey authenticates with a private key stored at PrivateKeyPath.
	AuthKey AuthMethod = "key"
)

// Server is a single remote endpoint.
type Server struct {
	Description          string     `yaml:"description,omitempty"`
	Host                 string     `yaml:"host"`
	Port                 uint16     `yaml:"port"`
	User                 string     `yaml:"user"`
	Auth                 AuthMethod `yaml:"auth"`
	Password             string     `yaml:"password,omitempty"`               // required when auth=password; plaintext
	PrivateKeyPath       string     `yaml:"private_key_path,omitempty"`       // required when auth=key; path only, never content
	PrivateKeyPassphrase string     `yaml:"private_key_passphrase,omitempty"` // optional when auth=key; plaintext
	HostKey              string     `yaml:"host_key"`                         // required; SHA256 fingerprint, no TOFU
}

// Document is the top-level servers.yaml structure.
type Document struct {
	Version  int               `yaml:"version"`
	Language string            `yaml:"language,omitempty"`
	Servers  map[string]Server `yaml:"servers"`
}

// Validate reports a field-level error describing the first problem found.
func (d *Document) Validate() error {
	if d == nil {
		return ErrInvalidDocument
	}
	if d.Version != Version {
		return fmt.Errorf("%w: version %d", ErrVersion, d.Version)
	}
	switch d.Language {
	case "", LanguageAuto, "en", "zh-CN":
	default:
		return fmt.Errorf("%w: unsupported language %q", ErrInvalidDocument, d.Language)
	}
	for alias, server := range d.Servers {
		if !ValidAlias(alias) {
			return fmt.Errorf("%w: invalid alias %q", ErrInvalidDocument, alias)
		}
		if err := server.validate(alias); err != nil {
			return err
		}
	}
	return nil
}

func (s Server) validate(alias string) error {
	scheme := alias + ":"
	if strings.TrimSpace(s.Host) == "" {
		return fmt.Errorf("%w: %s missing host", ErrInvalidDocument, scheme)
	}
	if s.Port == 0 {
		return fmt.Errorf("%w: %s missing port", ErrInvalidDocument, scheme)
	}
	if strings.TrimSpace(s.User) == "" {
		return fmt.Errorf("%w: %s missing user", ErrInvalidDocument, scheme)
	}
	if strings.TrimSpace(s.HostKey) == "" {
		return fmt.Errorf("%w: %s missing host_key", ErrInvalidDocument, scheme)
	}
	var method AuthMethod
	switch s.Auth {
	case AuthPassword:
		method = AuthPassword
	case AuthKey:
		method = AuthKey
	default:
		method = AuthPassword // legacy / unspecified defaults to password
	}
	switch method {
	case AuthPassword:
		if s.Password == "" {
			return fmt.Errorf("%w: %s requires password for auth=password", ErrInvalidDocument, scheme)
		}
		if s.PrivateKeyPath != "" || s.PrivateKeyPassphrase != "" {
			return fmt.Errorf("%w: %s must not set private-key fields with auth=password", ErrInvalidDocument, scheme)
		}
	case AuthKey:
		if s.PrivateKeyPath == "" {
			return fmt.Errorf("%w: %s requires private_key_path for auth=key", ErrInvalidDocument, scheme)
		}
		if s.Password != "" {
			return fmt.Errorf("%w: %s must not set password with auth=key", ErrInvalidDocument, scheme)
		}
	}
	return nil
}

// Server returns the server for alias, or an error if absent/invalid.
func (d *Document) Server(alias string) (*Server, error) {
	if d == nil {
		return nil, ErrInvalidDocument
	}
	if !ValidAlias(alias) {
		return nil, fmt.Errorf("%w: invalid alias %q", ErrInvalidDocument, alias)
	}
	server, ok := d.Servers[alias]
	if !ok {
		return nil, fmt.Errorf("%w: alias %q not found", ErrInvalidDocument, alias)
	}
	copy := server
	return &copy, nil
}

// Aliases returns the sorted list of alias names.
func (d *Document) Aliases() []string {
	if d == nil {
		return nil
	}
	aliases := make([]string, 0, len(d.Servers))
	for alias := range d.Servers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
}

// EffectiveDefaultLanguage returns the value to use when none is configured.
func (d *Document) EffectiveDefaultLanguage() string {
	return LanguageAuto
}

// Load reads, parses, permission-checkschelle, and validates servers.yaml.
// A missing file returns ErrNotFound; an unsafe-permission file returns
// ErrUnsafeFile.
func Load(path string) (*Document, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err := platform.PermsOK(path); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsafeFile, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read servers.yaml: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// Parse decodes and validates servers.yaml bytes without touching the disk.
func Parse(data []byte) (*Document, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc Document
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: multiple YAML documents", ErrInvalidDocument)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Save validates and atomically writes servers.yaml with private permissions.
func Save(path string, doc *Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode servers.yaml: %w", err)
	}
	if err := platform.WriteAtomic(path, data); err != nil {
		return fmt.Errorf("write servers.yaml: %w", err)
	}
	return nil
}

// ValidAlias reports whether alias is a legal server alias: 1-64 chars,
// alphanumeric, with '.', '_', '-' allowed after the first character.
func ValidAlias(alias string) bool {
	if len(alias) == 0 || len(alias) > 64 {
		return false
	}
	for index, character := range alias {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-')
		if !valid {
			return false
		}
	}
	return true
}
