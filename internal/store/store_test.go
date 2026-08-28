package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/taotecode/aegis-ssh/internal/platform"
)

func validDoc() *Document {
	return &Document{
		Version:  Version,
		Language: LanguageAuto,
		Servers: map[string]Server{
			"prod": {
				Description: "production web",
				Host:        "10.0.0.5",
				Port:        22,
				User:        "deploy",
				Auth:        AuthPassword,
				Password:    "s3cr3t",
				HostKey:     "SHA256:aaaa",
			},
			"db": {
				Host:           "10.0.0.9",
				Port:           22,
				User:           "root",
				Auth:           AuthKey,
				PrivateKeyPath: "~/.ssh/id_ed25519",
				HostKey:        "SHA256:bbbb",
			},
		},
	}
}

func TestValidateOK(t *testing.T) {
	if err := validDoc().Validate(); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}
}

func TestValidateBadVersion(t *testing.T) {
	doc := validDoc()
	doc.Version = 99
	if err := doc.Validate(); err == nil {
		t.Fatal("expected version error")
	}
}

func TestValidateBadAlias(t *testing.T) {
	doc := validDoc()
	doc.Servers["-bad"] = doc.Servers["prod"]
	if err := doc.Validate(); err == nil {
		t.Fatal("expected alias error")
	}
}

func TestValidatePasswordNeedsPassword(t *testing.T) {
	doc := validDoc()
	s := doc.Servers["prod"]
	s.Password = ""
	doc.Servers["prod"] = s
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("expected password error, got %v", err)
	}
}

func TestValidatePasswordRejectsKeyFields(t *testing.T) {
	doc := validDoc()
	s := doc.Servers["prod"]
	s.PrivateKeyPath = "/x"
	doc.Servers["prod"] = s
	if err := doc.Validate(); err == nil {
		t.Fatal("expected mixed-auth error")
	}
}

func TestValidateKeyNeedsPath(t *testing.T) {
	doc := validDoc()
	s := doc.Servers["db"]
	s.PrivateKeyPath = ""
	doc.Servers["db"] = s
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "private_key_path") {
		t.Fatalf("expected key-path error, got %v", err)
	}
}

func TestValidateKeyRejectsPassword(t *testing.T) {
	doc := validDoc()
	s := doc.Servers["db"]
	s.Password = "x"
	doc.Servers["db"] = s
	if err := doc.Validate(); err == nil {
		t.Fatal("expected mixed-auth error")
	}
}

func TestValidateMissingHostKey(t *testing.T) {
	doc := validDoc()
	s := doc.Servers["db"]
	s.HostKey = ""
	doc.Servers["db"] = s
	if err := doc.Validate(); err == nil {
		t.Fatal("expected host_key error")
	}
}

func TestParseAndSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.yaml")
	doc := validDoc()
	if err := Save(path, doc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// File should be private.
	if err := platform.PermsOK(path); err != nil {
		t.Fatalf("saved file not private: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(loaded.Servers))
	}
	if got := loaded.Servers["db"].PrivateKeyPath; got != "~/.ssh/id_ed25519" {
		t.Fatalf("key path = %q", got)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLoadUnsafePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows permission semantics differ; enforced via DACL in doctor")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nservers: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsafe-permissions error for mode 0644")
	}
}

func TestAliasesSorted(t *testing.T) {
	doc := validDoc()
	aliases := doc.Aliases()
	if len(aliases) != 2 || aliases[0] != "db" || aliases[1] != "prod" {
		t.Fatalf("aliases = %v", aliases)
	}
}

func TestServerLookup(t *testing.T) {
	doc := validDoc()
	s, err := doc.Server("prod")
	if err != nil || s.User != "deploy" {
		t.Fatalf("Server(prod) = %+v, %v", s, err)
	}
	if _, err := doc.Server("nope"); err == nil {
		t.Fatal("expected not-found error")
	}
}
