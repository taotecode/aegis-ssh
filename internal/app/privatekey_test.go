package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateKeyFileRequiresPrivateOwnedRegularFile(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(validPath, []byte("private-key-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateKeyFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { clear(got) }()
	if string(got) != "private-key-fixture" {
		t.Fatalf("read key = %q", got)
	}

	publicPath := filepath.Join(dir, "public-key")
	if err := os.WriteFile(publicPath, []byte("private-key-fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "key-link")
	if err := os.Symlink(validPath, linkPath); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(dir, "empty-key")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(dir, "oversized-key")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, maxPrivateKeyBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"", publicPath, linkPath, dir, emptyPath, oversizedPath, filepath.Join(dir, "missing")} {
		if key, err := readPrivateKeyFile(path); !errors.Is(err, ErrPrivateKey) || key != nil {
			clear(key)
			t.Fatalf("readPrivateKeyFile(%q) = %d bytes, %v", path, len(key), err)
		}
	}
}
