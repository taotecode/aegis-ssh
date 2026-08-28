package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootIsDotAegisSSH(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatalf("Root() error: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	if root != filepath.Join(home, ".aegis-ssh") {
		t.Fatalf("Root() = %q, want %q", root, filepath.Join(home, ".aegis-ssh"))
	}
}

func TestLayout(t *testing.T) {
	paths := Layout("/tmp/xyz")
	if paths.ConfigFile != filepath.Join("/tmp/xyz", "servers.yaml") {
		t.Fatalf("ConfigFile = %q", paths.ConfigFile)
	}
	if paths.AuditFile != filepath.Join("/tmp/xyz", "audit", "aegis.jsonl") {
		t.Fatalf("AuditFile = %q", paths.AuditFile)
	}
}

func TestExpandHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	cases := []struct{ in, want string }{
		{"~/foo", filepath.Join(home, "foo")},
		{"~", home},
		{"a/b", "a/b"},
		{"~x/foo", "~x/foo"}, // only a bare ~ or ~/ is expanded
	}
	for _, c := range cases {
		if got := ExpandHome(c.in); got != c.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Backslash form is a Windows convenience; the local separator is applied
	// on each OS (on Unix a literal backslash survives in the joined result).
	if got, wantBS := ExpandHome(`~\foo`), filepath.Join(home, `\foo`); got != wantBS {
		t.Errorf("ExpandHome(~\\foo) = %q, want %q", got, wantBS)
	}
}

func TestWriteAtomicCreatesPrivateFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sub", "servers.yaml")
	data := []byte("version: 1\n")
	if err := WriteAtomic(target, data); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content = %q", got)
	}
	if err := PermsOK(target); err != nil {
		t.Fatalf("PermsOK after write: %v", err)
	}
	// Overwrite must also succeed (atomic replace of existing).
	if err := WriteAtomic(target, []byte("version: 2\n")); err != nil {
		t.Fatalf("WriteAtomic overwrite: %v", err)
	}
}

func TestPermsOKRejectsMissing(t *testing.T) {
	if err := PermsOK(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestEnsurePrivateDirCreatesAndVerifies(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
	// Re-run on existing must be fine.
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatalf("EnsurePrivateDir rerun: %v", err)
	}
}

func TestRootSuffix(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(root, ".aegis-ssh") {
		t.Fatalf("root suffix wrong: %q", root)
	}
}
