package opslog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoggerFiltersLevelsAndWritesOnlyStructuredFields(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	logger, err := New(dir, "warn")
	if err != nil {
		t.Fatal(err)
	}
	logger.Write(Info, "broker", "ignored", "request", "prod", "", time.Second)
	logger.Write(Error, "broker", "failed", "request", "prod", "connection_failed", 2*time.Second)
	data, err := os.ReadFile(filepath.Join(dir, "aegis.log"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "ignored") || !strings.Contains(text, `"level":"error"`) || !strings.Contains(text, `"error_code":"connection_failed"`) {
		t.Fatalf("log=%q", text)
	}
	if info, err := os.Stat(filepath.Join(dir, "aegis.log")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info, err)
	}
}

func TestParseLevelRejectsUnknown(t *testing.T) {
	if _, ok := ParseLevel("trace"); ok {
		t.Fatal("trace unexpectedly accepted")
	}
}
