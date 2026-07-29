package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chenjw/aegis-ssh/internal/app"
)

func TestSanitizedErrorDoesNotExposeWrappedStorageDetails(t *testing.T) {
	secretPath := "/private/secret/vault.enc"
	got := sanitizedError(fmt.Errorf("open %s: %w", secretPath, app.ErrStorage))
	if got != "secure local storage operation failed" || strings.Contains(got, secretPath) {
		t.Fatalf("sanitizedError() = %q", got)
	}
}
