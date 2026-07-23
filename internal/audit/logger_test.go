package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chenjw/aegis-ssh/internal/policy"
)

func TestEventExposesOnlyApprovedAuditFields(t *testing.T) {
	allowed := map[string]bool{
		"Timestamp": true, "RequestID": true, "Interface": true,
		"ServerAlias": true, "Command": true, "Decision": true,
		"RiskCategories": true, "ApprovalState": true, "DurationMS": true,
		"ExitCode": true, "TimedOut": true, "Truncated": true,
		"Redactions": true, "RequireSync": true,
	}
	forbidden := map[string]bool{
		"host": true, "port": true, "username": true, "user": true,
		"password": true, "fingerprint": true, "stdout": true,
		"stderr": true, "rawoutput": true,
	}
	typeOfEvent := reflect.TypeOf(Event{})
	for i := 0; i < typeOfEvent.NumField(); i++ {
		field := typeOfEvent.Field(i)
		if !allowed[field.Name] {
			t.Errorf("Event exposes unapproved field %q", field.Name)
		}
		if forbidden[strings.ToLower(field.Name)] {
			t.Errorf("Event exposes forbidden field %q", field.Name)
		}
	}
	for name := range allowed {
		if _, ok := typeOfEvent.FieldByName(name); !ok {
			t.Errorf("Event is missing approved field %q", name)
		}
	}
	for _, name := range []string{"Command", "RequireSync"} {
		field, _ := typeOfEvent.FieldByName(name)
		if field.Tag.Get("json") != "-" {
			t.Errorf("Event.%s json tag = %q, want -", name, field.Tag.Get("json"))
		}
	}
}

func TestWriteHashesExactCommandAndRedactsPreview(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 1 << 20, Backups: 1})
	command := strings.Join([]string{
		"curl http://user:pw@192.0.2.1/path",
		"Authorization: Bearer synthetic.header.signature",
		"password=synthetic-assignment",
		"-----BEGIN PRIVATE KEY-----\nSYNTHETIC-PRIVATE-KEY\n-----END PRIVATE KEY-----",
	}, "\n")
	wantHash := sha256.Sum256([]byte(command))

	err := logger.Write(Event{
		Timestamp:      time.Date(2026, 7, 23, 9, 8, 7, 0, time.UTC),
		RequestID:      "request-1",
		Interface:      "mcp",
		ServerAlias:    "prod",
		Command:        command,
		Decision:       "approved",
		RiskCategories: []policy.Category{policy.PrivateKey, policy.NetworkIdentity},
		ApprovalState:  "consumed",
		DurationMS:     125,
		ExitCode:       7,
		TimedOut:       true,
		Truncated:      true,
		Redactions:     map[string]int{"private_key_block": 1},
	})
	if err != nil {
		t.Fatalf("Write(): %v", err)
	}

	raw := readAuditFile(t, filepath.Join(dir, auditFilename))
	for _, secret := range []string{
		command, "user", "pw", "192.0.2.1", "synthetic.header.signature",
		"synthetic-assignment", "SYNTHETIC-PRIVATE-KEY",
	} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("audit log leaked %q: %s", secret, raw)
		}
	}
	record := decodeRecord(t, raw)
	if got := record["command_sha256"]; got != hex.EncodeToString(wantHash[:]) {
		t.Errorf("command_sha256 = %v, want %s", got, hex.EncodeToString(wantHash[:]))
	}
	preview, ok := record["command_preview"].(string)
	if !ok || preview == "" {
		t.Fatalf("command_preview = %#v, want non-empty string", record["command_preview"])
	}
	if len(preview) > maxCommandPreviewBytes || !utf8.ValidString(preview) {
		t.Errorf("command_preview is %d bytes or invalid UTF-8: %q", len(preview), preview)
	}
	for _, marker := range []string{"[REDACTED:URL_CREDENTIAL]", "[REDACTED:IP_ADDRESS]", "[REDACTED:BEARER_TOKEN]"} {
		if !strings.Contains(preview, marker) {
			t.Errorf("command_preview missing %q: %q", marker, preview)
		}
	}
	if _, ok := record["command"]; ok {
		t.Error("serialized record contains raw command field")
	}
}

func TestWriteRedactsEachCommandPreviewCategoryIndependently(t *testing.T) {
	tests := []struct {
		name    string
		command string
		secret  string
		marker  string
	}{
		{"IP address", "192.0.2.42 echo ip", "192.0.2.42", "[REDACTED:IP_ADDRESS]"},
		{"private key block", "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-KEY-PAYLOAD\n-----END PRIVATE KEY-----", "SYNTHETIC-KEY-PAYLOAD", "[REDACTED:PRIVATE_KEY_BLOCK]"},
		{"bearer token", "Bearer synthetic.header.signature", "synthetic.header.signature", "[REDACTED:BEARER_TOKEN]"},
		{"access key", "AKIA" + strings.Repeat("S", 16), "AKIA" + strings.Repeat("S", 16), "[REDACTED:ACCESS_KEY]"},
		{"URL credential", "https://alice:synthetic-password@example.test/path", "alice:synthetic-password", "[REDACTED:URL_CREDENTIAL]"},
		{"credential assignment", "password=synthetic-assignment", "synthetic-assignment", "[REDACTED:CREDENTIAL_ASSIGNMENT]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := privateTempDir(t)
			logger := newTestLogger(t, dir, Options{})
			if err := logger.Write(Event{Command: test.command}); err != nil {
				t.Fatalf("Write(): %v", err)
			}
			raw := readAuditFile(t, filepath.Join(dir, auditFilename))
			if strings.Contains(string(raw), test.secret) {
				t.Errorf("audit log leaked %q: %s", test.secret, raw)
			}
			preview, ok := decodeRecord(t, raw)["command_preview"].(string)
			if !ok || !strings.Contains(preview, test.marker) {
				t.Errorf("command_preview = %q, want marker %q", preview, test.marker)
			}
		})
	}
}

func TestWriteProducesValidBoundedUTF8JSON(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 1 << 20})
	long := strings.Repeat("界", 300)
	categories := make([]policy.Category, 100)
	for i := range categories {
		categories[i] = policy.Category(strings.Repeat("c", 100) + string(rune('a'+i%26)))
	}
	redactions := make(map[string]int, 100)
	for i := range 100 {
		redactions[strings.Repeat("r", 100)+string(rune('a'+i%26))+string(rune('A'+i/26))] = i
	}

	if err := logger.Write(Event{
		RequestID: long, Interface: long, ServerAlias: long, Command: long,
		Decision: long, ApprovalState: long, RiskCategories: categories,
		Redactions: redactions,
	}); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	raw := readAuditFile(t, filepath.Join(dir, auditFilename))
	if !utf8.Valid(raw) {
		t.Fatal("audit line is not valid UTF-8")
	}
	record := decodeRecord(t, raw)
	for _, field := range []string{"request_id", "interface", "server_alias", "decision", "approval_state"} {
		value, ok := record[field].(string)
		if !ok || len(value) > maxEventStringBytes || !utf8.ValidString(value) {
			t.Errorf("%s = %#v, want valid UTF-8 <= %d bytes", field, record[field], maxEventStringBytes)
		}
	}
	gotCategories, ok := record["risk_categories"].([]any)
	if !ok || len(gotCategories) > maxRiskCategories {
		t.Errorf("risk_categories length = %d, want <= %d", len(gotCategories), maxRiskCategories)
	}
	gotRedactions, ok := record["redactions"].(map[string]any)
	if !ok || len(gotRedactions) > maxRedactionCounts {
		t.Errorf("redactions length = %d, want <= %d", len(gotRedactions), maxRedactionCounts)
	}

	tooLong := strings.Repeat("x", maxCommandBytes+1)
	if err := logger.Write(Event{Command: tooLong}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("Write(oversized command) error = %v, want ErrInvalidEvent", err)
	}
}

func TestNewCreatesPrivateDirectoryAndAuditFile(t *testing.T) {
	parent := privateTempDir(t)
	dir := filepath.Join(parent, "audit")
	logger, err := New(dir, Options{})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if logger == nil {
		t.Fatal("New() returned nil logger")
	}
	assertMode(t, dir, fs.ModeDir|0o700)
	assertMode(t, filepath.Join(dir, auditFilename), 0o600)
}

func TestNewCreatesAuditFileWithExactModeDespiteUmask(t *testing.T) {
	dir := privateTempDir(t)
	oldUmask := syscall.Umask(0o777)
	t.Cleanup(func() { syscall.Umask(oldUmask) })
	if _, err := New(dir, Options{}); err != nil {
		t.Fatalf("New() with restrictive umask: %v", err)
	}
	assertMode(t, filepath.Join(dir, auditFilename), 0o600)
}

func TestNewRejectsExcessiveBackupCount(t *testing.T) {
	dir := privateTempDir(t)
	if _, err := New(dir, Options{Backups: 101}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New(Backups=101) error = %v, want ErrInvalidOptions", err)
	}
}

func TestBoundedRedactionsUsesBoundedMemoryForLargeInput(t *testing.T) {
	counts := make(map[string]int, 16<<10)
	for i := range 16 << 10 {
		counts["category-"+strconv.Itoa(i)] = i
	}
	result := testing.Benchmark(func(b *testing.B) {
		for range b.N {
			benchmarkRedactionsSink = boundedRedactions(counts)
		}
	})
	if got := result.AllocedBytesPerOp(); got > 64<<10 {
		t.Fatalf("boundedRedactions allocated %d bytes/op, want <= %d", got, 64<<10)
	}
	if len(benchmarkRedactionsSink) > maxRedactionCounts {
		t.Fatalf("boundedRedactions length = %d, want <= %d", len(benchmarkRedactionsSink), maxRedactionCounts)
	}
}

func TestTruncateUTF8UsesBoundedMemoryForLargeInvalidInput(t *testing.T) {
	input := strings.Repeat("\xff", 4<<20)
	result := testing.Benchmark(func(b *testing.B) {
		for range b.N {
			benchmarkStringSink = truncateUTF8(input, maxEventStringBytes)
		}
	})
	if got := result.AllocedBytesPerOp(); got > 64<<10 {
		t.Fatalf("truncateUTF8 allocated %d bytes/op, want <= %d", got, 64<<10)
	}
	if len(benchmarkStringSink) > maxEventStringBytes || !utf8.ValidString(benchmarkStringSink) {
		t.Fatalf("truncateUTF8 returned invalid or oversized string of %d bytes", len(benchmarkStringSink))
	}
}

func TestNewRejectsUnsafeDirectory(t *testing.T) {
	parent := privateTempDir(t)
	private := filepath.Join(parent, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		make func(string) string
	}{
		{"symlink", func(path string) string {
			if err := os.Symlink(private, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"regular file", func(path string) string {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"broad mode", func(path string) string {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o750); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.make(filepath.Join(parent, strings.ReplaceAll(test.name, " ", "-")))
			if _, err := New(path, Options{}); err == nil {
				t.Fatalf("New(%q) succeeded for unsafe directory", path)
			}
		})
	}
}

func TestNewRejectsUnsafeAuditFile(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(*testing.T, string)
	}{
		{"symlink", func(t *testing.T, path string) {
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"broad mode", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := privateTempDir(t)
			test.make(t, filepath.Join(dir, auditFilename))
			if _, err := New(dir, Options{}); err == nil {
				t.Fatal("New() succeeded for unsafe audit file")
			}
		})
	}
}

func TestNewRejectsNamedPipeWithoutBlocking(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, auditFilename)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo(): %v", err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := New(dir, Options{})
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("New() succeeded for named pipe")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("New() blocked while opening named pipe")
	}
}

func TestPrivatePathValidationRejectsNonOwner(t *testing.T) {
	info := fakeFileInfo{mode: fs.ModeDir | 0o700, uid: uint32(os.Getuid() + 1)}
	if err := validatePrivateDirectory(info); !errors.Is(err, ErrUnsafeOwner) {
		t.Errorf("validatePrivateDirectory() = %v, want ErrUnsafeOwner", err)
	}
	info.mode = 0o600
	if err := validatePrivateFile(info); !errors.Is(err, ErrUnsafeOwner) {
		t.Errorf("validatePrivateFile() = %v, want ErrUnsafeOwner", err)
	}
}

func TestWriteRevalidatesAuditPath(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{})
	path := filepath.Join(dir, auditFilename)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(Event{Command: "true"}); err == nil {
		t.Fatal("Write() succeeded after audit file was replaced by symlink")
	}
}

func TestWriteSyncsLifecycleEventsAndPropagatesSyncFailure(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{})
	var syncCalls int
	logger.syncFile = func(*os.File) error {
		syncCalls++
		return nil
	}
	if err := logger.Write(Event{Command: "echo ordinary"}); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 0 {
		t.Fatalf("ordinary event called Sync %d times, want 0", syncCalls)
	}
	if err := logger.Write(Event{Command: "echo lifecycle", ApprovalState: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(Event{Command: "echo forced", RequireSync: true}); err != nil {
		t.Fatal(err)
	}
	if syncCalls != 2 {
		t.Fatalf("durable events called Sync %d times, want 2", syncCalls)
	}

	want := errors.New("synthetic sync failure")
	logger.syncFile = func(*os.File) error { return want }
	if err := logger.Write(Event{Command: "echo fail", ApprovalState: "denied"}); !errors.Is(err, want) {
		t.Fatalf("Write() error = %v, want wrapped sync failure", err)
	}
}

func TestWriteRotatesAndRetainsOnlyConfiguredBackups(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 128, Backups: 2})
	for i := range 6 {
		if err := logger.Write(Event{RequestID: string(rune('a' + i)), Command: "echo rotation"}); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
	}
	for _, suffix := range []string{"", ".1", ".2"} {
		path := filepath.Join(dir, auditFilename+suffix)
		assertMode(t, path, 0o600)
		for _, line := range nonEmptyLines(readAuditFile(t, path)) {
			var record map[string]any
			if err := json.Unmarshal(line, &record); err != nil {
				t.Errorf("%s contains invalid JSON line %q: %v", path, line, err)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, auditFilename+".3")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected .3 backup: %v", err)
	}
}

func TestNewRemovesBackupsBeyondChangedRetention(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 128, Backups: 3})
	for i := range 4 {
		if err := logger.Write(Event{RequestID: strconv.Itoa(i), Command: "echo retention"}); err != nil {
			t.Fatalf("Write(%d): %v", i, err)
		}
	}
	for index := 1; index <= 3; index++ {
		assertMode(t, backupPath(filepath.Join(dir, auditFilename), index), 0o600)
	}
	unmatched := filepath.Join(dir, auditFilename+".extra")
	if err := os.WriteFile(unmatched, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	outOfRange := backupPath(filepath.Join(dir, auditFilename), maxBackups+1)
	if err := os.WriteFile(outOfRange, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := New(dir, Options{MaxBytes: 128, Backups: 2}); err != nil {
		t.Fatalf("New(Backups=2): %v", err)
	}
	for index := 1; index <= 2; index++ {
		assertMode(t, backupPath(filepath.Join(dir, auditFilename), index), 0o600)
	}
	if _, err := os.Lstat(backupPath(filepath.Join(dir, auditFilename), 3)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup .3 remains after retention shrank to 2: %v", err)
	}

	if _, err := New(dir, Options{MaxBytes: 128, Backups: 0}); err != nil {
		t.Fatalf("New(Backups=0): %v", err)
	}
	for index := 1; index <= maxBackups; index++ {
		if _, err := os.Lstat(backupPath(filepath.Join(dir, auditFilename), index)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("backup .%d remains with retention disabled: %v", index, err)
		}
	}
	if got, err := os.ReadFile(unmatched); err != nil || string(got) != "keep" {
		t.Fatalf("non-matching file changed: data=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(outOfRange); err != nil || string(got) != "keep" {
		t.Fatalf("out-of-range backup changed: data=%q err=%v", got, err)
	}
}

func TestNewRejectsUnsafeExcessBackupWithoutDeletingIt(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 128, Backups: 3})
	for range 4 {
		if err := logger.Write(Event{Command: "echo unsafe retention"}); err != nil {
			t.Fatal(err)
		}
	}
	unsafe := backupPath(filepath.Join(dir, auditFilename), 3)
	if err := os.Chmod(unsafe, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, Options{MaxBytes: 128, Backups: 2}); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("New() error = %v, want ErrUnsafePermissions", err)
	}
	if info, err := os.Lstat(unsafe); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("unsafe excess backup was changed: info=%v err=%v", info, err)
	}
}

func TestNewSyncsDirectoryAfterRemovingExcessBackups(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 128, Backups: 1})
	for range 2 {
		if err := logger.Write(Event{Command: "echo cleanup sync"}); err != nil {
			t.Fatal(err)
		}
	}

	original := syncAuditDirectory
	t.Cleanup(func() { syncAuditDirectory = original })
	syncCalls := 0
	syncAuditDirectory = func(path string) error {
		syncCalls++
		if path != dir {
			t.Errorf("sync path = %q, want %q", path, dir)
		}
		return nil
	}
	if _, err := New(dir, Options{MaxBytes: 128, Backups: 0}); err != nil {
		t.Fatalf("New(): %v", err)
	}
	if syncCalls != 1 {
		t.Fatalf("directory sync calls = %d, want 1", syncCalls)
	}
}

func TestNewPropagatesDirectorySyncFailureAfterBackupCleanup(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 128, Backups: 1})
	for range 2 {
		if err := logger.Write(Event{Command: "echo cleanup sync failure"}); err != nil {
			t.Fatal(err)
		}
	}

	original := syncAuditDirectory
	t.Cleanup(func() { syncAuditDirectory = original })
	want := errors.New("synthetic cleanup directory sync failure")
	syncAuditDirectory = func(string) error { return want }
	if _, err := New(dir, Options{MaxBytes: 128, Backups: 0}); !errors.Is(err, want) {
		t.Fatalf("New() error = %v, want wrapped sync failure", err)
	}
	if _, err := os.Lstat(backupPath(filepath.Join(dir, auditFilename), 1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("excess backup remains after reported sync failure: %v", err)
	}
}

func TestRotationNeededAvoidsOverflowAndAllowsFirstOversizedRecord(t *testing.T) {
	tests := []struct {
		name       string
		current    int64
		lineLength int64
		maxBytes   int64
		want       bool
	}{
		{"empty file accepts oversized first record", 0, 1024, 128, false},
		{"exact threshold", 100, 28, 128, false},
		{"over threshold", 100, 29, 128, true},
		{"overflow boundary", math.MaxInt64 - 4, 8, math.MaxInt64, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rotationNeeded(test.current, test.lineLength, test.maxBytes); got != test.want {
				t.Errorf("rotationNeeded(%d, %d, %d) = %t, want %t", test.current, test.lineLength, test.maxBytes, got, test.want)
			}
		})
	}
}

func TestWriteWithZeroBackupsDiscardsRotatedCurrent(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 128, Backups: 0})
	for range 3 {
		if err := logger.Write(Event{Command: "echo discard"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, auditFilename+".1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected backup with Backups=0: %v", err)
	}
}

func TestConcurrentWriteProducesOneJSONLinePerEvent(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{MaxBytes: 1 << 20})
	const writers = 64
	var group sync.WaitGroup
	errorsByWriter := make(chan error, writers)
	for i := range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsByWriter <- logger.Write(Event{RequestID: string(rune(i + 1)), Command: "echo concurrent"})
		}()
	}
	group.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Errorf("Write(): %v", err)
		}
	}
	lines := nonEmptyLines(readAuditFile(t, filepath.Join(dir, auditFilename)))
	if len(lines) != writers {
		t.Fatalf("line count = %d, want %d", len(lines), writers)
	}
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid concurrent JSON line: %v", err)
		}
	}
}

func newTestLogger(t *testing.T, dir string, options Options) *Logger {
	t.Helper()
	logger, err := New(dir, options)
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return logger
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(%q): %v", dir, err)
	}
	return dir
}

func readAuditFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return data
}

func decodeRecord(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(line, &record); err != nil {
		t.Fatalf("invalid audit JSON %q: %v", line, err)
	}
	return record
}

func nonEmptyLines(data []byte) [][]byte {
	var result [][]byte
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line != "" {
			result = append(result, []byte(line))
		}
	}
	return result
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", path, err)
	}
	if got := info.Mode(); got != want {
		t.Errorf("mode of %q = %v, want %v", path, got, want)
	}
}

type fakeFileInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (info fakeFileInfo) Name() string       { return "fake" }
func (info fakeFileInfo) Size() int64        { return 0 }
func (info fakeFileInfo) Mode() fs.FileMode  { return info.mode }
func (info fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: info.uid} }

var (
	benchmarkRedactionsSink map[string]int
	benchmarkStringSink     string
)
