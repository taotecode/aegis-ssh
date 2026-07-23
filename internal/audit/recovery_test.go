package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestNewRejectsMaxBytesAboveFixedLimit(t *testing.T) {
	dir := privateTempDir(t)
	if _, err := New(dir, Options{MaxBytes: 64<<20 + 1}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New(MaxBytes > 64 MiB) error = %v, want ErrInvalidOptions", err)
	}
}

func TestBoundedRedactionsSelectsLexicographicallySmallestKeysDeterministically(t *testing.T) {
	ascending := make(map[string]int, 64)
	descending := make(map[string]int, 64)
	for index := range 64 {
		ascending[fmt.Sprintf("key-%03d", index)] = index
	}
	for index := 63; index >= 0; index-- {
		descending[fmt.Sprintf("key-%03d", index)] = index
	}
	wantKeys := make([]string, maxRedactionCounts)
	for index := range maxRedactionCounts {
		wantKeys[index] = fmt.Sprintf("key-%03d", index)
	}

	for run := range 20 {
		first := boundedRedactions(ascending)
		second := boundedRedactions(descending)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("run %d produced order-dependent redactions:\nfirst=%v\nsecond=%v", run, first, second)
		}
		gotKeys := make([]string, 0, len(first))
		for key := range first {
			gotKeys = append(gotKeys, key)
		}
		sort.Strings(gotKeys)
		if !reflect.DeepEqual(gotKeys, wantKeys) {
			t.Fatalf("run %d keys = %v, want %v", run, gotKeys, wantKeys)
		}
	}
}

func TestNewCleansNumericBackupsBeyondLegacyLimit(t *testing.T) {
	dir := privateTempDir(t)
	if _, err := New(dir, Options{Backups: maxBackups}); err != nil {
		t.Fatalf("New(): %v", err)
	}
	legacy := backupPath(filepath.Join(dir, auditFilename), maxBackups+1)
	if err := os.WriteFile(legacy, []byte("legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, auditFilename+".extra")
	if err := os.WriteFile(extra, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := New(dir, Options{Backups: 0}); err != nil {
		t.Fatalf("New(Backups=0): %v", err)
	}
	if _, err := os.Lstat(legacy); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("numeric backup beyond %d remains: %v", maxBackups, err)
	}
	if got, err := os.ReadFile(extra); err != nil || string(got) != "keep" {
		t.Fatalf("non-numeric backup changed: data=%q err=%v", got, err)
	}
}

func TestNewRemovesLeadingZeroBackupAliases(t *testing.T) {
	dir := privateTempDir(t)
	if _, err := New(dir, Options{Backups: 1}); err != nil {
		t.Fatalf("New(): %v", err)
	}
	canonical := backupPath(filepath.Join(dir, auditFilename), 1)
	aliases := []string{
		filepath.Join(dir, auditFilename+".01"),
		filepath.Join(dir, auditFilename+".001"),
	}
	for _, path := range append([]string{canonical}, aliases...) {
		if err := os.WriteFile(path, []byte("backup\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := New(dir, Options{Backups: 1}); err != nil {
		t.Fatalf("New(Backups=1): %v", err)
	}
	if _, err := os.Lstat(canonical); err != nil {
		t.Fatalf("canonical backup removed: %v", err)
	}
	for _, path := range aliases {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("leading-zero backup alias %q remains: %v", path, err)
		}
	}
}

func TestWriteRollsBackPartialJSONLine(t *testing.T) {
	dir := privateTempDir(t)
	want := errors.New("synthetic partial write")
	logger, err := newWithHooks(dir, Options{}, loggerHooks{
		write: func(file *os.File, data []byte) (int, error) {
			written, writeErr := file.Write(data[:len(data)/2])
			if writeErr != nil {
				return written, writeErr
			}
			return written, want
		},
	})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	if err := logger.Write(Event{Command: "echo partial"}); !errors.Is(err, want) {
		t.Fatalf("Write() error = %v, want partial write error", err)
	}
	if raw := readAuditFile(t, filepath.Join(dir, auditFilename)); len(raw) != 0 {
		t.Fatalf("audit file retained partial line: %q", raw)
	}
}

func TestWriteReportsPartialWriteAndRollbackFailure(t *testing.T) {
	dir := privateTempDir(t)
	writeFailure := errors.New("synthetic partial write")
	rollbackFailure := errors.New("synthetic truncate failure")
	logger, err := newWithHooks(dir, Options{}, loggerHooks{
		write: func(file *os.File, data []byte) (int, error) {
			written, writeErr := file.Write(data[:len(data)/2])
			if writeErr != nil {
				return written, writeErr
			}
			return written, writeFailure
		},
		truncate: func(*os.File, int64) error { return rollbackFailure },
	})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	err = logger.Write(Event{Command: "echo rollback failure"})
	if !errors.Is(err, writeFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("Write() error = %v, want both write and rollback failures", err)
	}
}

func TestNewRepairsTrailingPartialJSONLine(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, auditFilename)
	complete := []byte("{\"existing\":true}\n")
	if err := os.WriteFile(path, append(append([]byte(nil), complete...), []byte("{\"partial\":")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, Options{}); err != nil {
		t.Fatalf("New(): %v", err)
	}
	if got := readAuditFile(t, path); !reflect.DeepEqual(got, complete) {
		t.Fatalf("repaired audit = %q, want %q", got, complete)
	}
}

func TestWriteRepairsTrailingPartialJSONLineBeforeAppend(t *testing.T) {
	dir := privateTempDir(t)
	logger := newTestLogger(t, dir, Options{})
	path := filepath.Join(dir, auditFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(file, "{\"partial\":"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(Event{Command: "echo repaired"}); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	lines := nonEmptyLines(readAuditFile(t, path))
	if len(lines) != 1 {
		t.Fatalf("line count = %d, want 1: %q", len(lines), lines)
	}
	if record := decodeRecord(t, lines[0]); record["command_preview"] != "echo repaired" {
		t.Fatalf("unexpected repaired record: %v", record)
	}
}

func TestMultipleLoggersSerializeWritesAndRotation(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 256, Backups: 16}
	first := newTestLogger(t, dir, options)
	second := newTestLogger(t, dir, options)
	loggers := []*Logger{first, second}

	const writes = 12
	var group sync.WaitGroup
	errorsByWrite := make(chan error, writes)
	for index := range writes {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsByWrite <- loggers[index%len(loggers)].Write(Event{
				RequestID: "multi-" + strconv.Itoa(index),
				Command:   "echo multi logger rotation",
			})
		}()
	}
	group.Wait()
	close(errorsByWrite)
	for err := range errorsByWrite {
		if err != nil {
			t.Errorf("Write(): %v", err)
		}
	}

	seen := make(map[string]bool, writes)
	for index := 0; index <= options.Backups; index++ {
		path := filepath.Join(dir, auditFilename)
		if index > 0 {
			path = backupPath(path, index)
		}
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", path, err)
		}
		for _, line := range nonEmptyLines(raw) {
			record := decodeRecord(t, line)
			requestID, _ := record["request_id"].(string)
			if seen[requestID] {
				t.Errorf("duplicate request_id %q", requestID)
			}
			seen[requestID] = true
		}
	}
	if len(seen) != writes {
		t.Fatalf("retained request IDs = %d, want %d", len(seen), writes)
	}
	lockInfo, err := os.Lstat(filepath.Join(dir, "audit.lock"))
	if err != nil {
		t.Fatalf("Lstat(audit.lock): %v", err)
	}
	if lockInfo.Mode().Perm() != 0o600 || !lockInfo.Mode().IsRegular() || lockInfo.Size() != 0 {
		t.Fatalf("audit.lock info = mode %v size %d, want regular 0600 empty", lockInfo.Mode(), lockInfo.Size())
	}
}

func TestNewRejectsSymlinkLockFile(t *testing.T) {
	dir := privateTempDir(t)
	target := filepath.Join(dir, "lock-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "audit.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, Options{}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New() error = %v, want ErrUnsafePath", err)
	}
}

func TestSeparateProcessesSerializeAuditWrites(t *testing.T) {
	dir := privateTempDir(t)
	commands := make([]*exec.Cmd, 2)
	for index := range commands {
		commands[index] = exec.Command(os.Args[0], "-test.run=TestAuditProcessWriterHelper")
		commands[index].Env = append(os.Environ(),
			"AEGIS_AUDIT_HELPER_DIR="+dir,
			"AEGIS_AUDIT_HELPER_PREFIX=process-"+strconv.Itoa(index),
		)
		if err := commands[index].Start(); err != nil {
			t.Fatalf("start helper %d: %v", index, err)
		}
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("helper %d: %v", index, err)
		}
	}
	seen := collectCanonicalRequestIDs(t, dir, 100)
	for process := range 2 {
		for write := range 12 {
			requestID := fmt.Sprintf("process-%d-%d", process, write)
			if !seen[requestID] {
				t.Errorf("missing cross-process request %q; seen=%v", requestID, seen)
			}
		}
	}
	if len(seen) != 24 {
		t.Fatalf("cross-process record count = %d, want 24", len(seen))
	}
}

func TestAuditProcessWriterHelper(t *testing.T) {
	dir := os.Getenv("AEGIS_AUDIT_HELPER_DIR")
	if dir == "" {
		return
	}
	prefix := os.Getenv("AEGIS_AUDIT_HELPER_PREFIX")
	logger, err := New(dir, Options{MaxBytes: 1 << 20, Backups: 2})
	if err != nil {
		t.Fatal(err)
	}
	for index := range 12 {
		if err := logger.Write(Event{RequestID: prefix + "-" + strconv.Itoa(index), Command: "echo process writer"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRotationPreflightRejectsUnsafeBackupWithoutStaging(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 128, Backups: 2}
	logger := newTestLogger(t, dir, options)
	for index := range 3 {
		if err := logger.Write(Event{RequestID: "preflight-" + strconv.Itoa(index), Command: "echo preflight"}); err != nil {
			t.Fatal(err)
		}
	}
	unsafe := backupPath(filepath.Join(dir, auditFilename), 2)
	if err := os.Chmod(unsafe, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(Event{RequestID: "must-not-write", Command: "echo rejected preflight"}); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("Write() error = %v, want ErrUnsafePermissions", err)
	}
	assertNoRotationStaging(t, dir)
	if info, err := os.Lstat(unsafe); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("unsafe backup changed during preflight: info=%v err=%v", info, err)
	}
}

func TestWriteRetriesPendingDirectorySyncBeforeContinuing(t *testing.T) {
	dir := privateTempDir(t)
	failSync := false
	syncFailure := errors.New("synthetic persistent directory sync failure")
	syncCalls := 0
	logger, err := newWithHooks(dir, Options{MaxBytes: 128, Backups: 1}, loggerHooks{syncDir: func(path string) error {
		syncCalls++
		if failSync {
			return syncFailure
		}
		return syncDirectory(path)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Write(Event{RequestID: "before-sync-failure", Command: "echo before failure"}); err != nil {
		t.Fatal(err)
	}
	failSync = true
	if err := logger.Write(Event{RequestID: "failed-sync-write", Command: "echo trigger rotation sync failure"}); !errors.Is(err, syncFailure) {
		t.Fatalf("Write() error = %v, want directory sync failure", err)
	}
	callsAfterFailure := syncCalls
	failSync = false
	if err := logger.Write(Event{RequestID: "after-sync-retry", Command: "echo after retry"}); err != nil {
		t.Fatalf("Write() after sync recovery: %v", err)
	}
	if syncCalls <= callsAfterFailure {
		t.Fatal("next Write did not retry the pending directory sync")
	}
}

func TestNewAlwaysSyncsExistingAuditDirectory(t *testing.T) {
	dir := privateTempDir(t)
	newTestLogger(t, dir, Options{})
	want := errors.New("synthetic mandatory New directory sync failure")
	if _, err := newWithHooks(dir, Options{}, loggerHooks{syncDir: func(string) error { return want }}); !errors.Is(err, want) {
		t.Fatalf("newWithHooks() error = %v, want mandatory directory sync failure", err)
	}
}

func TestRotationRenameFailurePreservesRecordsAndNextNewRecovers(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 128, Backups: 3}
	seedAuditRecords(t, dir, options, "original", 4)
	failure := errors.New("synthetic rotation rename failure")
	renameCalls := 0
	logger, err := newWithHooks(dir, options, loggerHooks{rename: func(oldPath, newPath string) error {
		if strings.Contains(filepath.Base(oldPath), ".rotate.") {
			renameCalls++
			if renameCalls >= 2 {
				return failure
			}
		}
		return os.Rename(oldPath, newPath)
	}})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	if err := logger.Write(Event{RequestID: "failed-write", Command: "echo trigger failed rotation"}); !errors.Is(err, failure) {
		t.Fatalf("Write() error = %v, want rename failure", err)
	}
	seen := collectAuditArtifactRequestIDs(t, dir)
	for index := range 4 {
		requestID := "original-" + strconv.Itoa(index)
		if !seen[requestID] {
			t.Errorf("record %q missing after failed rotation; seen=%v", requestID, seen)
		}
	}

	recovered := newTestLogger(t, dir, options)
	if err := recovered.Write(Event{RequestID: "recovered-write", Command: "echo recovered rotation"}); err != nil {
		t.Fatalf("Write() after recovery: %v", err)
	}
	canonical := collectCanonicalRequestIDs(t, dir, options.Backups)
	for index := 1; index < 4; index++ {
		requestID := "original-" + strconv.Itoa(index)
		if !canonical[requestID] {
			t.Errorf("retained record %q missing after recovery; seen=%v", requestID, canonical)
		}
	}
	if !canonical["recovered-write"] {
		t.Errorf("new record missing after recovery; seen=%v", canonical)
	}
	assertNoRotationStaging(t, dir)
}

func TestRotationRemoveFailurePreservesCanonicalRecords(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 128, Backups: 3}
	path := filepath.Join(dir, auditFilename)
	writeAuditRecordFile(t, path, "current")
	writeAuditRecordFile(t, backupPath(path, 1), "backup-1")
	writeAuditRecordFile(t, backupPath(path, 3), "backup-3")
	failure := errors.New("synthetic rotation remove failure")
	logger, err := newWithHooks(dir, options, loggerHooks{remove: func(removePath string) error {
		if removePath == backupPath(path, 3) {
			return failure
		}
		return os.Remove(removePath)
	}})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	if err := logger.Write(Event{RequestID: "failed-remove", Command: "echo trigger remove failure"}); !errors.Is(err, failure) {
		t.Fatalf("Write() error = %v, want remove failure", err)
	}
	canonical := collectCanonicalRequestIDs(t, dir, options.Backups)
	for _, requestID := range []string{"current", "backup-1", "backup-3"} {
		if !canonical[requestID] {
			t.Errorf("record %q missing after remove failure; seen=%v", requestID, canonical)
		}
	}
}

func TestRotationOpenFailureLeavesCanonicalRecordsIntact(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 128, Backups: 2}
	seedAuditRecords(t, dir, options, "open-original", 3)
	failure := errors.New("synthetic staging open failure")
	logger, err := newWithHooks(dir, options, loggerHooks{openFile: func(path string, flags int, mode os.FileMode) (*os.File, error) {
		if strings.HasSuffix(path, ".rotate.new") {
			return nil, failure
		}
		return os.OpenFile(path, flags, mode)
	}})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	if err := logger.Write(Event{RequestID: "failed-open", Command: "echo trigger open failure"}); !errors.Is(err, failure) {
		t.Fatalf("Write() error = %v, want staging open failure", err)
	}
	canonical := collectCanonicalRequestIDs(t, dir, options.Backups)
	for index := range 3 {
		requestID := "open-original-" + strconv.Itoa(index)
		if !canonical[requestID] {
			t.Errorf("record %q missing after staging open failure; seen=%v", requestID, canonical)
		}
	}
}

func TestRotationPublishesTriggerEventBeforeCleanup(t *testing.T) {
	for _, test := range []struct {
		name          string
		requireSync   bool
		wantSyncCalls int
	}{
		{name: "ordinary"},
		{name: "durable", requireSync: true, wantSyncCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := privateTempDir(t)
			options := Options{MaxBytes: 128, Backups: 3}
			seedAuditRecords(t, dir, options, "transaction-original", 4)
			path := filepath.Join(dir, auditFilename)
			newPath := path + ".rotate.new"
			proofPath := path + ".rotate.newproof"
			cleanupFailure := errors.New("synthetic committed rotation cleanup failure")
			cleanupFailed := false
			stagedSyncCalls := 0
			logger, err := newWithHooks(dir, options, loggerHooks{
				remove: func(removePath string) error {
					if strings.Contains(filepath.Base(removePath), ".rotate.source.") && !cleanupFailed {
						currentInfo, currentErr := os.Lstat(path)
						proofInfo, proofErr := os.Lstat(proofPath)
						if currentErr == nil && proofErr == nil && os.SameFile(currentInfo, proofInfo) {
							cleanupFailed = true
							return cleanupFailure
						}
					}
					return os.Remove(removePath)
				},
				syncFile: func(file *os.File) error {
					if file.Name() == newPath {
						stagedSyncCalls++
					}
					return file.Sync()
				},
			})
			if err != nil {
				t.Fatalf("newWithHooks(): %v", err)
			}
			triggerID := "transaction-trigger-" + test.name
			writeErr := logger.Write(Event{
				RequestID:   triggerID,
				Command:     "echo trigger committed rotation cleanup failure",
				RequireSync: test.requireSync,
			})
			if !errors.Is(writeErr, cleanupFailure) {
				t.Fatalf("Write() error = %v, want cleanup failure", writeErr)
			}
			if !cleanupFailed {
				t.Fatal("committed rotation cleanup failure injection not reached")
			}

			if _, err := New(dir, options); err != nil {
				t.Fatalf("New() after committed rotation cleanup failure: %v", err)
			}
			canonical := collectCanonicalRequestIDs(t, dir, options.Backups)
			if !canonical[triggerID] {
				t.Errorf("trigger event %q missing after recovery; seen=%v", triggerID, canonical)
			}
			if stagedSyncCalls != test.wantSyncCalls {
				t.Errorf("staged new file Sync calls = %d, want %d", stagedSyncCalls, test.wantSyncCalls)
			}
			assertNoRotationStaging(t, dir)
		})
	}
}

func TestFinalPublishSyncFailureDoesNotRollbackCommittedRotation(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 128, Backups: 3}
	seedAuditRecords(t, dir, options, "publish-sync-original", 4)
	path := filepath.Join(dir, auditFilename)
	newPath := path + ".rotate.new"
	proofPath := path + ".rotate.newproof"
	publishSyncFailure := errors.New("synthetic final publish directory sync failure")
	rollbackFailure := errors.New("synthetic rollback link failure")
	publishSyncFailed := false
	rollbackAttempted := false
	logger, err := newWithHooks(dir, options, loggerHooks{
		link: func(oldPath, newPath string) error {
			if publishSyncFailed && oldPath == path+".rotate.source.1" && newPath == path+".rotate.work.1" {
				rollbackAttempted = true
				return rollbackFailure
			}
			return os.Link(oldPath, newPath)
		},
		syncDir: func(syncPath string) error {
			if !publishSyncFailed {
				currentInfo, currentErr := os.Lstat(path)
				proofInfo, proofErr := os.Lstat(proofPath)
				_, newErr := os.Lstat(newPath)
				if currentErr == nil && proofErr == nil && errors.Is(newErr, os.ErrNotExist) && os.SameFile(currentInfo, proofInfo) {
					publishSyncFailed = true
					return publishSyncFailure
				}
			}
			return syncDirectory(syncPath)
		},
	})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	triggerID := "final-publish-sync-trigger"
	writeErr := logger.Write(Event{RequestID: triggerID, Command: "echo trigger final publish sync failure", RequireSync: true})
	if !errors.Is(writeErr, publishSyncFailure) {
		t.Fatalf("Write() error = %v, want final publish sync failure", writeErr)
	}
	if !publishSyncFailed {
		t.Fatal("final publish sync failure injection not reached")
	}
	if rollbackAttempted {
		t.Error("rollback ran after final publish rename succeeded")
	}

	if _, err := New(dir, options); err != nil {
		t.Fatalf("New() after final publish sync failure: %v", err)
	}
	canonical := collectCanonicalRequestIDs(t, dir, options.Backups)
	if !canonical[triggerID] {
		t.Errorf("committed trigger event %q missing after recovery; seen=%v", triggerID, canonical)
	}
	assertNoRotationStaging(t, dir)
}

func TestRollbackCleanupFailureBetweenNewAndProofRemovalRecovers(t *testing.T) {
	dir := privateTempDir(t)
	options := Options{MaxBytes: 128, Backups: 3}
	seedAuditRecords(t, dir, options, "rollback-original", 4)
	canonicalBefore := collectCanonicalRequestIDs(t, dir, options.Backups)
	path := filepath.Join(dir, auditFilename)
	newPath := path + ".rotate.new"
	markerPath := path + ".rotate.marker"
	applyFailure := errors.New("synthetic apply failure before rollback")
	cleanupFailure := errors.New("synthetic proof cleanup failure")
	renameCalls := 0
	applyFailed := false
	cleanupInterrupted := false
	logger, err := newWithHooks(dir, options, loggerHooks{
		rename: func(oldPath, newPath string) error {
			if strings.Contains(filepath.Base(oldPath), ".rotate.work.") && !applyFailed {
				renameCalls++
				if renameCalls == 2 {
					applyFailed = true
					return applyFailure
				}
			}
			return os.Rename(oldPath, newPath)
		},
		remove: func(removePath string) error {
			if removePath == newPath && !cleanupInterrupted {
				if err := os.Remove(removePath); err != nil {
					return err
				}
				cleanupInterrupted = true
				return cleanupFailure
			}
			return os.Remove(removePath)
		},
	})
	if err != nil {
		t.Fatalf("newWithHooks(): %v", err)
	}
	writeErr := logger.Write(Event{RequestID: "failed-cleanup-write", Command: "echo trigger rollback cleanup failure"})
	if !errors.Is(writeErr, applyFailure) || !errors.Is(writeErr, cleanupFailure) {
		t.Fatalf("Write() error = %v, want apply and cleanup failures", writeErr)
	}
	if !applyFailed || !cleanupInterrupted {
		t.Fatalf("failure injection not reached: apply=%t cleanup=%t", applyFailed, cleanupInterrupted)
	}
	if _, err := os.Lstat(markerPath); err != nil {
		t.Fatalf("Lstat(%q): %v", markerPath, err)
	}
	if _, err := os.Lstat(newPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat(%q) error = %v, want not exist", newPath, err)
	}

	recovered, err := New(dir, options)
	if err != nil {
		t.Fatalf("New() after interrupted rollback cleanup: %v", err)
	}
	canonicalAfter := collectCanonicalRequestIDs(t, dir, options.Backups)
	for requestID := range canonicalBefore {
		if !canonicalAfter[requestID] {
			t.Errorf("record %q missing after recovery; seen=%v", requestID, canonicalAfter)
		}
	}
	if err := recovered.Write(Event{RequestID: "recovered-after-cleanup", Command: "echo recovered"}); err != nil {
		t.Fatalf("Write() after interrupted rollback cleanup: %v", err)
	}
	canonicalAfter = collectCanonicalRequestIDs(t, dir, options.Backups)
	if !canonicalAfter["recovered-after-cleanup"] {
		t.Errorf("recovered record missing; seen=%v", canonicalAfter)
	}
	assertNoRotationStaging(t, dir)
}

func seedAuditRecords(t *testing.T, dir string, options Options, prefix string, count int) {
	t.Helper()
	logger := newTestLogger(t, dir, options)
	for index := range count {
		if err := logger.Write(Event{RequestID: prefix + "-" + strconv.Itoa(index), Command: "echo seed rotation"}); err != nil {
			t.Fatalf("seed Write(%d): %v", index, err)
		}
	}
}

func writeAuditRecordFile(t *testing.T, path, requestID string) {
	t.Helper()
	line, _, err := encodeEvent(Event{RequestID: requestID, Command: "echo prebuilt rotation record"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, line, 0o600); err != nil {
		t.Fatal(err)
	}
}

func collectAuditArtifactRequestIDs(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), auditFilename) {
			continue
		}
		collectRequestIDsFromFile(t, filepath.Join(dir, entry.Name()), seen)
	}
	return seen
}

func collectCanonicalRequestIDs(t *testing.T, dir string, backups int) map[string]bool {
	t.Helper()
	seen := make(map[string]bool)
	for index := 0; index <= backups; index++ {
		path := filepath.Join(dir, auditFilename)
		if index > 0 {
			path = backupPath(path, index)
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		collectRequestIDsFromFile(t, path, seen)
	}
	return seen
}

func collectRequestIDsFromFile(t *testing.T, path string, seen map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	for _, line := range nonEmptyLines(raw) {
		record := decodeRecord(t, line)
		if requestID, ok := record["request_id"].(string); ok && requestID != "" {
			seen[requestID] = true
		}
	}
}

func assertNoRotationStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".rotate.") {
			t.Errorf("rotation staging remains after recovery: %s", entry.Name())
		}
	}
}
