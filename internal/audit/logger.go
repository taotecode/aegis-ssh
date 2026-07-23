package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/chenjw/aegis-ssh/internal/policy"
)

const (
	auditFilename          = "audit.jsonl"
	lockFilename           = "audit.lock"
	defaultMaxBytes        = 10 << 20
	maxMaxBytes            = 64 << 20
	maxCommandBytes        = 128 << 10
	maxCommandPreviewBytes = 160
	maxEventStringBytes    = 256
	maxCategoryBytes       = 64
	maxRedactionKeyBytes   = 64
	maxRiskCategories      = 32
	maxRedactionCounts     = 32
	maxBackups             = 100
)

var (
	ErrInvalidOptions    = errors.New("invalid audit options")
	ErrInvalidEvent      = errors.New("invalid audit event")
	ErrUnsafePath        = errors.New("unsafe audit path")
	ErrUnsafePermissions = errors.New("unsafe audit permissions")
	ErrUnsafeOwner       = errors.New("unsafe audit owner")
)

type Options struct {
	MaxBytes int64
	Backups  int
}

// Event contains only data approved for the audit boundary. Command is used to
// derive a digest and redacted preview and is never serialized directly.
type Event struct {
	Timestamp      time.Time         `json:"timestamp"`
	RequestID      string            `json:"request_id"`
	Interface      string            `json:"interface"`
	ServerAlias    string            `json:"server_alias"`
	Command        string            `json:"-"`
	Decision       string            `json:"decision"`
	RiskCategories []policy.Category `json:"risk_categories,omitempty"`
	ApprovalState  string            `json:"approval_state,omitempty"`
	DurationMS     int64             `json:"duration_ms"`
	ExitCode       int               `json:"exit_code"`
	TimedOut       bool              `json:"timed_out"`
	Truncated      bool              `json:"truncated"`
	Redactions     map[string]int    `json:"redactions,omitempty"`
	RequireSync    bool              `json:"-"`
}

type record struct {
	Timestamp      time.Time         `json:"timestamp"`
	RequestID      string            `json:"request_id"`
	Interface      string            `json:"interface"`
	ServerAlias    string            `json:"server_alias"`
	CommandSHA256  string            `json:"command_sha256"`
	CommandPreview string            `json:"command_preview"`
	Decision       string            `json:"decision"`
	RiskCategories []policy.Category `json:"risk_categories,omitempty"`
	ApprovalState  string            `json:"approval_state,omitempty"`
	DurationMS     int64             `json:"duration_ms"`
	ExitCode       int               `json:"exit_code"`
	TimedOut       bool              `json:"timed_out"`
	Truncated      bool              `json:"truncated"`
	Redactions     map[string]int    `json:"redactions,omitempty"`
}

type Logger struct {
	mu             sync.Mutex
	dir            string
	path           string
	maxBytes       int64
	backups        int
	syncFile       func(*os.File) error
	syncDir        func(string) error
	hooks          loggerHooks
	dirSyncPending bool
}

type loggerHooks struct {
	openFile func(string, int, fs.FileMode) (*os.File, error)
	rename   func(string, string) error
	remove   func(string) error
	link     func(string, string) error
	write    func(*os.File, []byte) (int, error)
	truncate func(*os.File, int64) error
	syncFile func(*os.File) error
	syncDir  func(string) error
}

func (hooks loggerHooks) withDefaults() loggerHooks {
	if hooks.openFile == nil {
		hooks.openFile = os.OpenFile
	}
	if hooks.rename == nil {
		hooks.rename = os.Rename
	}
	if hooks.remove == nil {
		hooks.remove = os.Remove
	}
	if hooks.link == nil {
		hooks.link = os.Link
	}
	if hooks.write == nil {
		hooks.write = func(file *os.File, data []byte) (int, error) { return file.Write(data) }
	}
	if hooks.truncate == nil {
		hooks.truncate = func(file *os.File, size int64) error { return file.Truncate(size) }
	}
	if hooks.syncFile == nil {
		hooks.syncFile = func(file *os.File) error { return file.Sync() }
	}
	if hooks.syncDir == nil {
		hooks.syncDir = syncDirectory
	}
	return hooks
}

func New(dir string, options Options) (*Logger, error) {
	return newWithHooks(dir, options, loggerHooks{})
}

func newWithHooks(dir string, options Options, hooks loggerHooks) (*Logger, error) {
	if dir == "" || options.MaxBytes < 0 || options.MaxBytes > maxMaxBytes || options.Backups < 0 || options.Backups > maxBackups {
		return nil, ErrInvalidOptions
	}
	hooks = hooks.withDefaults()
	maxBytes := options.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultMaxBytes
	}
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, err
	}

	logger := &Logger{
		dir:      dir,
		path:     filepath.Join(dir, auditFilename),
		maxBytes: maxBytes,
		backups:  options.Backups,
		syncFile: hooks.syncFile,
		syncDir:  hooks.syncDir,
		hooks:    hooks,
	}
	if err := logger.withExclusiveLock(logger.initializeLocked); err != nil {
		return nil, err
	}
	return logger, nil
}

func (logger *Logger) initializeLocked() error {
	if err := logger.syncMetadata(); err != nil {
		return fmt.Errorf("sync audit directory before recovery: %w", err)
	}
	if err := logger.recoverRotation(); err != nil {
		return err
	}
	file, created, err := logger.openAuditFile(logger.path)
	if err != nil {
		return err
	}
	if err := logger.repairTrailingPartialLine(file); err != nil {
		return closeWithError(file, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit file: %w", err)
	}
	if created {
		if err := logger.syncMetadata(); err != nil {
			return fmt.Errorf("sync audit directory: %w", err)
		}
	}
	if err := logger.cleanupExcessBackups(); err != nil {
		return err
	}
	if err := logger.syncMetadata(); err != nil {
		return fmt.Errorf("sync audit directory during initialization: %w", err)
	}
	return nil
}

func (logger *Logger) Write(event Event) error {
	if logger == nil || logger.syncFile == nil || logger.syncDir == nil {
		return ErrInvalidEvent
	}
	line, durable, err := encodeEvent(event)
	if err != nil {
		return err
	}

	logger.mu.Lock()
	defer logger.mu.Unlock()
	return logger.withExclusiveLock(func() error {
		if logger.dirSyncPending {
			if err := logger.syncMetadata(); err != nil {
				return fmt.Errorf("retry audit directory sync: %w", err)
			}
		}
		return logger.writeLocked(line, durable)
	})
}

func (logger *Logger) writeLocked(line []byte, durable bool) error {
	if err := inspectPrivateDirectory(logger.dir); err != nil {
		return err
	}
	if err := logger.recoverRotation(); err != nil {
		return err
	}
	file, created, err := logger.openAuditFile(logger.path)
	if err != nil {
		return err
	}
	if err := logger.repairTrailingPartialLine(file); err != nil {
		return closeWithError(file, err)
	}
	info, err := file.Stat()
	if err != nil {
		return closeWithError(file, fmt.Errorf("inspect audit file: %w", err))
	}
	if rotationNeeded(info.Size(), int64(len(line)), logger.maxBytes) {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close audit file for rotation: %w", err)
		}
		return logger.rotate(line, durable)
	}
	if created {
		if err := logger.syncMetadata(); err != nil {
			return closeWithError(file, fmt.Errorf("sync audit directory: %w", err))
		}
	}
	writeInfo, err := file.Stat()
	if err != nil {
		return closeWithError(file, fmt.Errorf("inspect audit file before write: %w", err))
	}
	if err := writeAllWith(file, line, logger.hooks.write); err != nil {
		rollbackErr := logger.hooks.truncate(file, writeInfo.Size())
		if rollbackErr == nil {
			rollbackErr = logger.syncFile(file)
		}
		if rollbackErr != nil {
			rollbackErr = fmt.Errorf("rollback partial audit event: %w", rollbackErr)
		}
		return closeWithError(file, errors.Join(fmt.Errorf("write audit event: %w", err), rollbackErr))
	}
	if durable {
		if err := logger.syncFile(file); err != nil {
			return closeWithError(file, fmt.Errorf("sync audit event: %w", err))
		}
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit file: %w", err)
	}
	return nil
}

func (logger *Logger) withExclusiveLock(operation func() error) error {
	lock, created, err := logger.openLockFile()
	if err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return closeWithError(lock, fmt.Errorf("lock audit directory: %w", err))
	}
	if created {
		if err := logger.syncMetadata(); err != nil {
			unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			return errors.Join(fmt.Errorf("sync audit lock creation: %w", err), unlockErr, lock.Close())
		}
	}
	operationErr := operation()
	unlockErr := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	closeErr := lock.Close()
	if unlockErr != nil {
		unlockErr = fmt.Errorf("unlock audit directory: %w", unlockErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close audit lock: %w", closeErr)
	}
	return errors.Join(operationErr, unlockErr, closeErr)
}

func (logger *Logger) openLockFile() (*os.File, bool, error) {
	path := filepath.Join(logger.dir, lockFilename)
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	file, err := logger.hooks.openFile(path, flags, 0)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		file, err = logger.hooks.openFile(path, flags|os.O_CREATE|os.O_EXCL, 0o600)
		created = err == nil
		if errors.Is(err, fs.ErrExist) {
			file, err = logger.hooks.openFile(path, flags, 0)
			created = false
		}
	}
	if err != nil {
		if isSymlink(path) {
			return nil, false, ErrUnsafePath
		}
		return nil, false, fmt.Errorf("open audit lock: %w", err)
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, false, closeWithError(file, fmt.Errorf("secure audit lock: %w", err))
		}
	}
	info, err := file.Stat()
	if err != nil {
		return nil, false, closeWithError(file, fmt.Errorf("inspect audit lock: %w", err))
	}
	if err := validatePrivateFile(info); err != nil {
		return nil, false, closeWithError(file, err)
	}
	if info.Size() != 0 {
		return nil, false, closeWithError(file, ErrUnsafePath)
	}
	return file, created, nil
}

func (logger *Logger) syncMetadata() error {
	if err := logger.syncDir(logger.dir); err != nil {
		logger.dirSyncPending = true
		return err
	}
	logger.dirSyncPending = false
	return nil
}

func rotationNeeded(currentSize, lineLength, maxBytes int64) bool {
	if currentSize <= 0 {
		return false
	}
	if currentSize > maxBytes {
		return true
	}
	return lineLength > maxBytes-currentSize
}

func (logger *Logger) repairTrailingPartialLine(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect audit tail: %w", err)
	}
	if info.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := file.ReadAt(last[:], info.Size()-1); err != nil {
		return fmt.Errorf("read audit tail: %w", err)
	}
	if last[0] == '\n' {
		return nil
	}

	const scanBytes = 4096
	buffer := make([]byte, scanBytes)
	truncateTo := int64(0)
	for end := info.Size(); end > 0; {
		start := end - scanBytes
		if start < 0 {
			start = 0
		}
		chunk := buffer[:end-start]
		if _, err := file.ReadAt(chunk, start); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("scan audit tail: %w", err)
		}
		if index := bytes.LastIndexByte(chunk, '\n'); index >= 0 {
			truncateTo = start + int64(index) + 1
			break
		}
		end = start
	}
	if err := logger.hooks.truncate(file, truncateTo); err != nil {
		return fmt.Errorf("truncate partial audit tail: %w", err)
	}
	if err := logger.syncFile(file); err != nil {
		return fmt.Errorf("sync repaired audit tail: %w", err)
	}
	return nil
}

func encodeEvent(event Event) ([]byte, bool, error) {
	if len(event.Command) > maxCommandBytes {
		return nil, false, ErrInvalidEvent
	}
	digest := sha256.Sum256([]byte(event.Command))
	preview := policy.NewRedactor(nil).WithMaxBytes(maxCommandPreviewBytes).RedactString(event.Command).Text
	entry := record{
		Timestamp:      event.Timestamp,
		RequestID:      truncateUTF8(event.RequestID, maxEventStringBytes),
		Interface:      truncateUTF8(event.Interface, maxEventStringBytes),
		ServerAlias:    truncateUTF8(event.ServerAlias, maxEventStringBytes),
		CommandSHA256:  hex.EncodeToString(digest[:]),
		CommandPreview: preview,
		Decision:       truncateUTF8(event.Decision, maxEventStringBytes),
		RiskCategories: boundedCategories(event.RiskCategories),
		ApprovalState:  truncateUTF8(event.ApprovalState, maxEventStringBytes),
		DurationMS:     event.DurationMS,
		ExitCode:       event.ExitCode,
		TimedOut:       event.TimedOut,
		Truncated:      event.Truncated,
		Redactions:     boundedRedactions(event.Redactions),
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return nil, false, fmt.Errorf("encode audit event: %w", err)
	}
	encoded = append(encoded, '\n')
	return encoded, event.ApprovalState != "" || event.RequireSync, nil
}

func boundedCategories(categories []policy.Category) []policy.Category {
	limit := len(categories)
	if limit > maxRiskCategories {
		limit = maxRiskCategories
	}
	if limit == 0 {
		return nil
	}
	result := make([]policy.Category, limit)
	for i := range limit {
		result[i] = policy.Category(truncateUTF8(string(categories[i]), maxCategoryBytes))
	}
	return result
}

func boundedRedactions(counts map[string]int) map[string]int {
	if len(counts) == 0 {
		return nil
	}
	type candidate struct {
		key   string
		count int
	}
	selected := make([]candidate, 0, min(len(counts), maxRedactionCounts))
	for key, count := range counts {
		position := sort.Search(len(selected), func(index int) bool { return selected[index].key >= key })
		if len(selected) == maxRedactionCounts && position == len(selected) {
			continue
		}
		if len(selected) < maxRedactionCounts {
			selected = append(selected, candidate{})
		}
		if position < len(selected) {
			copy(selected[position+1:], selected[position:len(selected)-1])
			selected[position] = candidate{key: key, count: count}
		}
	}
	result := make(map[string]int, len(selected))
	for _, item := range selected {
		boundedKey := truncateUTF8(item.key, maxRedactionKeyBytes)
		if boundedKey != "" {
			result[strings.Clone(boundedKey)] = item.count
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (logger *Logger) rotate(line []byte, durable bool) error {
	if err := logger.recoverRotation(); err != nil {
		return err
	}
	present := make([]bool, logger.backups+1)
	highestPresent := 0
	for index := 0; index <= logger.backups; index++ {
		exists, err := inspectPrivateFileIfExists(logger.canonicalPath(index))
		if err != nil {
			return fmt.Errorf("preflight audit rotation source %d: %w", index, err)
		}
		if index == 0 && !exists {
			return fmt.Errorf("preflight current audit file: %w", os.ErrNotExist)
		}
		present[index] = exists
		if exists {
			highestPresent = index
		}
	}
	limit := min(logger.backups, highestPresent+1)
	if err := logger.prepareRotation(present[:limit+1], line, durable); err != nil {
		return errors.Join(err, logger.recoverRotation())
	}
	published, err := logger.applyRotation(limit)
	if err != nil {
		if published {
			return err
		}
		return errors.Join(err, logger.rollbackRotation(limit))
	}
	return logger.cleanupRotationStaging()
}

func (logger *Logger) prepareRotation(present []bool, line []byte, durable bool) error {
	if err := logger.createEmptyMetadataFile(logger.rotationMarkerPath()); err != nil {
		return fmt.Errorf("create audit rotation marker: %w", err)
	}
	for index, exists := range present {
		if exists {
			if err := logger.linkMetadata(logger.canonicalPath(index), logger.rotationSourcePath(index)); err != nil {
				return fmt.Errorf("stage audit rotation source %d: %w", index, err)
			}
			continue
		}
		if err := logger.createEmptyMetadataFile(logger.rotationMissingPath(index)); err != nil {
			return fmt.Errorf("stage missing audit rotation source %d: %w", index, err)
		}
	}
	if err := logger.createRotationNewFile(line, durable); err != nil {
		return fmt.Errorf("stage new audit file: %w", err)
	}
	if err := logger.linkMetadata(logger.rotationNewPath(), logger.rotationProofPath()); err != nil {
		return fmt.Errorf("stage new audit proof: %w", err)
	}
	return nil
}

func (logger *Logger) applyRotation(limit int) (bool, error) {
	for target := limit; target >= 1; target-- {
		source := logger.rotationSourcePath(target - 1)
		if exists, err := inspectPrivateFileIfExists(source); err != nil {
			return false, fmt.Errorf("inspect staged rotation source %d: %w", target-1, err)
		} else if exists {
			work := logger.rotationWorkPath(target)
			if err := logger.linkMetadata(source, work); err != nil {
				return false, fmt.Errorf("prepare rotation target %d: %w", target, err)
			}
			if err := logger.renameMetadata(work, logger.canonicalPath(target)); err != nil {
				return false, fmt.Errorf("publish rotation target %d: %w", target, err)
			}
			continue
		}
		if err := logger.removeMetadataIfExists(logger.canonicalPath(target)); err != nil {
			return false, fmt.Errorf("remove empty rotation target %d: %w", target, err)
		}
	}
	if err := logger.hooks.rename(logger.rotationNewPath(), logger.path); err != nil {
		return false, fmt.Errorf("publish new current audit file: %w", err)
	}
	if err := logger.syncMetadata(); err != nil {
		return true, fmt.Errorf("sync published current audit file: %w", err)
	}
	return true, nil
}

func (logger *Logger) rollbackRotation(limit int) error {
	var rollbackErr error
	for index := 0; index <= limit; index++ {
		source := logger.rotationSourcePath(index)
		if exists, err := inspectPrivateFileIfExists(source); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("inspect rollback source %d: %w", index, err))
			break
		} else if exists {
			work := logger.rotationWorkPath(index)
			if err := logger.removeMetadataIfExists(work); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("clear rollback work %d: %w", index, err))
				break
			}
			if err := logger.linkMetadata(source, work); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("prepare rollback target %d: %w", index, err))
				break
			}
			if err := logger.renameMetadata(work, logger.canonicalPath(index)); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore rollback target %d: %w", index, err))
				break
			}
			continue
		}
		if exists, err := inspectPrivateFileIfExists(logger.rotationMissingPath(index)); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("inspect missing rollback source %d: %w", index, err))
			break
		} else if exists {
			if err := logger.removeMetadataIfExists(logger.canonicalPath(index)); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove rollback target %d: %w", index, err))
				break
			}
		}
	}
	if rollbackErr != nil {
		return rollbackErr
	}
	return logger.cleanupRotationStaging()
}

func (logger *Logger) recoverRotation() error {
	markerExists, err := inspectPrivateFileIfExists(logger.rotationMarkerPath())
	if err != nil {
		return fmt.Errorf("inspect audit rotation marker: %w", err)
	}
	if !markerExists {
		return nil
	}
	limit, staged, err := logger.rotationLimit()
	if err != nil {
		return err
	}
	if !staged {
		return logger.cleanupRotationStaging()
	}
	newExists, err := inspectPrivateFileIfExists(logger.rotationNewPath())
	if err != nil {
		return fmt.Errorf("inspect staged new audit file: %w", err)
	}
	proofExists, err := inspectPrivateFileIfExists(logger.rotationProofPath())
	if err != nil {
		return fmt.Errorf("inspect staged new audit proof: %w", err)
	}
	if newExists {
		return logger.rollbackRotation(limit)
	}
	if proofExists {
		currentInfo, err := os.Lstat(logger.path)
		if err != nil {
			return fmt.Errorf("inspect committed audit current: %w", err)
		}
		proofInfo, err := os.Lstat(logger.rotationProofPath())
		if err != nil {
			return fmt.Errorf("inspect committed audit proof: %w", err)
		}
		if err := validatePrivateFile(currentInfo); err != nil {
			return err
		}
		if !os.SameFile(currentInfo, proofInfo) {
			return fmt.Errorf("recover audit rotation: %w", ErrUnsafePath)
		}
	}
	return logger.cleanupRotationStaging()
}

func (logger *Logger) rotationLimit() (int, bool, error) {
	limit := -1
	staged := false
	for index := 0; index <= maxBackups; index++ {
		for _, path := range []string{logger.rotationSourcePath(index), logger.rotationMissingPath(index)} {
			exists, err := inspectPrivateFileIfExists(path)
			if err != nil {
				return 0, false, fmt.Errorf("inspect audit rotation staging %q: %w", filepath.Base(path), err)
			}
			if exists {
				staged = true
				if index > limit {
					limit = index
				}
			}
		}
		exists, err := inspectPrivateFileIfExists(logger.rotationWorkPath(index))
		if err != nil {
			return 0, false, fmt.Errorf("inspect audit rotation work %d: %w", index, err)
		}
		staged = staged || exists
	}
	for _, path := range []string{logger.rotationNewPath(), logger.rotationProofPath()} {
		exists, err := inspectPrivateFileIfExists(path)
		if err != nil {
			return 0, false, err
		}
		staged = staged || exists
	}
	if limit < 0 {
		limit = 0
	}
	return limit, staged, nil
}

func (logger *Logger) cleanupRotationStaging() error {
	for index := 0; index <= maxBackups; index++ {
		for _, path := range []string{logger.rotationWorkPath(index), logger.rotationSourcePath(index), logger.rotationMissingPath(index)} {
			if err := logger.removeMetadataIfExists(path); err != nil {
				return fmt.Errorf("remove audit rotation staging %q: %w", filepath.Base(path), err)
			}
		}
	}
	for _, path := range []string{logger.rotationProofPath(), logger.rotationNewPath()} {
		if err := logger.removeMetadataIfExists(path); err != nil {
			return fmt.Errorf("remove audit rotation staging %q: %w", filepath.Base(path), err)
		}
	}
	if err := logger.removeMetadataIfExists(logger.rotationMarkerPath()); err != nil {
		return fmt.Errorf("remove audit rotation marker: %w", err)
	}
	return nil
}

func (logger *Logger) linkMetadata(oldPath, newPath string) error {
	if err := logger.hooks.link(oldPath, newPath); err != nil {
		return err
	}
	return logger.syncMetadata()
}

func (logger *Logger) renameMetadata(oldPath, newPath string) error {
	if err := logger.hooks.rename(oldPath, newPath); err != nil {
		return err
	}
	return logger.syncMetadata()
}

func (logger *Logger) removeMetadataIfExists(path string) error {
	exists, err := inspectPrivateFileIfExists(path)
	if err != nil || !exists {
		return err
	}
	if err := logger.hooks.remove(path); err != nil {
		return err
	}
	return logger.syncMetadata()
}

func (logger *Logger) createEmptyMetadataFile(path string) error {
	file, err := logger.hooks.openFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWithError(file, err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return logger.syncMetadata()
}

func (logger *Logger) createRotationNewFile(line []byte, durable bool) error {
	file, err := logger.hooks.openFile(logger.rotationNewPath(), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return closeWithError(file, err)
	}
	if err := writeAllWith(file, line, logger.hooks.write); err != nil {
		return closeWithError(file, fmt.Errorf("write staged audit event: %w", err))
	}
	if durable {
		if err := logger.syncFile(file); err != nil {
			return closeWithError(file, fmt.Errorf("sync staged audit event: %w", err))
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	return logger.syncMetadata()
}

func (logger *Logger) canonicalPath(index int) string {
	if index == 0 {
		return logger.path
	}
	return backupPath(logger.path, index)
}

func (logger *Logger) rotationSourcePath(index int) string {
	return fmt.Sprintf("%s.rotate.source.%d", logger.path, index)
}

func (logger *Logger) rotationMissingPath(index int) string {
	return fmt.Sprintf("%s.rotate.missing.%d", logger.path, index)
}

func (logger *Logger) rotationWorkPath(index int) string {
	return fmt.Sprintf("%s.rotate.work.%d", logger.path, index)
}

func (logger *Logger) rotationNewPath() string {
	return logger.path + ".rotate.new"
}

func (logger *Logger) rotationProofPath() string {
	return logger.path + ".rotate.newproof"
}

func (logger *Logger) rotationMarkerPath() string {
	return logger.path + ".rotate.marker"
}

func (logger *Logger) cleanupExcessBackups() error {
	dir, err := logger.hooks.openFile(logger.dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open audit directory for backup cleanup: %w", err)
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("inspect audit directory for backup cleanup: %w", err)
	}
	if err := validatePrivateDirectory(info); err != nil {
		return err
	}
	for {
		names, readErr := dir.Readdirnames(64)
		for _, name := range names {
			index, ok := numericBackupIndex(name)
			if !ok || index <= uint64(logger.backups) {
				continue
			}
			path := filepath.Join(logger.dir, name)
			if exists, err := inspectPrivateFileIfExists(path); err != nil {
				return fmt.Errorf("inspect excess audit backup %q: %w", name, err)
			} else if !exists {
				continue
			}
			if err := logger.hooks.remove(path); err != nil {
				return fmt.Errorf("remove excess audit backup %q: %w", name, err)
			}
			if err := logger.syncMetadata(); err != nil {
				return fmt.Errorf("sync audit directory after removing backup %q: %w", name, err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("enumerate audit backups: %w", readErr)
		}
	}
}

func numericBackupIndex(name string) (uint64, bool) {
	prefix := auditFilename + "."
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == "" {
		return 0, false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	if suffix[0] == '0' {
		return ^uint64(0), true
	}
	index, err := strconv.ParseUint(suffix, 10, 64)
	if errors.Is(err, strconv.ErrRange) {
		return ^uint64(0), true
	}
	return index, err == nil && index > 0
}

func backupPath(path string, index int) string {
	return fmt.Sprintf("%s.%d", path, index)
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("create audit directory: %w", err)
			}
		} else if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure audit directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect audit directory: %w", err)
	}
	return validatePrivateDirectory(info)
}

func inspectPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect audit directory: %w", err)
	}
	return validatePrivateDirectory(info)
}

func validatePrivateDirectory(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != 0o700 {
		return ErrUnsafePermissions
	}
	return validateOwner(info)
}

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != 0o600 {
		return ErrUnsafePermissions
	}
	return validateOwner(info)
}

func validateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func (logger *Logger) openAuditFile(path string) (*os.File, bool, error) {
	flags := os.O_RDWR | os.O_APPEND | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	file, err := logger.hooks.openFile(path, flags, 0)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		file, err = logger.hooks.openFile(path, flags|os.O_CREATE|os.O_EXCL, 0o600)
		created = err == nil
		if errors.Is(err, fs.ErrExist) {
			file, err = logger.hooks.openFile(path, flags, 0)
			created = false
		}
	}
	if err != nil {
		if isSymlink(path) {
			return nil, false, ErrUnsafePath
		}
		return nil, false, fmt.Errorf("open audit file: %w", err)
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, false, closeWithError(file, fmt.Errorf("secure audit file: %w", err))
		}
	}
	info, statErr := file.Stat()
	if statErr != nil {
		return nil, false, closeWithError(file, fmt.Errorf("inspect audit file: %w", statErr))
	}
	if validationErr := validatePrivateFile(info); validationErr != nil {
		return nil, false, closeWithError(file, validationErr)
	}
	return file, created, nil
}

func inspectPrivateFileIfExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := validatePrivateFile(info); err != nil {
		return false, err
	}
	return true, nil
}

func syncDirectory(path string) error {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	info, err := dir.Stat()
	if err != nil {
		return closeWithError(dir, err)
	}
	if err := validatePrivateDirectory(info); err != nil {
		return closeWithError(dir, err)
	}
	if err := dir.Sync(); err != nil {
		return closeWithError(dir, err)
	}
	return dir.Close()
}

func writeAllWith(file *os.File, data []byte, write func(*os.File, []byte) (int, error)) error {
	for len(data) > 0 {
		written, err := write(file, data)
		if written < 0 || written > len(data) {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func closeWithError(file *os.File, err error) error {
	return errors.Join(err, file.Close())
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func truncateUTF8(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(value) <= maxBytes && utf8.ValidString(value) {
		return value
	}
	if len(value) > maxBytes {
		value = value[:maxBytes]
	}
	value = strings.ToValidUTF8(value, "\uFFFD")
	if len(value) > maxBytes {
		value = value[:maxBytes]
	}
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
