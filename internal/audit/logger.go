package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/chenjw/aegis-ssh/internal/policy"
)

const (
	auditFilename          = "audit.jsonl"
	defaultMaxBytes        = 10 << 20
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
	mu       sync.Mutex
	dir      string
	path     string
	maxBytes int64
	backups  int
	syncFile func(*os.File) error
	syncDir  func(string) error
}

func New(dir string, options Options) (*Logger, error) {
	if dir == "" || options.MaxBytes < 0 || options.Backups < 0 || options.Backups > maxBackups {
		return nil, ErrInvalidOptions
	}
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
		syncFile: func(file *os.File) error { return file.Sync() },
		syncDir:  syncDirectory,
	}
	file, created, err := openAuditFile(logger.path)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close audit file: %w", err)
	}
	if created {
		if err := logger.syncDir(dir); err != nil {
			return nil, fmt.Errorf("sync audit directory: %w", err)
		}
	}
	return logger, nil
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

	if err := inspectPrivateDirectory(logger.dir); err != nil {
		return err
	}
	file, created, err := openAuditFile(logger.path)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return closeWithError(file, fmt.Errorf("inspect audit file: %w", err))
	}
	if rotationNeeded(info.Size(), int64(len(line)), logger.maxBytes) {
		if err := file.Close(); err != nil {
			return fmt.Errorf("close audit file for rotation: %w", err)
		}
		if err := logger.rotate(); err != nil {
			return err
		}
		file, created, err = openAuditFile(logger.path)
		if err != nil {
			return err
		}
		created = true
	}
	if created {
		if err := logger.syncDir(logger.dir); err != nil {
			return closeWithError(file, fmt.Errorf("sync audit directory: %w", err))
		}
	}
	if err := writeAll(file, line); err != nil {
		return closeWithError(file, fmt.Errorf("write audit event: %w", err))
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

func rotationNeeded(currentSize, lineLength, maxBytes int64) bool {
	if currentSize <= 0 {
		return false
	}
	if currentSize > maxBytes {
		return true
	}
	return lineLength > maxBytes-currentSize
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
	result := make(map[string]int, min(len(counts), maxRedactionCounts))
	inspected := 0
	for key, count := range counts {
		inspected++
		boundedKey := truncateUTF8(key, maxRedactionKeyBytes)
		if boundedKey != "" {
			result[boundedKey] = count
		}
		if inspected >= maxRedactionCounts {
			break
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (logger *Logger) rotate() error {
	if logger.backups == 0 {
		if err := removePrivateFile(logger.path); err != nil {
			return fmt.Errorf("discard rotated audit file: %w", err)
		}
		return nil
	}

	oldest := backupPath(logger.path, logger.backups)
	if err := removePrivateFileIfExists(oldest); err != nil {
		return fmt.Errorf("remove oldest audit backup: %w", err)
	}
	for index := logger.backups - 1; index >= 1; index-- {
		source := backupPath(logger.path, index)
		exists, err := inspectPrivateFileIfExists(source)
		if err != nil {
			return fmt.Errorf("inspect audit backup %d: %w", index, err)
		}
		if !exists {
			continue
		}
		if err := os.Rename(source, backupPath(logger.path, index+1)); err != nil {
			return fmt.Errorf("rotate audit backup %d: %w", index, err)
		}
	}
	if exists, err := inspectPrivateFileIfExists(logger.path); err != nil {
		return fmt.Errorf("inspect current audit file: %w", err)
	} else if !exists {
		return fmt.Errorf("inspect current audit file: %w", os.ErrNotExist)
	}
	if err := os.Rename(logger.path, backupPath(logger.path, 1)); err != nil {
		return fmt.Errorf("rotate current audit file: %w", err)
	}
	return nil
}

func backupPath(path string, index int) string {
	return fmt.Sprintf("%s.%d", path, index)
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return fmt.Errorf("create audit directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
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

func openAuditFile(path string) (*os.File, bool, error) {
	flags := os.O_WRONLY | os.O_APPEND | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	file, err := os.OpenFile(path, flags, 0)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, 0o600)
		created = err == nil
		if errors.Is(err, fs.ErrExist) {
			file, err = os.OpenFile(path, flags, 0)
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

func removePrivateFileIfExists(path string) error {
	exists, err := inspectPrivateFileIfExists(path)
	if err != nil || !exists {
		return err
	}
	return os.Remove(path)
}

func removePrivateFile(path string) error {
	exists, err := inspectPrivateFileIfExists(path)
	if err != nil {
		return err
	}
	if !exists {
		return os.ErrNotExist
	}
	return os.Remove(path)
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

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
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
