package opslog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxBytes = int64(10 << 20)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
	Off
)

func ParseLevel(value string) (Level, bool) {
	switch value {
	case "debug":
		return Debug, true
	case "", "info":
		return Info, true
	case "warn":
		return Warn, true
	case "error":
		return Error, true
	case "off":
		return Off, true
	default:
		return Info, false
	}
}

type Logger struct {
	mu    sync.Mutex
	path  string
	level Level
}

func New(dir, configured string) (*Logger, error) {
	level, ok := ParseLevel(configured)
	if !ok {
		return nil, errors.New("invalid log level")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Logger{path: filepath.Join(dir, "aegis.log"), level: level}, nil
}

func (l *Logger) Write(level Level, component, event, requestID, alias, code string, duration time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.level || l.level == Off {
		return
	}
	record := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), "level": levelName(level),
		"component": component, "event": event,
	}
	if requestID != "" {
		record["request_id"] = requestID
	}
	if alias != "" {
		record["server_alias"] = alias
	}
	if code != "" {
		record["error_code"] = code
	}
	if duration > 0 {
		record["duration_ms"] = duration.Milliseconds()
	}
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	line = append(line, '\n')
	l.rotate(int64(len(line)))
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(line)
	_ = f.Close()
}

func (l *Logger) SetLevel(value string) bool {
	level, ok := ParseLevel(value)
	if !ok || l == nil {
		return false
	}
	l.mu.Lock()
	l.level = level
	l.mu.Unlock()
	return true
}

func (l *Logger) rotate(incoming int64) {
	info, err := os.Stat(l.path)
	if err != nil || info.Size()+incoming <= maxBytes {
		return
	}
	_ = os.Remove(l.path + ".3")
	_ = os.Rename(l.path+".2", l.path+".3")
	_ = os.Rename(l.path+".1", l.path+".2")
	_ = os.Rename(l.path, l.path+".1")
}

func levelName(level Level) string {
	return [...]string{"debug", "info", "warn", "error", "off"}[level]
}
