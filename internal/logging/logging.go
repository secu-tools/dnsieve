// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package logging provides structured logging with file rotation,
// flood protection, level filtering, and platform-aware log paths
// for DNSieve.
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Level represents a log severity level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// ParseLevel converts a string to a Level. Defaults to LevelInfo.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "INFO"
	}
}

// Config holds logging configuration (mapped from TOML config).
type Config struct {
	MaxSizeMB    int // Max log file size before rotation (default: 10)
	MaxBackups   int // Max rotated log files to keep (default: 5)
	MaxAgeDays   int // Max age of rotated logs in days (default: 30)
	FloodLimitPS int // Max log lines per second (0 = unlimited, default: 100)
}

// DefaultConfig returns sensible logging defaults.
func DefaultConfig() Config {
	return Config{
		MaxSizeMB:    10,
		MaxBackups:   5,
		MaxAgeDays:   30,
		FloodLimitPS: 100,
	}
}

// Logger wraps Go's standard logger with rotation, flood protection,
// and level-based filtering.
type Logger struct {
	mu          sync.Mutex
	logger      *log.Logger
	file        *os.File
	filePath    string
	config      Config
	currentSize int64
	module      string
	writer      io.Writer
	minLevel    Level

	// Flood protection
	floodMu     sync.Mutex
	lineCount   int
	floodWindow time.Time
	dropped     int
}

// customLogDir is set via --logdir to override the platform default.
var customLogDir string

// logDirFallback is set when /var/log/dnsieve is not writable and the
// exe-relative log/ directory is used instead.
var logDirFallback bool

// SetLogDir overrides the default log directory.
func SetLogDir(dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create log directory %s: %w", dir, err)
	}
	customLogDir = dir
	return nil
}

// UsingFallbackLogDir returns true when LogDir fell back to an
// exe-relative log/ directory because /var/log/dnsieve was not writable.
func UsingFallbackLogDir() bool {
	return logDirFallback
}

// LogDir returns the platform-appropriate log directory.
// If SetLogDir was called, returns that override.
// Linux/macOS: /var/log/dnsieve (falls back to <exe_dir>/log if no permission)
// Windows: <exe_dir>/log
func LogDir() string {
	if customLogDir != "" {
		return customLogDir
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		dir := "/var/log/dnsieve"
		if err := os.MkdirAll(dir, 0750); err == nil {
			return dir
		}
		logDirFallback = true
	}
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	dir := filepath.Join(filepath.Dir(exe), "log")
	if err := os.MkdirAll(dir, 0750); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR | [logging] failed to create log directory %s: %v\n", dir, err)
		return "."
	}
	return dir
}

// IsCustomLogDir reports whether a custom log directory was set via SetLogDir.
func IsCustomLogDir() bool {
	return customLogDir != ""
}

// New creates a new Logger that writes to the specified log file with rotation.
// It also writes to stdout so console output is preserved.
func New(filename string, cfg Config, module ...string) (*Logger, error) {
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 10
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}

	logDir := LogDir()
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", logDir, err)
	}

	filePath := filepath.Join(logDir, filename)

	mod := "main"
	if len(module) > 0 && module[0] != "" {
		mod = module[0]
	}

	l := &Logger{
		filePath:    filePath,
		config:      cfg,
		module:      mod,
		minLevel:    LevelInfo,
		floodWindow: time.Now(),
	}

	if err := l.openFile(); err != nil {
		return nil, err
	}
	return l, nil
}

// NewStdoutOnly creates a logger that writes only to stdout with no log file.
func NewStdoutOnly(cfg Config, module ...string) *Logger {
	mod := "main"
	if len(module) > 0 && module[0] != "" {
		mod = module[0]
	}
	l := &Logger{
		config:      cfg,
		module:      mod,
		minLevel:    LevelInfo,
		floodWindow: time.Now(),
	}
	l.writer = os.Stdout
	l.logger = log.New(os.Stdout, "", 0)
	return l
}

// NewWriterLogger creates a logger that writes all output to the provided
// writer. The minimum level defaults to LevelDebug so all messages are
// captured. Useful for capturing log output in tests.
func NewWriterLogger(w io.Writer, cfg Config, module string) *Logger {
	mod := module
	if mod == "" {
		mod = "test"
	}
	l := &Logger{
		config:      cfg,
		module:      mod,
		minLevel:    LevelDebug,
		floodWindow: time.Now(),
	}
	l.writer = w
	l.logger = log.New(w, "", 0)
	return l
}

// SetLevel sets the minimum log level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.minLevel = level
}

// SetLevelFromString sets the minimum log level from a string.
func (l *Logger) SetLevelFromString(s string) {
	l.SetLevel(ParseLevel(s))
}

// openFile opens (or creates) the log file and sets up the multi-writer.
func (l *Logger) openFile() error {
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", l.filePath, err)
	}
	info, err := f.Stat()
	if err != nil {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "ERROR | [logging] failed to close log file after stat error: %v\n", cerr)
		}
		return fmt.Errorf("stat log file: %w", err)
	}
	l.file = f
	l.currentSize = info.Size()
	l.writer = io.MultiWriter(f, os.Stdout)
	l.logger = log.New(l.writer, "", 0)
	return nil
}

// formatLine builds: "LEVEL | 2006/01/02 15:04:05 [module] message"
func (l *Logger) formatLine(level, msg string) string {
	ts := time.Now().Format("2006/01/02 15:04:05")
	return fmt.Sprintf("%-5s | %s [%s] %s", level, ts, l.module, msg)
}

// logMsg writes a formatted message at the given level with rotation.
func (l *Logger) logMsg(level, msg string) {
	line := l.formatLine(level, msg)
	l.logger.Println(line)
	l.currentSize += int64(len(line) + 2)
	if l.filePath != "" && l.currentSize >= int64(l.config.MaxSizeMB)*1024*1024 {
		l.rotate()
	}
}

// Debugf logs a DEBUG-level formatted message.
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.minLevel > LevelDebug {
		return
	}
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("DEBUG", fmt.Sprintf(format, v...))
}

// Infof logs an INFO-level formatted message.
func (l *Logger) Infof(format string, v ...interface{}) {
	if l.minLevel > LevelInfo {
		return
	}
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("INFO", fmt.Sprintf(format, v...))
}

// Warnf logs a WARN-level formatted message.
func (l *Logger) Warnf(format string, v ...interface{}) {
	if l.minLevel > LevelWarn {
		return
	}
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("WARN", fmt.Sprintf(format, v...))
}

// Errorf logs an ERROR-level formatted message.
func (l *Logger) Errorf(format string, v ...interface{}) {
	if l.minLevel > LevelError {
		return
	}
	if l.isFlooded() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logMsg("ERROR", fmt.Sprintf(format, v...))
}

// Fatalf logs a FATAL message and exits.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.mu.Lock()
	l.logMsg("FATAL", fmt.Sprintf(format, v...))
	l.mu.Unlock()
	os.Exit(1)
}

// Close flushes and closes the log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to close log file: %v\n", l.module, err)
		}
		l.file = nil
	}
}

// FilePath returns the current log file path.
func (l *Logger) FilePath() string {
	return l.filePath
}

// isFlooded checks flood protection limits.
func (l *Logger) isFlooded() bool {
	if l.config.FloodLimitPS <= 0 {
		return false
	}
	l.floodMu.Lock()
	defer l.floodMu.Unlock()
	now := time.Now()
	if now.Sub(l.floodWindow) >= time.Second {
		if l.dropped > 0 {
			l.mu.Lock()
			l.logMsg("WARN", fmt.Sprintf("Suppressed %d log messages in the last second", l.dropped))
			l.mu.Unlock()
		}
		l.floodWindow = now
		l.lineCount = 0
		l.dropped = 0
	}
	l.lineCount++
	if l.lineCount > l.config.FloodLimitPS {
		l.dropped++
		return true
	}
	return false
}

// rotate performs log file rotation.
func (l *Logger) rotate() {
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to close log file during rotation: %v\n", l.module, err)
		}
	}
	for i := l.config.MaxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.filePath, i)
		dst := fmt.Sprintf("%s.%d", l.filePath, i+1)
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to rotate log backup %s -> %s: %v\n", l.module, src, dst, err)
		}
	}
	if err := os.Rename(l.filePath, l.filePath+".1"); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to rename log file %s: %v\n", l.module, l.filePath, err)
	}
	for i := l.config.MaxBackups + 1; i <= l.config.MaxBackups+5; i++ {
		path := fmt.Sprintf("%s.%d", l.filePath, i)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to remove excess log backup %s: %v\n", l.module, path, err)
		}
	}
	l.cleanOldBackups()
	if err := l.openFile(); err != nil {
		l.writer = os.Stdout
		l.logger = log.New(os.Stdout, "", 0)
		l.logMsg("ERROR", fmt.Sprintf("Failed to open new log file after rotation: %v", err))
	}
}

// cleanOldBackups removes rotated logs older than MaxAgeDays.
func (l *Logger) cleanOldBackups() {
	cutoff := time.Now().Add(-time.Duration(l.config.MaxAgeDays) * 24 * time.Hour)
	base := filepath.Base(l.filePath)
	dir := filepath.Dir(l.filePath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), base+".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dir, entry.Name())
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "WARN  | [%s] failed to remove old log backup %s: %v\n", l.module, path, err)
			}
		}
	}
}
