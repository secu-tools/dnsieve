// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package logging provides structured logging with file rotation,
// flood protection, level filtering, and platform-aware log paths
// for DNSieve.
package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	MaxSizeMB  int // Max log file size before rotation (default: 10)
	MaxBackups int // Max rotated log files to keep (default: 5)
	MaxAgeDays int // Max age of rotated logs in days (default: 30)
	// StdoutMode controls the format and minimum level for stdout output.
	// Valid values: "json", "debug", "info", "warn", "error", "off".
	// "json" enables structured JSON output at debug level.
	// "off" disables stdout output entirely.
	// Defaults to "info" when empty.
	StdoutMode string
	// FileMode controls the format and minimum level for log-file output.
	// Same values as StdoutMode. Defaults to "info" when empty.
	FileMode string
	// Synchronous, when true, disables the async write channel so that log
	// writes are completed inline before the caller returns. Intended only
	// for tests that read the output buffer immediately after logging.
	Synchronous bool
}

// DefaultConfig returns sensible logging defaults.
func DefaultConfig() Config {
	return Config{
		MaxSizeMB:  10,
		MaxBackups: 5,
		MaxAgeDays: 30,
		StdoutMode: "info",
		FileMode:   "info",
	}
}

// parseOutputMode interprets a log output mode string.
// Returns isJSON, the minimum Level for that output, and whether it is enabled.
// Valid inputs (case-insensitive): "json", "debug", "info", "warn", "error", "off".
// An empty or unknown string defaults to info level, non-JSON, enabled.
// "json" enables structured JSON output at INFO level (use "debug" for DEBUG+JSON).
func parseOutputMode(mode string) (isJSON bool, minLvl Level, enabled bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "json":
		return true, LevelInfo, true
	case "debug":
		return false, LevelDebug, true
	case "info", "":
		return false, LevelInfo, true
	case "warn", "warning":
		return false, LevelWarn, true
	case "error":
		return false, LevelError, true
	case "off":
		return false, LevelDebug, false
	default:
		return false, LevelInfo, true
	}
}

// Logger wraps Go's standard logger with rotation, flood protection,
// and level-based filtering. It supports independent text and JSON output
// for both stdout and the log file, each with its own minimum log level.
type Logger struct {
	mu          sync.Mutex
	file        *os.File
	filePath    string
	config      Config
	currentSize int64
	module      string

	// minLevel is the cached minimum of stdoutMin and fileMin. It is used as
	// an unguarded fast-path check in Infof/Warnf/etc. to avoid a mutex
	// acquire when all outputs would filter the message anyway.
	minLevel Level

	// stdout output
	stdoutWriter io.Writer // non-nil when stdout is active
	stdoutJSON   bool      // true when stdout is in JSON mode
	stdoutMin    Level     // minimum level for stdout output

	// file output
	fileWriter io.Writer // non-nil when the log file is active
	fileJSON   bool      // true when the file is in JSON mode
	fileMin    Level     // minimum level for file output

	// logCh is the async write queue. DNS query goroutines enqueue log entries
	// here and return immediately; a single worker goroutine drains the channel
	// and performs all I/O under l.mu. The buffer absorbs query bursts without
	// stalling callers. Entries are dropped silently when the channel is full
	// rather than blocking the DNS path.
	logCh     chan logEntry
	wg        sync.WaitGroup
	closeOnce sync.Once
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
		filePath: filePath,
		config:   cfg,
		module:   mod,
	}

	if err := l.openFile(); err != nil {
		return nil, err
	}
	l.startWorker()
	return l, nil
}

// NewStdoutOnly creates a logger that writes only to stdout with no log file.
func NewStdoutOnly(cfg Config, module ...string) *Logger {
	mod := "main"
	if len(module) > 0 && module[0] != "" {
		mod = module[0]
	}
	l := &Logger{
		config: cfg,
		module: mod,
	}
	l.applyStdoutWriter(os.Stdout)
	l.updateMinLevel()
	l.startWorker()
	return l
}

// NewWriterLogger creates a logger that writes all output to the provided
// writer. Useful for capturing log output in tests.
// When cfg.StdoutMode is "json", the writer receives JSON-formatted lines.
// The minimum level is determined by cfg.StdoutMode (e.g. "json" -> DEBUG,
// "warn" -> WARN). Callers may call SetLevel to override after construction.
func NewWriterLogger(w io.Writer, cfg Config, module string) *Logger {
	mod := module
	if mod == "" {
		mod = "test"
	}
	l := &Logger{
		config: cfg,
		module: mod,
	}
	l.applyStdoutWriter(w)
	l.updateMinLevel()
	l.startWorker()
	return l
}

// applyStdoutWriter configures the stdout output fields from config.StdoutMode.
func (l *Logger) applyStdoutWriter(w io.Writer) {
	isJSON, minLvl, enabled := parseOutputMode(l.config.StdoutMode)
	if !enabled || w == nil {
		l.stdoutWriter = nil
		return
	}
	l.stdoutWriter = w
	l.stdoutJSON = isJSON
	l.stdoutMin = minLvl
}

// applyFileWriter configures the file output fields from config.FileMode.
func (l *Logger) applyFileWriter(w io.Writer) {
	isJSON, minLvl, enabled := parseOutputMode(l.config.FileMode)
	if !enabled || w == nil {
		l.fileWriter = nil
		return
	}
	l.fileWriter = w
	l.fileJSON = isJSON
	l.fileMin = minLvl
}

// updateMinLevel refreshes the cached minLevel field to be the minimum
// across all active output destinations. Must be called whenever the
// stdout/file writers or their minimum levels change.
func (l *Logger) updateMinLevel() {
	min := Level(255)
	if l.stdoutWriter != nil && l.stdoutMin < min {
		min = l.stdoutMin
	}
	if l.fileWriter != nil && l.fileMin < min {
		min = l.fileMin
	}
	if min > LevelFatal {
		min = LevelFatal
	}
	l.minLevel = min
}

// SetLevel sets the minimum log level for all active output destinations.
// This overrides the level derived from StdoutMode/FileMode. Primarily
// used in tests to adjust filtering at runtime.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stdoutWriter != nil {
		l.stdoutMin = level
	}
	if l.fileWriter != nil {
		l.fileMin = level
	}
	l.updateMinLevel()
}

// SetLevelFromString sets the minimum log level from a string.
func (l *Logger) SetLevelFromString(s string) {
	l.SetLevel(ParseLevel(s))
}

// openFile opens (or creates) the log file and configures the text/JSON writers.
// It also sets up stdout writers based on the mode configuration.
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
	l.applyFileWriter(f)
	l.applyStdoutWriter(os.Stdout)
	l.updateMinLevel()
	return nil
}

// jsonBufPool is a pool of byte buffers used when marshaling structured JSON
// log events. Reusing buffers avoids a heap allocation on every LogEvent call,
// which is critical at high query rates (e.g. 100k DNS requests/second).
// Each buffer is pre-grown to a reasonable event size to minimise resizing.
var jsonBufPool = sync.Pool{
	New: func() interface{} {
		b := &bytes.Buffer{}
		b.Grow(512)
		return b
	},
}

// textBufPool is a pool of byte buffers used when formatting plain-text log
// lines. Reusing buffers avoids the string-concatenation allocation that
// would otherwise occur when appending the trailing newline.
var textBufPool = sync.Pool{
	New: func() interface{} {
		b := &bytes.Buffer{}
		b.Grow(128)
		return b
	},
}

// formatLine builds: "LEVEL | 2006/01/02 15:04:05 [module] message"
func (l *Logger) formatLine(level, msg string) string {
	ts := time.Now().Format("2006/01/02 15:04:05")
	return fmt.Sprintf("%-5s | %s [%s] %s", level, ts, l.module, msg)
}

// writeText writes a formatted text line to text-format destinations whose
// minimum level is at or below levelVal. Must be called with l.mu held.
func (l *Logger) writeText(levelVal Level, line string) {
	stdoutWants := l.stdoutWriter != nil && !l.stdoutJSON && l.stdoutMin <= levelVal
	fileWants := l.fileWriter != nil && !l.fileJSON && l.fileMin <= levelVal
	if !stdoutWants && !fileWants {
		return
	}
	buf := textBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.WriteString(line)
	buf.WriteByte('\n')
	data := buf.Bytes()
	if stdoutWants {
		_, _ = l.stdoutWriter.Write(data)
	}
	if fileWants {
		_, _ = l.fileWriter.Write(data)
		l.currentSize += int64(len(data))
		if l.filePath != "" && l.currentSize >= int64(l.config.MaxSizeMB)*1024*1024 {
			l.rotate()
		}
	}
	textBufPool.Put(buf)
}

// writeJSON marshals event to JSON and writes it to JSON-format destinations
// whose minimum level is at or below levelVal. Must be called with l.mu held.
// A pooled bytes.Buffer is used to avoid a heap allocation per call; at high
// DNS query rates this is the dominant source of allocation pressure.
func (l *Logger) writeJSON(levelVal Level, event *Event) {
	stdoutWants := l.stdoutWriter != nil && l.stdoutJSON && l.stdoutMin <= levelVal
	fileWants := l.fileWriter != nil && l.fileJSON && l.fileMin <= levelVal
	if !stdoutWants && !fileWants {
		return
	}
	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false) // DNS names never contain HTML-special chars; avoids needless escaping
	if err := enc.Encode(event); err != nil {
		jsonBufPool.Put(buf)
		return
	}
	// json.Encoder.Encode already appends a trailing newline.
	b := buf.Bytes()
	if stdoutWants {
		_, _ = l.stdoutWriter.Write(b)
	}
	if fileWants {
		_, _ = l.fileWriter.Write(b)
		l.currentSize += int64(len(b))
		if l.filePath != "" && l.currentSize >= int64(l.config.MaxSizeMB)*1024*1024 {
			l.rotate()
		}
	}
	jsonBufPool.Put(buf)
}

// logChanSize is the capacity of the async log write channel. At 100k DNS
// requests/second a buffer of 8192 provides roughly 80ms of burst capacity
// before entries start being dropped.
const logChanSize = 8192

// logEntry is a pending log write created by the public logging methods and
// sent to the worker goroutine for actual I/O.
type logEntry struct {
	level    Level
	msg      string        // raw message; used for text line formatting and general JSON events
	event    *Event        // non-nil for structured dns_query events
	textOnly bool          // when true, the entry is never written to JSON outputs
	jsonOnly bool          // when true, the entry is never written to text outputs (dns_query events)
	done     chan struct{} // non-nil: Flush sentinel; worker closes it when reached
}

// startWorker initialises the async write channel and starts the background
// I/O goroutine. Must be called exactly once during logger construction.
// In Synchronous mode no goroutine is started; enqueue writes inline instead.
func (l *Logger) startWorker() {
	if l.config.Synchronous {
		return // writes happen inline in enqueue; no channel or goroutine needed
	}
	l.logCh = make(chan logEntry, logChanSize)
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		for entry := range l.logCh {
			if entry.done != nil {
				close(entry.done)
				continue
			}
			l.mu.Lock()
			if !entry.jsonOnly {
				l.writeText(entry.level, l.formatLine(entry.level.String(), entry.msg))
			}
			if !entry.textOnly && (l.stdoutJSON || l.fileJSON) {
				ev := entry.event
				if ev == nil {
					ev = NewGeneralEvent(entry.level, l.module, entry.msg)
				}
				l.writeJSON(entry.level, ev)
			}
			l.mu.Unlock()
		}
	}()
}

// enqueue sends entry to the async write channel without blocking. If the
// channel is full the entry is dropped silently; this prevents log I/O from
// ever stalling a DNS query goroutine.
// In Synchronous mode the entry is written inline before returning.
func (l *Logger) enqueue(entry logEntry) {
	if l.config.Synchronous {
		l.mu.Lock()
		if !entry.jsonOnly {
			l.writeText(entry.level, l.formatLine(entry.level.String(), entry.msg))
		}
		if !entry.textOnly && (l.stdoutJSON || l.fileJSON) {
			ev := entry.event
			if ev == nil {
				ev = NewGeneralEvent(entry.level, l.module, entry.msg)
			}
			l.writeJSON(entry.level, ev)
		}
		l.mu.Unlock()
		return
	}
	select {
	case l.logCh <- entry:
	default:
		// Channel full; drop rather than block the DNS path.
	}
}

// logMsg enqueues a message at the given level for async writing to all
// active destinations.
func (l *Logger) logMsg(levelVal Level, msg string) {
	l.enqueue(logEntry{level: levelVal, msg: msg})
}

// logTextOnly enqueues a message for writing only to text-format (non-JSON)
// outputs. Used for verbose per-query messages already captured in JSON events.
func (l *Logger) logTextOnly(levelVal Level, msg string) {
	l.enqueue(logEntry{level: levelVal, msg: msg, textOnly: true})
}

// hasTextOutput returns true when at least one text-format (non-JSON) output
// is active and accepts messages at the given level.
// May be called without the mutex as an optimistic fast-path check.
func (l *Logger) hasTextOutput(levelVal Level) bool {
	if l.stdoutWriter != nil && !l.stdoutJSON && l.stdoutMin <= levelVal {
		return true
	}
	if l.fileWriter != nil && !l.fileJSON && l.fileMin <= levelVal {
		return true
	}
	return false
}

// IsJSONEnabled reports whether any JSON output destination is configured.
// Callers may use this to skip building expensive structured event objects
// when JSON logging is disabled.
func (l *Logger) IsJSONEnabled() bool {
	return (l.stdoutWriter != nil && l.stdoutJSON) || (l.fileWriter != nil && l.fileJSON)
}

// IsStdoutJSONEnabled reports whether the stdout output is configured as JSON.
// Callers use this to decide whether to suppress plain-text banner output and
// emit structured JSON events instead, ensuring stdout is pure JSON.
func (l *Logger) IsStdoutJSONEnabled() bool {
	return l.stdoutWriter != nil && l.stdoutJSON
}

// IsTextEnabled reports whether any text-format (non-JSON) output is active.
// Callers may use this to decide whether to emit verbose messages that are
// already captured in structured JSON DNS events.
func (l *Logger) IsTextEnabled() bool {
	return (l.stdoutWriter != nil && !l.stdoutJSON) || (l.fileWriter != nil && !l.fileJSON)
}

// LogEvent enqueues a structured event for async writing.
// For TypeDNSQuery events: only written to JSON outputs (never text).
// If JSON is not enabled and the event is a dns_query type, it is dropped.
// For all other event types: written to both text and JSON outputs.
func (l *Logger) LogEvent(level Level, event *Event) {
	if l.minLevel > level {
		return
	}
	jsonOnly := event.Type == TypeDNSQuery
	if jsonOnly && !l.IsJSONEnabled() {
		// No JSON output configured; dns_query events are JSON-only.
		return
	}
	l.enqueue(logEntry{level: level, msg: event.Message, event: event, jsonOnly: jsonOnly})
}

// Debugf logs a DEBUG-level formatted message.
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.minLevel > LevelDebug {
		return
	}
	l.logMsg(LevelDebug, fmt.Sprintf(format, v...))
}

// Infof logs an INFO-level formatted message.
func (l *Logger) Infof(format string, v ...interface{}) {
	if l.minLevel > LevelInfo {
		return
	}
	l.logMsg(LevelInfo, fmt.Sprintf(format, v...))
}

// Warnf logs a WARN-level formatted message.
func (l *Logger) Warnf(format string, v ...interface{}) {
	if l.minLevel > LevelWarn {
		return
	}
	l.logMsg(LevelWarn, fmt.Sprintf(format, v...))
}

// Errorf logs an ERROR-level formatted message.
func (l *Logger) Errorf(format string, v ...interface{}) {
	if l.minLevel > LevelError {
		return
	}
	l.logMsg(LevelError, fmt.Sprintf(format, v...))
}

// Fatalf logs a FATAL message synchronously, bypassing the async queue to
// ensure the message is written before the process exits.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.mu.Lock()
	l.writeText(LevelFatal, l.formatLine("FATAL", msg))
	if l.stdoutJSON || l.fileJSON {
		l.writeJSON(LevelFatal, NewGeneralEvent(LevelFatal, l.module, msg))
	}
	l.mu.Unlock()
	os.Exit(1)
}

// InfofText logs an INFO message only to text-format (non-JSON) outputs.
// Use for verbose per-query messages that are already captured in a
// structured JSON DNS event, so they are not duplicated in JSON mode.
func (l *Logger) InfofText(format string, v ...interface{}) {
	if !l.hasTextOutput(LevelInfo) {
		return
	}
	l.logTextOnly(LevelInfo, fmt.Sprintf(format, v...))
}

// WarnfText logs a WARN message only to text-format (non-JSON) outputs.
// Use for verbose per-query messages that are already captured in a
// structured JSON DNS event, so they are not duplicated in JSON mode.
func (l *Logger) WarnfText(format string, v ...interface{}) {
	if !l.hasTextOutput(LevelWarn) {
		return
	}
	l.logTextOnly(LevelWarn, fmt.Sprintf(format, v...))
}

// Flush blocks until all pending log entries have been written to their
// destinations. It is intended for use in tests and shutdown sequences
// where callers need to ensure that buffered entries are visible before
// reading output or exiting. It does not close the logger.
// In Synchronous mode Flush is a no-op since writes complete inline.
func (l *Logger) Flush() {
	if l.logCh == nil {
		return
	}
	done := make(chan struct{})
	l.logCh <- logEntry{done: done}
	<-done
}

// Close drains the async write queue, waits for the worker goroutine to
// finish, then closes the log file. Safe to call multiple times.
// In Synchronous mode only the file is closed (there is no channel or worker).
func (l *Logger) Close() {
	l.closeOnce.Do(func() {
		if l.logCh != nil {
			close(l.logCh)
			l.wg.Wait()
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.file != nil {
			if err := l.file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR | [%s] failed to close log file: %v\n", l.module, err)
			}
			l.file = nil
		}
	})
}

// FilePath returns the current log file path.
func (l *Logger) FilePath() string {
	return l.filePath
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
		// Fall back to stdout only on rotation failure.
		l.applyStdoutWriter(os.Stdout)
		l.fileWriter = nil
		l.updateMinLevel()
		l.logMsg(LevelError, fmt.Sprintf("Failed to open new log file after rotation: %v", err))
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
