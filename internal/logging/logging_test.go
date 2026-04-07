// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"error", LevelError},
		{"fatal", LevelFatal},
		{"unknown", LevelInfo}, // default
		{"", LevelInfo},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ParseLevel(tc.input)
			if got != tc.expected {
				t.Errorf("ParseLevel(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelFatal, "FATAL"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := tc.level.String(); got != tc.expected {
				t.Errorf("Level(%d).String() = %q, want %q", tc.level, got, tc.expected)
			}
		})
	}
}

func TestNew_CreatesLogFile(t *testing.T) {
	tmpDir := t.TempDir()

	old := customLogDir
	defer func() { customLogDir = old }()
	customLogDir = tmpDir

	logger, err := New("test.log", DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	logPath := filepath.Join(tmpDir, "test.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("log file was not created")
	}
}

func TestLogger_WriteAndReadBack(t *testing.T) {
	tmpDir := t.TempDir()
	old := customLogDir
	defer func() { customLogDir = old }()
	customLogDir = tmpDir

	logger, err := New("test.log", DefaultConfig(), "mymod")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.SetLevel(LevelDebug)
	logger.Infof("test message %d", 42)
	logger.Close()

	data, err := os.ReadFile(filepath.Join(tmpDir, "test.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "INFO") {
		t.Error("log should contain INFO level")
	}
	if !strings.Contains(content, "[mymod]") {
		t.Error("log should contain module name")
	}
	if !strings.Contains(content, "test message 42") {
		t.Error("log should contain message text")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	old := customLogDir
	defer func() { customLogDir = old }()
	customLogDir = tmpDir

	logger, err := New("level_test.log", DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Set to WARN -- DEBUG and INFO should be suppressed
	logger.SetLevel(LevelWarn)
	logger.Debugf("debug message")
	logger.Infof("info message")
	logger.Warnf("warn message")
	logger.Errorf("error message")
	logger.Close()

	data, err := os.ReadFile(filepath.Join(tmpDir, "level_test.log"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	content := string(data)
	if strings.Contains(content, "debug message") {
		t.Error("DEBUG should be suppressed at WARN level")
	}
	if strings.Contains(content, "info message") {
		t.Error("INFO should be suppressed at WARN level")
	}
	if !strings.Contains(content, "warn message") {
		t.Error("WARN should be present")
	}
	if !strings.Contains(content, "error message") {
		t.Error("ERROR should be present")
	}
}

func TestLogger_SetLevelFromString(t *testing.T) {
	tmpDir := t.TempDir()
	old := customLogDir
	defer func() { customLogDir = old }()
	customLogDir = tmpDir

	logger, err := New("str_level.log", DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer logger.Close()

	logger.SetLevelFromString("error")
	logger.Infof("should be hidden")
	logger.Errorf("should be visible")

	// Verify by checking what was written
	logger.Close()
	data, _ := os.ReadFile(filepath.Join(tmpDir, "str_level.log"))
	content := string(data)
	if strings.Contains(content, "should be hidden") {
		t.Error("INFO should be hidden at ERROR level")
	}
	if !strings.Contains(content, "should be visible") {
		t.Error("ERROR should be visible")
	}
}

func TestLogger_FormatLine(t *testing.T) {
	logger := &Logger{module: "server"}
	line := logger.formatLine("INFO", "test message")

	// Format: "LEVEL | timestamp [module] message"
	if !strings.HasPrefix(line, "INFO  |") {
		t.Errorf("line should start with 'INFO  |', got: %s", line)
	}
	if !strings.Contains(line, "[server]") {
		t.Errorf("line should contain [server], got: %s", line)
	}
	if !strings.Contains(line, "test message") {
		t.Errorf("line should contain message, got: %s", line)
	}
}

func TestLogger_FilePath(t *testing.T) {
	tmpDir := t.TempDir()
	old := customLogDir
	defer func() { customLogDir = old }()
	customLogDir = tmpDir

	logger, err := New("path_test.log", DefaultConfig(), "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer logger.Close()

	expected := filepath.Join(tmpDir, "path_test.log")
	if got := logger.FilePath(); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestNewStdoutOnly(t *testing.T) {
	logger := NewStdoutOnly(DefaultConfig(), "test")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
	// Should not panic when writing
	logger.Infof("stdout-only message")
}

func TestSetLogDir(t *testing.T) {
	tmpDir := t.TempDir()
	customDir := filepath.Join(tmpDir, "customlogs")

	old := customLogDir
	defer func() { customLogDir = old }()

	if err := SetLogDir(customDir); err != nil {
		t.Fatalf("SetLogDir: %v", err)
	}

	if _, err := os.Stat(customDir); os.IsNotExist(err) {
		t.Error("custom log dir should be created")
	}

	if LogDir() != customDir {
		t.Errorf("LogDir() should return custom dir, got %s", LogDir())
	}
}

func TestDefaultConfigValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxSizeMB != 10 {
		t.Errorf("expected MaxSizeMB 10, got %d", cfg.MaxSizeMB)
	}
	if cfg.MaxBackups != 5 {
		t.Errorf("expected MaxBackups 5, got %d", cfg.MaxBackups)
	}
	if cfg.MaxAgeDays != 30 {
		t.Errorf("expected MaxAgeDays 30, got %d", cfg.MaxAgeDays)
	}
	if cfg.FloodLimitPS != 100 {
		t.Errorf("expected FloodLimitPS 100, got %d", cfg.FloodLimitPS)
	}
}

func TestLogger_Rotation(t *testing.T) {
	tmpDir := t.TempDir()
	old := customLogDir
	defer func() { customLogDir = old }()
	customLogDir = tmpDir

	// Very small max size to trigger rotation
	cfg := Config{
		MaxSizeMB:    0, // Will be set to default (10), let's use 1 for testing
		MaxBackups:   3,
		MaxAgeDays:   30,
		FloodLimitPS: 0, // Unlimited
	}

	logger, err := New("rotate.log", cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer logger.Close()

	// Manually trigger rotation
	logger.mu.Lock()
	logger.rotate()
	logger.mu.Unlock()

	// Write something after rotation
	logger.Infof("post-rotation message")
	logger.Close()

	// Check main log and backup exist
	mainPath := filepath.Join(tmpDir, "rotate.log")
	backupPath := filepath.Join(tmpDir, "rotate.log.1")

	if _, err := os.Stat(mainPath); os.IsNotExist(err) {
		t.Error("main log file should exist after rotation")
	}
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("backup log .1 should exist after rotation")
	}
}
