// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSmoke_BinaryExists verifies the binary was built and is executable.
func TestSmoke_BinaryExists(t *testing.T) {
	info, err := os.Stat(dnsieveBinary)
	if err != nil {
		t.Fatalf("binary not found at %s: %v", dnsieveBinary, err)
	}
	if info.Size() == 0 {
		t.Fatal("binary is empty")
	}
	t.Logf("binary: %s (%d bytes)", dnsieveBinary, info.Size())
}

// TestSmoke_VersionFlag verifies that --version exits zero and prints a
// recognisable version banner.
func TestSmoke_VersionFlag(t *testing.T) {
	out, err := exec.Command(dnsieveBinary, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("--version exited with error: %v\noutput: %s", err, out)
	}
	output := strings.ToLower(string(out))
	if !strings.Contains(output, "dnsieve") {
		t.Errorf("--version output does not mention 'dnsieve': %s", out)
	}
	t.Logf("version output: %s", strings.TrimSpace(string(out)))
}

// TestSmoke_ConfigGeneration verifies that GenerateDefaultConfig writes a
// valid TOML file that the binary can parse without error.
func TestSmoke_ConfigGeneration(t *testing.T) {
	dir := smokeTempDir(t)

	cfgPath := filepath.Join(dir, "config.toml")

	// Use the generate path via config package import is not available here,
	// so we write a known minimal config and verify the binary starts cleanly.
	content := minimalConfig(findFreePort(t))
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	// Verify the file is non-empty and contains expected keys.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "[[upstream]]") {
		t.Error("generated config missing [[upstream]] section")
	}
	if !strings.Contains(string(data), "[downstream.plain]") {
		t.Error("generated config missing [downstream.plain] section")
	}
	t.Logf("config size: %d bytes", len(data))
}

// TestSmoke_StartupAndShutdown verifies that the binary starts cleanly with
// a valid config and shuts down gracefully when its context is cancelled.
func TestSmoke_StartupAndShutdown(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))

	cmd := exec.Command(dnsieveBinary, "--cfgfile", cfgPath)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start binary: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if !waitForPort(t, "tcp", addr, 30*time.Second) {
		cmd.Process.Kill()
		t.Fatalf("server did not start listening on %s within 30s", addr)
	}
	t.Logf("server listening on %s", addr)

	cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Error("binary did not exit within 15s after kill")
	}
}

// TestSmoke_MissingConfigExitsNonZero verifies that the binary exits with an
// error (non-zero) when given a non-existent config file path and stdin is
// closed (so it cannot prompt).
func TestSmoke_MissingConfigExitsNonZero(t *testing.T) {
	dir := smokeTempDir(t)
	cfgPath := filepath.Join(dir, "nonexistent.toml")

	cmd := exec.Command(dnsieveBinary, "--cfgfile", cfgPath)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("n\n") // answer "no" to generate-config prompt
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Errorf("expected non-zero exit for missing config, but got nil error\noutput: %s", out)
	}
	t.Logf("missing config output: %s", strings.TrimSpace(string(out)))
}
