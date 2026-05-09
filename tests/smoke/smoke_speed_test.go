// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestSmoke_SpeedFlag_DefaultDomains verifies that `--speed` (with no
// --speed-domains argument) exits successfully and prints per-upstream results
// using the built-in default domain list.
func TestSmoke_SpeedFlag_DefaultDomains(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))

	cmd := exec.Command(dnsieveBinary, "--cfgfile", cfgPath, "--speed")
	cmd.Dir = dir

	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(120 * time.Second):
		cmd.Process.Kill()
		t.Fatal("--speed did not complete within 120s")
	}

	if runErr != nil {
		t.Fatalf("--speed exited with error: %v\noutput:\n%s", runErr, out)
	}
	output := string(out)
	if !strings.Contains(output, "DNSieve") {
		t.Errorf("expected version banner in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Speed Test") {
		t.Errorf("expected 'Speed Test' in output, got:\n%s", output)
	}
	t.Logf("--speed output:\n%s", output)
}

// TestSmoke_SpeedFlag_SingleDash verifies that `-speed` (single dash) works
// identically to `--speed`.
func TestSmoke_SpeedFlag_SingleDash(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))

	cmd := exec.Command(dnsieveBinary, "--cfgfile", cfgPath, "-speed")
	cmd.Dir = dir

	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(120 * time.Second):
		cmd.Process.Kill()
		t.Fatal("-speed did not complete within 120s")
	}

	if runErr != nil {
		t.Fatalf("-speed exited with error: %v\noutput:\n%s", runErr, out)
	}
	if !strings.Contains(string(out), "Speed Test") {
		t.Errorf("expected 'Speed Test' in output, got:\n%s", out)
	}
	t.Logf("-speed output:\n%s", out)
}

// TestSmoke_SpeedFlag_WithDomains verifies that --speed example.com,example.org
// (space-separated value) restricts the test to only the supplied domains and
// exits successfully.
func TestSmoke_SpeedFlag_WithDomains(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))

	cmd := exec.Command(dnsieveBinary,
		"--cfgfile", cfgPath,
		"--speed", "example.com,example.org",
	)
	cmd.Dir = dir

	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		cmd.Process.Kill()
		t.Fatal("--speed with domains did not complete within 60s")
	}

	if runErr != nil {
		t.Fatalf("--speed with domains exited with error: %v\noutput:\n%s", runErr, out)
	}
	output := string(out)
	if !strings.Contains(output, "Speed Test") {
		t.Errorf("expected 'Speed Test' in output, got:\n%s", output)
	}
	// Only the two supplied domains should appear in the query count line.
	if !strings.Contains(output, "2 domain(s)") {
		t.Errorf("expected '2 domain(s)' in output for two supplied domains, got:\n%s", output)
	}
	t.Logf("--speed with domains output:\n%s", output)
}

// TestSmoke_SpeedFlag_NoConfig verifies that --speed exits non-zero and
// prints an error when no config file exists and stdin is closed.
func TestSmoke_SpeedFlag_NoConfig(t *testing.T) {
	dir := smokeTempDir(t)

	cmd := exec.Command(dnsieveBinary,
		"--cfgfile", dir+"/nonexistent.toml",
		"--speed",
	)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader("") // closed stdin: suppress interactive prompt

	var out []byte
	var runErr error
	done := make(chan struct{})
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("--speed with no config did not exit within 30s")
	}

	if runErr == nil {
		t.Errorf("expected non-zero exit when config is missing, got success\noutput:\n%s", out)
	}

	output := strings.ToLower(string(out))
	if !strings.Contains(output, "config") {
		t.Errorf("expected config-related error message, got:\n%s", out)
	}
	t.Logf("no-config output: %s", strings.TrimSpace(string(out)))
}

// TestSmoke_SpeedFlag_DomainDetailsSection verifies that the per-domain
// breakdown ("Domain Details:") is included in the --speed output.
func TestSmoke_SpeedFlag_DomainDetailsSection(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))

	cmd := exec.Command(dnsieveBinary,
		"--cfgfile", cfgPath,
		"--speed", "example.com,example.org",
	)
	cmd.Dir = dir

	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		cmd.Process.Kill()
		t.Fatal("--speed domain-details did not complete within 60s")
	}

	if runErr != nil {
		t.Fatalf("--speed exited with error: %v\noutput:\n%s", runErr, out)
	}
	output := string(out)
	if !strings.Contains(output, "Domain Details") {
		t.Errorf("expected 'Domain Details' section in output, got:\n%s", output)
	}
	t.Logf("--speed domain-details output:\n%s", output)
}
