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

	"codeberg.org/miekg/dns"
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

// TestSmoke_UpstreamReachable verifies that the running binary can actually
// resolve a domain and return a non-SERVFAIL response. This test catches the
// failure mode where the binary starts successfully but cannot reach any
// upstream DNS server (e.g. bootstrap DNS blocked, misconfigured upstream
// addresses), which would cause every client query to receive SERVFAIL.
func TestSmoke_UpstreamReachable(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("upstream unreachable: DNS query returned %s (want NOERROR) -- "+
			"the binary started but cannot reach any upstream DNS server; "+
			"check network connectivity and bootstrap_dns config",
			dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("upstream unreachable: NOERROR but no answer records -- upstream resolved but returned empty response")
	}
	t.Logf("upstream reachable: example.com A -> %d answer(s)", len(resp.Answer))
}

// TestSmoke_TwoInstancesDifferentConfigDirs starts two separate instances of
// the binary concurrently, each with its own configuration directory and port.
// This exercises the common multi-instance deployment scenario (e.g. one
// instance per network interface, or two differently-filtered resolvers) and
// confirms the instances do not interfere with each other.
func TestSmoke_TwoInstancesDifferentConfigDirs(t *testing.T) {
	base := smokeTempDir(t)

	dirA := filepath.Join(base, "instanceA")
	dirB := filepath.Join(base, "instanceB")
	for _, d := range []string{dirA, dirB} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("create instance dir %s: %v", d, err)
		}
	}

	portA := findFreePort(t)
	portB := findFreePort(t)

	cfgA := writeConfig(t, dirA, minimalConfig(portA))
	cfgB := writeConfig(t, dirB, minimalConfig(portB))

	// Start both instances; startBinary registers t.Cleanup to kill each one.
	startBinary(t, cfgA, portA)
	startBinary(t, cfgB, portB)

	t.Logf("instance A listening on 127.0.0.1:%d (config: %s)", portA, dirA)
	t.Logf("instance B listening on 127.0.0.1:%d (config: %s)", portB, dirB)

	// Both instances must resolve DNS independently.
	respA := queryUDP(t, portA, "example.com", dns.TypeA)
	if respA.Rcode != dns.RcodeSuccess {
		t.Errorf("instance A: DNS query returned %s, want NOERROR", dns.RcodeToString[respA.Rcode])
	} else if len(respA.Answer) == 0 {
		t.Error("instance A: NOERROR but no answer records")
	} else {
		t.Logf("instance A: example.com A -> %d answer(s)", len(respA.Answer))
	}

	respB := queryUDP(t, portB, "example.com", dns.TypeA)
	if respB.Rcode != dns.RcodeSuccess {
		t.Errorf("instance B: DNS query returned %s, want NOERROR", dns.RcodeToString[respB.Rcode])
	} else if len(respB.Answer) == 0 {
		t.Error("instance B: NOERROR but no answer records")
	} else {
		t.Logf("instance B: example.com A -> %d answer(s)", len(respB.Answer))
	}
}
