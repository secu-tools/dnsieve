// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestMain provides a child-process mode for the CreateProcess round-trip
// test below. When DNSIEVE_TEST_PRINT_ARGS=1 the re-executed test binary
// prints the raw os.Args (one per line) exactly as the Windows command-line
// parser delivered them, then exits without running the test framework.
func TestMain(m *testing.M) {
	if os.Getenv("DNSIEVE_TEST_PRINT_ARGS") == "1" {
		for _, a := range os.Args {
			fmt.Println(a)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestServiceBinPath(t *testing.T) {
	tests := []struct {
		name     string
		exe      string
		svcName  string
		args     []string
		expected string
	}{
		{
			name:     "no args",
			exe:      `C:\dnsieve\dnsieve.exe`,
			svcName:  "dnsieve",
			expected: `"C:\dnsieve\dnsieve.exe" --svcname dnsieve`,
		},
		{
			name:     "paths without spaces stay unquoted",
			exe:      `C:\dnsieve\dnsieve.exe`,
			svcName:  "dnsieve_home",
			args:     []string{"--cfgfile", `C:\dnsieve\config.toml`},
			expected: `"C:\dnsieve\dnsieve.exe" --svcname dnsieve_home --cfgfile C:\dnsieve\config.toml`,
		},
		{
			name:     "paths with spaces are quoted",
			exe:      `C:\Program Files\dnsieve\dnsieve.exe`,
			svcName:  "dnsieve",
			args:     []string{"--cfgfile", `C:\Program Files\dnsieve\config.toml`, "--logdir", `D:\dnsieve logs`},
			expected: `"C:\Program Files\dnsieve\dnsieve.exe" --svcname dnsieve --cfgfile "C:\Program Files\dnsieve\config.toml" --logdir "D:\dnsieve logs"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serviceBinPath(tt.exe, tt.svcName, tt.args)
			if got != tt.expected {
				t.Errorf("serviceBinPath() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestServiceBinPath_CreateProcessRoundTrip verifies that the binPath command
// line built for the SCM parses back into the original arguments when Windows
// starts the process. The SCM passes the service ImagePath verbatim as the
// lpCommandLine of CreateProcess; launching a child with SysProcAttr.CmdLine
// reproduces that exact mechanism. The test binary is copied to a directory
// containing spaces so the executable path itself exercises the quoting.
func TestServiceBinPath_CreateProcessRoundTrip(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	spacedDir := filepath.Join(t.TempDir(), "dir with spaces")
	if err := os.MkdirAll(spacedDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	spacedExe := filepath.Join(spacedDir, "dnsieve helper.exe")
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read test binary: %v", err)
	}
	if err := os.WriteFile(spacedExe, data, 0o750); err != nil {
		t.Fatalf("copy test binary: %v", err)
	}

	cfgFile := `C:\Program Files\dn sieve\config file.toml`
	logDir := `D:\dnsieve logs\out`
	cfg := &ServiceConfig{CfgFile: cfgFile, LogDir: logDir}
	binPath := serviceBinPath(spacedExe, "dnsieve_roundtrip", cfg.ServerArgs())

	cmd := exec.Command(spacedExe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: binPath}
	cmd.Env = append(os.Environ(), "DNSIEVE_TEST_PRINT_ARGS=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run child with raw command line %q: %v", binPath, err)
	}

	got := strings.Split(strings.ReplaceAll(strings.TrimRight(string(out), "\r\n"), "\r\n", "\n"), "\n")
	want := []string{
		spacedExe,
		"--svcname", "dnsieve_roundtrip",
		"--cfgfile", cfgFile,
		"--logdir", logDir,
	}
	if len(got) != len(want) {
		t.Fatalf("parsed argv = %q (len %d), want %q (len %d)", got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
