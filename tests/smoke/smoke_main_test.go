// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

// Package smoke_test contains smoke tests for the DNSieve binary.
//
// These tests build the DNSieve binary, start it as a subprocess with a
// temporary config file, send real DNS queries to it, and verify that it
// responds correctly. They cover binary startup, config generation, plain DNS,
// DoH, and DoT end-to-end, running the program exactly as a user would.
//
// Smoke tests require a working internet connection and network access to
// public upstream DNS servers.
//
// Run with:
//
//	go test -buildvcs=false -count=1 -timeout 300s -tags smoke ./tests/smoke/
//
// Or via the build script:
//
//	./build.sh -testsmoke           # Linux / macOS
//	.\build.ps1 -testsmoke          # Windows
package smoke_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// dnsieveBinary is the path to the compiled DNSieve binary, set in TestMain.
var dnsieveBinary string

// smokeTmpDir is the root temp directory for this test run, cleaned up in TestMain.
var smokeTmpDir string

// TestMain builds the DNSieve binary once and then runs all smoke tests.
// All temporary files are created inside smokeTmpDir, which is removed after
// the test suite finishes.
func TestMain(m *testing.M) {
	root, err := findModuleRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: find module root: %v\n", err)
		os.Exit(1)
	}

	base := filepath.Join(os.TempDir(), "dnsieve")
	if err := os.MkdirAll(base, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: create dnsieve temp dir: %v\n", err)
		os.Exit(1)
	}

	smokeTmpDir, err = os.MkdirTemp(base, "smoke_")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: create smoke temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(smokeTmpDir)

	binName := "dnsieve"
	if runtime.GOOS == "windows" {
		binName = "dnsieve.exe"
	}
	dnsieveBinary = filepath.Join(smokeTmpDir, binName)

	fmt.Printf("=== SMOKE building DNSieve binary -> %s\n", dnsieveBinary)
	buildCmd := exec.Command("go", "build", "-buildvcs=false", "-o", dnsieveBinary, ".")
	buildCmd.Dir = root
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL smoke: build failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("=== SMOKE build complete")

	os.Exit(m.Run())
}

// findModuleRoot locates the go.mod file and returns its directory.
func findModuleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w", err)
	}
	modPath := strings.TrimSpace(string(out))
	if modPath == "" || modPath == os.DevNull {
		return "", fmt.Errorf("go.mod not found (not in a module)")
	}
	return filepath.Dir(modPath), nil
}
