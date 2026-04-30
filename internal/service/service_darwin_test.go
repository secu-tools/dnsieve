// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package service

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindDNSieveServicesDarwin_Empty(t *testing.T) {
	dir := t.TempDir()
	services := findDNSieveServicesDarwin(dir)
	if len(services) != 0 {
		t.Errorf("expected no services in empty dir, got %d", len(services))
	}
}

func TestFindDNSieveServicesDarwin_MatchingPlists(t *testing.T) {
	dir := t.TempDir()

	matching := []string{
		"com.dnsieve.dnsieve.plist",
		"com.dnsieve.dnsieve_home.plist",
	}
	for _, name := range matching {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("<plist/>"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Files that must be ignored.
	ignored := []string{
		"com.other.app.plist",     // wrong prefix
		"com.dnsieve.noextension", // missing .plist suffix
		"notdnsieve.plist",        // wrong prefix entirely
	}
	for _, name := range ignored {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// A directory entry whose name looks like a plist — must be skipped.
	if err := os.MkdirAll(filepath.Join(dir, "com.dnsieve.subdir.plist"), 0750); err != nil {
		t.Fatal(err)
	}

	services := findDNSieveServicesDarwin(dir)
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d: %v", len(services), services)
	}

	labels := make(map[string]string, len(services))
	for _, svc := range services {
		labels[svc.label] = svc.plistPath
	}

	for _, name := range matching {
		label := strings.TrimSuffix(name, ".plist")
		wantPath := filepath.Join(dir, name)
		gotPath, ok := labels[label]
		if !ok {
			t.Errorf("expected label %q not found in results", label)
			continue
		}
		if gotPath != wantPath {
			t.Errorf("label %q: plistPath = %q, want %q", label, gotPath, wantPath)
		}
	}
}

func TestFindDNSieveServicesDarwin_NonExistentDir(t *testing.T) {
	services := findDNSieveServicesDarwin("/nonexistent/path/does/not/exist/dnsieve")
	if len(services) != 0 {
		t.Errorf("expected no services for nonexistent dir, got %d", len(services))
	}
}

func TestFindDNSieveServicesDarwin_OnlySubdirs(t *testing.T) {
	dir := t.TempDir()
	// Only subdirectories — none should be returned.
	if err := os.MkdirAll(filepath.Join(dir, "com.dnsieve.dnsieve.plist"), 0750); err != nil {
		t.Fatal(err)
	}
	services := findDNSieveServicesDarwin(dir)
	if len(services) != 0 {
		t.Errorf("expected no services (only subdirs), got %d", len(services))
	}
}

func TestReadLineDarwin(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain line", "hello\n", "hello"},
		{"trimmed whitespace", "  trimmed  \n", "trimmed"},
		{"empty line", "\n", ""},
		{"no trailing newline", "no-newline", "no-newline"},
		{"whitespace only", "   \n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tt.input))
			got := readLineDarwin(r)
			if got != tt.want {
				t.Errorf("readLineDarwin(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
