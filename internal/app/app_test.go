// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package app

import (
	"strings"
	"testing"
)

func TestVersionString_ContainsBanner(t *testing.T) {
	vs := versionString()

	if !strings.Contains(vs, "DNSieve") {
		t.Error("version string should contain DNSieve")
	}
	if !strings.Contains(vs, "DNS Filtering Proxy") {
		t.Error("version string should contain description")
	}
	if !strings.Contains(vs, "Copyright") {
		t.Error("version string should contain copyright")
	}
	if !strings.Contains(vs, "jack-l.com") {
		t.Error("version string should contain author URL")
	}
	if !strings.Contains(vs, "github.com/secu-tools/dnsieve") {
		t.Error("version string should contain repo URL")
	}
}

func TestFullVersion(t *testing.T) {
	// Default values
	fv := fullVersion()
	if fv != "1.0.0.0" {
		t.Errorf("expected '1.0.0.0', got %q", fv)
	}
}

func TestResolveCommitLabel_Default(t *testing.T) {
	// With default "dev" value
	old := commit
	defer func() { commit = old }()

	commit = "dev"
	label := resolveCommitLabel()
	// Should return either "dev" or a VCS revision from build info
	if label == "" {
		t.Error("commit label should not be empty")
	}
}

func TestResolveCommitLabel_Custom(t *testing.T) {
	old := commit
	defer func() { commit = old }()

	commit = "abc1234"
	label := resolveCommitLabel()
	if label != "abc1234" {
		t.Errorf("expected abc1234, got %s", label)
	}
}

func TestVersionString_Format(t *testing.T) {
	vs := versionString()
	lines := strings.Split(vs, "\n")

	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}

	// Line 1: "DNSieve - DNS Filtering Proxy - VERSION (COMMIT)"
	if !strings.HasPrefix(lines[0], "DNSieve - DNS Filtering Proxy - ") {
		t.Errorf("first line format wrong: %s", lines[0])
	}

	// Line 2: "Copyright ..."
	if !strings.HasPrefix(lines[1], "Copyright") {
		t.Errorf("second line should start with Copyright: %s", lines[1])
	}

	// Line 3: "Github Repository: ..."
	if !strings.HasPrefix(lines[2], "Github Repository:") {
		t.Errorf("third line should start with 'Github Repository:': %s", lines[2])
	}
}
