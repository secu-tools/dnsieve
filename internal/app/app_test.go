// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package app

import (
	"os"
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

// ---------------------------------------------------------------------------
// patchSpeedArg
// ---------------------------------------------------------------------------

// withArgs temporarily replaces os.Args for the duration of fn.
func withArgs(args []string, fn func()) {
	orig := os.Args
	os.Args = args
	defer func() { os.Args = orig }()
	fn()
}

// TestPatchSpeedArg_BareAtEnd: bare --speed at the end of args gets an empty
// string injected so the flag package sees a value.
func TestPatchSpeedArg_BareAtEnd(t *testing.T) {
	withArgs([]string{"dnsieve", "--speed"}, func() {
		patchSpeedArg()
		if len(os.Args) != 3 {
			t.Fatalf("expected 3 args, got %d: %v", len(os.Args), os.Args)
		}
		if os.Args[2] != "" {
			t.Errorf("expected empty string injected, got %q", os.Args[2])
		}
	})
}

// TestPatchSpeedArg_BareBeforeFlag: bare --speed before another flag also
// gets an empty string injected; the following flag is preserved.
func TestPatchSpeedArg_BareBeforeFlag(t *testing.T) {
	withArgs([]string{"dnsieve", "--speed", "--cfgfile", "x.toml"}, func() {
		patchSpeedArg()
		if len(os.Args) != 5 {
			t.Fatalf("expected 5 args, got %d: %v", len(os.Args), os.Args)
		}
		if os.Args[2] != "" {
			t.Errorf("expected empty string after --speed, got %q", os.Args[2])
		}
		if os.Args[3] != "--cfgfile" {
			t.Errorf("expected --cfgfile preserved, got %q", os.Args[3])
		}
	})
}

// TestPatchSpeedArg_SpaceValue: --speed followed by a plain value (no dash)
// is left untouched; the value is already present.
func TestPatchSpeedArg_SpaceValue(t *testing.T) {
	withArgs([]string{"dnsieve", "--speed", "google.com,github.com"}, func() {
		patchSpeedArg()
		if len(os.Args) != 3 {
			t.Fatalf("expected 3 args (unchanged), got %d: %v", len(os.Args), os.Args)
		}
		if os.Args[2] != "google.com,github.com" {
			t.Errorf("value should be unchanged, got %q", os.Args[2])
		}
	})
}

// TestPatchSpeedArg_InlineEquals: --speed=value already has an inline value;
// no injection needed.
func TestPatchSpeedArg_InlineEquals(t *testing.T) {
	withArgs([]string{"dnsieve", "--speed=google.com"}, func() {
		patchSpeedArg()
		if len(os.Args) != 2 {
			t.Fatalf("expected 2 args (unchanged), got %d: %v", len(os.Args), os.Args)
		}
	})
}

// TestPatchSpeedArg_NoSpeedFlag: unrelated flags are not touched.
func TestPatchSpeedArg_NoSpeedFlag(t *testing.T) {
	withArgs([]string{"dnsieve", "--version"}, func() {
		patchSpeedArg()
		if len(os.Args) != 2 {
			t.Fatalf("expected 2 args (unchanged), got %d: %v", len(os.Args), os.Args)
		}
	})
}

// TestPatchSpeedArg_SingleDashBare: -speed (single dash) works the same as
// --speed.
func TestPatchSpeedArg_SingleDashBare(t *testing.T) {
	withArgs([]string{"dnsieve", "-speed"}, func() {
		patchSpeedArg()
		if len(os.Args) != 3 {
			t.Fatalf("expected 3 args, got %d: %v", len(os.Args), os.Args)
		}
		if os.Args[2] != "" {
			t.Errorf("expected empty string injected, got %q", os.Args[2])
		}
	})
}

// TestPatchSpeedArg_SingleDashInlineEquals: -speed=value is left untouched.
func TestPatchSpeedArg_SingleDashInlineEquals(t *testing.T) {
	withArgs([]string{"dnsieve", "-speed=example.com"}, func() {
		patchSpeedArg()
		if len(os.Args) != 2 {
			t.Fatalf("expected 2 args (unchanged), got %d: %v", len(os.Args), os.Args)
		}
	})
}

// ---------------------------------------------------------------------------
// isSpeedFlag
// ---------------------------------------------------------------------------

func TestIsSpeedFlag_DoubleDash(t *testing.T) {
	withArgs([]string{"dnsieve", "--speed"}, func() {
		if !isSpeedFlag() {
			t.Error("expected true for --speed")
		}
	})
}

func TestIsSpeedFlag_SingleDash(t *testing.T) {
	withArgs([]string{"dnsieve", "-speed"}, func() {
		if !isSpeedFlag() {
			t.Error("expected true for -speed")
		}
	})
}

func TestIsSpeedFlag_NotPresent(t *testing.T) {
	withArgs([]string{"dnsieve", "--version"}, func() {
		if isSpeedFlag() {
			t.Error("expected false when --speed is absent")
		}
	})
}

// TestIsSpeedFlag_ValueNotBare: even when --speed has a following value token,
// isSpeedFlag still returns true because the --speed token is present in
// os.Args. The flag.Lookup check handles the non-empty value case; isSpeedFlag
// is the fallback for the empty-value (bare) case, but returning true here is
// safe because flag.Lookup takes precedence in the conditional.
func TestIsSpeedFlag_ValueNotBare(t *testing.T) {
	withArgs([]string{"dnsieve", "--speed", "google.com"}, func() {
		if !isSpeedFlag() {
			t.Error("expected true: --speed token is present even when a value follows")
		}
	})
}
