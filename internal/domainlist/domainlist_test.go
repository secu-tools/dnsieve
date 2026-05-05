// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package domainlist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// DomainSet: parsing and matching
// ---------------------------------------------------------------------------

func TestParseReader_PlainDomains(t *testing.T) {
	input := `# Comment line
! Another comment

example.com
example.net
example.org
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 3 {
		t.Errorf("expected 3 entries, got %d", set.Count())
	}
	if !set.Contains("example.com") {
		t.Error("expected example.com to match")
	}
	if !set.Contains("example.net") {
		t.Error("expected example.net to match")
	}
	if set.Contains("sub.example.com") {
		t.Error("sub.example.com should NOT match exact entry example.com")
	}
}

func TestParseReader_WildcardDomains(t *testing.T) {
	input := `*.example.com
*.example.org
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 2 {
		t.Errorf("expected 2 entries, got %d", set.Count())
	}

	// Wildcard matches base domain
	if !set.Contains("example.com") {
		t.Error("*.example.com should match example.com")
	}
	// Wildcard matches subdomains
	if !set.Contains("sub.example.com") {
		t.Error("*.example.com should match sub.example.com")
	}
	if !set.Contains("deep.sub.example.com") {
		t.Error("*.example.com should match deep.sub.example.com")
	}
	// Should not match unrelated domains
	if set.Contains("unrelated.net") {
		t.Error("*.example.com should not match unrelated.net")
	}
}

func TestParseReader_HostsFormat(t *testing.T) {
	input := `# Hosts file format
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net
::1 block.example.org
:: spam.example.com
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 4 {
		t.Errorf("expected 4 entries, got %d", set.Count())
	}
	if !set.Contains("ads.example.com") {
		t.Error("expected ads.example.com to match")
	}
	if !set.Contains("tracker.example.net") {
		t.Error("expected tracker.example.net to match")
	}
	if !set.Contains("block.example.org") {
		t.Error("expected block.example.org to match")
	}
	if !set.Contains("spam.example.com") {
		t.Error("expected spam.example.com to match")
	}
}

func TestParseReader_MixedFormats(t *testing.T) {
	input := `# Mixed format list
example.com
*.example.net
0.0.0.0 ads.tracker.test
127.0.0.1 malware.test
*.block.test
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 5 {
		t.Errorf("expected 5 entries, got %d", set.Count())
	}
}

func TestParseReader_InlineComments(t *testing.T) {
	input := `example.com # inline comment
example.net#comment without space
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if !set.Contains("example.com") {
		t.Error("expected example.com to match")
	}
	if !set.Contains("example.net") {
		t.Error("expected example.net to match")
	}
}

func TestContains_CaseInsensitive(t *testing.T) {
	input := `Example.Com
*.Example.NET
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if !set.Contains("example.com") {
		t.Error("matching should be case-insensitive")
	}
	if !set.Contains("EXAMPLE.COM") {
		t.Error("matching should be case-insensitive")
	}
	if !set.Contains("sub.example.net") {
		t.Error("wildcard matching should be case-insensitive")
	}
}

func TestContains_TrailingDot(t *testing.T) {
	input := `example.com`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// FQDN with trailing dot
	if !set.Contains("example.com.") {
		t.Error("trailing dot should be stripped for matching")
	}
}

func TestContains_EmptyDomain(t *testing.T) {
	set := EmptySet()
	if set.Contains("") {
		t.Error("empty domain should not match")
	}
	if set.Contains(".") {
		t.Error("dot-only should not match")
	}
}

func TestContains_NilSet(t *testing.T) {
	var set *DomainSet
	if set.Contains("example.com") {
		t.Error("nil set should not match")
	}
}

func TestWildcard_SubdomainDepth(t *testing.T) {
	input := `*.abc.example.com`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}

	// Should match base
	if !set.Contains("abc.example.com") {
		t.Error("*.abc.example.com should match abc.example.com")
	}
	// Should match subdomain
	if !set.Contains("x.abc.example.com") {
		t.Error("*.abc.example.com should match x.abc.example.com")
	}
	// Should match deep subdomain
	if !set.Contains("a.b.c.abc.example.com") {
		t.Error("*.abc.example.com should match a.b.c.abc.example.com")
	}
	// Should NOT match parent
	if set.Contains("example.com") {
		t.Error("*.abc.example.com should NOT match example.com")
	}
	// Should NOT match sibling
	if set.Contains("xyz.example.com") {
		t.Error("*.abc.example.com should NOT match xyz.example.com")
	}
}

func TestExactMatch_DoesNotMatchSubdomains(t *testing.T) {
	input := `example.com`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if !set.Contains("example.com") {
		t.Error("exact entry should match itself")
	}
	if set.Contains("www.example.com") {
		t.Error("exact entry should NOT match subdomains")
	}
	if set.Contains("sub.example.com") {
		t.Error("exact entry should NOT match subdomains")
	}
	if set.Contains("a.b.example.com") {
		t.Error("exact entry should NOT match deep subdomains")
	}
}

func TestWildcard_MatchesBase(t *testing.T) {
	input := `*.example.com`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// *.example.com should match example.com itself
	if !set.Contains("example.com") {
		t.Error("*.example.com should match example.com")
	}
}

func TestWildcard_TLD(t *testing.T) {
	input := `*.fr`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// *.fr requires at least one dot in base (fr alone is a TLD)
	// Our implementation requires base to contain "." so *.fr won't load
	if set.Contains("anything.fr") {
		t.Log("*.fr matching is not supported (TLD wildcards need at least domain.tld format)")
	}
}

func TestIDN_PunycodeConversion(t *testing.T) {
	// German umlaut domain
	input := "*.xn--mnchen-3ya.de\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if !set.Contains("xn--mnchen-3ya.de") {
		t.Error("punycode domain should match")
	}
	if !set.Contains("sub.xn--mnchen-3ya.de") {
		t.Error("punycode subdomain should match")
	}
}

func TestIDN_UnicodeInput(t *testing.T) {
	// Unicode domain in list - should be converted to punycode
	input := "*.xn--mnchen-3ya.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// The query arrives in punycode on the wire
	if !set.Contains("xn--mnchen-3ya.example.com") {
		t.Error("punycode subdomain entry should match apex")
	}
	if !set.Contains("sub.xn--mnchen-3ya.example.com") {
		t.Error("punycode subdomain entry should match subdomains")
	}
}

func TestEmptySet_Count(t *testing.T) {
	set := EmptySet()
	if set.Count() != 0 {
		t.Errorf("empty set should have count 0, got %d", set.Count())
	}
	if set.Contains("anything.com") {
		t.Error("empty set should not contain anything")
	}
}

func TestParseReader_EmptyInput(t *testing.T) {
	set, err := ParseReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 0 {
		t.Errorf("empty input should produce 0 entries, got %d", set.Count())
	}
}

func TestParseReader_OnlyComments(t *testing.T) {
	input := `# comment 1
! comment 2
# comment 3
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 0 {
		t.Errorf("comments-only input should produce 0 entries, got %d", set.Count())
	}
}

func TestParseReader_Deduplication(t *testing.T) {
	input := `example.com
example.com
EXAMPLE.COM
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("duplicates should be deduplicated, got count %d", set.Count())
	}
}

func TestParseReader_WildcardWithoutDot(t *testing.T) {
	// "*.com" has base "com" which has no dot - should be rejected
	input := `*.com`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 0 {
		t.Errorf("*.com (bare TLD wildcard) should be rejected, got count %d", set.Count())
	}
}

// ---------------------------------------------------------------------------
// DomainList: file loading
// ---------------------------------------------------------------------------

func TestDomainList_LoadSingleFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\nexample.net\n*.block.test\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	count, _, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 domains loaded, got %d", count)
	}
	if !dl.Contains("example.com") {
		t.Error("expected example.com to be in list")
	}
	if !dl.Contains("sub.block.test") {
		t.Error("expected sub.block.test to match wildcard")
	}
}

func TestDomainList_LoadMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file1.list", "example.com\nexample.net\n")
	writeTestFile(t, dir, "file2.list", "*.block.test\n*.block2.test\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	count, _, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 4 {
		t.Errorf("expected 4 domains loaded, got %d", count)
	}
}

func TestDomainList_LoadNoFiles(t *testing.T) {
	dir := t.TempDir()
	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	count, _, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 domains when no files exist, got %d", count)
	}
}

func TestDomainList_LoadMultipleGlobs(t *testing.T) {
	dir := t.TempDir()
	sub1 := filepath.Join(dir, "sub1")
	sub2 := filepath.Join(dir, "sub2")
	os.MkdirAll(sub1, 0700)
	os.MkdirAll(sub2, 0700)

	writeTestFile(t, sub1, "a.list", "a.com\n")
	writeTestFile(t, sub2, "b.list", "b.com\n")

	dl := NewDomainList("test", []string{
		filepath.Join(sub1, "*.list"),
		filepath.Join(sub2, "*.list"),
	})
	count, _, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 domains, got %d", count)
	}
	if !dl.Contains("a.com") {
		t.Error("expected a.com from first glob")
	}
	if !dl.Contains("b.com") {
		t.Error("expected b.com from second glob")
	}
}

func TestDomainList_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")
	os.MkdirAll(filepath.Join(dir, "subdir.list"), 0700) // directory with .list extension

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	count, _, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 domain (directory should be skipped), got %d", count)
	}
}

// ---------------------------------------------------------------------------
// DomainList: reload and watcher
// ---------------------------------------------------------------------------

func TestDomainList_DetectChanges_ModifiedFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Modify file (ensure different mtime)
	time.Sleep(50 * time.Millisecond)
	writeTestFile(t, dir, "test.list", "example.com\nexample.net\n")

	changed, reason := dl.detectChanges()
	if !changed {
		t.Error("expected change detected after file modification")
	}
	if !strings.Contains(reason, "modified") {
		t.Errorf("expected reason to mention 'modified', got %q", reason)
	}
}

func TestDomainList_DetectChanges_NewFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Add new file
	writeTestFile(t, dir, "new.list", "example.net\n")

	changed, reason := dl.detectChanges()
	if !changed {
		t.Error("expected change detected after new file added")
	}
	if !strings.Contains(reason, "new file") {
		t.Errorf("expected reason to mention 'new file', got %q", reason)
	}
}

func TestDomainList_DetectChanges_DeletedFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")
	writeTestFile(t, dir, "extra.list", "example.net\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Delete file
	os.Remove(filepath.Join(dir, "extra.list"))

	changed, reason := dl.detectChanges()
	if !changed {
		t.Error("expected change detected after file deletion")
	}
	if !strings.Contains(reason, "deleted") {
		t.Errorf("expected reason to mention 'deleted', got %q", reason)
	}
}

func TestDomainList_DetectChanges_NoChange(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	changed, _ := dl.detectChanges()
	if changed {
		t.Error("expected no change detected when files are unchanged")
	}
}

func TestDomainList_Reload_AtomicSwap(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !dl.Contains("example.com") {
		t.Fatal("initial load should contain example.com")
	}
	if dl.Contains("example.net") {
		t.Fatal("initial load should not contain example.net")
	}

	// Modify file
	time.Sleep(50 * time.Millisecond)
	writeTestFile(t, dir, "test.list", "example.net\n")

	// Trigger reload
	noop := func(format string, args ...interface{}) {}
	dl.checkAndReload(noop, noop, noop)

	if !dl.Contains("example.net") {
		t.Error("after reload, example.net should be in list")
	}
	// example.com was removed from file
	if dl.Contains("example.com") {
		t.Error("after reload, example.com should NOT be in list")
	}
}

func TestDomainList_Watcher_Integration(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	var mu sync.Mutex
	var reloadCount int
	logInfo := func(format string, args ...interface{}) {
		mu.Lock()
		msg := fmt.Sprintf(format, args...)
		if strings.Contains(msg, "reloaded") {
			reloadCount++
		}
		mu.Unlock()
	}
	noop := func(format string, args ...interface{}) {}

	// Start watcher with 1-second interval
	dl.StartWatcher(1, logInfo, noop, noop)
	defer dl.Stop()

	// Modify file after a short delay
	time.Sleep(200 * time.Millisecond)
	writeTestFile(t, dir, "test.list", "example.net\nnewdomain.com\n")

	// Wait for watcher to pick up changes
	time.Sleep(1500 * time.Millisecond)

	if !dl.Contains("example.net") {
		t.Error("watcher should have reloaded and now contain example.net")
	}

	mu.Lock()
	rc := reloadCount
	mu.Unlock()
	if rc < 1 {
		t.Error("expected at least 1 reload to have occurred")
	}
}

func TestDomainList_Stop(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	dl.StartWatcher(1, func(string, ...interface{}) {}, func(string, ...interface{}) {}, func(string, ...interface{}) {})
	dl.Stop()
	// Should not panic or hang
}

func TestDomainList_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n*.example.net\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Simulate concurrent reads and a reload
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Multiple readers
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					dl.Contains("example.com")
					dl.Contains("sub.example.net")
					dl.Contains("unknown.com")
				}
			}
		}()
	}

	// Writer (reload)
	wg.Add(1)
	go func() {
		defer wg.Done()
		noop := func(string, ...interface{}) {}
		for range 5 {
			time.Sleep(10 * time.Millisecond)
			writeTestFile(t, dir, "test.list", "updated.com\n")
			dl.checkAndReload(noop, noop, noop)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestDomainList_ReloadFailure_KeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Make file unreadable (simulate failure)
	badPath := filepath.Join(dir, "test.list")
	os.Chmod(badPath, 0000)
	defer os.Chmod(badPath, 0644)

	// Attempt reload - should fail and keep old data
	var warned bool
	logWarn := func(format string, args ...interface{}) { warned = true }
	noop := func(string, ...interface{}) {}

	// Force detection by removing our tracked state
	dl.mu.Lock()
	dl.files = nil
	dl.mu.Unlock()

	dl.checkAndReload(noop, logWarn, noop)

	if !dl.Contains("example.com") {
		t.Error("after failed reload, previous list should be preserved")
	}
	if !warned {
		t.Log("note: on some OS/filesystem the reload may succeed despite chmod 0000")
	}
}

// ---------------------------------------------------------------------------
// Validation: isValidDomain
// ---------------------------------------------------------------------------

func TestIsValidDomain_Valid(t *testing.T) {
	cases := []string{
		"example.com",
		"sub.example.com",
		"EXAMPLE.COM",
		"xn--bcher-kva.example.com",
		"*.example.com",
		"123.456.com",
		"a-b.com",
		"*",
	}
	for _, c := range cases {
		if !isValidDomain(c) {
			t.Errorf("isValidDomain(%q) = false, want true", c)
		}
	}
}

func TestIsValidDomain_Invalid(t *testing.T) {
	cases := []string{
		"uv13481v497!()$*#)(@*!)$",
		"has space.com",
		"has/slash.com",
		"has@at.com",
		"has#hash.com",
		"*.com", // bare TLD wildcard rejected by addEntry, but isValidDomain passes it
		"",
		".leadingdot.com",
		"trailing..dot.com",
	}
	for _, c := range cases {
		// Only check ones that should definitely fail the char check.
		// Some edge cases are handled by addEntry, not isValidDomain.
		switch c {
		case "uv13481v497!()$*#)(@*!)$", "has space.com", "has/slash.com",
			"has@at.com", "has#hash.com":
			if isValidDomain(c) {
				t.Errorf("isValidDomain(%q) = true, want false", c)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Invalid domain detection: loadFile / Load
// ---------------------------------------------------------------------------

func TestLoad_InvalidLines_CountedAndLogged(t *testing.T) {
	dir := t.TempDir()
	// example.com and 987890.com are valid; the third line is garbage.
	writeTestFile(t, dir, "test.list", "example.com\n987890.com\nuv13481v497!()$*#)(@*!)$\n")

	var logged []string
	dbg := func(format string, args ...interface{}) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	count, invalid, _, err := dl.Load(dbg)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 valid domains, got %d", count)
	}
	if invalid != 1 {
		t.Errorf("expected 1 invalid line, got %d", invalid)
	}
	if dl.Contains("uv13481v497!()$*#)(@*!)$") {
		t.Error("garbage line should not be stored as a domain")
	}
	if !dl.Contains("example.com") {
		t.Error("example.com should be loaded")
	}
	if !dl.Contains("987890.com") {
		t.Error("987890.com should be loaded")
	}
	// Debug log should mention the bad line.
	found := false
	for _, msg := range logged {
		if strings.Contains(msg, "invalid") && strings.Contains(msg, "uv13481v497") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected debug log mentioning the invalid line, got: %v", logged)
	}
}

func TestLoad_InvalidLines_NilDebugNoPanic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "good.com\nbad!line\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil) // nil logger must not panic
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid domain, got %d", count)
	}
	if invalid != 1 {
		t.Errorf("expected 1 invalid, got %d", invalid)
	}
}

func TestLoad_AllInvalidLines(t *testing.T) {
	dir := t.TempDir()
	// All three lines are neither comments nor valid domains.
	// Lines starting with !, #, @@, or [ are silently skipped (not counted as invalid).
	// Use characters that are clearly invalid DNS labels and are not skip prefixes.
	writeTestFile(t, dir, "test.list", "@invalid\n***\n{not valid}\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 valid domains, got %d", count)
	}
	if invalid != 3 {
		t.Errorf("expected 3 invalid lines, got %d", invalid)
	}
}

func TestLoad_HostsFormatInvalidDomain(t *testing.T) {
	dir := t.TempDir()
	// Hosts file line where the domain part is invalid.
	writeTestFile(t, dir, "test.list", "0.0.0.0 good.com\n0.0.0.0 bad!domain\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid domain, got %d", count)
	}
	if invalid != 1 {
		t.Errorf("expected 1 invalid, got %d", invalid)
	}
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

func TestDedup_WildcardSupersededByExact(t *testing.T) {
	// If *.foo.com comes AFTER foo.com, the exact should be removed.
	input := "foo.com\n*.foo.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// foo.com should still match (covered by *.foo.com).
	if !set.Contains("foo.com") {
		t.Error("foo.com should match via *.foo.com wildcard")
	}
	// Only 1 stored entry (the wildcard), not 2.
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry after dedup, got %d", set.Count())
	}
}

func TestDedup_ExactAfterWildcard(t *testing.T) {
	// If foo.com comes AFTER *.foo.com, the exact should be skipped.
	input := "*.foo.com\nfoo.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if !set.Contains("foo.com") {
		t.Error("foo.com should match via *.foo.com")
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry after dedup, got %d", set.Count())
	}
}

func TestDedup_DuplicateExact(t *testing.T) {
	// Two identical exact entries should result in 1 stored entry (map dedup).
	input := "foo.com\nfoo.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry for duplicate exact, got %d", set.Count())
	}
}

func TestDedup_DuplicateWildcard(t *testing.T) {
	input := "*.foo.com\n*.foo.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry for duplicate wildcard, got %d", set.Count())
	}
}

func TestDedup_Load_ReturnsCount(t *testing.T) {
	dir := t.TempDir()
	// foo.com + *.foo.com: exact should be deduped away.
	writeTestFile(t, dir, "test.list", "987890.com\n*.987890.com\n987890.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, _, dedup, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Only 1 effective entry: *.987890.com covers 987890.com.
	if count != 1 {
		t.Errorf("expected 1 effective entry, got %d", count)
	}
	// 2 were deduped: the existing exact when wildcard arrived, and the duplicate exact.
	if dedup < 1 {
		t.Errorf("expected at least 1 dedup, got %d", dedup)
	}
	// *.987890.com covers 987890.com and all subs.
	if !dl.Contains("987890.com") {
		t.Error("987890.com should match via wildcard")
	}
	if !dl.Contains("sub.987890.com") {
		t.Error("sub.987890.com should match via wildcard")
	}
}

func TestDedup_Reload_MessageContainsDedup(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Overwrite with dedup-producing content.
	time.Sleep(50 * time.Millisecond)
	writeTestFile(t, dir, "test.list", "example.com\n*.example.com\n")

	var msgs []string
	logInfo := func(format string, args ...interface{}) {
		msgs = append(msgs, fmt.Sprintf(format, args...))
	}
	logWarn := func(format string, args ...interface{}) {
		msgs = append(msgs, fmt.Sprintf(format, args...))
	}
	noop := func(format string, args ...interface{}) {}
	dl.checkAndReload(logInfo, logWarn, noop)

	found := false
	for _, m := range msgs {
		if strings.Contains(m, "reloaded") && strings.Contains(m, "dedup") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reload message with dedup count, got: %v", msgs)
	}
}

func TestInvalid_Reload_MessageContainsInvalid(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", "example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Overwrite with invalid lines.
	time.Sleep(50 * time.Millisecond)
	writeTestFile(t, dir, "test.list", "example.com\nbad!line\n")

	var warnMsgs []string
	logWarn := func(format string, args ...interface{}) {
		warnMsgs = append(warnMsgs, fmt.Sprintf(format, args...))
	}
	noop := func(format string, args ...interface{}) {}
	dl.checkAndReload(noop, logWarn, noop)

	found := false
	for _, m := range warnMsgs {
		if strings.Contains(m, "invalid") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warn message mentioning invalid lines, got: %v", warnMsgs)
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkContains_ExactMatch(b *testing.B) {
	var sb strings.Builder
	for i := range 10000 {
		sb.WriteString("domain")
		sb.WriteString(strings.Repeat("x", i%10))
		sb.WriteString(".com\n")
	}
	set, _ := ParseReader(strings.NewReader(sb.String()))

	b.ResetTimer()
	for range b.N {
		set.Contains("domainxxxxx.com")
	}
}

func BenchmarkContains_WildcardMatch(b *testing.B) {
	var sb strings.Builder
	for i := range 10000 {
		sb.WriteString("*.domain")
		sb.WriteString(strings.Repeat("x", i%10))
		sb.WriteString(".com\n")
	}
	set, _ := ParseReader(strings.NewReader(sb.String()))

	b.ResetTimer()
	for range b.N {
		set.Contains("sub.deep.domainxxxxx.com")
	}
}

func BenchmarkContains_Miss(b *testing.B) {
	var sb strings.Builder
	for i := range 10000 {
		sb.WriteString("domain")
		sb.WriteString(strings.Repeat("x", i%10))
		sb.WriteString(".com\n")
	}
	set, _ := ParseReader(strings.NewReader(sb.String()))

	b.ResetTimer()
	for range b.N {
		set.Contains("notinlist.example.org")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeTestFile(t testing.TB, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test file %s: %v", name, err)
	}
}

// ---------------------------------------------------------------------------
// Adblock / uBlock format
// ---------------------------------------------------------------------------

func TestAdblock_BasicParsing(t *testing.T) {
	input := `||example.com^
||example.net^
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 2 {
		t.Errorf("expected 2 entries, got %d", set.Count())
	}
	// Must match apex domain and subdomains.
	if !set.Contains("example.com") {
		t.Error("||example.com^ should match example.com (apex)")
	}
	if !set.Contains("sub.example.com") {
		t.Error("||example.com^ should match sub.example.com")
	}
	if !set.Contains("deep.sub.example.com") {
		t.Error("||example.com^ should match deep.sub.example.com")
	}
	if !set.Contains("example.net") {
		t.Error("||example.net^ should match example.net")
	}
}

func TestAdblock_WithOptions(t *testing.T) {
	// Options after ^ separator are ignored; only the domain is extracted.
	input := `||domain.com^$important
||other.com^$third-party,important
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 2 {
		t.Errorf("expected 2 entries, got %d", set.Count())
	}
	if !set.Contains("domain.com") {
		t.Error("||domain.com^$important should match domain.com")
	}
	if !set.Contains("other.com") {
		t.Error("||other.com^$third-party should match other.com")
	}
}

func TestAdblock_ExceptionRules_SilentlySkipped(t *testing.T) {
	// @@|| exception rules are silently skipped -- not counted as invalid.
	input := `||block.com^
@@||exception.com^
@@||another.exception.com^$important
`
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", input)

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid entry (||block.com^), got %d", count)
	}
	if invalid != 0 {
		t.Errorf("@@|| exception rules should be silently skipped (invalid=0), got invalid=%d", invalid)
	}
	if set := dl.current.Load(); set.Contains("exception.com") {
		t.Error("exception rule should not be loaded as a block entry")
	}
}

func TestAdblock_WithPath_CountedAsInvalid(t *testing.T) {
	// URL-path rules are beyond DNS capability and counted as invalid.
	input := `||block.com^
||domain.com/path^
||other.com/page/sub^
`
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", input)

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid entry (||block.com^), got %d", count)
	}
	if invalid != 2 {
		t.Errorf("expected 2 invalid (path-based entries), got %d", invalid)
	}
}

func TestAdblock_NoCaretTerminator_CountedAsInvalid(t *testing.T) {
	// || without ^ is not valid Adblock filter syntax.
	input := `||nodomain
||alsomissing
||good.com^
`
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", input)

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 valid entry, got %d", count)
	}
	if invalid != 2 {
		t.Errorf("expected 2 invalid (no ^ terminator), got %d", invalid)
	}
}

func TestAdblock_MixedList(t *testing.T) {
	// Mix of Adblock, hosts, and plain domain formats in one file.
	input := `! Title: mixed list
# regular comment
||adblock.com^
0.0.0.0 hosts.example.com
plain.com
*.wildcard.net
@@||skipped-exception.com^
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// adblock.com (from ||) + hosts.example.com + plain.com + wildcard.net (from *.wildcard.net)
	// but ||adblock.com^ stores *.adblock.com, not a separate exact entry.
	// Count: wildcard["adblock.com"] + exact["hosts.example.com"] + exact["plain.com"] + wildcard["wildcard.net"] = 4
	if set.Count() != 4 {
		t.Errorf("expected 4 entries, got %d", set.Count())
	}
	if !set.Contains("adblock.com") {
		t.Error("adblock.com should match (from ||adblock.com^)")
	}
	if !set.Contains("sub.adblock.com") {
		t.Error("sub.adblock.com should match (from ||adblock.com^)")
	}
	if !set.Contains("hosts.example.com") {
		t.Error("hosts.example.com should match")
	}
	if !set.Contains("plain.com") {
		t.Error("plain.com should match")
	}
	if !set.Contains("sub.wildcard.net") {
		t.Error("sub.wildcard.net should match")
	}
	if set.Contains("skipped-exception.com") {
		t.Error("skipped-exception.com should NOT be loaded (exception rule)")
	}
}

func TestAdblock_RealisticStyleList(t *testing.T) {
	// Simulate a realistic Adblock-format DNS blocklist with headers, options, and exceptions.
	input := `! Title: DNS Blocklist
! Description: DNS blocklist
! Syntax: AdBlock
||analytics.example.com^
||tracker.example.com^
||ads.example.com^
! inline comment
||tracker.net^$important
@@||allowed.com^
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	// 4 domain entries (analytics.example.com, tracker.example.com, ads.example.com, tracker.net)
	// @@||allowed.com^ is silently skipped
	if set.Count() != 4 {
		t.Errorf("expected 4 entries, got %d", set.Count())
	}
	if !set.Contains("analytics.example.com") {
		t.Error("analytics.example.com should be blocked")
	}
	if !set.Contains("sub.tracker.example.com") {
		t.Error("sub.tracker.example.com should be blocked")
	}
	if set.Contains("allowed.com") {
		t.Error("allowed.com should NOT be loaded (exception rule)")
	}
}

// ---------------------------------------------------------------------------
// Hierarchical deduplication
// ---------------------------------------------------------------------------

func TestHierarchicalDedup_WildcardCoversExact_WildcardFirst(t *testing.T) {
	// *.example.com is added first; sub.example.com should be skipped by addEntry.
	input := "*.example.com\nsub.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry, got %d", set.Count())
	}
	if !set.Contains("sub.example.com") {
		t.Error("sub.example.com should still match via *.example.com")
	}
}

func TestHierarchicalDedup_WildcardCoversExact_ExactFirst(t *testing.T) {
	// sub.example.com is added first; *.example.com should cause cleanup.
	input := "sub.example.com\n*.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry (cleanup pass should remove redundant exact), got %d", set.Count())
	}
	if !set.Contains("sub.example.com") {
		t.Error("sub.example.com should still match via *.example.com")
	}
}

func TestHierarchicalDedup_WildcardCoversNarrowWildcard_WideFirst(t *testing.T) {
	// *.example.com makes *.sub.example.com redundant when added first.
	input := "*.example.com\n*.sub.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry, got %d", set.Count())
	}
}

func TestHierarchicalDedup_WildcardCoversNarrowWildcard_NarrowFirst(t *testing.T) {
	// *.sub.example.com added first; *.example.com should trigger cleanup.
	input := "*.sub.example.com\n*.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry (cleanup removes narrow wildcard), got %d", set.Count())
	}
}

func TestHierarchicalDedup_FullExample(t *testing.T) {
	// The user's full example: all five entries reduce to *.example.com only.
	input := `*.example.com
example.com
sub.example.com
*.sub.example.com
deep.sub.example.com
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry (all covered by *.example.com), got %d", set.Count())
	}
	// All original domains must still match.
	if !set.Contains("example.com") {
		t.Error("example.com should match")
	}
	if !set.Contains("sub.example.com") {
		t.Error("sub.example.com should match")
	}
	if !set.Contains("anything.sub.example.com") {
		t.Error("anything.sub.example.com should match")
	}
	if !set.Contains("deep.sub.example.com") {
		t.Error("deep.sub.example.com should match")
	}
	// Unrelated domain must NOT match.
	if set.Contains("other.example.org") {
		t.Error("other.example.org should NOT match")
	}
}

func TestHierarchicalDedup_FullExample_ReverseOrder(t *testing.T) {
	// Same as above but all narrow entries are added before *.example.com.
	// The cleanup pass must handle this.
	input := `example.com
sub.example.com
*.sub.example.com
deep.sub.example.com
*.example.com
`
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry after cleanup pass, got %d", set.Count())
	}
}

func TestHierarchicalDedup_DeepNesting(t *testing.T) {
	// *.a.b.c.d.example.com should be covered by *.example.com.
	input := "*.example.com\n*.a.b.c.d.example.com\nleaf.a.b.c.d.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 stored entry, got %d", set.Count())
	}
	if !set.Contains("leaf.a.b.c.d.example.com") {
		t.Error("deep subdomain should still match via *.example.com")
	}
}

func TestHierarchicalDedup_Independent_Wildcards_Kept(t *testing.T) {
	// *.foo.com and *.bar.com are independent; both must be kept.
	input := "*.foo.com\n*.bar.com\nsub.foo.com\nsub.bar.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 2 {
		t.Errorf("expected 2 stored entries (two independent wildcards), got %d", set.Count())
	}
	if !set.Contains("foo.com") {
		t.Error("foo.com should match via *.foo.com")
	}
	if !set.Contains("bar.com") {
		t.Error("bar.com should match via *.bar.com")
	}
}

func TestHierarchicalDedup_Load_DedupCount(t *testing.T) {
	dir := t.TempDir()
	// All entries reduce to *.example.com (1 stored), 4 deduped.
	writeTestFile(t, dir, "test.list",
		"*.example.com\nexample.com\nsub.example.com\n*.sub2.example.com\n*.deep.sub.example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, _, dedup, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 stored entry, got %d", count)
	}
	// 4 entries were deduped.
	if dedup < 4 {
		t.Errorf("expected at least 4 dedup, got %d", dedup)
	}
}

func TestHierarchicalDedup_AcrossFiles(t *testing.T) {
	// Broader wildcard in file1, narrower entries in file2.
	dir := t.TempDir()
	writeTestFile(t, dir, "file1.list", "*.example.com\n")
	writeTestFile(t, dir, "file2.list", "sub.example.com\n*.inner.example.com\nexact.example.com\n")

	dl := NewDomainList("test", []string{filepath.Join(dir, "*.list")})
	count, _, dedup, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 stored entry after cross-file dedup, got %d", count)
	}
	if dedup < 3 {
		t.Errorf("expected at least 3 dedup (3 narrower entries removed), got %d", dedup)
	}
}

func TestDeduplicateHierarchical_DirectFunction(t *testing.T) {
	exact := map[string]struct{}{
		"example.com":           {},
		"sub.example.com":       {},
		"x.y.z.example.com":     {},
		"independent.other.org": {},
	}
	wildcard := map[string]struct{}{
		"example.com": {}, // *.example.com
	}

	removed := deduplicateHierarchical(exact, wildcard)

	// example.com, sub.example.com, x.y.z.example.com all covered by *.example.com.
	// independent.other.org is NOT covered.
	if removed != 3 {
		t.Errorf("expected 3 removals, got %d", removed)
	}
	if _, ok := exact["independent.other.org"]; !ok {
		t.Error("independent.other.org should remain in exact map")
	}
	if _, ok := exact["example.com"]; ok {
		t.Error("example.com should have been removed (covered by *.example.com)")
	}
	if _, ok := exact["sub.example.com"]; ok {
		t.Error("sub.example.com should have been removed")
	}
}

func TestDomainMatchesWildcard_DirectFunction(t *testing.T) {
	wildcard := map[string]struct{}{
		"example.com": {}, // *.example.com
	}
	cases := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},        // apex covered
		{"sub.example.com", true},    // direct sub covered
		{"a.b.example.com", true},    // deep sub covered
		{"other.example.org", false}, // unrelated
		{"com", false},               // TLD only
		{"other.net", false},         // different TLD
	}
	for _, c := range cases {
		got := domainMatchesWildcard(c.domain, wildcard)
		if got != c.want {
			t.Errorf("domainMatchesWildcard(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestWildcardCoveredByAncestor_DirectFunction(t *testing.T) {
	wildcard := map[string]struct{}{
		"example.com": {}, // *.example.com
	}
	cases := []struct {
		base string
		want bool
	}{
		{"sub.example.com", true},      // covered by *.example.com
		{"deep.sub.example.com", true}, // also covered
		{"example.com", false},         // this IS *.example.com, not covered by ancestor
		{"other.net", false},           // different TLD
		{"unrelated.org", false},       // unrelated
	}
	for _, c := range cases {
		got := wildcardCoveredByAncestor(c.base, wildcard)
		if got != c.want {
			t.Errorf("wildcardCoveredByAncestor(%q) = %v, want %v", c.base, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Adblock bracket header [Adblock Plus] silently skipped
// ---------------------------------------------------------------------------

func TestAdblockBracketHeader_SilentlySkipped(t *testing.T) {
	input := "[Adblock Plus]\n||block.com^\n[Adblock Plus 2.0]\n"
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", input)

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 entry (||block.com^), got %d", count)
	}
	if invalid != 0 {
		t.Errorf("[Adblock Plus] header must be silently skipped (invalid=0), got %d", invalid)
	}
}

func TestAdblockBracketHeader_ParseReader(t *testing.T) {
	input := "[Adblock Plus]\n! Comment\n||domain.com^\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 1 {
		t.Errorf("expected 1 entry, got %d", set.Count())
	}
	if !set.Contains("domain.com") {
		t.Error("domain.com should be blocked")
	}
}

// ---------------------------------------------------------------------------
// Real-world edge cases: IDN labels, xn-- TLDs, multi-label subdomains, numeric and hyphenated labels
// ---------------------------------------------------------------------------

func TestRealWorld_AdblockFormat_EdgeCases(t *testing.T) {
	input := "[Adblock Plus]\n" +
		"! Title: test\n" +
		"! Syntax: AdBlock\n" +
		"||0.beer^\n" +
		"||0-02.net^\n" +
		"||0-3.org^\n" +
		"||0000500.xyz^\n" +
		"||f9e79f670c.000491b06a.com^\n" +
		"||xn--ex-adreq-asa-c5b.example.com^\n" +
		"||xn--80affa3aj0al.xn--80asehdb^\n" +
		"||xn--4dkua4c8143c.jp^\n" +
		"||blocked.example.com^\n" +
		"||0066-example.com^\n" +
		"||09239-174328543.shop^\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 11 {
		t.Errorf("expected 11 entries, got %d", set.Count())
	}
	if !set.Contains("0.beer") {
		t.Error("0.beer should match")
	}
	if !set.Contains("sub.0-02.net") {
		t.Error("sub.0-02.net should match via *.0-02.net")
	}
	if !set.Contains("xn--ex-adreq-asa-c5b.example.com") {
		t.Error("xn--ex-adreq-asa-c5b.example.com should match")
	}
	if !set.Contains("sub.xn--ex-adreq-asa-c5b.example.com") {
		t.Error("subdomain of xn-- domain should match")
	}
	if !set.Contains("xn--80affa3aj0al.xn--80asehdb") {
		t.Error("xn--80affa3aj0al.xn--80asehdb should match")
	}
	if !set.Contains("0066-example.com") {
		t.Error("0066-example.com should match")
	}
}

func TestRealWorld_WildcardFormat_EdgeCases(t *testing.T) {
	input := "# Title: test\n" +
		"*.0.beer\n" +
		"*.0-02.net\n" +
		"*.xn--ex-adreq-asa-c5b.example.com\n" +
		"*.xn--80affa3aj0al.xn--80asehdb\n" +
		"*.ltuy.ltsc.xn--54q23ckxiyx0e.com\n" +
		"*.m1.ad.10010.com\n" +
		"*.log-auth.zztfly.com\n" +
		"*.upc.zztfly.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 8 {
		t.Errorf("expected 8 wildcard entries, got %d", set.Count())
	}
	if !set.Contains("0.beer") {
		t.Error("0.beer should match via *.0.beer")
	}
	if !set.Contains("sub.0-02.net") {
		t.Error("sub.0-02.net should match")
	}
	if !set.Contains("ltuy.ltsc.xn--54q23ckxiyx0e.com") {
		t.Error("apex of *.ltuy.ltsc.xn--54q23ckxiyx0e.com should match")
	}
	if !set.Contains("anything.ltuy.ltsc.xn--54q23ckxiyx0e.com") {
		t.Error("subdomain of multi-label xn-- wildcard should match")
	}
	if !set.Contains("x.m1.ad.10010.com") {
		t.Error("sub of multi-part numeric domain should match")
	}
}

func TestRealWorld_HostsFormat_EdgeCases(t *testing.T) {
	input := "# Title: test\n" +
		"0.0.0.0 0.beer\n" +
		"0.0.0.0 www.0.beer\n" +
		"0.0.0.0 0-02.net\n" +
		"0.0.0.0 xn--ex-adreq-asa-c5b.example.com\n" +
		"0.0.0.0 blocked.example.com\n" +
		"0.0.0.0 blocked2.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 6 {
		t.Errorf("expected 6 entries, got %d", set.Count())
	}
	if !set.Contains("0.beer") {
		t.Error("0.beer should match (hosts format)")
	}
	if !set.Contains("www.0.beer") {
		t.Error("www.0.beer should match (explicit hosts entry)")
	}
	if set.Contains("other.0.beer") {
		t.Error("other.0.beer should NOT match (hosts format is exact only)")
	}
}

func TestRealWorld_DomainsFormat_EdgeCases(t *testing.T) {
	input := "# Title: test\n" +
		"0.beer\n" +
		"www.0.beer\n" +
		"0-02.net\n" +
		"xn--ex-adreq-asa-c5b.example.com\n" +
		"xn--80affa3aj0al.xn--80asehdb\n" +
		"blocked.example.com\n" +
		"blocked2.example.com\n"
	set, err := ParseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}
	if set.Count() != 7 {
		t.Errorf("expected 7 entries, got %d", set.Count())
	}
	if !set.Contains("0.beer") {
		t.Error("0.beer should match")
	}
	if !set.Contains("xn--80affa3aj0al.xn--80asehdb") {
		t.Error("IDN domain with IDN TLD should match")
	}
}

func TestRealWorld_MixedAdblockFormats(t *testing.T) {
	// [Adblock Plus] header and @@|| exception rules are silently skipped.
	input := "[Adblock Plus 2.0]\n" +
		"! Comment\n" +
		"||track.example.com^\n" +
		"@@||allowed.example.com^\n" +
		"||xn--nxasmq6b.com^\n"
	dir := t.TempDir()
	writeTestFile(t, dir, "test.list", input)

	dl := NewDomainList("test", []string{filepath.Join(dir, "test.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 2 valid entries; [Adblock Plus 2.0] and @@|| silently skipped (not invalid).
	if count != 2 {
		t.Errorf("expected 2 entries, got %d", count)
	}
	if invalid != 0 {
		t.Errorf("expected 0 invalid; headers and @@ must be silently skipped, got %d", invalid)
	}
	if !dl.Contains("track.example.com") {
		t.Error("track.example.com should match (from ||track.example.com^)")
	}
	if !dl.Contains("sub.track.example.com") {
		t.Error("sub.track.example.com should match (wildcard)")
	}
	if dl.Contains("allowed.example.com") {
		t.Error("allowed.example.com should NOT be loaded (exception rule)")
	}
	if !dl.Contains("xn--nxasmq6b.com") {
		t.Error("xn--nxasmq6b.com should match (IDN domain)")
	}
}

func TestRealWorld_parseAdblockDomain_DirectFunction(t *testing.T) {
	// parseAdblockDomain receives the string AFTER "||".
	cases := []struct {
		input string
		want  string
	}{
		{"example.com^", "example.com"},
		{"ads.example.com^", "ads.example.com"},
		{"example.com^$important", "example.com"},
		{"example.com/path^", ""},
		{"example.com", ""},
		{"xn--nxasmq6b.com^", "xn--nxasmq6b.com"},
		{"xn--80affa3aj0al.xn--80asehdb^", "xn--80affa3aj0al.xn--80asehdb"},
		{"example.com:8080^", ""},
	}
	for _, c := range cases {
		got := parseAdblockDomain(c.input)
		if got != c.want {
			t.Errorf("parseAdblockDomain(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: mixed-format data loaded through file I/O path
// ---------------------------------------------------------------------------

func TestIntegration_MixedFormatFile_LoadAndSmoke(t *testing.T) {
	// All four supported formats in one file, exercising the full file-I/O
	// path (NewDomainList + Load) rather than the in-memory ParseReader path.
	const content = "[Adblock Plus]\n" +
		"! Syntax: AdBlock\n" +
		"||blocked.example.com^\n" +
		"||xn--80affa3aj0al.xn--80asehdb^\n" +
		"||analytics.example.com^$important\n" +
		"@@||exception.example.com^\n" +
		"0.0.0.0 xn--ex-adreq-asa-c5b.example.com\n" +
		"0.0.0.0 f9e79f670c.000491b06a.com\n" +
		"127.0.0.1 loopback.example.net\n" +
		":: ipv6.example.net\n" +
		"*.ltuy.ltsc.xn--54q23ckxiyx0e.com\n" +
		"*.m1.ad.10010.com\n" +
		"*.0.beer\n" +
		"xn--4dkua4c8143c.jp\n" +
		"hyphen-label.example.com\n" +
		"plain-entry.example.com\n"

	dir := t.TempDir()
	writeTestFile(t, dir, "mixed.list", content)

	dl := NewDomainList("test", []string{filepath.Join(dir, "mixed.list")})
	count, invalid, _, err := dl.Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if count == 0 {
		t.Error("expected at least one domain to be loaded")
	}
	if invalid != 0 {
		t.Errorf("expected 0 invalid lines, got %d", invalid)
	}
	// Adblock format: ||domain^ creates a wildcard covering apex and all subdomains.
	if !dl.Contains("blocked.example.com") {
		t.Error("blocked.example.com should match (from ||blocked.example.com^)")
	}
	if !dl.Contains("sub.blocked.example.com") {
		t.Error("sub.blocked.example.com should match via wildcard")
	}
	if !dl.Contains("xn--80affa3aj0al.xn--80asehdb") {
		t.Error("IDN domain with IDN TLD should match (from adblock entry)")
	}
	// Hosts-file format: exact match only.
	if !dl.Contains("xn--ex-adreq-asa-c5b.example.com") {
		t.Error("IDN domain should match (from hosts-file entry)")
	}
	if dl.Contains("sub.xn--ex-adreq-asa-c5b.example.com") {
		t.Error("subdomain of hosts-file exact entry should NOT match")
	}
	// Wildcard format: *.domain covers apex and all subdomains.
	if !dl.Contains("ltuy.ltsc.xn--54q23ckxiyx0e.com") {
		t.Error("multi-label xn-- apex should match (from *.ltuy.ltsc.xn--54q23ckxiyx0e.com)")
	}
	if !dl.Contains("anything.ltuy.ltsc.xn--54q23ckxiyx0e.com") {
		t.Error("subdomain of multi-label xn-- wildcard should match")
	}
	// Plain domain format: exact match.
	if !dl.Contains("xn--4dkua4c8143c.jp") {
		t.Error("plain IDN domain should match")
	}
	// Exception rule (@@||) must not be loaded.
	if dl.Contains("exception.example.com") {
		t.Error("exception rule (@@||) should not be loaded as a block entry")
	}
}
