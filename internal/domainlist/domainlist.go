// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package domainlist provides efficient domain matching for whitelist and
// blacklist features. It supports loading domains from files with glob
// patterns, automatic hot-reload via file modification detection, and
// thread-safe concurrent lookups using atomic pointer swaps.
//
// Supported domain entry formats:
//   - "example.com"       exact match only (subdomains NOT matched)
//   - "*.example.com"     matches example.com AND all subdomains
//   - "||example.com^"    Adblock/uBlock double-pipe: matches example.com AND all subdomains
//   - Lines starting with # or ! are comments
//   - Lines starting with [ (e.g. "[Adblock Plus]") are silently skipped
//   - Lines starting with @@ (Adblock exception rules) are silently skipped
//   - Hosts-file format auto-detected: "0.0.0.0 domain" or "127.0.0.1 domain"
//   - Empty lines are skipped
//   - IDN (internationalized) domains are converted to punycode (xn--)
//
// Deduplication:
//   - "*.foo.com" supersedes "foo.com" (wildcard already covers the apex)
//   - "*.example.com" supersedes any narrower wildcard like "*.sub.example.com"
//     and any exact entry like "sub.example.com" at any depth
//   - Deduplication runs hierarchically after all files are loaded
package domainlist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
)

// DomainSet is an immutable snapshot of domain entries optimized for fast
// concurrent lookups. It uses two maps:
//   - exact: domains that match only themselves (no subdomains)
//   - wildcard: domains where the entry AND all subdomains match
type DomainSet struct {
	exact    map[string]struct{}
	wildcard map[string]struct{}
	count    int
}

// EmptySet returns a DomainSet with no entries.
func EmptySet() *DomainSet {
	return &DomainSet{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	}
}

// Count returns the total number of domain entries in the set.
func (s *DomainSet) Count() int {
	return s.count
}

// Contains reports whether the given domain matches any entry in the set.
// The domain should be a fully-qualified or bare domain name (trailing dot
// is stripped automatically). Matching is case-insensitive.
//
// Matching rules:
//   - Exact entries match only the domain itself
//   - Wildcard entries (from "*.domain") match the base domain AND all subdomains
func (s *DomainSet) Contains(domain string) bool {
	if s == nil || s.count == 0 {
		return false
	}

	d := normalize(domain)
	if d == "" {
		return false
	}

	// Check exact match
	if _, ok := s.exact[d]; ok {
		return true
	}

	// Check wildcard: the domain itself or any parent domain in wildcard map
	return s.matchWildcard(d)
}

// matchWildcard walks up the domain hierarchy checking for wildcard matches.
func (s *DomainSet) matchWildcard(d string) bool {
	curr := d
	for {
		if _, ok := s.wildcard[curr]; ok {
			return true
		}
		idx := strings.IndexByte(curr, '.')
		if idx < 0 {
			return false
		}
		curr = curr[idx+1:]
	}
}

// normalize lowercases a domain and strips the trailing dot.
func normalize(domain string) string {
	d := strings.TrimSpace(strings.ToLower(domain))
	d = strings.TrimSuffix(d, ".")
	return d
}

// toASCII converts a domain that may contain Unicode to punycode (ACE form).
// If conversion fails, the input is returned as-is.
func toASCII(domain string) string {
	ace, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return domain
	}
	return ace
}

// ParseReader reads domain entries from r and returns a DomainSet.
// It auto-detects hosts-file format, plain domain format, and Adblock format.
func ParseReader(r io.Reader) (*DomainSet, error) {
	exact := make(map[string]struct{})
	wildcard := make(map[string]struct{})
	var dedup int

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, scannerBufSize), scannerBufSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		// Silently skip Adblock/AdGuard format headers ("[Adblock Plus]", etc.)
		// and exception rules ("@@||..."). Neither is applicable for DNS filtering.
		if line[0] == '[' || strings.HasPrefix(line, "@@") {
			continue
		}

		domain := extractDomain(line)
		if domain == "" {
			continue
		}

		addEntry(domain, exact, wildcard, &dedup)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan domain list: %w", err)
	}

	// Hierarchical dedup: remove entries covered by broader wildcards.
	dedup += deduplicateHierarchical(exact, wildcard)

	return &DomainSet{
		exact:    exact,
		wildcard: wildcard,
		count:    len(exact) + len(wildcard),
	}, nil
}

// extractDomain parses a single line and returns the domain entry,
// or an empty string when the line is not a recognised domain format.
// It handles hosts-file lines ("0.0.0.0 domain"), plain domain lines, and
// Adblock/uBlock double-pipe lines ("||domain.com^").
// The returned value passes isValidDomain before being returned.
func extractDomain(line string) string {
	// Adblock/uBlock double-pipe: ||domain.com^[options]
	// Returns *.domain.com so the wildcard covers the apex and all subdomains.
	if strings.HasPrefix(line, "||") {
		d := parseAdblockDomain(line[2:])
		if d == "" || !isValidDomain(d) {
			return ""
		}
		return "*." + d
	}

	// Handle inline comments (# after domain)
	if idx := strings.IndexByte(line, '#'); idx > 0 {
		line = strings.TrimSpace(line[:idx])
		if line == "" {
			return ""
		}
	}

	// Hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain"
	fields := strings.Fields(line)
	if len(fields) >= 2 && isHostsPrefix(fields[0]) {
		d := fields[1]
		if !isValidDomain(d) {
			return ""
		}
		return d
	}

	// Plain domain format (single field)
	if len(fields) == 1 {
		if !isValidDomain(fields[0]) {
			return ""
		}
		return fields[0]
	}

	// Unknown format - skip
	return ""
}

// parseAdblockDomain extracts the domain from the part after "||" in an
// Adblock-format line. It returns "" when the entry contains a URL path
// (beyond DNS capability) or is otherwise malformed.
func parseAdblockDomain(s string) string {
	idx := strings.IndexByte(s, '^')
	if idx < 0 {
		return ""
	}
	domain := s[:idx]
	// Reject path-based rules (URL filtering, not DNS filtering).
	if strings.ContainsAny(domain, "/:?") {
		return ""
	}
	return domain
}

// isHostsPrefix returns true if s is a hosts-file IP prefix.
func isHostsPrefix(s string) bool {
	return s == "0.0.0.0" || s == "127.0.0.1" || s == "::1" || s == "::"
}

// isValidDomain returns true when s looks like a syntactically plausible DNS
// label sequence. It accepts plain labels, ACE labels (xn--...), and the
// wildcard prefix "*.". It rejects anything containing non-DNS characters
// such as spaces, slashes, or punctuation other than hyphens and dots.
// It does NOT perform a network lookup; it is a cheap syntactic guard only.
func isValidDomain(s string) bool {
	if s == "*" {
		return true // global wildcard
	}
	// Strip wildcard prefix for label validation.
	check := s
	if strings.HasPrefix(check, "*.") {
		check = check[2:]
	}
	if check == "" {
		return false
	}
	for _, label := range strings.Split(check, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			// Allow ASCII letters, digits, hyphens, and any non-ASCII
			// rune (Unicode labels are later IDNA-converted).
			if r > 127 {
				continue
			}
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// addEntry normalizes and adds a domain entry to the exact or wildcard map.
// dedup is incremented when an entry is superseded by (or supersedes) a
// wildcard already in the maps. Returns true when an entry was stored.
// Note: full hierarchical deduplication (e.g. removing entries covered by
// a broader wildcard added later) is performed by deduplicateHierarchical.
func addEntry(entry string, exact, wildcard map[string]struct{}, dedup *int) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}

	// Wildcard entry: *.example.com
	if strings.HasPrefix(entry, "*.") {
		base := entry[2:]
		base = normalize(base)
		base = toASCII(base)
		if base == "" || !strings.Contains(base, ".") {
			return false
		}
		// Skip if a broader ancestor wildcard already covers this one.
		if wildcardCoveredByAncestor(base, wildcard) {
			*dedup++
			return false
		}
		// Remove same-level exact entry: *.foo.com covers foo.com.
		if _, had := exact[base]; had {
			delete(exact, base)
			*dedup++
		}
		wildcard[base] = struct{}{}
		return true
	}

	// Global wildcard.
	if entry == "*" {
		exact["*"] = struct{}{}
		return true
	}

	// Exact match entry.
	d := normalize(entry)
	d = toASCII(d)
	if d == "" {
		return false
	}
	// Skip if any wildcard in the map already covers this domain.
	if domainMatchesWildcard(d, wildcard) {
		*dedup++
		return false
	}
	exact[d] = struct{}{}
	return true
}

// domainMatchesWildcard reports whether domain is matched by any entry in
// the wildcard map. It walks up the label hierarchy: for "sub.example.com"
// it checks wildcard["sub.example.com"] (i.e. *.sub.example.com), then
// wildcard["example.com"] (i.e. *.example.com), then wildcard["com"].
// This mirrors DomainSet.matchWildcard and is used during deduplication.
func domainMatchesWildcard(domain string, wildcard map[string]struct{}) bool {
	curr := domain
	for {
		if _, ok := wildcard[curr]; ok {
			return true
		}
		idx := strings.IndexByte(curr, '.')
		if idx < 0 {
			return false
		}
		curr = curr[idx+1:]
	}
}

// wildcardCoveredByAncestor reports whether a wildcard entry with the given
// base is made redundant by a broader wildcard already in the map.
// For example, wildcard "sub.example.com" (i.e. *.sub.example.com)
// is covered if wildcard["example.com"] (i.e. *.example.com) exists.
func wildcardCoveredByAncestor(base string, wildcard map[string]struct{}) bool {
	idx := strings.IndexByte(base, '.')
	if idx < 0 {
		return false
	}
	return domainMatchesWildcard(base[idx+1:], wildcard)
}

// deduplicateHierarchical removes entries from exact and wildcard maps that
// are made redundant by a broader wildcard in the same maps. This handles
// cases where the broader wildcard was added after the narrower entries.
// Returns the number of entries removed.
// It must be called after all entries have been added to the maps.
func deduplicateHierarchical(exact, wildcard map[string]struct{}) int {
	dedup := 0
	// Remove exact entries covered by any wildcard at this level or above.
	for d := range exact {
		if domainMatchesWildcard(d, wildcard) {
			delete(exact, d)
			dedup++
		}
	}
	// Remove wildcard entries covered by a broader ancestor wildcard.
	for base := range wildcard {
		if wildcardCoveredByAncestor(base, wildcard) {
			delete(wildcard, base)
			dedup++
		}
	}
	return dedup
}

// fileState tracks modification time for change detection.
type fileState struct {
	path    string
	modTime time.Time
	size    int64
}

// DomainList is the thread-safe, reloadable wrapper around DomainSet.
// It provides concurrent-safe Contains() via an atomic pointer to the
// current DomainSet, and supports background reload with file change
// detection.
type DomainList struct {
	current  atomic.Pointer[DomainSet]
	patterns []string
	name     string // "whitelist" or "blacklist" for logging

	// Watcher state
	mu         sync.Mutex
	files      []fileState
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
}

// LogFunc is the signature for logging callbacks.
type LogFunc func(format string, args ...interface{})

// loadStats accumulates counters from a load/reload pass.
type loadStats struct {
	invalid int // lines that were syntactically unrecognised
	dedup   int // entries superseded by an existing wildcard (or vice versa)
}

// NewDomainList creates a new DomainList. It does not load any domains
// until Load() is called.
func NewDomainList(name string, patterns []string) *DomainList {
	dl := &DomainList{
		patterns: patterns,
		name:     name,
	}
	dl.current.Store(EmptySet())
	return dl
}

// Contains reports whether the domain matches any entry in the current set.
// This is safe for concurrent use from multiple goroutines.
func (dl *DomainList) Contains(domain string) bool {
	return dl.current.Load().Contains(domain)
}

// Count returns the current number of loaded domain entries.
func (dl *DomainList) Count() int {
	return dl.current.Load().Count()
}

// Load performs the initial load of domain files matching the configured
// glob patterns. logDebug may be nil. Returns the number of domains loaded,
// the number of invalid lines, the number of deduplicated entries, and any
// error.
func (dl *DomainList) Load(logDebug LogFunc) (count, invalid, dedup int, err error) {
	set, files, stats, err := dl.loadFromPatterns(logDebug)
	if err != nil {
		return 0, 0, 0, err
	}
	dl.current.Store(set)
	dl.mu.Lock()
	dl.files = files
	dl.mu.Unlock()
	return set.Count(), stats.invalid, stats.dedup, nil
}

// StartWatcher begins a background goroutine that checks for file changes
// every ttlSeconds and reloads the domain set if modifications are detected.
// logInfo and logWarn are called for informational and warning messages.
// logDebug is called for debug-level messages.
func (dl *DomainList) StartWatcher(ttlSeconds int, logInfo, logWarn, logDebug LogFunc) {
	if ttlSeconds <= 0 {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	dl.cancelFunc = cancel

	dl.wg.Add(1)
	go dl.watchLoop(ctx, time.Duration(ttlSeconds)*time.Second, logInfo, logWarn, logDebug)
}

// Stop cancels the background watcher and waits for it to finish.
func (dl *DomainList) Stop() {
	if dl.cancelFunc != nil {
		dl.cancelFunc()
		dl.wg.Wait()
	}
}

// watchLoop periodically checks for file changes and reloads if needed.
func (dl *DomainList) watchLoop(ctx context.Context, interval time.Duration, logInfo, logWarn, logDebug LogFunc) {
	defer dl.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dl.checkAndReload(logInfo, logWarn, logDebug)
		}
	}
}

// checkAndReload detects file changes and triggers a reload if needed.
func (dl *DomainList) checkAndReload(logInfo, logWarn, logDebug LogFunc) {
	changed, reason := dl.detectChanges()
	if !changed {
		logDebug("%s: no file changes detected", dl.name)
		return
	}

	logInfo("%s: file change detected (%s), reloading...", dl.name, reason)
	start := time.Now()

	set, files, stats, err := dl.loadFromPatterns(logDebug)
	if err != nil {
		logWarn("%s: reload failed: %v (keeping previous list)", dl.name, err)
		return
	}

	// Atomic swap - old set becomes garbage collected
	dl.current.Store(set)
	dl.mu.Lock()
	dl.files = files
	dl.mu.Unlock()

	elapsed := time.Since(start)
	msg := fmt.Sprintf("%s: reloaded %d domains", dl.name, set.Count())
	if stats.dedup > 0 {
		msg += fmt.Sprintf(" (%d dedup)", stats.dedup)
	}
	if stats.invalid > 0 {
		msg += fmt.Sprintf(", %d invalid", stats.invalid)
	}
	msg += fmt.Sprintf(" from %d files in %v", len(files), elapsed.Round(time.Millisecond))
	if stats.invalid > 0 {
		logWarn("%s", msg)
	} else {
		logInfo("%s", msg)
	}
}

// detectChanges checks if any files have been modified, added, or removed.
func (dl *DomainList) detectChanges() (changed bool, reason string) {
	dl.mu.Lock()
	oldFiles := dl.files
	dl.mu.Unlock()

	// Expand current glob patterns to get current file list
	currentPaths, err := expandGlobs(dl.patterns)
	if err != nil {
		return true, "glob error"
	}

	// Build map of old files for comparison
	oldMap := make(map[string]fileState, len(oldFiles))
	for _, f := range oldFiles {
		oldMap[f.path] = f
	}

	// Check for new or modified files
	currentMap := make(map[string]struct{}, len(currentPaths))
	for _, path := range currentPaths {
		currentMap[path] = struct{}{}
		info, err := os.Stat(path)
		if err != nil {
			return true, fmt.Sprintf("cannot stat %s", filepath.Base(path))
		}
		old, exists := oldMap[path]
		if !exists {
			return true, fmt.Sprintf("new file %s", filepath.Base(path))
		}
		if !info.ModTime().Equal(old.modTime) || info.Size() != old.size {
			return true, fmt.Sprintf("modified %s", filepath.Base(path))
		}
	}

	// Check for deleted files
	for _, f := range oldFiles {
		if _, exists := currentMap[f.path]; !exists {
			return true, fmt.Sprintf("deleted %s", filepath.Base(f.path))
		}
	}

	return false, ""
}

// loadFromPatterns expands glob patterns, reads all matching files, and
// builds a new DomainSet. Returns the set, the file states used for change
// detection, aggregated load statistics, and any error.
// logDebug may be nil.
func (dl *DomainList) loadFromPatterns(logDebug LogFunc) (*DomainSet, []fileState, loadStats, error) {
	paths, err := expandGlobs(dl.patterns)
	if err != nil {
		return nil, nil, loadStats{}, fmt.Errorf("expand glob patterns: %w", err)
	}

	if len(paths) == 0 {
		return EmptySet(), nil, loadStats{}, nil
	}

	exact := make(map[string]struct{})
	wildcard := make(map[string]struct{})
	var files []fileState
	var stats loadStats

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			// File may have been deleted between glob expansion and here.
			// Treat it as gone: skip it and continue loading the other files.
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, loadStats{}, fmt.Errorf("stat %s: %w", path, err)
		}

		fileInvalid, fileDedup, err := loadFile(path, exact, wildcard, logDebug)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, loadStats{}, fmt.Errorf("load %s: %w", path, err)
		}
		stats.invalid += fileInvalid
		stats.dedup += fileDedup

		files = append(files, fileState{
			path:    path,
			modTime: info.ModTime(),
			size:    info.Size(),
		})
	}

	// Hierarchical dedup: remove entries covered by any ancestor wildcard.
	// This handles cases where the broader wildcard was added after narrower
	// entries (across files or within the same file).
	stats.dedup += deduplicateHierarchical(exact, wildcard)

	set := &DomainSet{
		exact:    exact,
		wildcard: wildcard,
		count:    len(exact) + len(wildcard),
	}
	return set, files, stats, nil
}

// loadFile reads a single domain list file into the provided maps.
// Returns counts of invalid lines and deduplicated entries.
// logDebug may be nil; when non-nil each invalid line is logged with its
// line number and content.
func loadFile(path string, exact, wildcard map[string]struct{}, logDebug LogFunc) (invalid, dedup int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	base := filepath.Base(path)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, scannerBufSize), scannerBufSize)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		// Silently skip Adblock/AdGuard format headers ("[Adblock Plus]", etc.)
		// and exception rules ("@@||..."). Neither is applicable for DNS filtering.
		if line[0] == '[' || strings.HasPrefix(line, "@@") {
			continue
		}

		domain := extractDomain(line)
		if domain == "" {
			invalid++
			if logDebug != nil {
				logDebug("%s: line %d invalid, skipping: %q", base, lineNum, line)
			}
			continue
		}

		addEntry(domain, exact, wildcard, &dedup)
	}

	return invalid, dedup, scanner.Err()
}

// expandGlobs takes a list of glob patterns and returns all matching file
// paths, deduplicated and sorted.
func expandGlobs(patterns []string) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
		for _, m := range matches {
			// Only include regular files
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			abs, err := filepath.Abs(m)
			if err != nil {
				abs = m
			}
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				result = append(result, abs)
			}
		}
	}
	return result, nil
}

// LargeListThreshold is the number of domains above which a warning is logged.
const LargeListThreshold = 100000

// scannerBufSize is the maximum line length supported by the scanner.
// 1 MB is generous enough for any realistic domain list line.
const scannerBufSize = 1 << 20 // 1 MB
