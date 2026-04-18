// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package cache provides a concurrent-safe DNS response cache with TTL
// expiration and TTL-priority eviction for DNSieve.
// When capacity is reached, the entry with the earliest expiration time is
// evicted first (not least-recently-used). This avoids premature eviction of
// long-lived records while still bounding memory use.
package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
)

// Entry represents a single cached DNS response.
// Data holds the wire-format packed bytes for space efficiency and to
// guarantee deep copy independence when serving cached responses.
type Entry struct {
	Data       []byte // packed wire-format DNS message
	Blocked    bool
	DNSSEC     bool // true if this entry was cached from a DO=1 query
	ExpiresAt  time.Time
	InsertedAt time.Time
}

// IsExpired reports whether this entry has passed its TTL.
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Cache is a concurrent-safe DNS response cache.
type Cache struct {
	mu           sync.RWMutex
	entries      map[string]*Entry
	maxEntries   int
	blockedTTL   time.Duration
	minTTL       time.Duration
	renewPercent int      // % of TTL remaining that triggers background refresh (0 = disabled)
	refreshing   sync.Map // tracks keys with an in-flight background refresh

	// refreshFunc is called in a background goroutine when a nearly-expired
	// entry is served. The caller sets this after construction.
	refreshFunc func(query *dns.Msg)
}

// New creates a new cache with the given settings.
// renewPercent is the threshold (as percentage of total TTL remaining) that
// triggers a background refresh when a client requests the entry. Set to 0
// to disable proactive refresh. Valid range: 0-99.
func New(maxEntries int, blockedTTLSec, minTTLSec, renewPercent int) *Cache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if blockedTTLSec <= 0 {
		blockedTTLSec = 86400
	}
	if minTTLSec <= 0 {
		minTTLSec = 60
	}
	return &Cache{
		entries:      make(map[string]*Entry),
		maxEntries:   maxEntries,
		blockedTTL:   time.Duration(blockedTTLSec) * time.Second,
		minTTL:       time.Duration(minTTLSec) * time.Second,
		renewPercent: renewPercent,
	}
}

// SetRefreshFunc sets the callback invoked when a nearly-expired cache entry
// is served. The function is called in a new goroutine and should resolve
// the query and call Put with the fresh response.
func (c *Cache) SetRefreshFunc(fn func(query *dns.Msg)) {
	c.refreshFunc = fn
}

// cacheKey builds a canonical key from the DNS question section.
// Format: "lowername/qtype/qclass" or "lowername/qtype/qclass/DO" for
// DNSSEC-requesting queries (RFC 3225 DO bit cache segregation).
func cacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	qtype := dns.RRToType(q)
	var b strings.Builder
	b.WriteString(strings.ToLower(q.Header().Name))
	b.WriteByte('/')
	if s, ok := dns.TypeToString[qtype]; ok {
		b.WriteString(s)
	} else {
		fmt.Fprintf(&b, "TYPE%d", qtype)
	}
	b.WriteByte('/')
	if s, ok := dns.ClassToString[q.Header().Class]; ok {
		b.WriteString(s)
	} else {
		fmt.Fprintf(&b, "CLASS%d", q.Header().Class)
	}
	if hasDOBit(msg) {
		b.WriteString("/DO")
	}
	return b.String()
}

// hasDOBit checks whether the message has the DNSSEC OK (DO) bit set.
func hasDOBit(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if opt, ok := rr.(*dns.OPT); ok {
			return opt.Security()
		}
	}
	return false
}

// Get retrieves a cached response for the given query.
// Returns (nil, false) if not found or expired. When an entry's remaining
// TTL falls below renew_percent of its total TTL, a one-shot background
// refresh is triggered (deduplicated per key) while the current entry is
// returned. The second return value is true when a new background refresh
// goroutine was launched for this call.
// Refresh applies to both normal and blocked entries so that changes in
// block status (domain unblocked or newly blocked) are detected proactively
// rather than waiting for TTL expiry.
func (c *Cache) Get(query *dns.Msg) (*Entry, bool) {
	key := cacheKey(query)
	if key == "" {
		return nil, false
	}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if entry.IsExpired() {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}

	// Background refresh: trigger when remaining TTL falls below renewPercent.
	// Only one refresh goroutine is in flight per key at a time.
	// Both blocked and non-blocked entries are eligible so that upstream
	// block-status changes are reflected before the entry expires.
	var refreshTriggered bool
	if c.renewPercent > 0 && c.refreshFunc != nil {
		lastTTL := entry.ExpiresAt.Sub(entry.InsertedAt)
		remaining := time.Until(entry.ExpiresAt)
		threshold := lastTTL * time.Duration(c.renewPercent) / 100
		if remaining > 0 && remaining < threshold {
			refreshTriggered = c.triggerRefresh(key, query)
		}
	}

	return entry, refreshTriggered
}

// triggerRefresh launches a background refresh for key if none is already
// in flight. Returns true when a new goroutine was launched, false when a
// refresh was already in flight. It clones the query to avoid sharing the
// caller's pointer.
func (c *Cache) triggerRefresh(key string, query *dns.Msg) bool {
	if _, loaded := c.refreshing.LoadOrStore(key, struct{}{}); loaded {
		return false // refresh already in flight for this key
	}
	queryCopy := cloneMsg(query)
	if queryCopy == nil {
		c.refreshing.Delete(key)
		return false
	}
	go func() {
		defer c.refreshing.Delete(key)
		c.refreshFunc(queryCopy)
	}()
	return true
}

// Put stores a DNS response in the cache.
// The TTL is computed from the response records, clamped by config limits.
func (c *Cache) Put(query *dns.Msg, resp *dns.Msg, blocked bool) {
	key := cacheKey(query)
	if key == "" || resp == nil {
		return
	}

	ttl := c.computeTTL(resp, blocked)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.entries) >= c.maxEntries {
		c.evictOldest()
	}

	// Pack the response into wire-format bytes for independent storage.
	if err := resp.Pack(); err != nil {
		return // silently skip uncacheable messages
	}
	data := make([]byte, len(resp.Data))
	copy(data, resp.Data)

	c.entries[key] = &Entry{
		Data:       data,
		Blocked:    blocked,
		DNSSEC:     hasDOBit(query),
		ExpiresAt:  time.Now().Add(ttl),
		InsertedAt: time.Now(),
	}
}

// computeTTL determines the cache TTL for a response.
// For blocked responses, uses blockedTTL. For normal responses, respects the
// upstream DNS TTL but enforces a minimum floor (minTTL).
func (c *Cache) computeTTL(msg *dns.Msg, blocked bool) time.Duration {
	if blocked {
		return c.blockedTTL
	}

	// Extract minimum TTL from records (respect upstream TTL)
	var minRRTTL time.Duration
	found := false
	for _, rr := range msg.Answer {
		rrTTL := time.Duration(rr.Header().TTL) * time.Second
		if !found || rrTTL < minRRTTL {
			minRRTTL = rrTTL
			found = true
		}
	}
	for _, rr := range msg.Ns {
		rrTTL := time.Duration(rr.Header().TTL) * time.Second
		if !found || rrTTL < minRRTTL {
			minRRTTL = rrTTL
			found = true
		}
	}

	if !found {
		// No records with TTL; use minTTL as a reasonable fallback.
		return c.minTTL
	}

	// Enforce minimum TTL floor
	if minRRTTL < c.minTTL {
		return c.minTTL
	}
	return minRRTTL
}

// evictOldest removes the entry with the earliest expiration time (TTL-priority
// eviction). Expired entries are removed immediately when encountered.
// Must be called with c.mu held.
func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range c.entries {
		if v.IsExpired() {
			delete(c.entries, k)
			return
		}
		if first || v.ExpiresAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.ExpiresAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// Len returns the current number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Flush removes all entries from the cache and clears any pending refresh state.
func (c *Cache) Flush() {
	c.mu.Lock()
	c.entries = make(map[string]*Entry)
	c.mu.Unlock()
	// Clear in-flight refresh tracking so new refreshes can be triggered.
	c.refreshing.Clear()
}

// cloneMsg returns a deep copy of a DNS message by packing to wire format
// and unpacking into a fresh Msg. Returns nil if pack/unpack fails.
func cloneMsg(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}
	if err := m.Pack(); err != nil {
		return nil
	}
	clone := new(dns.Msg)
	clone.Data = make([]byte, len(m.Data))
	copy(clone.Data, m.Data)
	if err := clone.Unpack(); err != nil {
		return nil
	}
	return clone
}

// MakeCachedResponse creates a DNS response from a cached entry,
// adjusting the reply header to match the original query and updating
// TTLs to reflect time remaining. Each call returns an independent copy.
func MakeCachedResponse(query *dns.Msg, entry *Entry) *dns.Msg {
	// Unpack from stored wire bytes -- gives a fresh, independent message.
	resp := new(dns.Msg)
	resp.Data = make([]byte, len(entry.Data))
	copy(resp.Data, entry.Data)
	if err := resp.Unpack(); err != nil {
		return nil
	}

	resp.ID = query.ID
	resp.Question = query.Question

	// Adjust TTLs based on remaining cache time
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 0 {
		remaining = 0
	}
	remainingSec := uint32(remaining.Seconds())
	if remainingSec == 0 {
		remainingSec = 1
	}

	for _, rr := range resp.Answer {
		if rr.Header().TTL > remainingSec {
			rr.Header().TTL = remainingSec
		}
	}
	for _, rr := range resp.Ns {
		if rr.Header().TTL > remainingSec {
			rr.Header().TTL = remainingSec
		}
	}
	for _, rr := range resp.Extra {
		if rr.Header().TTL > remainingSec {
			rr.Header().TTL = remainingSec
		}
	}

	// Re-pack so resp.Data reflects all field changes (ID, TTLs, Question).
	// dns.Msg.WriteTo only calls Pack when len(Data)==0, so we must pack here
	// to ensure the wire bytes are consistent with the updated struct fields.
	if err := resp.Pack(); err != nil {
		return nil
	}

	return resp
}
