// SPDX-License-Identifier: MIT
package cache

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func makeQuery(name string, qtype uint16) *dns.Msg {
	return dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
}

func makeResp(query *dns.Msg, ttl uint32) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: ttl},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	return resp
}

func TestNew_Defaults(t *testing.T) {
	c := New(0, 0, 0, 0)
	if c.maxEntries != 10000 {
		t.Errorf("expected default maxEntries 10000, got %d", c.maxEntries)
	}
}

func TestNew_CustomValues(t *testing.T) {
	c := New(500, 3600, 5, 0)
	if c.maxEntries != 500 {
		t.Errorf("expected maxEntries 500, got %d", c.maxEntries)
	}
}

func TestPutGet_BasicRoundTrip(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("example.com", dns.TypeA)
	resp := makeResp(query, 300)

	c.Put(query, resp, false)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	if entry.Blocked {
		t.Error("entry should not be blocked")
	}
	cached := MakeCachedResponse(query, entry)
	if cached == nil || len(cached.Answer) != 1 {
		t.Error("cached msg should have 1 answer")
	}
}

func TestPutGet_BlockedEntry(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("malware.example.com", dns.TypeA)
	resp := makeResp(query, 300)

	c.Put(query, resp, true)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	if !entry.Blocked {
		t.Error("entry should be blocked")
	}
}

func TestPutGet_CaseSensitivity(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query1 := makeQuery("example.com", dns.TypeA)
	resp := makeResp(query1, 300)
	c.Put(query1, resp, false)

	query2 := makeQuery("EXAMPLE.COM", dns.TypeA)
	entry, _ := c.Get(query2)
	if entry == nil {
		t.Fatal("cache should be case-insensitive for domain names")
	}
}

func TestPutGet_DifferentTypes(t *testing.T) {
	c := New(100, 3600, 5, 0)

	queryA := makeQuery("example.com", dns.TypeA)
	respA := makeResp(queryA, 300)
	c.Put(queryA, respA, false)

	queryAAAA := makeQuery("example.com", dns.TypeAAAA)
	if entry, _ := c.Get(queryAAAA); entry != nil {
		t.Error("A and AAAA should have different cache keys")
	}
}

func TestGet_Miss(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("nonexistent.example.com", dns.TypeA)
	if entry, _ := c.Get(query); entry != nil {
		t.Error("expected cache miss")
	}
}

func TestGet_Expired(t *testing.T) {
	c := New(100, 1, 1, 0)

	query := makeQuery("example.com", dns.TypeA)
	resp := makeResp(query, 1)
	c.Put(query, resp, false)

	time.Sleep(1200 * time.Millisecond)

	entry, _ := c.Get(query)
	if entry != nil {
		t.Error("expired entry should return nil")
	}
}

func TestPut_EmptyQuery(t *testing.T) {
	c := New(100, 3600, 5, 0)

	empty := &dns.Msg{}
	resp := &dns.Msg{}
	c.Put(empty, resp, false)

	if c.Len() != 0 {
		t.Error("empty query should not be cached")
	}
}

func TestPut_NilResponse(t *testing.T) {
	c := New(100, 3600, 5, 0)
	query := makeQuery("example.com", dns.TypeA)
	c.Put(query, nil, false)

	if c.Len() != 0 {
		t.Error("nil response should not be cached")
	}
}

func TestPut_Eviction(t *testing.T) {
	c := New(3, 86400, 10, 0)

	for i := 0; i < 5; i++ {
		query := makeQuery(fmt.Sprintf("test%d.example.com", i), dns.TypeA)
		resp := makeResp(query, 300)
		c.Put(query, resp, false)
	}

	if c.Len() > 3 {
		t.Errorf("cache should have at most 3 entries, got %d", c.Len())
	}
}

func TestFlush(t *testing.T) {
	c := New(100, 3600, 5, 0)

	for i := 0; i < 10; i++ {
		query := makeQuery(fmt.Sprintf("test%d.example.com", i), dns.TypeA)
		resp := makeResp(query, 300)
		c.Put(query, resp, false)
	}

	if c.Len() != 10 {
		t.Errorf("expected 10 entries, got %d", c.Len())
	}

	c.Flush()

	if c.Len() != 0 {
		t.Errorf("expected 0 entries after flush, got %d", c.Len())
	}
}

func TestPut_Overwrite(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("example.com", dns.TypeA)
	resp1 := makeResp(query, 100)
	c.Put(query, resp1, false)

	resp2 := makeResp(query, 500)
	c.Put(query, resp2, true)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	if !entry.Blocked {
		t.Error("overwritten entry should be blocked")
	}
}

func TestPut_DeepCopy(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("example.com", dns.TypeA)
	resp := makeResp(query, 300)
	c.Put(query, resp, false)

	// Modify the original response (change IP via the embedded rdata field)
	resp.Answer[0].(*dns.A).A = rdata.A{Addr: netip.MustParseAddr("1.1.1.1")}

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cache hit")
	}
	cached := MakeCachedResponse(query, entry)
	if cached == nil {
		t.Fatal("MakeCachedResponse returned nil")
	}
	a := cached.Answer[0].(*dns.A)
	if a.Addr == netip.MustParseAddr("1.1.1.1") {
		t.Error("cache should store a deep copy, not a reference")
	}
}

func TestMakeCachedResponse(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("example.com", dns.TypeA)
	resp := makeResp(query, 300)
	c.Put(query, resp, false)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cache hit")
	}

	newQuery := makeQuery("example.com", dns.TypeA)
	newQuery.ID = 12345

	cachedResp := MakeCachedResponse(newQuery, entry)
	if cachedResp == nil {
		t.Fatal("MakeCachedResponse returned nil")
	}
	if cachedResp.ID != 12345 {
		t.Errorf("cached response should use new query ID, got %d", cachedResp.ID)
	}
}

func TestMakeCachedResponse_TTLDecrement(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("ttl.example.com", dns.TypeA)
	resp := makeResp(query, 300)
	c.Put(query, resp, false)

	// Wait a moment to allow some time to elapse.
	time.Sleep(1100 * time.Millisecond)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("entry should still be present after 1s")
	}

	cached := MakeCachedResponse(query, entry)
	if cached == nil {
		t.Fatal("MakeCachedResponse returned nil")
	}
	if len(cached.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
	ttl := cached.Answer[0].Header().TTL
	if ttl >= 300 {
		t.Errorf("expected TTL < 300 after 1s elapsed, got %d", ttl)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(100, 3600, 5, 0)
	done := make(chan struct{})

	for i := 0; i < 10; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				query := makeQuery(fmt.Sprintf("test%d-%d.example.com", n, j), dns.TypeA)
				resp := makeResp(query, 300)
				c.Put(query, resp, false)
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				query := makeQuery(fmt.Sprintf("test%d-%d.example.com", n, j), dns.TypeA)
				c.Get(query)
			}
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestMakeCachedResponse_WireFormatIDMatchesQuery verifies that the packed
// wire bytes in a cached response carry the new query's ID, not the original
// cached ID. This is critical because dns.Msg.WriteTo only calls Pack when
// len(Data)==0, so MakeCachedResponse must explicitly re-pack after updating
// the ID.
func TestMakeCachedResponse_WireFormatIDMatchesQuery(t *testing.T) {
	c := New(100, 3600, 5, 0)

	// Store a response under query ID 1111.
	q1 := makeQuery("example.com", dns.TypeA)
	q1.ID = 1111
	resp := makeResp(q1, 300)
	resp.ID = 1111
	c.Put(q1, resp, false)

	entry, _ := c.Get(q1)
	if entry == nil {
		t.Fatal("expected cache hit")
	}

	// Retrieve with a different query ID.
	q2 := makeQuery("example.com", dns.TypeA)
	q2.ID = 2222

	cached := MakeCachedResponse(q2, entry)
	if cached == nil {
		t.Fatal("MakeCachedResponse returned nil")
	}

	// Struct field must be updated.
	if cached.ID != 2222 {
		t.Errorf("struct ID = %d, want 2222", cached.ID)
	}

	// Wire-format ID must also be updated (verifies Pack was called).
	if len(cached.Data) == 0 {
		t.Fatal("expected non-empty Data after MakeCachedResponse")
	}
	wire := new(dns.Msg)
	wire.Data = make([]byte, len(cached.Data))
	copy(wire.Data, cached.Data)
	if err := wire.Unpack(); err != nil {
		t.Fatalf("Unpack cached Data: %v", err)
	}
	if wire.ID != 2222 {
		t.Errorf("wire-format ID = %d, want 2222 (WriteTo would send wrong ID)", wire.ID)
	}
}

// =============================================================================
// Background refresh tests
// =============================================================================

func TestNew_RenewPercent_Stored(t *testing.T) {
	c := New(100, 3600, 5, 10)
	if c.renewPercent != 10 {
		t.Errorf("expected renewPercent=10, got %d", c.renewPercent)
	}
	c2 := New(100, 3600, 5, 0)
	if c2.renewPercent != 0 {
		t.Errorf("expected renewPercent=0, got %d", c2.renewPercent)
	}
}

func TestGet_RefreshNotTriggeredWhenDisabled(t *testing.T) {
	c := New(100, 3600, 5, 0) // renewPercent=0 disables refresh

	var called bool
	c.SetRefreshFunc(func(_ *dns.Msg) { called = true })

	// Insert with very short TTL so it's within any threshold
	query := makeQuery("test.example.com", dns.TypeA)
	resp := makeResp(query, 1)
	c.Put(query, resp, false)

	c.Get(query)
	// Give goroutine time to potentially run (it should not)
	time.Sleep(50 * time.Millisecond)

	if called {
		t.Error("refresh func should not be called when renewPercent=0")
	}
}

func TestGet_RefreshTriggeredForBlockedEntry(t *testing.T) {
	// Blocked entries must also trigger background refresh so that upstream
	// block-status changes (domain unblocked or newly blocked) are detected
	// proactively rather than waiting for TTL expiry.
	// blockedTTL=1s, renewPercent=90 => threshold=0.9s.
	// After 0.95s sleep only ~0.05s remains, which is < threshold.
	c := New(100, 1, 1, 90)

	triggered := make(chan struct{}, 1)
	c.SetRefreshFunc(func(_ *dns.Msg) {
		select {
		case triggered <- struct{}{}:
		default:
		}
	})

	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := makeResp(query, 300)
	c.Put(query, resp, true) // blocked=true; TTL comes from blockedTTL=1s

	time.Sleep(950 * time.Millisecond) // ~0.05s remaining, below 0.9s threshold
	c.Get(query)

	select {
	case <-triggered:
		// Good: blocked entry triggered background refresh
	case <-time.After(500 * time.Millisecond):
		t.Error("expected refresh to be triggered for blocked entry")
	}
}

func TestGet_RefreshBoolReturnValues(t *testing.T) {
	// Verify that the second return value of Get correctly signals whether a
	// new background refresh goroutine was launched.
	c := New(100, 3600, 1, 90) // renewPercent=90, min_ttl=1s

	done := make(chan struct{}, 2)
	c.SetRefreshFunc(func(_ *dns.Msg) { done <- struct{}{} })

	query := makeQuery("bool-check.example.com", dns.TypeA)
	resp := makeResp(query, 2) // 2s TTL, threshold = 1.8s
	c.Put(query, resp, false)

	// Immediately after insertion: well above threshold, no refresh.
	_, triggered := c.Get(query)
	if triggered {
		t.Error("expected false when entry is fresh (above threshold)")
	}

	// Past threshold: should return true.
	time.Sleep(1900 * time.Millisecond)
	_, triggered = c.Get(query)
	if !triggered {
		t.Error("expected true when refresh was launched")
	}
	<-done // drain goroutine
}

func TestGet_RefreshAlreadyInFlightReturnsFalse(t *testing.T) {
	// When a refresh is already in flight for a key, subsequent Gets must
	// return false (not launch a second goroutine).
	c := New(100, 3600, 1, 99)

	blocker := make(chan struct{})
	c.SetRefreshFunc(func(_ *dns.Msg) { <-blocker })

	query := makeQuery("inflight.example.com", dns.TypeA)
	resp := makeResp(query, 1)
	c.Put(query, resp, false)
	time.Sleep(600 * time.Millisecond) // past threshold

	// First Get launches the goroutine.
	_, first := c.Get(query)
	if !first {
		t.Error("expected true for first refresh trigger")
	}

	// Second Get: refresh already in flight, must return false.
	_, second := c.Get(query)
	if second {
		t.Error("expected false when refresh is already in-flight")
	}

	close(blocker)
	time.Sleep(50 * time.Millisecond)
}

func TestGet_RefreshTriggeredAtThreshold(t *testing.T) {
	// Use a 2s TTL entry and renewPercent=90 so the threshold is 1.8s.
	// We sleep 1.9s, meaning ~0.1s remaining < 1.8s threshold.
	c := New(100, 3600, 5, 90)

	triggered := make(chan struct{}, 1)
	c.SetRefreshFunc(func(_ *dns.Msg) {
		select {
		case triggered <- struct{}{}:
		default:
		}
	})

	query := makeQuery("threshold.example.com", dns.TypeA)
	resp := makeResp(query, 2)
	c.Put(query, resp, false)

	time.Sleep(1900 * time.Millisecond) // 0.1s remaining, should be below 90% threshold

	c.Get(query)

	select {
	case <-triggered:
		// Good: refresh was triggered
	case <-time.After(500 * time.Millisecond):
		t.Error("expected refresh to be triggered within 500ms")
	}
}

func TestGet_RefreshNotTriggeredWhenAboveThreshold(t *testing.T) {
	// Use a long TTL and small renewPercent so the threshold is far away.
	c := New(100, 3600, 5, 10) // 10% of 300s = 30s threshold

	var called bool
	c.SetRefreshFunc(func(_ *dns.Msg) { called = true })

	query := makeQuery("above.example.com", dns.TypeA)
	resp := makeResp(query, 300) // 300s TTL, 30s threshold
	c.Put(query, resp, false)

	c.Get(query) // well above threshold, no refresh
	time.Sleep(50 * time.Millisecond)

	if called {
		t.Error("refresh func should not be called when well above threshold")
	}
}

func TestGet_RefreshDeduplication(t *testing.T) {
	// Multiple concurrent Gets should only trigger one refresh goroutine.
	c := New(100, 3600, 5, 99)

	callCount := make(chan struct{}, 100)
	slowRefresh := make(chan struct{})
	c.SetRefreshFunc(func(_ *dns.Msg) {
		callCount <- struct{}{}
		<-slowRefresh // block until test unblocks
	})

	query := makeQuery("dedup.example.com", dns.TypeA)
	resp := makeResp(query, 1)
	c.Put(query, resp, false)
	time.Sleep(600 * time.Millisecond) // let entry get close to expiry

	// Fire multiple concurrent Gets
	for i := 0; i < 10; i++ {
		c.Get(query)
	}
	// Allow first goroutine to start
	time.Sleep(50 * time.Millisecond)
	close(slowRefresh) // unblock all

	// Wait for goroutines to drain
	time.Sleep(100 * time.Millisecond)

	n := len(callCount)
	if n != 1 {
		t.Errorf("expected exactly 1 refresh call (deduplication), got %d", n)
	}
}

func TestGet_RefreshRetriggeredAfterCompletion(t *testing.T) {
	// After one refresh completes, the next eligible Get should trigger again.
	c := New(100, 3600, 5, 99)

	callCount := 0
	done := make(chan struct{}, 10)
	c.SetRefreshFunc(func(_ *dns.Msg) {
		callCount++
		done <- struct{}{}
	})

	query := makeQuery("retrigger.example.com", dns.TypeA)
	resp := makeResp(query, 1)
	c.Put(query, resp, false)
	time.Sleep(600 * time.Millisecond)

	// First trigger
	c.Get(query)
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first refresh did not complete")
	}

	// Wait a bit then trigger again (entry hasn't expired yet, still near threshold)
	time.Sleep(10 * time.Millisecond)
	c.Get(query)
	select {
	case <-done:
		if callCount != 2 {
			t.Errorf("expected 2 refresh calls after re-trigger, got %d", callCount)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("second refresh did not complete")
	}
}

func TestGet_RefreshNonCacheableKeepsOldEntry(t *testing.T) {
	// When the refresh func does NOT call Put (simulating non-cacheable result),
	// the old cache entry should remain valid.
	c := New(100, 3600, 5, 99)

	query := makeQuery("noncacheable.example.com", dns.TypeA)
	resp := makeResp(query, 2)
	c.Put(query, resp, false)

	// Refresh func does nothing (simulates non-cacheable upstream response)
	done := make(chan struct{}, 1)
	c.SetRefreshFunc(func(_ *dns.Msg) {
		done <- struct{}{}
		// deliberately does NOT call c.Put
	})

	time.Sleep(1800 * time.Millisecond) // get close to boundary

	entry, _ := c.Get(query) // should trigger refresh but keep old entry
	if entry == nil {
		t.Fatal("old cache entry should still be valid while refresh is pending")
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("refresh func not called")
	}
	time.Sleep(50 * time.Millisecond)

	// Old entry still there (refresh didn't update it)
	entry2, _ := c.Get(query)
	if entry2 == nil {
		t.Error("old entry should remain after non-cacheable refresh")
	}
}

func TestGet_RefreshSuccessUpdatesEntry(t *testing.T) {
	// When the refresh func calls Put with a longer TTL, the new entry is served.
	c := New(100, 3600, 5, 99)

	query := makeQuery("refresh-success.example.com", dns.TypeA)
	oldResp := makeResp(query, 2)
	c.Put(query, oldResp, false)

	done := make(chan struct{}, 1)
	c.SetRefreshFunc(func(q *dns.Msg) {
		newResp := makeResp(q, 300) // fresh long TTL
		c.Put(q, newResp, false)
		done <- struct{}{}
	})

	time.Sleep(1800 * time.Millisecond)
	c.Get(query) // triggers refresh

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("refresh func not called")
	}
	time.Sleep(50 * time.Millisecond)

	// New entry should have longer TTL remaining
	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("entry should exist after successful refresh")
	}
	remaining := time.Until(entry.ExpiresAt)
	if remaining < 250*time.Second {
		t.Errorf("expected refreshed entry to have ~300s TTL, remaining=%s", remaining)
	}
}

func TestFlush_ClearsRefreshingState(t *testing.T) {
	c := New(100, 3600, 5, 99)

	// Simulate a key being in refreshing state
	c.refreshing.Store("example.com./A/IN", struct{}{})

	// Verify it's tracked
	_, tracked := c.refreshing.Load("example.com./A/IN")
	if !tracked {
		t.Fatal("expected key to be tracked before flush")
	}

	c.Flush()

	// After flush, refreshing state should be cleared
	_, tracked = c.refreshing.Load("example.com./A/IN")
	if tracked {
		t.Error("refreshing state should be cleared after Flush")
	}
}

func TestCloneMsg_RoundTrip(t *testing.T) {
	original := makeQuery("clone.example.com", dns.TypeA)
	clone := cloneMsg(original)
	if clone == nil {
		t.Fatal("cloneMsg returned nil")
	}
	if clone == original {
		t.Fatal("cloneMsg returned same pointer")
	}
	if len(clone.Question) == 0 {
		t.Fatal("cloned message has no questions")
	}
	if clone.Question[0].Header().Name != original.Question[0].Header().Name {
		t.Error("cloned message has wrong question name")
	}
}

func TestCloneMsg_nil(t *testing.T) {
	if cloneMsg(nil) != nil {
		t.Error("cloneMsg(nil) should return nil")
	}
}

// TestCacheKey_DOBitSegregation verifies that queries with the DO (DNSSEC OK)
// bit set are stored under a different cache key than the same query without
// DO=1. This is required by RFC 3225 and prevents a DO=0 client from reading
// a cached DNSSEC-signed response that was fetched on behalf of a DO=1 client.
func TestCacheKey_DOBitSegregation(t *testing.T) {
	c := New(100, 3600, 5, 0)

	queryNoDO := makeQuery("dnssec.example.com", dns.TypeA)
	respNoDO := makeResp(queryNoDO, 300)
	c.Put(queryNoDO, respNoDO, false)

	// Build the same query but with DO=1.
	queryDO := makeQuery("dnssec.example.com", dns.TypeA)
	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.SetUDPSize(4096)
	opt.SetSecurity(true)
	queryDO.Pseudo = append(queryDO.Pseudo, opt)

	// DO=1 query must not hit the DO=0 cache entry.
	if entry, _ := c.Get(queryDO); entry != nil {
		t.Error("DO=1 query must not get a cache hit from a DO=0 entry")
	}

	// Cache a response for the DO=1 query and verify DO=0 still gets its own entry.
	respDO := makeResp(queryDO, 300)
	c.Put(queryDO, respDO, false)

	if c.Len() != 2 {
		t.Errorf("expected 2 separate cache entries (DO=0 and DO=1), got %d", c.Len())
	}

	// DO=0 query still returns the DO=0 entry.
	if entry, _ := c.Get(queryNoDO); entry == nil {
		t.Error("DO=0 query should still return the DO=0 cache entry")
	}
}

// =============================================================================
// F-01: Cache key collision tests for unknown RR types/classes
// =============================================================================

// TestCacheKey_UnknownTypesAreDistinct verifies that two queries with different
// unknown RR types produce distinct cache keys and do not collide.
func TestCacheKey_UnknownTypesAreDistinct(t *testing.T) {
	c := New(100, 3600, 5, 0)

	// Use two different unknown type numbers -- must construct manually
	// since dnsutil.SetQuestion returns nil for unknown types.
	q1 := new(dns.Msg)
	q1.ID = dns.ID()
	q1.RecursionDesired = true
	q1.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: "unknown.example.com.", Class: dns.ClassINET},
		RFC3597: rdata.RFC3597{RRType: 65534},
	}}

	q2 := new(dns.Msg)
	q2.ID = dns.ID()
	q2.RecursionDesired = true
	q2.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: "unknown.example.com.", Class: dns.ClassINET},
		RFC3597: rdata.RFC3597{RRType: 65533},
	}}

	resp1 := new(dns.Msg)
	dnsutil.SetReply(resp1, q1)
	c.Put(q1, resp1, false)

	// q2 should miss; it must not collide with q1.
	if entry, _ := c.Get(q2); entry != nil {
		t.Error("different unknown types must not share cache entries")
	}

	resp2 := new(dns.Msg)
	dnsutil.SetReply(resp2, q2)
	c.Put(q2, resp2, false)

	if c.Len() != 2 {
		t.Errorf("expected 2 entries for distinct unknown types, got %d", c.Len())
	}
}

// TestCacheKey_UnknownClassesAreDistinct verifies that unknown DNS classes
// produce distinct cache keys.
func TestCacheKey_UnknownClassesAreDistinct(t *testing.T) {
	c := New(100, 3600, 5, 0)

	q1 := new(dns.Msg)
	q1.ID = 1
	q1.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: "classtest.example.com.", Class: 65534},
		RFC3597: rdata.RFC3597{RRType: dns.TypeA},
	}}

	q2 := new(dns.Msg)
	q2.ID = 2
	q2.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: "classtest.example.com.", Class: 65533},
		RFC3597: rdata.RFC3597{RRType: dns.TypeA},
	}}

	resp1 := new(dns.Msg)
	dnsutil.SetReply(resp1, q1)
	c.Put(q1, resp1, false)

	if entry, _ := c.Get(q2); entry != nil {
		t.Error("different unknown classes must not share cache entries")
	}
}

// TestCacheKey_KnownVsUnknownType verifies that a known type like A (1) and
// an unknown type produce separate cache keys with non-empty type components.
func TestCacheKey_KnownVsUnknownType(t *testing.T) {
	c := New(100, 3600, 5, 0)

	qKnown := makeQuery("mixed.example.com", dns.TypeA)
	qUnknown := new(dns.Msg)
	qUnknown.ID = dns.ID()
	qUnknown.RecursionDesired = true
	qUnknown.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: "mixed.example.com.", Class: dns.ClassINET},
		RFC3597: rdata.RFC3597{RRType: 65500},
	}}

	resp := makeResp(qKnown, 300)
	c.Put(qKnown, resp, false)

	if entry, _ := c.Get(qUnknown); entry != nil {
		t.Error("known vs unknown type must not share cache entries")
	}
}

// TestCache_GetPut_UnknownTypeNoCollision is a round-trip test storing and
// retrieving entries with unknown RR types.
func makeUnknownQuery(name string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.ID = dns.ID()
	q.RecursionDesired = true
	q.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET},
		RFC3597: rdata.RFC3597{RRType: qtype},
	}}
	return q
}

func TestCache_GetPut_UnknownTypeNoCollision(t *testing.T) {
	c := New(100, 3600, 5, 0)

	for _, qtype := range []uint16{65534, 65533, 65000, 64000} {
		q := makeUnknownQuery("rr-test.example.com", qtype)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, q)
		c.Put(q, resp, false)
	}

	if c.Len() != 4 {
		t.Errorf("expected 4 entries for 4 distinct unknown types, got %d", c.Len())
	}

	for _, qtype := range []uint16{65534, 65533, 65000, 64000} {
		q := makeUnknownQuery("rr-test.example.com", qtype)
		if entry, _ := c.Get(q); entry == nil {
			t.Errorf("cache miss for unknown type %d", qtype)
		}
	}
}

// =============================================================================
// F-07: Negative caching TTL tests
// =============================================================================

// TestComputeTTL_NXDOMAINWithSOA verifies that NXDOMAIN responses with SOA
// records use the SOA TTL for cache duration.
func TestComputeTTL_NXDOMAINWithSOA(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("nxdomain.example.com", dns.TypeA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeNameError
	resp.Ns = append(resp.Ns, &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
	})

	ttl := c.computeTTL(resp, false)
	if ttl < 5*time.Second {
		t.Errorf("expected TTL >= minTTL for NXDOMAIN with SOA, got %v", ttl)
	}
	// SOA TTL is 900s, should be used as basis.
	if ttl > 901*time.Second {
		t.Errorf("expected TTL <= 901s from SOA, got %v", ttl)
	}
}

// TestComputeTTL_NoRecords verifies fallback to minTTL when no records present.
func TestComputeTTL_NoRecords(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("nodata.example.com", dns.TypeA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)

	ttl := c.computeTTL(resp, false)
	if ttl != 5*time.Second {
		t.Errorf("expected minTTL fallback (5s) for no-record response, got %v", ttl)
	}
}

// TestComputeTTL_Blocked verifies blocked responses use blockedTTL.
func TestComputeTTL_Blocked(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := makeResp(query, 300)

	ttl := c.computeTTL(resp, true)
	if ttl != 3600*time.Second {
		t.Errorf("expected blockedTTL (3600s) for blocked resp, got %v", ttl)
	}
}

// TestComputeTTL_MinTTLFloor verifies that minTTL floor is enforced.
func TestComputeTTL_MinTTLFloor(t *testing.T) {
	c := New(100, 3600, 60, 0) // minTTL=60s

	query := makeQuery("short-ttl.example.com", dns.TypeA)
	resp := makeResp(query, 5) // 5s TTL, below minTTL

	ttl := c.computeTTL(resp, false)
	if ttl != 60*time.Second {
		t.Errorf("expected minTTL floor (60s), got %v", ttl)
	}
}

// TestComputeTTL_MultipleRecords verifies minimum TTL is used across records.
func TestComputeTTL_MultipleRecords(t *testing.T) {
	c := New(100, 3600, 5, 0)

	query := makeQuery("multi.example.com", dns.TypeA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer,
		&dns.A{
			Hdr: dns.Header{Name: "multi.example.com.", Class: dns.ClassINET, TTL: 300},
		},
		&dns.A{
			Hdr: dns.Header{Name: "multi.example.com.", Class: dns.ClassINET, TTL: 60},
		},
	)

	ttl := c.computeTTL(resp, false)
	if ttl != 60*time.Second {
		t.Errorf("expected min TTL (60s), got %v", ttl)
	}
}

// =============================================================================
// Eviction tests
// =============================================================================

// TestEvictOldest_PrefersExpired verifies that eviction first removes expired
// entries before falling back to earliest-expiring.
func TestEvictOldest_PrefersExpired(t *testing.T) {
	c := New(3, 1, 1, 0)

	// Insert 3 entries with very short TTLs
	for i := 0; i < 3; i++ {
		q := makeQuery(fmt.Sprintf("evict%d.example.com", i), dns.TypeA)
		r := makeResp(q, 1)
		c.Put(q, r, false)
	}

	// Wait for entries to expire
	time.Sleep(1200 * time.Millisecond)

	// Insert a new entry; should evict an expired one
	q := makeQuery("new.example.com", dns.TypeA)
	r := makeResp(q, 300)
	c.Put(q, r, false)

	if c.Len() > 3 {
		t.Errorf("expected at most 3 entries after eviction, got %d", c.Len())
	}

	// The new entry should be retrievable
	if entry, _ := c.Get(q); entry == nil {
		t.Error("new entry should be in cache after eviction")
	}
}

// =============================================================================
// Concurrent safety tests
// =============================================================================

// TestConcurrentPutGetFlush verifies no races under mixed operations.
func TestConcurrentPutGetFlush(t *testing.T) {
	c := New(100, 3600, 5, 25)
	c.SetRefreshFunc(func(q *dns.Msg) {
		resp := makeResp(q, 300)
		c.Put(q, resp, false)
	})

	done := make(chan struct{})

	// Writers
	for i := 0; i < 5; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				q := makeQuery(fmt.Sprintf("cc%d-%d.example.com", n, j), dns.TypeA)
				r := makeResp(q, 300)
				c.Put(q, r, j%3 == 0)
			}
		}(i)
	}

	// Readers
	for i := 0; i < 5; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				q := makeQuery(fmt.Sprintf("cc%d-%d.example.com", n, j), dns.TypeA)
				entry, _ := c.Get(q)
				if entry != nil {
					_ = MakeCachedResponse(q, entry)
				}
			}
		}(i)
	}

	// Flusher
	go func() {
		defer func() { done <- struct{}{} }()
		time.Sleep(10 * time.Millisecond)
		c.Flush()
	}()

	for i := 0; i < 11; i++ {
		<-done
	}
}
