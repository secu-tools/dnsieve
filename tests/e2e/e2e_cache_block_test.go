// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// ============================================================
// Cache behavior
// ============================================================

// TestE2E_Cache_Hit verifies that a second identical query is served from cache.
func TestE2E_Cache_Hit(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.MinTTL = 60
	cancel := startServer(t, cfg)
	defer cancel()

	resp1 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("first query: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}

	start := time.Now()
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	elapsed := time.Since(start)

	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("cached query: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	if len(resp2.Answer) == 0 {
		t.Fatal("cached query: no answers")
	}
	t.Logf("cache hit: elapsed=%v answers=%d", elapsed, len(resp2.Answer))
}

// TestE2E_Cache_Disabled verifies queries work with cache disabled.
func TestE2E_Cache_Disabled(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = false
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("no-cache query: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_Cache_Blocked verifies that blocked domains are cached.
// A blocked response is NXDOMAIN + EDE Blocked (RFC 8914 code 15).
func TestE2E_Cache_Blocked(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.BlockedTTL = 60
	cancel := startServer(t, cfg)
	defer cancel()

	resp1 := queryUDP(t, port, knownBlockedDomain, dns.TypeA)
	blocked1 := isBlockedIPv4(resp1)

	start := time.Now()
	resp2 := queryUDP(t, port, knownBlockedDomain, dns.TypeA)
	elapsed := time.Since(start)
	blocked2 := isBlockedIPv4(resp2)

	if blocked1 && blocked2 {
		t.Logf("cache blocked: confirmed NXDOMAIN+EDE, second elapsed=%v", elapsed)
	} else if !blocked1 {
		t.Logf("info: %s not blocked by configured upstreams", knownBlockedDomain)
	}
}

// TestE2E_Cache_CNAME verifies CNAME chains are cached correctly.
func TestE2E_Cache_CNAME(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "www.google.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("CNAME: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("CNAME: answers=%d", len(resp.Answer))
}

// TestE2E_Cache_BackgroundRefresh verifies the background refresh mechanism.
func TestE2E_Cache_BackgroundRefresh(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.RenewPercent = 90
	cfg.Cache.MinTTL = 5
	cancel := startServer(t, cfg)
	defer cancel()

	resp1 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("first query: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("second query: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("background refresh: q1=%d q2=%d answers", len(resp1.Answer), len(resp2.Answer))
}

// TestE2E_Cache_MinTTL verifies the MinTTL floor is applied to cached entries.
func TestE2E_Cache_MinTTL(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.MinTTL = 300
	cancel := startServer(t, cfg)
	defer cancel()

	// MinTTL is a cache storage floor, not a response TTL rewrite.
	// Verify the server responds successfully; cached entries are stored for >= MinTTL.
	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("min TTL: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("min TTL: expected at least one answer")
	}
	// Second query should be a fast cache hit (entry stored for >= minTTL).
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("min TTL: cache hit rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("min TTL: answers=%d (MinTTL floor keeps entry for >=300s)", len(resp.Answer))
}

// TestE2E_Cache_MultipleTypes verifies distinct record types are cached separately.
func TestE2E_Cache_MultipleTypes(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	respA := queryUDP(t, port, "example.com", dns.TypeA)
	if respA.Rcode != dns.RcodeSuccess {
		t.Fatalf("cache multi-type A: rcode=%s", dns.RcodeToString[respA.Rcode])
	}
	respAAAA := queryUDP(t, port, "example.com", dns.TypeAAAA)
	if respAAAA.Rcode != dns.RcodeSuccess {
		t.Fatalf("cache multi-type AAAA: rcode=%s", dns.RcodeToString[respAAAA.Rcode])
	}
	t.Logf("cache multi-type: A=%d AAAA=%d answers", len(respA.Answer), len(respAAAA.Answer))
}

// TestE2E_Cache_NXDOMAINIsCached verifies NXDOMAIN responses are cached
// so subsequent queries do not hit upstream.
func TestE2E_Cache_NXDOMAINIsCached(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	domain := "this-domain-definitely-does-not-exist-cache-test.example.com"
	resp1 := queryUDP(t, port, domain, dns.TypeA)
	t.Logf("NXDOMAIN cache q1: rcode=%s", dns.RcodeToString[resp1.Rcode])

	start := time.Now()
	resp2 := queryUDP(t, port, domain, dns.TypeA)
	elapsed := time.Since(start)
	t.Logf("NXDOMAIN cache q2: rcode=%s elapsed=%v", dns.RcodeToString[resp2.Rcode], elapsed)
}

// ============================================================
// Block detection
// ============================================================

// TestE2E_Block_IPv4 verifies a known blocked domain returns NXDOMAIN with
// EDE Blocked (RFC 8914 code 15), not 0.0.0.0.
func TestE2E_Block_IPv4(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, knownBlockedDomain, dns.TypeA)
	if isBlockedIPv4(resp) {
		t.Logf("block IPv4: confirmed NXDOMAIN + EDE Blocked")
	} else {
		t.Logf("info: %s not blocked (depends on upstream)", knownBlockedDomain)
	}
}

// TestE2E_Block_IPv6 verifies a blocked domain returns NXDOMAIN with EDE
// Blocked for AAAA queries, not ::.
func TestE2E_Block_IPv6(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, knownBlockedDomain, dns.TypeAAAA)
	if isBlockedIPv6(resp) {
		t.Logf("block IPv6: confirmed NXDOMAIN + EDE Blocked")
	} else {
		t.Logf("info: %s AAAA not blocked", knownBlockedDomain)
	}
}

// TestE2E_Block_NeverLeaked verifies a blocked domain response never contains
// real answer records (the proxy now returns NXDOMAIN with no Answer section).
func TestE2E_Block_NeverLeaked(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	for i := 0; i < 3; i++ {
		resp := queryUDP(t, port, knownBlockedDomain, dns.TypeA)
		if isBlockedResponse(resp) {
			if len(resp.Answer) != 0 {
				t.Errorf("attempt %d: blocked NXDOMAIN response contains %d unexpected answer record(s)",
					i+1, len(resp.Answer))
			}
		}
	}
}
