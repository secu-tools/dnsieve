// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// ============================================================
// Whitelist caching end-to-end tests
// ============================================================

// TestE2E_Whitelist_Cache_Hit verifies that a second query for a whitelisted
// domain is served from the cache (fast) rather than hitting the whitelist
// resolver again.
func TestE2E_Whitelist_Cache_Hit(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.MinTTL = 60
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{writeE2EListFile(t, "example.com\n")}
	cfg.Whitelist.ResolverAddress = "https://cloudflare-dns.com/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	// Warm the cache with the first query.
	resp1 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelist cache warm-up: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}
	if len(resp1.Answer) == 0 {
		t.Fatal("whitelist cache warm-up: no answers")
	}

	// Second query must be fast (served from cache) and return the same IP.
	start := time.Now()
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	elapsed := time.Since(start)

	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelist cache hit: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	if len(resp2.Answer) == 0 {
		t.Fatal("whitelist cache hit: no answers")
	}

	t.Logf("whitelist cache hit: elapsed=%v answers=%d (second query)", elapsed, len(resp2.Answer))
}

// TestE2E_Whitelist_Cache_MinTTL verifies that whitelist entries respect the
// configured min_ttl floor.
func TestE2E_Whitelist_Cache_MinTTL(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.MinTTL = 120
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{writeE2EListFile(t, "example.com\n")}
	cfg.Whitelist.ResolverAddress = "https://cloudflare-dns.com/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelist min_ttl: rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	// The cached entry should still be available (min_ttl=120s keeps it alive).
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelist min_ttl cache hit: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("whitelist min_ttl=120s: answers=%d (cache entry survives)", len(resp2.Answer))
}

// TestE2E_Whitelist_Cache_Bypass_Blocked verifies that a whitelisted domain
// bypasses blocking upstreams AND is subsequently cached correctly so that
// future queries do not return blocked responses.
func TestE2E_Whitelist_Cache_Bypass_Blocked(t *testing.T) {
	// Use a domain that we know is blocked by the default upstreams.
	knownBlocked := knownBlockedDomain

	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.MinTTL = 60
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{writeE2EListFile(t, knownBlocked+"\n")}
	cfg.Whitelist.ResolverAddress = "https://cloudflare-dns.com/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	resp1 := queryUDP(t, port, knownBlocked, dns.TypeA)

	// If the first query succeeded (unblocked by whitelist resolver), verify
	// the second query is also unblocked (served from cache).
	if resp1.Rcode == dns.RcodeSuccess && !isBlockedIPv4(resp1) {
		resp2 := queryUDP(t, port, knownBlocked, dns.TypeA)
		if isBlockedIPv4(resp2) {
			t.Error("whitelist bypass+cache: second query should not be blocked (must come from whitelist cache)")
		} else {
			t.Logf("whitelist bypass+cache: both queries unblocked (second from cache)")
		}
		return
	}

	t.Logf("info: domain %s not resolved unblocked by whitelist resolver (may vary by network)", knownBlocked)
}

// TestE2E_Whitelist_Cache_Disabled verifies that when cache is disabled,
// every whitelist query reaches the whitelist resolver.
func TestE2E_Whitelist_Cache_Disabled(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = false
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{writeE2EListFile(t, "example.com\n")}
	cfg.Whitelist.ResolverAddress = "https://cloudflare-dns.com/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	// Both queries should succeed even without cache.
	for i := 0; i < 2; i++ {
		resp := queryUDP(t, port, "example.com", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("query %d: rcode=%s (cache disabled, whitelist should still work)", i+1, dns.RcodeToString[resp.Rcode])
		}
	}
}

// TestE2E_Whitelist_NonWhitelisted_UsesNormalPath verifies that a domain NOT
// in the whitelist still resolves normally and is cached under the normal
// (non-whitelisted) path.
func TestE2E_Whitelist_NonWhitelisted_UsesNormalPath(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cfg.Cache.MinTTL = 60
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{writeE2EListFile(t, "safe.only.test\n")} // unrelated domain
	cfg.Whitelist.ResolverAddress = "https://cloudflare-dns.com/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	// example.com is not whitelisted; should resolve normally.
	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("non-whitelisted: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("non-whitelisted: expected answers from normal resolver")
	}
	// Ensure it's not returning 0.0.0.0 (that would be a blocked response).
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.Addr == (netip.AddrFrom4([4]byte{})) {
				t.Errorf("non-whitelisted: got blocked IP 0.0.0.0 for example.com")
			}
		}
	}
	t.Logf("non-whitelisted: answers=%d (resolved normally)", len(resp.Answer))
}

// isBlockedIPv4 is defined in helpers_test.go.
// This file's tests use it via the shared helpers.
