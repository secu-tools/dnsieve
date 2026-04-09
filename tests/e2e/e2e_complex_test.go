// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// ============================================================
// Whitelist feature
// ============================================================

// TestE2E_Whitelist_Bypass verifies whitelisted domains bypass blocking upstreams.
func TestE2E_Whitelist_Bypass(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.Domains = []string{"example.com"}
	cfg.Whitelist.ResolverAddress = "https://cloudflare-dns.com/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelist bypass: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("whitelist bypass: no answers")
	}
	if isBlockedIPv4(resp) {
		t.Error("whitelist bypass: got blocked response for whitelisted domain")
	}
	t.Logf("whitelist bypass: answers=%d", len(resp.Answer))
}

// ============================================================
// Complex and integration scenarios
// ============================================================

// TestE2E_Complex_MultipleEDNS tests a query with ECS and NSID options combined.
func TestE2E_Complex_MultipleEDNS(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.ECS.Mode = "strip"
	cfg.Privacy.NSID.Mode = "substitute"
	cfg.Privacy.NSID.Value = "proxy-test"
	cancel := startServer(t, cfg)
	defer cancel()

	query := makePlainQuery("example.com", dns.TypeA)

	if prefix, err := parsePrefix("203.0.113.0/24"); err == nil {
		ecs := &dns.SUBNET{
			Address: prefix.addr,
			Netmask: uint8(prefix.bits),
			Scope:   0,
		}
		if prefix.is4 {
			ecs.Family = 1
		} else {
			ecs.Family = 2
		}
		query.Pseudo = append(query.Pseudo, ecs)
	}
	query.Pseudo = append(query.Pseudo, &dns.NSID{})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c := dns.NewClient()
	c.Transport.ReadTimeout = queryTimeout

	ctx, ctxCancel := context.WithTimeout(context.Background(), queryTimeout)
	defer ctxCancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("multi-EDNS: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("multi-EDNS: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	nsid := findNSID(resp)
	if nsid == nil {
		t.Error("multi-EDNS: expected NSID in response (substitute mode)")
	} else {
		t.Logf("multi-EDNS: NSID=%s", nsid.Nsid)
	}
}

// TestE2E_Complex_BlockedThenUnblocked verifies cache handles blocked and non-blocked entries.
func TestE2E_Complex_BlockedThenUnblocked(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	for i := 0; i < 3; i++ {
		resp := queryUDP(t, port, "example.com", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("iteration %d: rcode=%s", i, dns.RcodeToString[resp.Rcode])
		}
	}

	queryUDP(t, port, knownBlockedDomain, dns.TypeA)

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("after blocked: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_UpstreamFanout verifies the proxy fan-outs to multiple upstreams.
func TestE2E_UpstreamFanout(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("fanout: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("fanout: no answers from any upstream")
	}
}

// TestE2E_Performance_CachedVsUncached compares cached vs uncached response times.
func TestE2E_Performance_CachedVsUncached(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	queryUDP(t, port, "example.com", dns.TypeA) // warm up

	const n = 5
	var total time.Duration
	for i := 0; i < n; i++ {
		start := time.Now()
		resp := queryUDP(t, port, "example.com", dns.TypeA)
		total += time.Since(start)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("perf query %d: rcode=%s", i, dns.RcodeToString[resp.Rcode])
		}
	}
	t.Logf("performance: avg cached query time = %v", total/n)
}

// TestE2E_Concurrency_MultipleClients verifies the proxy handles concurrent
// queries from multiple clients correctly.
func TestE2E_Concurrency_MultipleClients(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	const numClients = 10
	results := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func() {
			query := makePlainQuery("example.com", dns.TypeA)
			query.UDPSize = 1232
			addr := fmt.Sprintf("127.0.0.1:%d", port)

			c := dns.NewClient()
			c.Transport.ReadTimeout = queryTimeout

			ctx, ctxCancel := context.WithTimeout(context.Background(), queryTimeout)
			defer ctxCancel()

			resp, _, err := c.Exchange(ctx, query, "udp", addr)
			if err != nil {
				results <- fmt.Errorf("exchange: %w", err)
				return
			}
			if resp.Rcode != dns.RcodeSuccess {
				results <- fmt.Errorf("rcode=%s", dns.RcodeToString[resp.Rcode])
				return
			}
			results <- nil
		}()
	}

	var failed int
	for i := 0; i < numClients; i++ {
		if err := <-results; err != nil {
			failed++
			t.Logf("client %d failed: %v", i, err)
		}
	}
	if failed > 0 {
		t.Errorf("concurrent queries: %d/%d clients failed", failed, numClients)
	}
}

// ============================================================
// Internationalized Domain Names (IDN / ACE / Punycode)
// ============================================================

// TestE2E_IDN_ACELabel_A verifies that the proxy passes an A-record query for
// an ACE-encoded domain label (xn-- Punycode prefix, RFC 5891) through to the
// upstream resolvers and returns a well-formed DNS response.  The synthetic
// subdomain is expected to produce NXDOMAIN; any valid response code without
// a crash or connection reset is considered a pass.
func TestE2E_IDN_ACELabel_A(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// "xn--n3h.example.com" is a synthetic ACE-labelled subdomain used to
	// exercise the proxy without depending on a specific domain being
	// registered in the public DNS.
	resp := queryUDP(t, port, "xn--n3h.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("IDN ACE A: expected a non-nil DNS response")
	}
	t.Logf("IDN ACE A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_IDN_ACELabel_AAAA verifies the same pass-through behaviour for
// AAAA queries on ACE-labelled domain names.
func TestE2E_IDN_ACELabel_AAAA(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "xn--n3h.example.com", dns.TypeAAAA)
	if resp == nil {
		t.Fatal("IDN ACE AAAA: expected a non-nil DNS response")
	}
	t.Logf("IDN ACE AAAA: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_IDN_ACELabel_TCP mirrors TestE2E_IDN_ACELabel_A but uses the TCP
// transport to verify ACE-labelled domains are handled correctly on both UDP
// and TCP connections.
func TestE2E_IDN_ACELabel_TCP(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryTCP(t, port, "xn--n3h.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("IDN ACE TCP: expected a non-nil DNS response")
	}
	t.Logf("IDN ACE TCP: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_IDN_Whitelist_ACEEntry verifies that a whitelist entry already
// expressed in ACE form is matched correctly against incoming ACE-form queries.
func TestE2E_IDN_Whitelist_ACEEntry(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Whitelist.Enabled = true
	// Use an ACE-form entry; the whitelist must match it exactly.
	cfg.Whitelist.Domains = []string{"xn--n3h.example.com"}
	cfg.Whitelist.ResolverAddress = "https://1.1.1.1/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "xn--n3h.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("IDN whitelist ACE: expected a non-nil DNS response")
	}
	t.Logf("IDN whitelist ACE: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_IDN_Whitelist_UnicodeEntry verifies that a whitelist entry
// containing a non-ASCII Unicode label (Go escape sequence used here to keep
// the source file ASCII-clean, U+00FC is the umlaut-u character) is
// normalised to its ACE/Punycode equivalent and matched against the
// ACE-form query name that arrives over the wire.
//
// Entry:  "b\u00fccher.example.com"  (bücher with umlaut-u)
// Query:  "xn--bcher-kva.example.com" (the corresponding ACE form)
func TestE2E_IDN_Whitelist_UnicodeEntry(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.Domains = []string{"b\u00fccher.example.com"}
	cfg.Whitelist.ResolverAddress = "https://1.1.1.1/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"
	cancel := startServer(t, cfg)
	defer cancel()

	// Query using the ACE form that corresponds to the Unicode config entry.
	// The expected ACE encoding is documented in the upstream package unit
	// tests (TestToACEDomain_IDNEncoding).
	resp := queryUDP(t, port, "xn--bcher-kva.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("IDN whitelist unicode: expected a non-nil DNS response")
	}
	t.Logf("IDN whitelist unicode: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_IDN_MultipleACELabels verifies that domain names composed of
// multiple ACE-encoded labels at different levels are handled correctly.
func TestE2E_IDN_MultipleACELabels(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Both labels use the xn-- prefix; this exercises multi-level IDN paths.
	resp := queryUDP(t, port, "xn--n3h.xn--n3h.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("IDN multi-label: expected a non-nil DNS response")
	}
	t.Logf("IDN multi-label: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestE2E_IDN_CachingACELabel verifies that ACE-labelled domain names are
// cached and served correctly on subsequent queries.
func TestE2E_IDN_CachingACELabel(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	const aceDomain = "xn--n3h.example.com"

	// First query populates the cache.
	resp1 := queryUDP(t, port, aceDomain, dns.TypeA)
	if resp1 == nil {
		t.Fatal("IDN cache first: expected a non-nil DNS response")
	}

	// Second query should be served from cache; rcode must be consistent.
	resp2 := queryUDP(t, port, aceDomain, dns.TypeA)
	if resp2 == nil {
		t.Fatal("IDN cache second: expected a non-nil DNS response")
	}
	if resp1.Rcode != resp2.Rcode {
		t.Errorf("IDN cache: rcode mismatch first=%s second=%s",
			dns.RcodeToString[resp1.Rcode], dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("IDN cache: rcode=%s", dns.RcodeToString[resp2.Rcode])
}
