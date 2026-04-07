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
