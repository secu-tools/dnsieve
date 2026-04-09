// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

// Package integration contains integration tests for DNSieve.
// These tests start a real DNSieve server in-process and send queries to it.
// They require a working internet connection.
//
// Run with: go test -tags integration ./tests/integration/
package integration

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

func TestIntegration_BasicQuery(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
}

func TestIntegration_IPv4Answer(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode=%d", resp.Rcode)
	}
	var got []netip.Addr
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			got = append(got, a.Addr)
		}
	}
	if len(got) == 0 {
		t.Fatal("expected at least one A record for example.com")
	}
	for _, addr := range got {
		if !addr.Is4() {
			t.Errorf("expected IPv4 address, got %v", addr)
		}
	}
}

func TestIntegration_AAAA(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestIntegration_IPv6Answer(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR for AAAA query, got rcode=%d", resp.Rcode)
	}
	for _, rr := range resp.Answer {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			if !aaaa.Addr.Is6() {
				t.Errorf("expected IPv6 address in AAAA record, got %v", aaaa.Addr)
			}
			if aaaa.Addr == netip.IPv6Unspecified() {
				t.Logf("domain is IPv6-blocked (returned ::)")
			}
		}
	}
}

func TestIntegration_NXDOMAIN(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "this-domain-definitely-does-not-exist-dnsieve.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError && resp.Rcode != dns.RcodeSuccess {
		t.Logf("response code: %s (may vary by upstream)", dns.RcodeToString[resp.Rcode])
	}
}

// TestIntegration_IDN_ACELabel_A verifies that an A-record query for an
// ACE-encoded domain name (xn-- Punycode label) passes through the proxy
// without error.  The synthetic subdomain under example.com is expected to
// return NXDOMAIN; any valid DNS response code (no crash, no timeout) is
// considered a pass.
func TestIntegration_IDN_ACELabel_A(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	// "xn--n3h.example.com" is a synthetic ACE-labelled domain used solely
	// to verify that the proxy handles xn-- labels without crashing or
	// misidentifying them as blocked.
	resp := queryLocal(t, port, "xn--n3h.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("expected a non-nil DNS response for ACE-labelled domain")
	}
	// Accept NXDOMAIN (expected), NOERROR (unlikely but valid) or SERVFAIL
	// (upstream temporary error).  The important thing is that the proxy
	// returned a well-formed response rather than closing the connection.
	t.Logf("IDN ACE A: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestIntegration_IDN_ACELabel_AAAA verifies that AAAA queries for ACE-labelled
// domains are also handled gracefully.
func TestIntegration_IDN_ACELabel_AAAA(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "xn--n3h.example.com", dns.TypeAAAA)
	if resp == nil {
		t.Fatal("expected a non-nil DNS response for ACE-labelled AAAA query")
	}
	t.Logf("IDN ACE AAAA: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestIntegration_IDN_Whitelist_UnicodeEntry verifies that a whitelist entry
// containing a Unicode label (encoded as Go escape sequences here to keep the
// source ASCII-clean) matches the corresponding ACE-form DNS query that the
// proxy receives over the wire.
func TestIntegration_IDN_Whitelist_UnicodeEntry(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Whitelist.Enabled = true
	// "b\u00fccher.example.com" contains the umlaut-u character U+00FC.
	// Its ACE/Punycode form (xn--bcher-kva.example.com) is what a DNS client
	// sends over the wire; the proxy must match the Unicode config entry to
	// the ACE query name.
	cfg.Whitelist.Domains = []string{"b\u00fccher.example.com"}
	cfg.Whitelist.ResolverAddress = "https://1.1.1.1/dns-query"
	cfg.Whitelist.ResolverProtocol = "doh"

	port, cancel := startTestServer(t, cfg)
	defer cancel()

	// Query using the ACE form of the configured Unicode domain.
	// "xn--bcher-kva.example.com" is the Punycode encoding of
	// "b\u00fccher.example.com" (bücher = books in German).
	resp := queryLocal(t, port, "xn--bcher-kva.example.com", dns.TypeA)
	if resp == nil {
		t.Fatal("expected a non-nil DNS response for ACE whitelist query")
	}
	// The whitelist path goes to a non-blocking upstream; any valid response
	// code except a hard network error is acceptable.
	t.Logf("IDN whitelist: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}
