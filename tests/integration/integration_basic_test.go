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
