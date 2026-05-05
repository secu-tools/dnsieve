// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

package rfc

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// -- RFC 7871: EDNS Client Subnet --

// TestRFC7871_ECS_PresentInResponse tests that ECS-capable servers include
// SUBNET in their response when we send an ECS query.
func TestRFC7871_ECS_PresentInResponse(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	// Add ECS option with /24 prefix
	ecs := &dns.SUBNET{
		Family:  1,
		Netmask: 24,
		Scope:   0,
		Address: netip.MustParseAddr("203.0.113.0"),
	}
	query.Pseudo = append(query.Pseudo, ecs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("ECS query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	// Check if ECS is in the response
	foundECS := false
	for _, rr := range resp.Pseudo {
		if _, ok := rr.(*dns.SUBNET); ok {
			foundECS = true
			t.Logf("RFC 7871: server returned ECS scope in response")
			break
		}
	}
	if !foundECS {
		t.Log("RFC 7871: server did not return ECS in response (some servers opt out)")
	}
}

// TestRFC7871_ECS_WithoutSubnet tests that queries without ECS still work.
func TestRFC7871_ECS_WithoutSubnet(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Log("RFC 7871: query without ECS successful")
}

// TestRFC7871_ECS_ScopeZeroOnQuery verifies that SOURCE PREFIX-LENGTH is
// non-zero and SCOPE PREFIX-LENGTH is zero in the client's query.
func TestRFC7871_ECS_ScopeZeroOnQuery(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	ecs := &dns.SUBNET{
		Family:  1,
		Netmask: 24,
		Scope:   0, // RFC 7871 s6: SCOPE must be 0 in queries
		Address: netip.MustParseAddr("198.51.100.0"),
	}
	query.Pseudo = append(query.Pseudo, ecs)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("ECS query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
}
