// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

package rfc

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// -- RFC 8482: Providing Minimal-Sized Responses to ANY Queries --

// TestRFC8482_ANY_Response tests that ANY queries return a valid response.
// Per RFC 8482, servers may respond with a minimal answer (HINFO, SOA, or
// a synthesized answer) instead of all records.
func TestRFC8482_ANY_Response(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeANY)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("ANY query: %v", err)
	}

	// RFC 8482 allows NOERROR with minimal answers, NOTIMP, or REFUSED
	switch resp.Rcode {
	case dns.RcodeSuccess:
		t.Logf("RFC 8482: ANY returned NOERROR with %d answers", len(resp.Answer))
	case dns.RcodeNotImplemented:
		t.Log("RFC 8482: server returned NOTIMP for ANY (valid per RFC 8482)")
	case dns.RcodeRefused:
		t.Log("RFC 8482: server returned REFUSED for ANY (valid per RFC 8482)")
	default:
		t.Logf("RFC 8482: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestRFC8482_ANY_TCP tests ANY query over TCP.
func TestRFC8482_ANY_TCP(t *testing.T) {
	query := makeQuery("google.com.", dns.TypeANY)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "tcp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("TCP ANY query: %v", err)
	}

	t.Logf("RFC 8482: ANY over TCP rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}
