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

// -- RFC 8914: Extended DNS Errors --

// TestRFC8914_EDE_InResponse tests that DNSSEC-validating servers may
// return EDE in their responses on validation failure.
func TestRFC8914_EDE_InResponse(t *testing.T) {
	// Query a known DNSSEC-signed domain
	query := makeQuery("dnssec-failed.org.", dns.TypeA)
	query.UDPSize = 4096
	query.Security = true // Set DO bit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Quad9 validates DNSSEC and may return EDE
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "9.9.9.9:53")
	if err != nil {
		t.Fatalf("EDE query: %v", err)
	}

	// Look for EDE in pseudo section
	for _, rr := range resp.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			t.Logf("RFC 8914: EDE InfoCode=%d ExtraText=%q", ede.InfoCode, ede.ExtraText)
			return
		}
	}

	t.Logf("RFC 8914: no EDE in response (rcode=%s), server may not support EDE", dns.RcodeToString[resp.Rcode])
}

// TestRFC8914_EDE_NotRequired tests that queries to normal domains succeed
// without EDE.
func TestRFC8914_EDE_NotRequired(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096
	query.Security = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "9.9.9.9:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	for _, rr := range resp.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			t.Logf("RFC 8914: unexpected EDE on valid domain: InfoCode=%d", ede.InfoCode)
		}
	}
}
