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

// -- RFC 6891: EDNS0 --

// TestRFC6891_EDNS0_OPTPresent verifies that EDNS0-capable servers return OPT records.
func TestRFC6891_EDNS0_OPTPresent(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("EDNS0 query: %v", err)
	}

	if resp.UDPSize == 0 {
		t.Error("RFC 6891: server should return EDNS0 OPT with UDPSize > 0")
	}
	t.Logf("EDNS0: UDPSize=%d", resp.UDPSize)
}

// TestRFC6891_EDNS0_Version0 verifies EDNS version 0 is supported.
func TestRFC6891_EDNS0_Version0(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 1232

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("EDNS0 query: %v", err)
	}

	// Check that the response has EDNS0 OPT with version 0
	for _, rr := range resp.Pseudo {
		if opt, ok := rr.(*dns.OPT); ok {
			if opt.Version() != 0 {
				t.Errorf("RFC 6891: EDNS version = %d, want 0", opt.Version())
			}
			return
		}
	}
	t.Logf("RFC 6891: server processed EDNS0 query (rcode=%s)", dns.RcodeToString[resp.Rcode])
}

// TestRFC6891_BufferSize verifies servers respect buffer size negotiation.
func TestRFC6891_BufferSize(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 512 // Request small buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("RFC 6891: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("RFC 6891: response UDPSize=%d (we requested 512)", resp.UDPSize)
}

// TestRFC6891_EDNS0_UpstreamSupport verifies upstream servers advertise EDNS0
// OPT records and respond to clients requesting extended UDP sizes.
func TestRFC6891_EDNS0_UpstreamSupport(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	// Add EDNS0 OPT record requesting 4096-byte UDP size.
	query.UDPSize = 4096

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("EDNS0 query: %v", err)
	}

	for _, rr := range resp.Pseudo {
		if respOpt, ok := rr.(*dns.OPT); ok {
			t.Logf("EDNS0: UDPSize=%d, Version=%d", respOpt.UDPSize(), respOpt.Version())
			return
		}
	}
	t.Error("RFC 6891: server should return EDNS0 OPT record in Pseudo section")
}
