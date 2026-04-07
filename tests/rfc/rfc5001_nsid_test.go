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

// -- RFC 5001: DNS Name Server Identifier --

// TestRFC5001_NSID_Request tests that servers return NSID when requested.
func TestRFC5001_NSID_Request(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	// Add NSID request (empty NSID = request for server's NSID)
	query.Pseudo = append(query.Pseudo, &dns.NSID{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("NSID query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	foundNSID := false
	for _, rr := range resp.Pseudo {
		if nsid, ok := rr.(*dns.NSID); ok {
			foundNSID = true
			t.Logf("RFC 5001: NSID = %q", nsid.Nsid)
			break
		}
	}
	if !foundNSID {
		t.Log("RFC 5001: server did not return NSID (not all servers advertise NSID)")
	}
}

// TestRFC5001_WithoutNSID verifies queries without NSID still work.
func TestRFC5001_WithoutNSID(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
}
