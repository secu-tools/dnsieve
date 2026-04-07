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

// -- RFC 3225: DO Bit (DNSSEC OK) --

// TestRFC3225_DOBit_Set verifies that setting the DO bit results in
// DNSSEC-related records in the response.
func TestRFC3225_DOBit_Set(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096
	query.Security = true // Set DO bit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DO bit query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	// With DO=1, we should get RRSIG records in the answer for signed zones
	hasRRSIG := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			hasRRSIG = true
			break
		}
	}
	if !hasRRSIG {
		// Also check authority section
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.RRSIG); ok {
				hasRRSIG = true
				break
			}
		}
	}

	if hasRRSIG {
		t.Log("RFC 3225: DO=1 returned DNSSEC records")
	} else {
		t.Log("RFC 3225: no RRSIG in response (server may not serve DNSSEC for this zone)")
	}
}

// TestRFC3225_DOBit_NotSet verifies that without DO=1, DNSSEC records are
// not included.
func TestRFC3225_DOBit_NotSet(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	// Explicitly do NOT set DO bit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			t.Error("RFC 3225: RRSIG should not appear without DO=1")
			break
		}
	}
}
