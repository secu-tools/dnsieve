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

// -- RFC 1034 + RFC 2181 foundational behavior --

// TestRFC1034_CNAMEAliasResolution verifies that aliasing works end-to-end
// by querying a commonly-aliased name and validating a successful response.
func TestRFC1034_CNAMEAliasResolution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("www.github.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 1034 query failed: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 1034: rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Error("RFC 1034: expected at least one answer for aliased hostname")
	}

	hasAliasHop := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			hasAliasHop = true
			break
		}
	}
	t.Logf("RFC 1034: answers=%d cname_present=%v", len(resp.Answer), hasAliasHop)
}

// TestRFC2181_RRSetTTLUniformity checks that if multiple A RRs are returned
// for one owner name, their TTL values are consistent within the RRset.
func TestRFC2181_RRSetTTLUniformity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("cloudflare.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 2181 query failed: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 2181: rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	var (
		ttlRef uint32
		seen   int
	)
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) != dns.TypeA {
			continue
		}
		seen++
		if seen == 1 {
			ttlRef = rr.Header().TTL
			continue
		}
		if rr.Header().TTL != ttlRef {
			t.Errorf("RFC 2181: mixed TTLs in A RRset: first=%d got=%d", ttlRef, rr.Header().TTL)
		}
	}

	if seen < 2 {
		t.Log("RFC 2181: less than 2 A records observed; RRset TTL uniformity not strongly exercised")
	}
}

// TestRFC2181_CNAMEOwnerHasNoOtherData verifies that if a CNAME appears for
// an owner name, no other data for that same owner is mixed in that answer.
func TestRFC2181_CNAMEOwnerHasNoOtherData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("www.github.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("RFC 2181 query failed: %v", err)
	}

	for _, rr := range resp.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		owner := cname.Header().Name
		for _, other := range resp.Answer {
			if other.Header().Name != owner {
				continue
			}
			if dns.RRToType(other) != dns.TypeCNAME {
				t.Errorf("RFC 2181: owner %s has CNAME and %s", owner, dns.TypeToString[dns.RRToType(other)])
			}
		}
	}
}
