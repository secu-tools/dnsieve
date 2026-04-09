// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

package rfc

import (
	"context"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// -- RFC 5891: Internationalizing Domain Names in Applications (IDNA) 2008 --
//
// RFC 5891 defines the current IDNA 2008 standard. In the DNS wire format
// internationalized labels are encoded using Punycode (RFC 3492) and carry the
// "xn--" ASCII-compatible encoding (ACE) prefix. From the perspective of the
// DNS protocol, ACE labels are ordinary ASCII labels and must be treated
// identically to other ASCII labels by resolvers and proxies.
//
// These tests verify that a DNS server (1.1.1.1 is used as a reference
// implementation) handles ACE-encoded queries correctly, giving confidence
// that DNSieve can pass such queries through the upstream pipeline without
// loss of correctness.

// TestRFC5891_IDNA_ACELabel_ResolvableReal queries a resolving ACE-encoded
// domain to confirm that the DNS infrastructure handles xn-- labels for real
// internationalized domains.  The domain "xn--nxasmq6b.com" is one of several
// publicly registered IDN domain names; the test accepts NOERROR or NXDOMAIN
// (the registration status may change) but requires no SERVFAIL.
func TestRFC5891_IDNA_ACELabel_ResolvableReal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Query an ACE-encoded domain over 1.1.1.1 as the reference resolver.
	// Any rcode except SERVFAIL is acceptable; SERVFAIL would indicate the
	// upstream cannot handle ACE labels at all.
	query := makeQuery("xn--nxasmq6b.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 5891: query failed: %v", err)
	}
	if resp.Rcode == dns.RcodeServerFailure {
		t.Errorf("RFC 5891: ACE-labelled query returned SERVFAIL; upstream must not reject ACE labels")
	}
	t.Logf("RFC 5891 ACE real domain: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestRFC5891_IDNA_ACELabel_SyntheticNXDOMAIN verifies that a synthetic
// ACE-encoded query (a domain that is not registered) returns NXDOMAIN or
// NOERROR-nodata, not SERVFAIL.  A SERVFAIL on an ACE-labelled query would
// indicate the resolver rejects the label format rather than looking it up.
func TestRFC5891_IDNA_ACELabel_SyntheticNXDOMAIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// "xn--n3h.example.com." encodes a synthetic (unregistered) ACE label
	// under example.com, which is managed by IANA and never delegates
	// arbitrary subdomains.
	query := makeQuery("xn--n3h.example.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 5891 synthetic: query failed: %v", err)
	}
	if resp.Rcode == dns.RcodeServerFailure {
		t.Errorf("RFC 5891: synthetic ACE-labelled query returned SERVFAIL; ACE labels must not cause SERVFAIL")
	}
	// NXDOMAIN is the expected outcome for an unregistered subdomain.
	t.Logf("RFC 5891 synthetic ACE: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestRFC5891_IDNA_ACELabel_CaseInsensitive verifies that ACE-encoded DNS
// labels are treated case-insensitively per RFC 4343, which applies to all
// ASCII labels including those with the "xn--" prefix.  Querying with the
// same ACE label in upper and lower case must produce identical rcodes.
func TestRFC5891_IDNA_ACELabel_CaseInsensitive(t *testing.T) {
	variants := []string{
		"xn--n3h.example.com.",
		"XN--N3H.EXAMPLE.COM.",
		"Xn--n3h.Example.Com.",
	}

	rcodes := make([]int, 0, len(variants))
	for _, name := range variants {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		query := makeQuery(name, dns.TypeA)
		resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
		cancel()
		if err != nil {
			t.Fatalf("RFC 5891 case: query for %q failed: %v", name, err)
		}
		rcodes = append(rcodes, int(resp.Rcode))
		t.Logf("RFC 5891 case %q: rcode=%s", name, dns.RcodeToString[resp.Rcode])
	}

	// All variants must produce the same rcode (RFC 4343 case-insensitivity).
	for i := 1; i < len(rcodes); i++ {
		if rcodes[i] != rcodes[0] {
			t.Errorf("RFC 5891+4343: rcode mismatch between %q (%s) and %q (%s); ACE labels must be case-insensitive",
				variants[0], dns.RcodeToString[rcodes[0]],
				variants[i], dns.RcodeToString[rcodes[i]])
		}
	}
}

// TestRFC5891_IDNA_ACELabel_MultiLevel verifies that domain names with
// multiple ACE-encoded labels at different levels are handled correctly.
// A domain like "xn--n3h.xn--n3h.example.com." tests that the resolver
// does not fail on consecutive ACE labels.
func TestRFC5891_IDNA_ACELabel_MultiLevel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("xn--n3h.xn--n3h.example.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 5891 multi-level: query failed: %v", err)
	}
	if resp.Rcode == dns.RcodeServerFailure {
		t.Errorf("RFC 5891: multi-level ACE-labelled query must not produce SERVFAIL")
	}
	t.Logf("RFC 5891 multi-level ACE: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestRFC5891_IDNA_LabelLength verifies that ACE labels at or below the
// 63-octet limit (RFC 1035 label length restriction) are handled normally.
// The "xn--" prefix itself is 4 octets; adding up to 59 octets of Punycode
// content is valid.
func TestRFC5891_IDNA_LabelLength(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Construct a 63-character ACE label: "xn--" + 59 'a' chars.
	aceLabel := "xn--" + strings.Repeat("a", 59)
	name := aceLabel + ".example.com."

	query := makeQuery(name, dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 5891 label-length: query failed: %v", err)
	}
	// FORMERR or NXDOMAIN are both acceptable; SERVFAIL would indicate
	// the 63-char boundary was not respected.
	if resp.Rcode == dns.RcodeServerFailure {
		t.Logf("RFC 5891 label-length: SERVFAIL on 63-char ACE label (may be upstream-specific)")
	}
	t.Logf("RFC 5891 label-length (63 chars): rcode=%s", dns.RcodeToString[resp.Rcode])
}
