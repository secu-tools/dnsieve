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

// -- RFC 3597: Handling of Unknown DNS RR Types --

const qtypeUnknownRFC3597 uint16 = 65400

// TestRFC3597_UnknownQType_UDP verifies that querying an unknown type does not
// break parser/transport handling.
func TestRFC3597_UnknownQType_UDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("example.com.", qtypeUnknownRFC3597)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 3597 UDP unknown type query failed: %v", err)
	}

	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeNotImplemented, dns.RcodeRefused:
		// Valid outcomes across resolver implementations.
	default:
		t.Errorf("RFC 3597: unexpected rcode=%s for unknown qtype", dns.RcodeToString[resp.Rcode])
	}

	if err := resp.Pack(); err != nil {
		t.Errorf("RFC 3597: response should be serializable, pack failed: %v", err)
	}
}

// TestRFC3597_UnknownQType_TCP verifies the same behavior over TCP.
func TestRFC3597_UnknownQType_TCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("example.com.", qtypeUnknownRFC3597)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "tcp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("RFC 3597 TCP unknown type query failed: %v", err)
	}

	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeNotImplemented, dns.RcodeRefused:
	default:
		t.Errorf("RFC 3597 TCP: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}
