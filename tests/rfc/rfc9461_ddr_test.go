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

// -- RFC 9461/9462: Discovery of Designated Resolvers (DDR) --

// TestRFC9461_DDR_Query tests querying _dns.resolver.arpa SVCB to discover
// encrypted resolvers per RFC 9461.
func TestRFC9461_DDR_Query(t *testing.T) {
	query := makeQuery("_dns.resolver.arpa.", dns.TypeSVCB)

	servers := []struct {
		name    string
		address string
	}{
		{"Cloudflare", "1.1.1.1:53"},
		{"Google", "8.8.8.8:53"},
	}

	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", srv.address)
			if err != nil {
				t.Fatalf("DDR query to %s: %v", srv.name, err)
			}

			if resp.Rcode == dns.RcodeNameError {
				t.Logf("RFC 9461: %s returned NXDOMAIN (DDR not supported)", srv.name)
				return
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Logf("RFC 9461: %s returned rcode=%s", srv.name, dns.RcodeToString[resp.Rcode])
				return
			}

			for _, rr := range resp.Answer {
				if svcb, ok := rr.(*dns.SVCB); ok {
					t.Logf("RFC 9461: %s SVCB priority=%d target=%s",
						srv.name, svcb.Priority, svcb.Target)
				}
			}

			if len(resp.Answer) == 0 {
				t.Logf("RFC 9461: %s returned NOERROR with 0 answers", srv.name)
			}
		})
	}
}

// TestRFC9461_DDR_WrongType verifies that DDR queries with non-SVCB type
// don't return SVCB records.
func TestRFC9461_DDR_WrongType(t *testing.T) {
	query := makeQuery("_dns.resolver.arpa.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DDR A query: %v", err)
	}

	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.SVCB); ok {
			t.Error("RFC 9461: A query for _dns.resolver.arpa should not return SVCB")
		}
	}
	t.Logf("RFC 9461: A query rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}
