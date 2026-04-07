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

// -- RFC 9460: SVCB and HTTPS Resource Records --

const typeHTTPSRFC9460 uint16 = 65

// TestRFC9460_HTTPSQuery verifies HTTPS RR queries are handled safely.
func TestRFC9460_HTTPSQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("cloudflare.com.", typeHTTPSRFC9460)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 9460 HTTPS query failed: %v", err)
	}

	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeNotImplemented, dns.RcodeRefused:
	default:
		t.Errorf("RFC 9460 HTTPS: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	if err := resp.Pack(); err != nil {
		t.Errorf("RFC 9460 HTTPS: response should remain packable: %v", err)
	}
}

// TestRFC9460_SVCBQuery verifies SVCB RR transport and parser behavior.
func TestRFC9460_SVCBQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery("cloudflare.com.", dns.TypeSVCB)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("RFC 9460 SVCB query failed: %v", err)
	}

	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeNotImplemented, dns.RcodeRefused:
	default:
		t.Errorf("RFC 9460 SVCB: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	if resp.Rcode == dns.RcodeSuccess {
		count := 0
		for _, rr := range resp.Answer {
			typ := dns.RRToType(rr)
			if typ == dns.TypeSVCB || typ == typeHTTPSRFC9460 {
				count++
			}
		}
		t.Logf("RFC 9460: SVCB/HTTPS-like answers observed=%d total_answers=%d", count, len(resp.Answer))
	}
}
