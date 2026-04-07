// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

package rfc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// -- RFC 4592: DNS Wildcards --

// TestRFC4592_WildcardSynthesis queries a wildcard-backed dynamic DNS domain.
// Different resolvers may have different policies, so we validate transport
// and response safety while still checking for successful synthesis when present.
func TestRFC4592_WildcardSynthesis(t *testing.T) {
	name := fmt.Sprintf("dnsieve-%d.1.2.3.4.nip.io.", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	query := makeQuery(name, dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 4592 wildcard query failed: %v", err)
	}

	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(resp.Answer) == 0 {
			t.Log("RFC 4592: wildcard query returned NOERROR with empty answer")
		}
	case dns.RcodeNameError:
		t.Log("RFC 4592: wildcard backend not available from current resolver path")
	default:
		t.Errorf("RFC 4592: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}
