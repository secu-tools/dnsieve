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

// -- RFC 4343: Case Insensitivity --

// TestRFC4343_CaseInsensitivity verifies that DNS is case-insensitive per RFC 4343.
func TestRFC4343_CaseInsensitivity(t *testing.T) {
	variants := []string{
		"example.com.",
		"EXAMPLE.COM.",
		"Example.Com.",
		"eXaMpLe.CoM.",
	}

	for _, name := range variants {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			query := makeQuery(name, dns.TypeA)
			resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
			if err != nil {
				t.Fatalf("query for %s: %v", name, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("RFC 4343: %s rcode = %s, want NOERROR", name, dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) == 0 {
				t.Errorf("RFC 4343: %s returned 0 answers", name)
			}
		})
	}
}
