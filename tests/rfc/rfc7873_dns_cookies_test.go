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

// -- RFC 7873: DNS Cookies --

// TestRFC7873_CookieInResponse tests that cookie-capable servers respond
// with a DNS cookie when we include one in the query.
func TestRFC7873_CookieInResponse(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	// Add a client cookie (8 bytes = 16 hex chars)
	cookie := &dns.COOKIE{Cookie: "0123456789abcdef"}
	query.Pseudo = append(query.Pseudo, cookie)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("cookie query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	foundCookie := false
	for _, rr := range resp.Pseudo {
		if c, ok := rr.(*dns.COOKIE); ok {
			foundCookie = true
			if len(c.Cookie) <= 16 {
				t.Error("RFC 7873: server cookie response should include server cookie (>16 hex chars)")
			}
			t.Logf("RFC 7873: cookie response length=%d chars", len(c.Cookie))
			break
		}
	}
	if !foundCookie {
		t.Log("RFC 7873: server did not return cookie (not all servers support cookies)")
	}
}

// TestRFC7873_NoCookieStillWorks tests that queries without cookies work.
func TestRFC7873_NoCookieStillWorks(t *testing.T) {
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
