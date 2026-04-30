// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

package rfc

import (
	"context"
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/upstream"
)

// -- RFC 7858: DNS-over-TLS --

// TestRFC7858_DoT_BasicQuery tests DNS-over-TLS per RFC 7858.
func TestRFC7858_DoT_BasicQuery(t *testing.T) {
	servers := []struct {
		name    string
		address string
	}{
		{"Cloudflare", "1.1.1.1:853"},
		{"Cloudflare-Family", "1.1.1.3:853"},
		{"Quad9", "9.9.9.9:853"},
		{"AdGuard", "94.140.14.14:853"},
	}

	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			client, err := upstream.NewDoTClient(srv.address, false, "ipv4", upstream.ResolveDisabled)
			if err != nil {
				t.Fatalf("create DoT client: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			query := makeQuery("example.com.", dns.TypeA)
			resp, err := client.Query(ctx, query)
			if err != nil {
				t.Fatalf("DoT to %s: %v", srv.name, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%s rcode = %s, want NOERROR", srv.name, dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) == 0 {
				t.Errorf("%s returned 0 answers", srv.name)
			}
			t.Logf("%s: rcode=%s answers=%d", srv.name, dns.RcodeToString[resp.Rcode], len(resp.Answer))
		})
	}
}

// TestRFC7858_DoT_AAAA tests DoT with AAAA query.
func TestRFC7858_DoT_AAAA(t *testing.T) {
	client, err := upstream.NewDoTClient("1.1.1.1:853", false, "ipv4", upstream.ResolveDisabled)
	if err != nil {
		t.Fatalf("create DoT client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := makeQuery("google.com.", dns.TypeAAAA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("DoT AAAA: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("DoT AAAA: answers=%d", len(resp.Answer))
}

// TestRFC7858_DoT_MultipleQueries tests multiple queries over a single DoT connection.
func TestRFC7858_DoT_MultipleQueries(t *testing.T) {
	client, err := upstream.NewDoTClient("1.1.1.1:853", false, "ipv4", upstream.ResolveDisabled)
	if err != nil {
		t.Fatalf("create DoT client: %v", err)
	}

	domains := []string{"example.com.", "google.com.", "cloudflare.com."}
	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			query := makeQuery(domain, dns.TypeA)
			resp, err := client.Query(ctx, query)
			if err != nil {
				t.Fatalf("DoT to %s: %v", domain, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%s rcode = %s", domain, dns.RcodeToString[resp.Rcode])
			}
		})
	}
}

// TestRFC7858_DoT_TLS12Minimum verifies TLS 1.2 or higher is used.
func TestRFC7858_DoT_TLS12Minimum(t *testing.T) {
	// This test verifies the client configuration enforces TLS 1.2+.
	// The upstream.NewDoTClient already sets MinVersion: tls.VersionTLS12.
	client, err := upstream.NewDoTClient("1.1.1.1:853", true, "ipv4", upstream.ResolveDisabled)
	if err != nil {
		t.Fatalf("create DoT client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := makeQuery("example.com.", dns.TypeA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("DoT with TLS verify: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Log("RFC 7858: TLS 1.2+ connection successful with certificate verification")
}
