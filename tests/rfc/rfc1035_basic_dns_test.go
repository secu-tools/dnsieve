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

// -- RFC 1035: Standard DNS --

// TestRFC1035_PlainDNS_UDP tests standard DNS over UDP.
func TestRFC1035_PlainDNS_UDP(t *testing.T) {
	servers := []struct {
		name    string
		address string
	}{
		{"Cloudflare", "1.1.1.1:53"},
		{"Quad9", "9.9.9.9:53"},
		{"Google", "8.8.8.8:53"},
	}

	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			query := makeQuery("example.com.", dns.TypeA)
			resp, rtt, err := new(dns.Client).Exchange(ctx, query, "udp", srv.address)
			if err != nil {
				t.Fatalf("UDP to %s: %v", srv.name, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%s rcode = %s", srv.name, dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) == 0 {
				t.Errorf("%s returned 0 answers", srv.name)
			}
			t.Logf("%s: rcode=%s answers=%d rtt=%v", srv.name, dns.RcodeToString[resp.Rcode], len(resp.Answer), rtt)
		})
	}
}

// TestRFC1035_PlainDNS_TCP tests standard DNS over TCP.
func TestRFC1035_PlainDNS_TCP(t *testing.T) {
	servers := []struct {
		name    string
		address string
	}{
		{"Cloudflare", "1.1.1.1:53"},
		{"Quad9", "9.9.9.9:53"},
	}

	for _, srv := range servers {
		t.Run(srv.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			query := makeQuery("google.com.", dns.TypeTXT)
			resp, _, err := new(dns.Client).Exchange(ctx, query, "tcp", srv.address)
			if err != nil {
				t.Fatalf("TCP to %s: %v", srv.name, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%s rcode = %s", srv.name, dns.RcodeToString[resp.Rcode])
			}
			t.Logf("%s: TCP rcode=%s answers=%d", srv.name, dns.RcodeToString[resp.Rcode], len(resp.Answer))
		})
	}
}

// TestRFC1035_QuestionEcho verifies that the Question section is echoed in responses.
func TestRFC1035_QuestionEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := makeQuery("example.com.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if len(resp.Question) == 0 {
		t.Error("RFC 1035: response should echo the Question section")
	} else if resp.Question[0].Header().Name != "example.com." {
		t.Errorf("RFC 1035: question name = %s, want example.com.", resp.Question[0].Header().Name)
	}
}

// TestRFC1035_RecursionAvailable verifies RA bit in recursive server responses.
func TestRFC1035_RecursionAvailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := makeQuery("example.com.", dns.TypeA)
	query.RecursionDesired = true
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if !resp.RecursionAvailable {
		t.Error("RFC 1035: recursive server should set RA=1")
	}
}

// TestRFC1035_NXDOMAIN verifies NXDOMAIN response for non-existent domain.
func TestRFC1035_NXDOMAIN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := makeQuery("this-domain-does-not-exist-12345.example.", dns.TypeA)
	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("RFC 1035: expected NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
}
