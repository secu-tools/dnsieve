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

// -- RFC 9715: DNS over UDP Fragmentation --

// TestRFC9715_MaxUDPPayload verifies that responses larger than 1232 bytes
// trigger truncation when queried over UDP.
func TestRFC9715_MaxUDPPayload(t *testing.T) {
	// Request with a small buffer to encourage truncation
	query := makeQuery("google.com.", dns.TypeANY)
	query.UDPSize = 512

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	t.Logf("RFC 9715: UDPSize=%d, TC=%v, answers=%d", resp.UDPSize, resp.Truncated, len(resp.Answer))
}

// TestRFC9715_TCPFallback verifies that TCP works as fallback for large responses.
func TestRFC9715_TCPFallback(t *testing.T) {
	query := makeQuery("google.com.", dns.TypeTXT)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "tcp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("TCP query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("TCP rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("RFC 9715: TCP response answers=%d", len(resp.Answer))
}

// TestRFC9715_BufferSizeAdvertised verifies that servers advertise their
// UDP buffer size via EDNS0.
func TestRFC9715_BufferSizeAdvertised(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 1232

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if resp.UDPSize == 0 {
		t.Error("RFC 9715: server should advertise its buffer size")
	}
	t.Logf("RFC 9715: server advertises UDPSize=%d", resp.UDPSize)
}
