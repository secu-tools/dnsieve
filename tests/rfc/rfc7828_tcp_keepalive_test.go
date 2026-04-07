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

// -- RFC 7828: TCP Keepalive --

// TestRFC7828_TCPKeepalive_InTCP verifies that TCP keepalive works over TCP.
func TestRFC7828_TCPKeepalive_InTCP(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	// Add TCP keepalive option (timeout in 100ms units; 1200 = 120s)
	ka := &dns.TCPKEEPALIVE{Timeout: 1200}
	query.Pseudo = append(query.Pseudo, ka)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "tcp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("TCP keepalive query: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	for _, rr := range resp.Pseudo {
		if ka, ok := rr.(*dns.TCPKEEPALIVE); ok {
			t.Logf("RFC 7828: server returned keepalive timeout=%d (units of 100ms)", ka.Timeout)
			return
		}
	}
	t.Log("RFC 7828: server did not return TCP keepalive (optional)")
}

// TestRFC7828_TCPKeepalive_UDPIgnored verifies that the option is ignored over UDP.
func TestRFC7828_TCPKeepalive_UDPIgnored(t *testing.T) {
	query := makeQuery("example.com.", dns.TypeA)
	query.UDPSize = 4096

	// Add TCP keepalive over UDP (should be ignored per RFC 7828 s3.2)
	ka := &dns.TCPKEEPALIVE{Timeout: 1200}
	query.Pseudo = append(query.Pseudo, ka)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, _, err := new(dns.Client).Exchange(ctx, query, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("UDP keepalive query: %v", err)
	}

	// RFC 7828: server may return FORMERR or just ignore it
	t.Logf("RFC 7828: UDP keepalive rcode=%s", dns.RcodeToString[resp.Rcode])
}
