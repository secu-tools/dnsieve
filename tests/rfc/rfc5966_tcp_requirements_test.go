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

// -- RFC 5966: DNS over TCP Requirements --

// TestRFC5966_TCPIsSupported verifies recursive resolvers accept DNS queries
// over TCP for ordinary lookups.
func TestRFC5966_TCPIsSupported(t *testing.T) {
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	for _, server := range servers {
		t.Run(server, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()

			query := makeQuery("example.com.", dns.TypeA)
			resp, _, err := new(dns.Client).Exchange(ctx, query, "tcp", server)
			if err != nil {
				t.Fatalf("RFC 5966 TCP query to %s failed: %v", server, err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("RFC 5966 TCP query to %s rcode=%s", server, dns.RcodeToString[resp.Rcode])
			}
		})
	}
}

// TestRFC5966_UDPTruncationThenTCPRetry verifies behavior for large payloads:
// UDP may truncate, and TCP should return a non-truncated answer.
func TestRFC5966_UDPTruncationThenTCPRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	udpQuery := makeQuery("org.", dns.TypeDNSKEY)
	udpQuery.UDPSize = 512

	udpResp, _, err := new(dns.Client).Exchange(ctx, udpQuery, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 5966 UDP phase failed: %v", err)
	}

	if !udpResp.Truncated {
		t.Logf("RFC 5966: UDP response not truncated (rcode=%s answers=%d)", dns.RcodeToString[udpResp.Rcode], len(udpResp.Answer))
		return
	}

	tcpQuery := makeQuery("org.", dns.TypeDNSKEY)
	tcpResp, _, err := new(dns.Client).Exchange(ctx, tcpQuery, "tcp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("RFC 5966 TCP retry failed: %v", err)
	}
	if tcpResp.Truncated {
		t.Error("RFC 5966: TCP retry should not be truncated")
	}
	if tcpResp.Rcode != dns.RcodeSuccess {
		t.Errorf("RFC 5966: TCP retry rcode=%s", dns.RcodeToString[tcpResp.Rcode])
	}
}
