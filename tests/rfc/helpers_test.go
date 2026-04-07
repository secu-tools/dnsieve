// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

// Package rfc contains DNSieve RFC compliance tests.
// These tests require network access and perform round-trip DNS queries
// to public resolvers to verify protocol compliance.
//
// Run with: go test -tags rfc ./tests/rfc/ -v
package rfc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	rdata "codeberg.org/miekg/dns/rdata"
)

// -- helpers --

// packQuery packs a DNS message into wire format.
func packQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	query := dnsutil.SetQuestion(new(dns.Msg), name, qtype)
	query.RecursionDesired = true
	query.ID = 0 // RFC 8484 s4.1: DNS ID is set to 0 for DoH
	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return query.Data
}

// dohPost sends a DNS wire-format query via HTTP POST and returns the body.
func dohPost(ctx context.Context, url string, wireQuery []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wireQuery))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		return nil, fmt.Errorf("Content-Type %q, want application/dns-message", ct)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

// parseResponse unpacks a DNS wire-format response.
func parseResponse(t *testing.T, serverName string, body []byte) *dns.Msg {
	t.Helper()
	resp := new(dns.Msg)
	resp.Data = body
	if err := resp.Unpack(); err != nil {
		t.Fatalf("unpack from %s: %v", serverName, err)
	}
	return resp
}

// verifyDOHResponse asserts a successful DNS response with at least one answer.
func verifyDOHResponse(t *testing.T, serverName string, dnsResp *dns.Msg) {
	t.Helper()
	if dnsResp.Rcode != dns.RcodeSuccess {
		t.Errorf("%s rcode = %s, want NOERROR", serverName, dns.RcodeToString[dnsResp.Rcode])
	}
	if len(dnsResp.Answer) == 0 {
		t.Errorf("%s returned 0 answers for example.com A", serverName)
	}
	t.Logf("%s: rcode=%s answers=%d", serverName, dns.RcodeToString[dnsResp.Rcode], len(dnsResp.Answer))
}

// makeQuery creates a standard DNS query. For unknown qtypes not recognized by
// the library, it uses dns.RFC3597 to construct the question manually.
func makeQuery(name string, qtype uint16) *dns.Msg {
	q := dnsutil.SetQuestion(new(dns.Msg), name, qtype)
	if q != nil {
		q.RecursionDesired = true
		return q
	}
	// dnsutil.SetQuestion returns nil for unknown qtypes; build manually.
	q = new(dns.Msg)
	q.ID = dns.ID()
	q.RecursionDesired = true
	q.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET},
		RFC3597: rdata.RFC3597{RRType: qtype},
	}}
	return q
}
