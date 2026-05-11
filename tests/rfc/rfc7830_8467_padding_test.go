// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build rfc

package rfc

import (
	"context"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// -- RFC 7830 / RFC 8467: EDNS(0) Padding --

// TestRFC7830_Padding_QueryAccepted tests that public DoH resolvers accept
// a DNS query containing an EDNS(0) PADDING option without returning an error.
// The padding option is option code 12 (0xC) per RFC 7830.
func TestRFC7830_Padding_QueryAccepted(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.RecursionDesired = true
	query.ID = 0 // RFC 8484 s4.1
	query.UDPSize = 4096
	// Add PADDING option with zero bytes (minimum valid padding)
	query.Pseudo = append(query.Pseudo, &dns.PADDING{Padding: ""})

	if err := query.Pack(); err != nil {
		t.Fatalf("pack padded query: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wireResp, err := dohPost(ctx, "https://cloudflare-dns.com", query.Data)
	if err != nil {
		t.Skipf("DoH unreachable (network): %v", err)
	}

	resp := parseResponse(t, "cloudflare-dns.com", wireResp)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("RFC 7830: padded query returned rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Error("RFC 7830: padded query returned no answers")
	}
	t.Logf("RFC 7830: padded query accepted, rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestRFC7830_Padding_128ByteBlockQuery tests that a query padded to a
// 128-byte block boundary (RFC 8467 s4.1) is accepted by a public DoH server.
func TestRFC7830_Padding_128ByteBlockQuery(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.RecursionDesired = true
	query.ID = 0
	query.UDPSize = 4096

	// Pack first to measure the current size, then add padding to 128-byte block
	if err := query.Pack(); err != nil {
		t.Fatalf("pack base query: %v", err)
	}
	size := len(query.Data)
	query.Data = nil

	const block = 128
	paddingData := (block - (size+4)%block) % block
	query.Pseudo = append(query.Pseudo, &dns.PADDING{
		Padding: strings.Repeat("00", paddingData),
	})

	// Verify alignment before sending
	if err := query.Pack(); err != nil {
		t.Fatalf("pack padded query: %v", err)
	}
	if len(query.Data)%block != 0 {
		t.Fatalf("pre-send check: padded query size = %d, not a multiple of %d", len(query.Data), block)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wireResp, err := dohPost(ctx, "https://cloudflare-dns.com", query.Data)
	if err != nil {
		t.Skipf("DoH unreachable (network): %v", err)
	}

	resp := parseResponse(t, "cloudflare-dns.com", wireResp)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("RFC 8467: 128-byte block query returned rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("RFC 8467 s4.1: 128-byte block padded query accepted, size=%d answers=%d",
		len(query.Data), len(resp.Answer))
}

// TestRFC7830_Padding_OptionCode verifies that the PADDING option code is 12
// (0xC) as specified in RFC 7830 section 4.
func TestRFC7830_Padding_OptionCode(t *testing.T) {
	const wantCode = uint16(0xC)
	if dns.CodePADDING != wantCode {
		t.Errorf("RFC 7830: PADDING option code = 0x%X, want 0x%X", dns.CodePADDING, wantCode)
	}
	t.Logf("RFC 7830: PADDING option code = 0x%X (correct)", dns.CodePADDING)
}

// TestRFC7830_Padding_ResponseFromCloudflare tests that Cloudflare DoH
// responds to padded queries without error. Note: not all resolvers echo
// back padding in their responses; this test only checks for a valid reply.
func TestRFC7830_Padding_ResponseFromCloudflare(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.RecursionDesired = true
	query.ID = 0
	query.UDPSize = 4096
	query.Pseudo = append(query.Pseudo, &dns.PADDING{Padding: ""})

	if err := query.Pack(); err != nil {
		t.Fatalf("pack padded query: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wireResp, err := dohPost(ctx, "https://1.1.1.1", query.Data)
	if err != nil {
		t.Skipf("DoH unreachable (network): %v", err)
	}

	resp := parseResponse(t, "1.1.1.1", wireResp)
	verifyDOHResponse(t, "1.1.1.1 (padded query)", resp)

	// Log whether the server echoed padding back
	hasPad := false
	for _, rr := range resp.Pseudo {
		if _, ok := rr.(*dns.PADDING); ok {
			hasPad = true
			break
		}
	}
	t.Logf("RFC 7830: Cloudflare 1.1.1.1 echoed padding = %v (informational, not all servers do)", hasPad)
}

// TestRFC8467_Padding_Quad9 tests that Quad9 DoH accepts padded queries.
func TestRFC8467_Padding_Quad9(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.RecursionDesired = true
	query.ID = 0
	query.UDPSize = 4096
	query.Pseudo = append(query.Pseudo, &dns.PADDING{Padding: ""})

	if err := query.Pack(); err != nil {
		t.Fatalf("pack padded query: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	wireResp, err := dohPost(ctx, "https://dns.quad9.net", query.Data)
	if err != nil {
		t.Skipf("DoH unreachable (network): %v", err)
	}

	resp := parseResponse(t, "dns.quad9.net", wireResp)
	verifyDOHResponse(t, "dns.quad9.net (padded query)", resp)
	t.Logf("RFC 8467: Quad9 accepted padded query, rcode=%s answers=%d",
		dns.RcodeToString[resp.Rcode], len(resp.Answer))
}
