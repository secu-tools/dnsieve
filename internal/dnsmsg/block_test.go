// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package dnsmsg

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func makeQuery(name string, qtype uint16) *dns.Msg {
	return dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
}

func makeReply(query *dns.Msg, rcode int, answers ...dns.RR) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = uint16(rcode)
	resp.Answer = append(resp.Answer, answers...)
	return resp
}

func TestInspectResponse_NilMessage(t *testing.T) {
	result := InspectResponse(nil)
	if !result.ServFail {
		t.Error("nil message should be marked as ServFail")
	}
}

func TestInspectResponse_NormalA(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})

	result := InspectResponse(resp)
	if result.Blocked {
		t.Error("normal A record should not be blocked")
	}
	if result.ServFail {
		t.Error("normal A record should not be ServFail")
	}
}

func TestInspectResponse_BlockedA_ZeroIP(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.A{
		Hdr: dns.Header{Name: "malware.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
	})

	result := InspectResponse(resp)
	if !result.Blocked {
		t.Error("0.0.0.0 A answer should be detected as blocked")
	}
}

func TestInspectResponse_BlockedAAAA_ZeroIP(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeAAAA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.AAAA{
		Hdr:  dns.Header{Name: "malware.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
	})

	result := InspectResponse(resp)
	if !result.Blocked {
		t.Error(":: AAAA answer should be detected as blocked")
	}
}

func TestInspectResponse_NormalAAAA(t *testing.T) {
	query := makeQuery("example.com", dns.TypeAAAA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.AAAA{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")},
	})

	result := InspectResponse(resp)
	if result.Blocked {
		t.Error("normal AAAA record should not be blocked")
	}
}

func TestInspectResponse_SERVFAIL(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeServerFailure)

	result := InspectResponse(resp)
	if !result.ServFail {
		t.Error("SERVFAIL should be detected")
	}
	if result.Blocked {
		t.Error("SERVFAIL should not be treated as blocked")
	}
}

func TestInspectResponse_REFUSED(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeRefused)

	result := InspectResponse(resp)
	if !result.Blocked {
		t.Error("REFUSED should be detected as blocked")
	}
}

func TestInspectResponse_NXDOMAIN_NoAuthority_Quad9Block(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeNameError)

	result := InspectResponse(resp)
	if !result.Blocked {
		t.Error("NXDOMAIN with no authority should be detected as blocked (Quad9 style)")
	}
	if !result.NXDomain {
		t.Error("NXDOMAIN flag should be set")
	}
}

func TestInspectResponse_NXDOMAIN_WithAuthority_Genuine(t *testing.T) {
	query := makeQuery("nonexistent.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeNameError)
	resp.Ns = append(resp.Ns, &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		},
	})

	result := InspectResponse(resp)
	if result.Blocked {
		t.Error("genuine NXDOMAIN with SOA should NOT be blocked")
	}
	if !result.NXDomain {
		t.Error("NXDomain flag should still be set")
	}
}

func TestInspectResponse_NoRecords(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess)

	result := InspectResponse(resp)
	if result.Blocked {
		t.Error("NODATA (no records) should not be blocked by default")
	}
}

func TestInspectResponse_MixedAnswers_OneBlocked(t *testing.T) {
	query := makeQuery("test.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess,
		&dns.A{
			Hdr: dns.Header{Name: "test.example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
		},
		&dns.A{
			Hdr: dns.Header{Name: "test.example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
		},
	)

	result := InspectResponse(resp)
	if !result.Blocked {
		t.Error("response with 0.0.0.0 in answers should be blocked")
	}
}

func TestInspectWireResponse_Valid(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	if err := resp.Pack(); err != nil {
		t.Fatalf("failed to pack: %v", err)
	}
	wire := make([]byte, len(resp.Data))
	copy(wire, resp.Data)

	msg, result := InspectWireResponse(wire)
	if msg == nil {
		t.Fatal("parsed msg should not be nil")
	}
	if result.Blocked {
		t.Error("normal response should not be blocked")
	}
}

func TestInspectWireResponse_Invalid(t *testing.T) {
	_, result := InspectWireResponse([]byte{0xff, 0xff, 0xff})
	if !result.ServFail {
		t.Error("invalid wire data should be treated as ServFail")
	}
}

func TestMakeBlockedResponse_A(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query)

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("blocked A: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("blocked A: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked A: expected EDE Blocked (code 15) in Pseudo section")
	}
}

func TestMakeBlockedResponse_AAAA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeAAAA)
	resp := MakeBlockedResponse(query)

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("blocked AAAA: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("blocked AAAA: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked AAAA: expected EDE Blocked (code 15) in Pseudo section")
	}
}

func TestMakeBlockedResponse_OtherType(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeMX)
	resp := MakeBlockedResponse(query)

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("blocked MX: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("blocked MX: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked MX: expected EDE Blocked (code 15) in Pseudo section")
	}
}

func TestMakeBlockedResponse_EDE(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query)

	var ede *dns.EDE
	for _, rr := range resp.Pseudo {
		if e, ok := rr.(*dns.EDE); ok {
			ede = e
			break
		}
	}
	if ede == nil {
		t.Fatal("expected EDE option in Pseudo section")
	}
	if ede.InfoCode != dns.ExtendedErrorBlocked {
		t.Errorf("EDE InfoCode=%d, want %d (Blocked)", ede.InfoCode, dns.ExtendedErrorBlocked)
	}
	if ede.ExtraText == "" {
		t.Error("EDE ExtraText should not be empty")
	}
}

func TestMakeBlockedResponse_UDPSizeSet(t *testing.T) {
	// UDPSize must be non-zero so the OPT record (with EDE) is included
	// in the wire format before PrepareClientResponse sets the final value.
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query)

	if resp.UDPSize == 0 {
		t.Error("UDPSize should be non-zero so OPT record is always emitted")
	}
}

func TestMakeBlockedResponse_IDEchoed(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	query.ID = 0xABCD
	resp := MakeBlockedResponse(query)

	if resp.ID != query.ID {
		t.Errorf("ID=%04x, want %04x", resp.ID, query.ID)
	}
}

func TestMakeBlockedResponse_RecursionAvailable(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query)

	if !resp.RecursionAvailable {
		t.Error("RA bit should be set in blocked response")
	}
}

func TestMakeBlockedResponse_NoSpoofedIP(t *testing.T) {
	// Verify that neither 0.0.0.0 nor :: appear in any answer record.
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query)

	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if a.Addr == netip.AddrFrom4([4]byte{}) {
				t.Error("blocked response must not include 0.0.0.0 in Answer")
			}
		case *dns.AAAA:
			if a.Addr == netip.IPv6Unspecified() {
				t.Error("blocked response must not include :: in Answer")
			}
		}
	}
}

func TestMakeBlockedResponse_WireRoundTrip(t *testing.T) {
	// Verify the response can be packed and unpacked, preserving EDE.
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query)

	if err := resp.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	wire := make([]byte, len(resp.Data))
	copy(wire, resp.Data)

	got := new(dns.Msg)
	got.Data = wire
	if err := got.Unpack(); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if got.Rcode != dns.RcodeRefused {
		t.Errorf("after roundtrip rcode=%s, want REFUSED", dns.RcodeToString[got.Rcode])
	}
	if !hasEDEBlocked(got) {
		t.Error("after roundtrip: EDE Blocked not preserved in Pseudo section")
	}
}

// hasEDEBlocked is a test helper that reports whether the message contains an
// EDE option with InfoCode == ExtendedErrorBlocked (15).
func hasEDEBlocked(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok && ede.InfoCode == dns.ExtendedErrorBlocked {
			return true
		}
	}
	return false
}

func TestAllServersAgree_AllGenuineNXDOMAIN(t *testing.T) {
	results := []InspectResult{
		{NXDomain: true, Blocked: false},
		{NXDomain: true, Blocked: false},
		{NXDomain: true, Blocked: false},
	}
	if !AllServersAgree(results) {
		t.Error("should agree when all return genuine NXDOMAIN")
	}
}

func TestAllServersAgree_Disagreement(t *testing.T) {
	results := []InspectResult{
		{NXDomain: true, Blocked: false},
		{NXDomain: false, Blocked: false, Rcode: dns.RcodeSuccess},
	}
	if AllServersAgree(results) {
		t.Error("should NOT agree when servers disagree")
	}
}

func TestAllServersAgree_AllOK(t *testing.T) {
	results := []InspectResult{
		{NXDomain: false, Rcode: dns.RcodeSuccess},
		{NXDomain: false, Rcode: dns.RcodeSuccess},
	}
	if AllServersAgree(results) {
		t.Error("should NOT report agreement when none is NXDOMAIN")
	}
}

func TestAllServersAgree_Empty(t *testing.T) {
	if AllServersAgree(nil) {
		t.Error("nil results should not agree")
	}
	if AllServersAgree([]InspectResult{}) {
		t.Error("empty results should not agree")
	}
}

func TestAllServersAgree_SkipsServFail(t *testing.T) {
	results := []InspectResult{
		{NXDomain: true, Blocked: false},
		{ServFail: true},
		{NXDomain: true, Blocked: false},
	}
	if !AllServersAgree(results) {
		t.Error("should agree on NXDOMAIN, skipping ServFail")
	}
}

// TestAllServersAgree_BlockedNXDomain verifies that a Quad9-style blocked
// NXDOMAIN (NXDomain=true AND Blocked=true) is NOT treated as genuine NXDOMAIN
// agreement. The implementation must reject results where Blocked=true even if
// NXDomain=true.
func TestAllServersAgree_BlockedNXDomain(t *testing.T) {
	results := []InspectResult{
		// NXDomain=true but Blocked=true -> Quad9-style block, not genuine NXDOMAIN
		{NXDomain: true, Blocked: true},
		{NXDomain: true, Blocked: true},
	}
	if AllServersAgree(results) {
		t.Error("blocked NXDOMAIN should NOT count as genuine NXDOMAIN agreement")
	}
}

// TestAllServersAgree_MixedBlockedAndGenuine verifies that a mix of blocked
// and genuine NXDOMAIN returns false.
func TestAllServersAgree_MixedBlockedAndGenuine(t *testing.T) {
	results := []InspectResult{
		{NXDomain: true, Blocked: false}, // genuine
		{NXDomain: true, Blocked: true},  // Quad9-style block
	}
	if AllServersAgree(results) {
		t.Error("mix of genuine and blocked NXDOMAIN should not agree")
	}
}

func TestExtractMinTTL_Normal(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess,
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
		},
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 100},
			A:   rdata.A{Addr: netip.MustParseAddr("5.6.7.8")},
		},
	)
	min := ExtractMinTTL(resp)
	if min != 100 {
		t.Errorf("expected min TTL 100, got %d", min)
	}
}

func TestExtractMinTTL_Nil(t *testing.T) {
	if got := ExtractMinTTL(nil); got != 0 {
		t.Errorf("ExtractMinTTL(nil) = %d, want 0", got)
	}
}

func TestExtractMinTTL_NoRecords(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess)
	if got := ExtractMinTTL(resp); got != 0 {
		t.Errorf("ExtractMinTTL(empty) = %d, want 0", got)
	}
}

func TestExtractMinTTL_AuthorityOnly(t *testing.T) {
	query := makeQuery("nonexistent.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeNameError)
	resp.Ns = append(resp.Ns, &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 600},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Minttl: 300},
	})
	got := ExtractMinTTL(resp)
	if got != 600 {
		t.Errorf("ExtractMinTTL(authority only) = %d, want 600", got)
	}
}
