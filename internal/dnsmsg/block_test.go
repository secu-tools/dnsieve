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

func TestMakeBlockedResponse_NullMode_A(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "dns.quad9.net")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("null mode A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("null mode A: expected 1 answer record, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("null mode A: expected *dns.A, got %T", resp.Answer[0])
	}
	if a.Addr != netip.AddrFrom4([4]byte{0, 0, 0, 0}) {
		t.Errorf("null mode A: addr=%s, want 0.0.0.0", a.Addr)
	}
	if !hasEDEBlocked(resp) {
		t.Error("null mode A: expected EDE Blocked (code 15)")
	}
}

func TestMakeBlockedResponse_NullMode_AAAA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeAAAA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "dns.quad9.net")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("null mode AAAA: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("null mode AAAA: expected 1 answer record, got %d", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("null mode AAAA: expected *dns.AAAA, got %T", resp.Answer[0])
	}
	if aaaa.Addr != netip.IPv6Unspecified() {
		t.Errorf("null mode AAAA: addr=%s, want ::", aaaa.Addr)
	}
	if !hasEDEBlocked(resp) {
		t.Error("null mode AAAA: expected EDE Blocked (code 15)")
	}
}

func TestMakeBlockedResponse_NullMode_MX_NODATA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeMX)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("null mode MX: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("null mode MX: expected no answer records (NODATA), got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("null mode MX: expected EDE Blocked (code 15)")
	}
}

func TestMakeBlockedResponse_NullMode_TXT_NODATA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeTXT)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("null mode TXT: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("null mode TXT: expected NODATA, got %d answers", len(resp.Answer))
	}
}

func TestMakeBlockedResponse_NXDomainMode_A(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "security.cloudflare-dns.com")

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("nxdomain mode A: rcode=%s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("nxdomain mode A: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("nxdomain mode A: expected EDE Blocked (code 15)")
	}
}

func TestMakeBlockedResponse_NXDomainMode_AAAA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeAAAA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "")

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("nxdomain mode AAAA: rcode=%s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("nxdomain mode AAAA: expected no answers, got %d", len(resp.Answer))
	}
}

func TestMakeBlockedResponse_NODATAMode_A(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNODATA, "dns.quad9.net")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("nodata mode A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("nodata mode A: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("nodata mode A: expected EDE Blocked (code 15)")
	}
}

func TestMakeBlockedResponse_NODATAMode_AAAA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeAAAA)
	resp := MakeBlockedResponse(query, BlockingModeNODATA, "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("nodata mode AAAA: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("nodata mode AAAA: expected no answers, got %d", len(resp.Answer))
	}
}

func TestMakeBlockedResponse_RefusedMode_A(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeRefused, "dns.quad9.net")

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("refused mode A: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("refused mode A: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("refused mode A: expected EDE Blocked (code 15)")
	}
}

func TestMakeBlockedResponse_RefusedMode_AAAA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeAAAA)
	resp := MakeBlockedResponse(query, BlockingModeRefused, "")

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("refused mode AAAA: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("refused mode AAAA: expected no answers, got %d", len(resp.Answer))
	}
}

func TestMakeBlockedResponse_EDE_WithBlockedBy(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "dns.quad9.net")

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
	want := "Blocked (dns.quad9.net)"
	if ede.ExtraText != want {
		t.Errorf("EDE ExtraText=%q, want %q", ede.ExtraText, want)
	}
}

func TestMakeBlockedResponse_EDE_WithoutBlockedBy(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

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
	if ede.ExtraText != "Blocked" {
		t.Errorf("EDE ExtraText=%q, want \"Blocked\"", ede.ExtraText)
	}
}

func TestMakeBlockedResponse_EDE_AllModes(t *testing.T) {
	modes := []string{BlockingModeNull, BlockingModeNXDomain, BlockingModeNODATA, BlockingModeRefused}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			query := makeQuery("blocked.example.com", dns.TypeA)
			resp := MakeBlockedResponse(query, mode, "test-upstream")

			if !hasEDEBlocked(resp) {
				t.Errorf("mode %s: expected EDE Blocked (code 15)", mode)
			}
		})
	}
}

func TestMakeBlockedResponse_UDPSizeSet(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if resp.UDPSize == 0 {
		t.Error("UDPSize should be non-zero so OPT record is always emitted")
	}
}

func TestMakeBlockedResponse_IDEchoed(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	query.ID = 0xABCD
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if resp.ID != query.ID {
		t.Errorf("ID=%04x, want %04x", resp.ID, query.ID)
	}
}

func TestMakeBlockedResponse_RecursionAvailable(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if !resp.RecursionAvailable {
		t.Error("RA bit should be set in blocked response")
	}
}

func TestMakeBlockedResponse_NullMode_CNAME_NODATA(t *testing.T) {
	// CNAME queries should get NODATA in null mode (no synthesized records).
	query := makeQuery("blocked.example.com", dns.TypeCNAME)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("null mode CNAME: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("null mode CNAME: expected NODATA, got %d answers", len(resp.Answer))
	}
}

func TestMakeBlockedResponse_NullMode_SRV_NODATA(t *testing.T) {
	query := makeQuery("_sip._tcp.blocked.example.com", dns.TypeSRV)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("null mode SRV: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("null mode SRV: expected NODATA, got %d answers", len(resp.Answer))
	}
}

func TestMakeBlockedResponse_DefaultMode_FallsBackToNull(t *testing.T) {
	// An empty string mode should default to null behavior.
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, "", "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("default mode A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("default mode A: expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("default mode A: expected *dns.A, got %T", resp.Answer[0])
	}
	if a.Addr != netip.AddrFrom4([4]byte{0, 0, 0, 0}) {
		t.Errorf("default mode A: addr=%s, want 0.0.0.0", a.Addr)
	}
}

func TestMakeBlockedResponse_WireRoundTrip_AllModes(t *testing.T) {
	modes := []struct {
		mode  string
		rcode uint16
	}{
		{BlockingModeNull, dns.RcodeSuccess},
		{BlockingModeNXDomain, dns.RcodeNameError},
		{BlockingModeNODATA, dns.RcodeSuccess},
		{BlockingModeRefused, dns.RcodeRefused},
	}
	for _, tc := range modes {
		t.Run(tc.mode, func(t *testing.T) {
			query := makeQuery("blocked.example.com", dns.TypeA)
			resp := MakeBlockedResponse(query, tc.mode, "test-upstream")

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
			if got.Rcode != tc.rcode {
				t.Errorf("after roundtrip rcode=%s, want %s",
					dns.RcodeToString[got.Rcode], dns.RcodeToString[tc.rcode])
			}
			if !hasEDEBlocked(got) {
				t.Error("after roundtrip: EDE Blocked not preserved")
			}
		})
	}
}

func TestMakeBlockedResponse_NullMode_CorrectName(t *testing.T) {
	// Verify the synthesized answer record uses the correct query name.
	query := makeQuery("specific.blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	if resp.Answer[0].Header().Name != "specific.blocked.example.com." {
		t.Errorf("answer name=%s, want specific.blocked.example.com.",
			resp.Answer[0].Header().Name)
	}
}

func TestMakeBlockedResponse_NullMode_TTL(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	if resp.Answer[0].Header().TTL != blockedTTL {
		t.Errorf("answer TTL=%d, want %d", resp.Answer[0].Header().TTL, blockedTTL)
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

// --- HasDNSSEC detection (RFC 3225 / RFC 4034) ---

// TestInspectResponse_HasDNSSEC_False_Normal verifies that a plain A response
// without RRSIG records and without the AD bit is not tagged as HasDNSSEC.
func TestInspectResponse_HasDNSSEC_False_Normal(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})

	result := InspectResponse(resp)
	if result.HasDNSSEC {
		t.Error("plain A response without RRSIG/AD should have HasDNSSEC=false")
	}
}

// TestInspectResponse_HasDNSSEC_ADSet verifies that a response with the
// AD (Authenticated Data) bit set is tagged HasDNSSEC=true. AD=1 means
// the upstream validated the full DNSSEC chain.
func TestInspectResponse_HasDNSSEC_ADSet(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	resp.AuthenticatedData = true

	result := InspectResponse(resp)
	if !result.HasDNSSEC {
		t.Error("response with AD=1 should have HasDNSSEC=true")
	}
}

// TestInspectResponse_HasDNSSEC_RRSIGInAnswer verifies that a response with
// RRSIG records in the Answer section is tagged HasDNSSEC=true.
func TestInspectResponse_HasDNSSEC_RRSIGInAnswer(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess,
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
		},
		&dns.RRSIG{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			RRSIG: rdata.RRSIG{
				TypeCovered: dns.TypeA,
				Algorithm:   8, // RSA/SHA-256
				Labels:      2,
				OrigTTL:     300,
				SignerName:  "example.com.",
			},
		},
	)

	result := InspectResponse(resp)
	if !result.HasDNSSEC {
		t.Error("response with RRSIG in Answer should have HasDNSSEC=true")
	}
	if result.Blocked {
		t.Error("RRSIG-carrying response should not be blocked")
	}
}

// TestInspectResponse_HasDNSSEC_RRSIGInAuthority verifies that a response
// with RRSIG in the Authority section (e.g., NSEC/NSEC3 denial proofs) is
// tagged HasDNSSEC=true.
func TestInspectResponse_HasDNSSEC_RRSIGInAuthority(t *testing.T) {
	query := makeQuery("nonexistent.example.com", dns.TypeA)
	// Genuine NXDOMAIN with SOA + RRSIG covering the SOA in Authority
	resp := makeReply(query, dns.RcodeNameError)
	resp.Ns = append(resp.Ns,
		&dns.SOA{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
			SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com."},
		},
		&dns.RRSIG{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
			RRSIG: rdata.RRSIG{
				TypeCovered: dns.TypeSOA,
				Algorithm:   8,
				Labels:      2,
				OrigTTL:     900,
				SignerName:  "example.com.",
			},
		},
	)

	result := InspectResponse(resp)
	if !result.HasDNSSEC {
		t.Error("NXDOMAIN response with RRSIG in Authority should have HasDNSSEC=true")
	}
	if result.Blocked {
		t.Error("genuine NXDOMAIN with SOA+RRSIG should not be blocked")
	}
	if !result.NXDomain {
		t.Error("NXDomain flag should be set")
	}
}

// TestInspectResponse_HasDNSSEC_SERVFAIL_False verifies that SERVFAIL
// responses are never tagged HasDNSSEC, even if the message somehow carries
// an AD bit (SERVFAIL is returned before DNSSEC detection runs).
func TestInspectResponse_HasDNSSEC_SERVFAIL_False(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeServerFailure)
	resp.AuthenticatedData = true // ignored for SERVFAIL

	result := InspectResponse(resp)
	if result.HasDNSSEC {
		t.Error("SERVFAIL response should never have HasDNSSEC=true")
	}
	if !result.ServFail {
		t.Error("should be ServFail")
	}
}

// TestInspectResponse_HasDNSSEC_Refused verifies that a REFUSED (blocked)
// response with AD=1 still has HasDNSSEC=true; the proxy can record both
// facts but the blocked flag takes precedence in upstream selection.
func TestInspectResponse_HasDNSSEC_Refused_WithAD(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeRefused)
	resp.AuthenticatedData = true

	result := InspectResponse(resp)
	if !result.Blocked {
		t.Error("REFUSED should be blocked")
	}
	if !result.HasDNSSEC {
		t.Error("REFUSED + AD=1 should still record HasDNSSEC=true")
	}
}

// TestInspectResponse_HasDNSSEC_OnlyAnswer verifies RRSIG only in Answer
// (not Authority) is still detected.
func TestInspectResponse_HasDNSSEC_NoRRSIG_OnlySOA(t *testing.T) {
	query := makeQuery("nonexistent.example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeNameError)
	resp.Ns = append(resp.Ns, &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com."},
	})
	// SOA without RRSIG — unsigned NXDOMAIN

	result := InspectResponse(resp)
	if result.HasDNSSEC {
		t.Error("NXDOMAIN with SOA but no RRSIG should have HasDNSSEC=false")
	}
}

// =============================================================================
// F-02: BADCOOKIE (RFC 7873) tests
// =============================================================================

// TestInspectResponse_BADCOOKIE_TreatedAsServFail verifies that RCODE 23
// (BADCOOKIE) is treated as a server failure so it is never cached or
// selected as a valid upstream response.
func TestInspectResponse_BADCOOKIE_TreatedAsServFail(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, int(dns.RcodeBadCookie))

	result := InspectResponse(resp)
	if !result.ServFail {
		t.Error("BADCOOKIE should be treated as ServFail")
	}
	if result.Blocked {
		t.Error("BADCOOKIE should not be treated as blocked")
	}
}

// TestInspectResponse_BADCOOKIE_NotBlocked verifies BADCOOKIE is not
// misclassified as a block signal.
func TestInspectResponse_BADCOOKIE_NotBlocked(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, int(dns.RcodeBadCookie))
	// Add some answer records to ensure the block-IP check path isn't reached
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})

	result := InspectResponse(resp)
	if !result.ServFail {
		t.Error("BADCOOKIE should be ServFail even with answer records")
	}
	if result.Blocked {
		t.Error("BADCOOKIE should not be blocked")
	}
}

// TestInspectResponse_BADCOOKIE_HasDNSSEC_False verifies BADCOOKIE does not
// trigger DNSSEC detection.
func TestInspectResponse_BADCOOKIE_HasDNSSEC_False(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, int(dns.RcodeBadCookie))
	resp.AuthenticatedData = true

	result := InspectResponse(resp)
	if result.HasDNSSEC {
		t.Error("BADCOOKIE response should not have HasDNSSEC=true")
	}
}

// =============================================================================
// Additional InspectResponse edge cases
// =============================================================================

// TestInspectResponse_FORMERR verifies format error responses are not
// classified as blocked or ServFail.
func TestInspectResponse_FORMERR(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeFormatError)

	result := InspectResponse(resp)
	if result.ServFail {
		t.Error("FORMERR should not be ServFail")
	}
	if result.Blocked {
		t.Error("FORMERR should not be blocked")
	}
	if result.NXDomain {
		t.Error("FORMERR should not be NXDomain")
	}
}

// TestInspectResponse_NOTIMPL verifies NOTIMPL responses.
func TestInspectResponse_NOTIMPL(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeNotImplemented)

	result := InspectResponse(resp)
	if result.ServFail {
		t.Error("NOTIMPL should not be ServFail")
	}
	if result.Blocked {
		t.Error("NOTIMPL should not be blocked")
	}
}

// TestAllServersAgree_MixedGenuineAndBlocked verifies that AllServersAgree
// returns false when responses disagree about block status.
func TestAllServersAgree_MixedGenuineAndBlocked(t *testing.T) {
	// One genuine NXDOMAIN (with SOA), one blocked NXDOMAIN (without SOA)
	results := []InspectResult{
		{NXDomain: true, Blocked: false}, // genuine
		{NXDomain: true, Blocked: true},  // blocked
	}
	if AllServersAgree(results) {
		t.Error("servers should not agree when one is blocked and one is genuine")
	}
}

// TestAllServersAgree_AllGenuine verifies all genuine NXDOMAINs agree.
func TestAllServersAgree_AllGenuine(t *testing.T) {
	results := []InspectResult{
		{NXDomain: true, Blocked: false},
		{NXDomain: true, Blocked: false},
	}
	if !AllServersAgree(results) {
		t.Error("servers should agree when all are genuine NXDOMAIN")
	}
}

// TestExtractMinTTL_EmptyMessage verifies ExtractMinTTL returns 0 for
// messages with no records.
func TestExtractMinTTL_EmptyMessage(t *testing.T) {
	msg := new(dns.Msg)
	if ttl := ExtractMinTTL(msg); ttl != 0 {
		t.Errorf("expected 0 for empty message, got %d", ttl)
	}
}

// TestExtractMinTTL_MultipleRecords verifies min TTL extraction.
func TestExtractMinTTL_MultipleRecords(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeReply(query, dns.RcodeSuccess,
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
		},
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("5.6.7.8")},
		},
	)
	if ttl := ExtractMinTTL(resp); ttl != 60 {
		t.Errorf("expected 60, got %d", ttl)
	}
}

// TestMakeBlockedResponse_PreservesQueryID verifies the blocked response
// carries the query's transaction ID.
func TestMakeBlockedResponse_PreservesQueryID(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	query.ID = 12345

	resp := MakeBlockedResponse(query, BlockingModeNull, "test-upstream")
	if resp.ID != 12345 {
		t.Errorf("expected ID=12345, got %d", resp.ID)
	}
}

// TestMakeBlockedResponse_HasEDERecord verifies that blocked responses include
// an EDE pseudo-record (RFC 8914).
func TestMakeBlockedResponse_HasEDERecord(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "")

	hasEDE := false
	for _, rr := range resp.Pseudo {
		if _, ok := rr.(*dns.EDE); ok {
			hasEDE = true
			break
		}
	}
	if !hasEDE {
		t.Error("blocked response should include an EDE record")
	}
}

// TestMakeBlockedResponse_InvalidMode verifies that an unknown blocking mode
// defaults to null-route (RcodeSuccess with 0.0.0.0 answer).
func TestMakeBlockedResponse_InvalidMode(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, "invalid_mode", "")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("unknown mode should default to null-route (NOERROR), got %s",
			dns.RcodeToString[resp.Rcode])
	}
}

// --- RFC 2308: Negative caching SOA in blocked responses ---

// TestMakeBlockedResponse_NXDOMAIN_HasSOA verifies that NXDOMAIN blocked
// responses include a synthesized SOA in the Authority section per RFC 2308.
func TestMakeBlockedResponse_NXDOMAIN_HasSOA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "upstream")

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("NXDOMAIN mode: rcode=%s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Ns) == 0 {
		t.Fatal("RFC 2308: NXDOMAIN blocked response must include SOA in Authority section")
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("Authority record should be SOA, got %T", resp.Ns[0])
	}
	if soa.Ns == "" {
		t.Error("synthesized SOA must have a non-empty MNAME")
	}
	if soa.Minttl == 0 {
		t.Error("synthesized SOA MINIMUM must be non-zero for negative caching TTL")
	}
	if soa.Header().TTL != blockedSOATTL {
		t.Errorf("SOA TTL = %d, want %d", soa.Header().TTL, blockedSOATTL)
	}
	if soa.Header().Name != "blocked.example.com." {
		t.Errorf("SOA owner = %s, want blocked.example.com.", soa.Header().Name)
	}
}

// TestMakeBlockedResponse_NODATA_HasSOA verifies that NODATA blocked
// responses include a synthesized SOA in the Authority section per RFC 2308.
func TestMakeBlockedResponse_NODATA_HasSOA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNODATA, "upstream")

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("NODATA mode: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Error("NODATA mode: answer section must be empty")
	}
	if len(resp.Ns) == 0 {
		t.Fatal("RFC 2308: NODATA blocked response must include SOA in Authority section")
	}
	if _, ok := resp.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("NODATA Authority record should be SOA, got %T", resp.Ns[0])
	}
}

// TestMakeBlockedResponse_Null_NoSOA verifies that null-mode blocked
// responses do NOT include a spurious SOA (they have a synthesized answer).
func TestMakeBlockedResponse_Null_NoSOA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNull, "upstream")

	if len(resp.Ns) != 0 {
		t.Error("null-mode blocked response should not include Authority section SOA")
	}
}

// TestMakeBlockedResponse_Refused_NoSOA verifies that refused-mode blocked
// responses do NOT include a spurious SOA.
func TestMakeBlockedResponse_Refused_NoSOA(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeRefused, "upstream")

	if len(resp.Ns) != 0 {
		t.Error("refused-mode blocked response should not include Authority section SOA")
	}
}

// TestMakeBlockedResponse_NXDOMAIN_NoQuestion_NoSOA verifies that if the
// query has no question section, no SOA is added (safe fallback).
func TestMakeBlockedResponse_NXDOMAIN_NoQuestion_NoSOA(t *testing.T) {
	query := new(dns.Msg)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "upstream")

	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode=%s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	// No SOA should be synthesized when there is no question
	if len(resp.Ns) != 0 {
		t.Error("no SOA should be synthesized when query has no question section")
	}
}

// TestMakeBlockedResponse_NXDOMAIN_SOA_WireRoundTrip verifies that the
// synthesized SOA in an NXDOMAIN blocked response survives Pack/Unpack.
// Per RFC 2308, the SOA must be present and readable by downstream resolvers
// that rely on the MINIMUM field for negative caching TTL.
func TestMakeBlockedResponse_NXDOMAIN_SOA_WireRoundTrip(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "")

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

	if len(got.Ns) == 0 {
		t.Fatal("SOA should be present in Authority section after roundtrip")
	}
	soa, ok := got.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("first Authority RR type=%T, want *dns.SOA", got.Ns[0])
	}
	if soa.Minttl != blockedSOATTL {
		t.Errorf("SOA Minttl=%d, want %d (blockedSOATTL)", soa.Minttl, blockedSOATTL)
	}
}

// TestMakeBlockedResponse_NODATA_SOA_WireRoundTrip verifies that the SOA in
// a NODATA (NOERROR empty) blocked response also survives Pack/Unpack.
func TestMakeBlockedResponse_NODATA_SOA_WireRoundTrip(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNODATA, "")

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

	if len(got.Ns) == 0 {
		t.Fatal("SOA should be present in Authority section after roundtrip")
	}
	if _, ok := got.Ns[0].(*dns.SOA); !ok {
		t.Fatalf("first Authority RR type=%T, want *dns.SOA", got.Ns[0])
	}
}

// TestMakeBlockedResponse_NXDOMAIN_SOA_MinimumTTL verifies that the
// synthesized SOA has its Minttl field set to blockedSOATTL so that
// RFC 2308-compliant downstream caches negative-cache for the correct TTL.
func TestMakeBlockedResponse_NXDOMAIN_SOA_MinimumTTL(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "")

	if len(resp.Ns) == 0 {
		t.Fatal("expected SOA in Authority section")
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("Authority[0] type=%T, want *dns.SOA", resp.Ns[0])
	}
	if soa.Hdr.TTL != blockedSOATTL {
		t.Errorf("SOA Hdr.TTL=%d, want %d", soa.Hdr.TTL, blockedSOATTL)
	}
	if soa.Minttl != blockedSOATTL {
		t.Errorf("SOA Minttl=%d, want %d", soa.Minttl, blockedSOATTL)
	}
}

// TestMakeBlockedResponse_NXDOMAIN_SOA_OwnerMatchesQuery verifies that the
// synthesized SOA owner name matches the queried domain name.
func TestMakeBlockedResponse_NXDOMAIN_SOA_OwnerMatchesQuery(t *testing.T) {
	query := makeQuery("evil.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "")

	if len(resp.Ns) == 0 {
		t.Fatal("expected SOA in Authority section")
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("Authority[0] type=%T, want *dns.SOA", resp.Ns[0])
	}
	if soa.Hdr.Name != "evil.example.com." {
		t.Errorf("SOA owner=%q, want %q", soa.Hdr.Name, "evil.example.com.")
	}
}

// TestMakeBlockedResponse_NXDOMAIN_SOA_SyntheticNS verifies that the
// synthesized SOA uses the expected synthetic MNAME and MBOX values.
func TestMakeBlockedResponse_NXDOMAIN_SOA_SyntheticNS(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	resp := MakeBlockedResponse(query, BlockingModeNXDomain, "")

	if len(resp.Ns) == 0 {
		t.Fatal("expected SOA in Authority section")
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("Authority[0] type=%T, want *dns.SOA", resp.Ns[0])
	}
	if soa.Ns != "ns.dnsieve.invalid." {
		t.Errorf("SOA MNAME=%q, want ns.dnsieve.invalid.", soa.Ns)
	}
	if soa.Mbox != "hostmaster.dnsieve.invalid." {
		t.Errorf("SOA MBOX=%q, want hostmaster.dnsieve.invalid.", soa.Mbox)
	}
}
