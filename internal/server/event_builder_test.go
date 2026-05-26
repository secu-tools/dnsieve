// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// --- buildUpstreamInfos: EDE extraction ---

// TestBuildUpstreamInfos_EDE verifies that an EDE option in the upstream
// response pseudo-section is extracted and placed in UpstreamInfo.
func TestBuildUpstreamInfos_EDE(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeSuccess
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 15, ExtraText: "Blocked (dns.quad9.net)"}}

	results := []*upstream.Result{
		{Index: 0, Client: "dns.quad9.net", Msg: msg, Inspect: dnsmsg.InspectResult{Blocked: true}},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	info := infos[0]
	if info.EDECode == nil {
		t.Fatal("expected EDECode to be set")
	}
	if *info.EDECode != 15 {
		t.Errorf("expected EDECode=15, got %d", *info.EDECode)
	}
	if info.EDEText != "Blocked (dns.quad9.net)" {
		t.Errorf("unexpected EDEText: %q", info.EDEText)
	}
}

// TestBuildUpstreamInfos_EDECodeZero verifies that EDE code 0 (Other) is
// reported as a non-nil pointer so it is distinguishable from absent.
func TestBuildUpstreamInfos_EDECodeZero(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 0, ExtraText: "Unexpected error"}}

	results := []*upstream.Result{
		{Index: 0, Client: "ns.example.com", Msg: msg, Inspect: dnsmsg.InspectResult{}},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].EDECode == nil {
		t.Fatal("expected EDECode to be non-nil even for code 0")
	}
	if *infos[0].EDECode != 0 {
		t.Errorf("expected EDECode=0, got %d", *infos[0].EDECode)
	}
}

// TestBuildUpstreamInfos_NoEDE verifies that EDECode is nil and NSID is empty
// when the upstream response carries no EDNS options.
func TestBuildUpstreamInfos_NoEDE(t *testing.T) {
	msg := new(dns.Msg)
	results := []*upstream.Result{
		{Index: 0, Client: "ns.example.com", Msg: msg, Inspect: dnsmsg.InspectResult{}},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].EDECode != nil {
		t.Errorf("expected EDECode=nil, got %v", *infos[0].EDECode)
	}
	if infos[0].NSID != "" {
		t.Errorf("expected NSID empty, got %q", infos[0].NSID)
	}
}

// --- buildUpstreamInfos: NSID extraction ---

// TestBuildUpstreamInfos_NSID_UTF8 verifies that a hex-encoded NSID that
// decodes to valid UTF-8 is stored as a readable string.
func TestBuildUpstreamInfos_NSID_UTF8(t *testing.T) {
	// "ns1.example" in hex
	nsidHex := "6e73312e6578616d706c65"
	msg := new(dns.Msg)
	msg.Pseudo = []dns.RR{&dns.NSID{Nsid: nsidHex}}

	results := []*upstream.Result{
		{Index: 0, Client: "ns.example.com", Msg: msg, Inspect: dnsmsg.InspectResult{}},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].NSID != "ns1.example" {
		t.Errorf("expected NSID=\"ns1.example\", got %q", infos[0].NSID)
	}
}

// TestBuildUpstreamInfos_NSID_NonUTF8 verifies that a NSID whose raw bytes
// are not valid UTF-8 is kept as the original hex string.
func TestBuildUpstreamInfos_NSID_NonUTF8(t *testing.T) {
	// 0x80 and 0xFF are not valid single-byte UTF-8 code points.
	nsidHex := "80ff"
	msg := new(dns.Msg)
	msg.Pseudo = []dns.RR{&dns.NSID{Nsid: nsidHex}}

	results := []*upstream.Result{
		{Index: 0, Client: "ns.example.com", Msg: msg, Inspect: dnsmsg.InspectResult{}},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].NSID != "80ff" {
		t.Errorf("expected NSID=\"80ff\" (hex fallback), got %q", infos[0].NSID)
	}
}

// TestBuildUpstreamInfos_SlowThreshold verifies the slow flag logic is
// unaffected by EDE additions.
func TestBuildUpstreamInfos_SlowThreshold(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 22, ExtraText: "No Reachable Authority"}}

	results := []*upstream.Result{
		{
			Index:      0,
			Client:     "ns.example.com",
			Msg:        msg,
			DurationMS: 600,
			Inspect:    dnsmsg.InspectResult{},
		},
	}
	infos := buildUpstreamInfos(results, 500*time.Millisecond)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if !infos[0].Slow {
		t.Error("expected Slow=true for 600ms > 500ms threshold")
	}
	if infos[0].EDECode == nil || *infos[0].EDECode != 22 {
		t.Errorf("expected EDECode=22, got %v", infos[0].EDECode)
	}
}

// --- buildResponseInfo: AD bit ---

// TestBuildResponseInfo_AD verifies that the Authentic Data bit is captured.
func TestBuildResponseInfo_AD(t *testing.T) {
	msg := new(dns.Msg)
	msg.AuthenticatedData = true
	msg.Rcode = dns.RcodeSuccess
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if !ri.AD {
		t.Error("expected AD=true")
	}
}

// TestBuildResponseInfo_AD_NotSet verifies that AD is false when not set.
func TestBuildResponseInfo_AD_NotSet(t *testing.T) {
	msg := new(dns.Msg)
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.AD {
		t.Error("expected AD=false")
	}
}

// --- buildResponseInfo: RRSIG ---

// TestBuildResponseInfo_RRSIG_Answer verifies that an RRSIG in the Answer
// section sets HasRRSIG.
func TestBuildResponseInfo_RRSIG_Answer(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.RRSIG{
			Hdr:   dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			RRSIG: rdata.RRSIG{TypeCovered: dns.TypeA, Algorithm: 8, Labels: 2, OrigTTL: 300, SignerName: "example.com."},
		},
	}
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if !ri.HasRRSIG {
		t.Error("expected HasRRSIG=true for RRSIG in Answer")
	}
}

// TestBuildResponseInfo_RRSIG_Authority verifies that an RRSIG in the
// Authority section (e.g. denial-of-existence proof) sets HasRRSIG.
func TestBuildResponseInfo_RRSIG_Authority(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{
		&dns.RRSIG{
			Hdr:   dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			RRSIG: rdata.RRSIG{TypeCovered: dns.TypeSOA, Algorithm: 8, Labels: 2, OrigTTL: 300, SignerName: "example.com."},
		},
	}
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if !ri.HasRRSIG {
		t.Error("expected HasRRSIG=true for RRSIG in Authority")
	}
}

// TestBuildResponseInfo_NoRRSIG verifies HasRRSIG is false for a plain
// non-DNSSEC response.
func TestBuildResponseInfo_NoRRSIG(t *testing.T) {
	msg := new(dns.Msg)
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.HasRRSIG {
		t.Error("expected HasRRSIG=false for response with no RRSIG")
	}
}

// --- buildResponseInfo: EDE ---

// TestBuildResponseInfo_EDE verifies that an EDE option in the response
// pseudo-section is extracted into EDECode and EDEText.
func TestBuildResponseInfo_EDE(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 15, ExtraText: "Blocked (dns.quad9.net)"}}

	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.EDECode == nil {
		t.Fatal("expected EDECode to be set")
	}
	if *ri.EDECode != 15 {
		t.Errorf("expected EDECode=15, got %d", *ri.EDECode)
	}
	if ri.EDEText != "Blocked (dns.quad9.net)" {
		t.Errorf("unexpected EDEText: %q", ri.EDEText)
	}
}

// TestBuildResponseInfo_EDE_CodeZero verifies that EDE code 0 is reported as
// a non-nil pointer so it is distinguishable from absent.
func TestBuildResponseInfo_EDE_CodeZero(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 0, ExtraText: "Unexpected"}}

	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.EDECode == nil {
		t.Fatal("expected EDECode to be non-nil even for code 0")
	}
	if *ri.EDECode != 0 {
		t.Errorf("expected EDECode=0, got %d", *ri.EDECode)
	}
}

// TestBuildResponseInfo_NoEDE verifies EDECode is nil when absent.
func TestBuildResponseInfo_NoEDE(t *testing.T) {
	msg := new(dns.Msg)
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.EDECode != nil {
		t.Errorf("expected EDECode=nil, got %d", *ri.EDECode)
	}
}

// --- buildResponseInfo: AuthorityCount ---

// TestBuildResponseInfo_AuthorityCount verifies that len(resp.Ns) is
// reported in AuthorityCount, e.g. for NXDOMAIN + SOA.
func TestBuildResponseInfo_AuthorityCount(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{
		&dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900}},
	}
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.AuthorityCount != 1 {
		t.Errorf("expected AuthorityCount=1, got %d", ri.AuthorityCount)
	}
}

// TestBuildResponseInfo_AuthorityCount_Zero verifies AuthorityCount is zero
// for responses with an empty Authority section.
func TestBuildResponseInfo_AuthorityCount_Zero(t *testing.T) {
	msg := new(dns.Msg)
	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if ri.AuthorityCount != 0 {
		t.Errorf("expected AuthorityCount=0, got %d", ri.AuthorityCount)
	}
}

// --- decodeNSID ---

// TestDecodeNSID_ValidUTF8 verifies that a valid hex-encoded UTF-8 string is
// decoded to its text representation.
func TestDecodeNSID_ValidUTF8(t *testing.T) {
	// "hello" in hex
	got := decodeNSID("68656c6c6f")
	if got != "hello" {
		t.Errorf("expected \"hello\", got %q", got)
	}
}

// TestDecodeNSID_InvalidHex verifies that an invalid hex input is returned
// unchanged.
func TestDecodeNSID_InvalidHex(t *testing.T) {
	got := decodeNSID("zz!!")
	if got != "zz!!" {
		t.Errorf("expected \"zz!!\", got %q", got)
	}
}

// TestDecodeNSID_NonUTF8 verifies that valid hex that decodes to non-UTF-8
// bytes falls back to the original hex string.
func TestDecodeNSID_NonUTF8(t *testing.T) {
	// 0xFF alone is not a valid UTF-8 sequence.
	got := decodeNSID("ff")
	if got != "ff" {
		t.Errorf("expected \"ff\" (hex fallback), got %q", got)
	}
}

// TestDecodeNSID_Empty verifies that an empty hex string returns an empty string.
func TestDecodeNSID_Empty(t *testing.T) {
	got := decodeNSID("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
