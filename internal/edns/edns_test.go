// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package edns

import (
	"net/netip"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"

	"github.com/secu-tools/dnsieve/internal/config"
)

func defaultTestConfig() *config.Config {
	cfg := config.DefaultConfig()
	return cfg
}

func makeQuery(name string, qtype uint16) *dns.Msg {
	q := dnsutil.SetQuestion(new(dns.Msg), name, qtype)
	q.RecursionDesired = true
	return q
}

// makeQueryWithDO builds a DO=1 query the way one arrives off the wire.
// Msg.Unpack decomposes the OPT record into the message-level UDPSize and
// Security fields, leaving Pseudo holding only the individual EDNS options,
// so a hand-appended *dns.OPT would be a shape no client can actually send.
func makeQueryWithDO(name string, qtype uint16) *dns.Msg {
	q := makeQuery(name, qtype)
	q.UDPSize = 4096
	q.Security = true
	if err := q.Pack(); err != nil {
		panic("makeQueryWithDO: pack: " + err.Error())
	}
	out := new(dns.Msg)
	out.Data = append([]byte(nil), q.Data...)
	if err := out.Unpack(); err != nil {
		panic("makeQueryWithDO: unpack: " + err.Error())
	}
	return out
}

func makeQueryWithECS(name string, qtype uint16, addr string, mask int) *dns.Msg {
	q := makeQuery(name, qtype)
	a := netip.MustParseAddr(addr)
	ecs := &dns.SUBNET{
		Address: a,
		Netmask: uint8(mask),
		Scope:   0,
	}
	if a.Is4() {
		ecs.Family = 1
	} else {
		ecs.Family = 2
	}
	q.Pseudo = append(q.Pseudo, ecs)
	return q
}

func makeQueryWithCookie(name string, qtype uint16, cookie string) *dns.Msg {
	q := makeQuery(name, qtype)
	c := &dns.COOKIE{Cookie: cookie}
	q.Pseudo = append(q.Pseudo, c)
	return q
}

func makeQueryWithNSID(name string, qtype uint16) *dns.Msg {
	q := makeQuery(name, qtype)
	q.Pseudo = append(q.Pseudo, &dns.NSID{})
	return q
}

func findPseudoType[T dns.RR](msg *dns.Msg) T {
	var zero T
	for _, rr := range msg.Pseudo {
		if t, ok := rr.(T); ok {
			return t
		}
	}
	return zero
}

// --- RFC 6891: OPT Record Rebuild ---

func TestPrepareUpstreamQuery_RebuildOPT(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	// Client query with a 4096 buffer in Pseudo
	q := makeQuery("example.com.", dns.TypeA)
	q.UDPSize = 4096

	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	// Verify the message-level UDPSize is set (library creates OPT during Pack)
	if out.UDPSize != MaxUDPPayload {
		t.Errorf("UDP size = %d, want %d", out.UDPSize, MaxUDPPayload)
	}
	// Client's Pseudo should have been stripped
	for _, rr := range out.Pseudo {
		if _, ok := rr.(*dns.OPT); ok {
			t.Error("client OPT should not be in upstream Pseudo (library handles OPT via UDPSize/Security fields)")
		}
	}
}

func TestPrepareUpstreamQuery_TCP_LargeBuffer(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true)

	if out.UDPSize != 65535 {
		t.Errorf("TCP UDP size = %d, want 65535", out.UDPSize)
	}
}

// --- RFC 3225: DO Bit Forwarding ---

func TestPrepareUpstreamQuery_DOBit_Forwarded(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	q := makeQueryWithDO("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if !out.Security {
		t.Error("DO bit should be forwarded to upstream via msg.Security")
	}
}

func TestPrepareUpstreamQuery_DOBit_AlwaysSet(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	// Even when the client does not set DO=1, the proxy always sets DO=1 on
	// upstream queries to ensure DNSSEC-validated responses (AD=1) are returned.
	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if !out.Security {
		t.Error("proxy must always set DO=1 on upstream queries for DNSSEC validation")
	}
}

func TestClientRequestsDNSSEC(t *testing.T) {
	withDO := makeQueryWithDO("example.com.", dns.TypeA)
	if !ClientRequestsDNSSEC(withDO) {
		t.Error("should detect DO=1")
	}

	withoutDO := makeQuery("example.com.", dns.TypeA)
	if ClientRequestsDNSSEC(withoutDO) {
		t.Error("should not detect DO when no OPT")
	}

	if ClientRequestsDNSSEC(nil) {
		t.Error("should handle nil query")
	}
}

// --- RFC 7871: ECS Handling ---

func TestECS_Strip(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.ECS.Mode = "strip"
	m := NewMiddleware(cfg)

	q := makeQueryWithECS("example.com.", dns.TypeA, "192.168.1.1", 24)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.SUBNET](out) != nil {
		t.Error("ECS should be stripped in strip mode")
	}
}

func TestECS_Forward(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.ECS.Mode = "forward"
	m := NewMiddleware(cfg)

	q := makeQueryWithECS("example.com.", dns.TypeA, "192.168.1.1", 24)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	ecs := findPseudoType[*dns.SUBNET](out)
	if ecs == nil {
		t.Fatal("ECS should be forwarded in forward mode")
	}
	if ecs.Address.String() != "192.168.1.1" {
		t.Errorf("ECS address = %s, want 192.168.1.1", ecs.Address)
	}
}

func TestECS_Substitute(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.ECS.Mode = "substitute"
	cfg.Privacy.ECS.Subnet = "203.0.113.0/24"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	ecs := findPseudoType[*dns.SUBNET](out)
	if ecs == nil {
		t.Fatal("ECS should be present in substitute mode")
	}
	if ecs.Address.String() != "203.0.113.0" {
		t.Errorf("ECS address = %s, want 203.0.113.0", ecs.Address)
	}
	if ecs.Netmask != 24 {
		t.Errorf("ECS netmask = %d, want 24", ecs.Netmask)
	}
	if ecs.Family != 1 {
		t.Errorf("ECS family = %d, want 1", ecs.Family)
	}
}

func TestECS_Substitute_IPv6(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.ECS.Mode = "substitute"
	cfg.Privacy.ECS.Subnet = "2001:db8::/32"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	ecs := findPseudoType[*dns.SUBNET](out)
	if ecs == nil {
		t.Fatal("ECS should be present in substitute mode")
	}
	if ecs.Family != 2 {
		t.Errorf("ECS family = %d, want 2 for IPv6", ecs.Family)
	}
	if ecs.Netmask != 32 {
		t.Errorf("ECS netmask = %d, want 32", ecs.Netmask)
	}
}

func TestECS_Forward_NoClientECS(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.ECS.Mode = "forward"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.SUBNET](out) != nil {
		t.Error("no ECS should be added when client did not send ECS in forward mode")
	}
}

// --- RFC 7873: Cookie Handling ---

func TestCookies_Strip(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "strip"
	m := NewMiddleware(cfg)

	q := makeQueryWithCookie("example.com.", dns.TypeA, "abcdef0123456789")
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.COOKIE](out) != nil {
		t.Error("cookies should be stripped in strip mode")
	}
}

func TestCookies_Reoriginate(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	cookie := findPseudoType[*dns.COOKIE](out)
	if cookie == nil {
		t.Fatal("cookie should be present in reoriginate mode")
	}
	if len(cookie.Cookie) < 16 {
		t.Errorf("client cookie should be at least 8 bytes (16 hex chars), got %d chars", len(cookie.Cookie))
	}
}

func TestCookies_Reoriginate_PerUpstream(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out1 := m.PrepareUpstreamQuery(q, "upstream1", false)
	out2 := m.PrepareUpstreamQuery(q, "upstream2", false)

	c1 := findPseudoType[*dns.COOKIE](out1)
	c2 := findPseudoType[*dns.COOKIE](out2)

	if c1 == nil || c2 == nil {
		t.Fatal("cookies should be present for both upstreams")
	}
	if c1.Cookie == c2.Cookie {
		t.Error("different upstreams should have different client cookies")
	}
}

func TestCookies_Reoriginate_ServerCookieState(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// Simulate receiving a server cookie
	serverCookie := &dns.COOKIE{Cookie: "abcdef0123456789" + "serverpart1234567890"}
	m.processResponseCookie(serverCookie, "upstream1")

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	cookie := findPseudoType[*dns.COOKIE](out)
	if cookie == nil {
		t.Fatal("cookie should be present")
	}
	// Should include server cookie from state
	if len(cookie.Cookie) <= 16 {
		t.Error("cookie should include server cookie from state")
	}
}

func TestCookies_ResponseStripping(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "strip"
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Pseudo = append(resp.Pseudo, &dns.COOKIE{Cookie: "testcookie123456"})
	m.ProcessUpstreamResponse(resp, "upstream1")

	if findPseudoType[*dns.COOKIE](resp) != nil {
		t.Error("cookies should be stripped from response in strip mode")
	}
}

// --- RFC 5001: NSID Handling ---

func TestNSID_Strip(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.NSID.Mode = "strip"
	m := NewMiddleware(cfg)

	q := makeQueryWithNSID("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.NSID](out) != nil {
		t.Error("NSID should be stripped in strip mode")
	}
}

func TestNSID_Forward(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.NSID.Mode = "forward"
	m := NewMiddleware(cfg)

	q := makeQueryWithNSID("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.NSID](out) == nil {
		t.Error("NSID should be forwarded in forward mode")
	}
}

func TestNSID_Forward_OnlyWhenRequested(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.NSID.Mode = "forward"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.NSID](out) != nil {
		t.Error("NSID should not be forwarded when client did not request it")
	}
}

func TestNSID_Substitute(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.NSID.Mode = "substitute"
	cfg.Privacy.NSID.Value = "dnsieve-01"
	m := NewMiddleware(cfg)

	q := makeQueryWithNSID("example.com.", dns.TypeA)
	resp := new(dns.Msg)

	m.HandleNSIDSubstitute(q, resp)

	nsid := findPseudoType[*dns.NSID](resp)
	if nsid == nil {
		t.Fatal("NSID should be added in substitute mode")
	}
	// Value is hex-encoded
	if nsid.Nsid == "" {
		t.Error("NSID value should not be empty")
	}
}

func TestNSID_Substitute_NotRequestedByClient(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.NSID.Mode = "substitute"
	cfg.Privacy.NSID.Value = "dnsieve-01"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA) // no NSID request
	resp := new(dns.Msg)

	m.HandleNSIDSubstitute(q, resp)

	if findPseudoType[*dns.NSID](resp) != nil {
		t.Error("NSID should not be added when client did not request it")
	}
}

// --- RFC 7828: TCP Keepalive ---

func TestTCPKeepalive_PresentOnTCP(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.TCPKeepalive.ClientTimeoutSec = 60
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true)

	ka := findPseudoType[*dns.TCPKEEPALIVE](out)
	if ka == nil {
		t.Fatal("TCP keepalive should be present on TCP queries")
	}
	// 120 seconds * 10 = 1200 (100ms units) for upstream
	if ka.Timeout != uint16(cfg.TCPKeepalive.UpstreamTimeoutSec*10) {
		t.Errorf("keepalive timeout = %d, want %d", ka.Timeout, cfg.TCPKeepalive.UpstreamTimeoutSec*10)
	}
}

func TestTCPKeepalive_AbsentOnUDP(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.TCPKEEPALIVE](out) != nil {
		t.Error("TCP keepalive should not be present on UDP queries")
	}
}

func TestTCPKeepalive_ClientResponse(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.TCPKeepalive.ClientTimeoutSec = 90
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	m.PrepareClientResponse(resp, true, true, false)

	ka := findPseudoType[*dns.TCPKEEPALIVE](resp)
	if ka == nil {
		t.Fatal("TCP keepalive should be present in client TCP response")
	}
	if ka.Timeout != uint16(90*10) {
		t.Errorf("client keepalive timeout = %d, want %d", ka.Timeout, 90*10)
	}
}

// --- RFC 8914: EDE Forwarding ---

func TestEDE_ForwardedAsIs(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	ede := &dns.EDE{InfoCode: 15, ExtraText: "Blocked"}
	resp.Pseudo = append(resp.Pseudo, ede)

	m.ProcessUpstreamResponse(resp, "upstream1")

	found := findPseudoType[*dns.EDE](resp)
	if found == nil {
		t.Fatal("EDE should be forwarded as-is")
	}
	if found.InfoCode != 15 {
		t.Errorf("EDE info code = %d, want 15", found.InfoCode)
	}
	if found.ExtraText != "Blocked" {
		t.Errorf("EDE text = %q, want Blocked", found.ExtraText)
	}
}

// --- RFC 9715: Fragmentation Avoidance ---

func TestNeedsTruncation_SmallResponse(t *testing.T) {
	resp := new(dns.Msg)
	resp.Response = true
	dnsutil.SetReply(resp, makeQuery("example.com.", dns.TypeA))

	if NeedsTruncation(resp, false, 1232) {
		t.Error("small response should not need truncation")
	}
}

func TestNeedsTruncation_TCP_NoTruncation(t *testing.T) {
	resp := new(dns.Msg)
	resp.Response = true

	if NeedsTruncation(resp, true, 1232) {
		t.Error("TCP responses should never be truncated")
	}
}

func TestMakeTruncatedResponse(t *testing.T) {
	q := makeQuery("example.com.", dns.TypeA)
	tr := MakeTruncatedResponse(q)

	if !tr.Truncated {
		t.Error("TC should be set")
	}
	if !tr.Response {
		t.Error("QR should be set")
	}
	if tr.ID != q.ID {
		t.Errorf("ID = %d, want %d", tr.ID, q.ID)
	}
}

// --- RFC 6672: DNAME Synthesis ---

func TestDNAME_Synthesis(t *testing.T) {
	q := makeQuery("x.example.com.", dns.TypeA)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)

	dname := &dns.DNAME{
		Hdr: dns.Header{
			Name:  "example.com.",
			Class: dns.ClassINET,
			TTL:   300,
		},
	}
	dname.Target = "example.net."
	resp.Answer = append(resp.Answer, dname)

	SynthesizeDNAME(q, resp)

	// Should have DNAME + synthesized CNAME
	if len(resp.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2", len(resp.Answer))
	}

	cname, ok := resp.Answer[1].(*dns.CNAME)
	if !ok {
		t.Fatal("second answer should be CNAME")
	}
	if cname.Target != "x.example.net." {
		t.Errorf("CNAME target = %s, want x.example.net.", cname.Target)
	}
}

func TestDNAME_NoSynthesis_WhenCNAMEExists(t *testing.T) {
	q := makeQuery("x.example.com.", dns.TypeA)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)

	dname := &dns.DNAME{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
	}
	dname.Target = "example.net."
	cname := &dns.CNAME{
		Hdr: dns.Header{Name: "x.example.com.", Class: dns.ClassINET, TTL: 300},
	}
	cname.Target = "x.example.net."
	resp.Answer = append(resp.Answer, dname, cname)

	SynthesizeDNAME(q, resp)

	// Should not add another CNAME
	if len(resp.Answer) != 2 {
		t.Errorf("answer count = %d, want 2 (no extra CNAME)", len(resp.Answer))
	}
}

func TestDNAME_NoSynthesis_OwnerItself(t *testing.T) {
	q := makeQuery("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)

	dname := &dns.DNAME{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
	}
	dname.Target = "example.net."
	resp.Answer = append(resp.Answer, dname)

	SynthesizeDNAME(q, resp)

	// DNAME does not match the owner name itself
	if len(resp.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(resp.Answer))
	}
}

// --- RFC 9461/9462: DDR ---

func TestDDR_Disabled(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = false

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeSVCB)
	if HandleDDR(q, cfg) != nil {
		t.Error("DDR should return nil when disabled")
	}
}

func TestDDR_Enabled_NoListeners(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeSVCB)
	resp := HandleDDR(q, cfg)
	if resp == nil {
		t.Fatal("DDR should return a response when enabled")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("DDR with no encrypted listeners should return NXDOMAIN, got %s", dns.RcodeToString[resp.Rcode])
	}
}

func TestDDR_Enabled_WithDoT(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true
	cfg.Downstream.DoT.Enabled = true

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeSVCB)
	q.ID = 1234
	resp := HandleDDR(q, cfg)
	if resp == nil {
		t.Fatal("DDR should return a response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("DDR rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Error("DDR should have at least one SVCB answer")
	}
	if resp.ID != 1234 {
		t.Errorf("DDR response ID = %d, want 1234", resp.ID)
	}
}

func TestDDR_WrongDomain(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true

	q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeSVCB)
	if HandleDDR(q, cfg) != nil {
		t.Error("DDR should not respond to non-DDR queries")
	}
}

func TestDDR_WrongType(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeA)
	if HandleDDR(q, cfg) != nil {
		t.Error("DDR should not respond to non-SVCB queries for _dns.resolver.arpa.")
	}
}

// --- Response Processing ---

func TestProcessUpstreamResponse_StripsCookiesAndKeepalive(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Pseudo = append(resp.Pseudo,
		&dns.COOKIE{Cookie: "testcookie"},
		&dns.TCPKEEPALIVE{Timeout: 600},
		&dns.EDE{InfoCode: 1, ExtraText: "test"},
	)

	m.ProcessUpstreamResponse(resp, "upstream1")

	// Cookies should be stripped
	if findPseudoType[*dns.COOKIE](resp) != nil {
		t.Error("cookies should be stripped from response")
	}
	// Keepalive should be stripped
	if findPseudoType[*dns.TCPKEEPALIVE](resp) != nil {
		t.Error("upstream keepalive should be stripped from response")
	}
	// EDE should be kept
	if findPseudoType[*dns.EDE](resp) == nil {
		t.Error("EDE should be forwarded")
	}
}

func TestProcessUpstreamResponse_NilSafe(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)
	m.ProcessUpstreamResponse(nil, "upstream1") // should not panic
}

// --- MaxUDPPayload Constant ---

func TestMaxUDPPayload(t *testing.T) {
	if MaxUDPPayload != 1232 {
		t.Errorf("MaxUDPPayload = %d, want 1232 per RFC 9715", MaxUDPPayload)
	}
}

// --- buildSubstituteECS ---

func TestBuildSubstituteECS_InvalidSubnet(t *testing.T) {
	ecs := buildSubstituteECS("not-a-subnet")
	if ecs != nil {
		t.Error("invalid subnet should return nil")
	}
}

func TestBuildSubstituteECS_Empty(t *testing.T) {
	ecs := buildSubstituteECS("")
	if ecs != nil {
		t.Error("empty subnet should return nil")
	}
}

// --- RFC 7873: Extended Cookie Tests ---

// TestCookies_DefaultMode_IsReoriginate verifies that a middleware built from
// the default config uses "reoriginate" mode, which is the expected default.
func TestCookies_DefaultMode_IsReoriginate(t *testing.T) {
	cfg := defaultTestConfig()
	if cfg.Privacy.Cookies.Mode != "reoriginate" {
		t.Fatalf("default config must have cookies mode \"reoriginate\", got %q", cfg.Privacy.Cookies.Mode)
	}
	m := NewMiddleware(cfg)
	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)
	if findPseudoType[*dns.COOKIE](out) == nil {
		t.Error("default mode (reoriginate) must include a cookie in upstream queries")
	}
}

// TestNewMiddleware_CookieStore_Reoriginate checks that the cookie store is
// initialised when the mode is "reoriginate".
func TestNewMiddleware_CookieStore_Reoriginate(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)
	if m.cookies == nil {
		t.Error("cookie store must be non-nil in reoriginate mode")
	}
}

// TestNewMiddleware_CookieStore_Strip checks that no cookie store is allocated
// in strip mode.
func TestNewMiddleware_CookieStore_Strip(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "strip"
	m := NewMiddleware(cfg)
	if m.cookies != nil {
		t.Error("cookie store must be nil in strip mode")
	}
}

// TestCookies_Reoriginate_ConsistentClientCookie verifies that the same
// client cookie is reused across multiple queries to the same upstream.
func TestCookies_Reoriginate_ConsistentClientCookie(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out1 := m.PrepareUpstreamQuery(q, "upstream1", false)
	out2 := m.PrepareUpstreamQuery(q, "upstream1", false)

	c1 := findPseudoType[*dns.COOKIE](out1)
	c2 := findPseudoType[*dns.COOKIE](out2)

	if c1 == nil || c2 == nil {
		t.Fatal("cookie must be present in both queries")
	}
	if c1.Cookie != c2.Cookie {
		t.Errorf("client cookie should be stable across queries to same upstream: %q vs %q", c1.Cookie, c2.Cookie)
	}
}

// TestCookies_Reoriginate_ClientCookieExactLength checks that the client
// cookie portion is exactly 16 hex characters (8 bytes per RFC 7873).
func TestCookies_Reoriginate_ClientCookieExactLength(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	cookie := findPseudoType[*dns.COOKIE](out)
	if cookie == nil {
		t.Fatal("cookie must be present")
	}
	// Without a stored server cookie the full cookie equals the client cookie.
	if len(cookie.Cookie) != 16 {
		t.Errorf("client-only cookie length = %d, want 16 hex chars", len(cookie.Cookie))
	}
}

// TestCookies_Reoriginate_ServerCookieAppended verifies that once a server
// cookie has been received it is appended to subsequent upstream queries.
func TestCookies_Reoriginate_ServerCookieAppended(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// Prime client cookie.
	q := makeQuery("example.com.", dns.TypeA)
	out1 := m.PrepareUpstreamQuery(q, "upstream1", false)
	c1 := findPseudoType[*dns.COOKIE](out1)
	if c1 == nil {
		t.Fatal("initial cookie must be present")
	}
	clientPart := c1.Cookie

	// Simulate upstream returning a server cookie (client(16) + server(>=8 chars)).
	serverCookieHex := "aabbccddeeff0011"
	resp := &dns.COOKIE{Cookie: clientPart + serverCookieHex}
	m.processResponseCookie(resp, "upstream1")

	// Next query should carry client+server cookies.
	out2 := m.PrepareUpstreamQuery(q, "upstream1", false)
	c2 := findPseudoType[*dns.COOKIE](out2)
	if c2 == nil {
		t.Fatal("cookie must be present after server cookie stored")
	}
	if len(c2.Cookie) <= 16 {
		t.Errorf("cookie should include server part after receiving server cookie, got len=%d", len(c2.Cookie))
	}
	if c2.Cookie[16:] != serverCookieHex {
		t.Errorf("server cookie = %q, want %q", c2.Cookie[16:], serverCookieHex)
	}
}

// TestCookies_Reoriginate_ServerCookieShort verifies that a response cookie
// with no server part (length <= 16) does not overwrite the server cookie
// state (the server cookie field stays empty).
func TestCookies_Reoriginate_ServerCookieShort(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// Cookie with exactly 16 chars - client-only, no server cookie.
	shortCookie := &dns.COOKIE{Cookie: "abcdef0123456789"}
	m.processResponseCookie(shortCookie, "upstream1")

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)
	cookie := findPseudoType[*dns.COOKIE](out)
	if cookie == nil {
		t.Fatal("cookie must be present")
	}
	// Should still be client-only (16 chars) because nothing was stored.
	if len(cookie.Cookie) != 16 {
		t.Errorf("cookie len = %d, want 16 (no server cookie stored)", len(cookie.Cookie))
	}
}

// TestCookies_Reoriginate_ResponseCookiesStrippedFromClient verifies that
// cookies are not forwarded to the downstream client in reoriginate mode.
func TestCookies_Reoriginate_ResponseCookiesStrippedFromClient(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Pseudo = append(resp.Pseudo, &dns.COOKIE{Cookie: "abcdef0123456789aabbcc"})

	m.ProcessUpstreamResponse(resp, "upstream1")

	if findPseudoType[*dns.COOKIE](resp) != nil {
		t.Error("cookies must be stripped from responses sent to clients (reoriginate mode)")
	}
}

// TestCookies_Strip_NoClientCookieAdded verifies that strip mode adds no
// cookie option to upstream queries, regardless of what the client sent.
func TestCookies_Strip_NoClientCookieAdded(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "strip"
	m := NewMiddleware(cfg)

	// Even with a client-supplied cookie, the upstream query must not carry one.
	q := makeQueryWithCookie("example.com.", dns.TypeA, "abcdef01234567890011")
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	if findPseudoType[*dns.COOKIE](out) != nil {
		t.Error("strip mode must not add any cookie to upstream queries")
	}
}

// TestCookies_Reoriginate_PerUpstream_IndependentServerState verifies that
// server cookie state is tracked independently per upstream.
func TestCookies_Reoriginate_PerUpstream_IndependentServerState(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// Prime client cookies for both upstreams.
	q := makeQuery("example.com.", dns.TypeA)
	out1 := m.PrepareUpstreamQuery(q, "upstream1", false)
	out2 := m.PrepareUpstreamQuery(q, "upstream2", false)

	c1 := findPseudoType[*dns.COOKIE](out1)
	c2 := findPseudoType[*dns.COOKIE](out2)
	if c1 == nil || c2 == nil {
		t.Fatal("cookies must be present for both upstreams")
	}

	// upstream1 receives a server cookie; upstream2 does not.
	serverHex := "1122334455667788"
	m.processResponseCookie(&dns.COOKIE{Cookie: c1.Cookie + serverHex}, "upstream1")

	next1 := m.PrepareUpstreamQuery(q, "upstream1", false)
	next2 := m.PrepareUpstreamQuery(q, "upstream2", false)

	nc1 := findPseudoType[*dns.COOKIE](next1)
	nc2 := findPseudoType[*dns.COOKIE](next2)

	if nc1 == nil || nc2 == nil {
		t.Fatal("cookies must be present for both upstreams after state update")
	}
	if len(nc1.Cookie) <= 16 {
		t.Error("upstream1 should carry server cookie")
	}
	if len(nc2.Cookie) != 16 {
		t.Errorf("upstream2 should still have client-only cookie (len=16), got len=%d", len(nc2.Cookie))
	}
}

// --- Regression: msgPool pool corruption (slice bounds panic) ---

// TestPrepareUpstreamQuery_DataIsNil is a regression test for the UDP buffer
// pool corruption that caused a "slice bounds out of range" panic on Linux.
//
// Root cause: query.Copy() copies the unexported msgPool field from the
// original server request.  When the upstream client calls WriteTo on the
// copy, the DNS library packs the message into an exact-fit allocation and
// then returns that small slice to the server's pool.  The next recvmmsg
// call draws the undersized buffer from the pool and panics when a larger
// UDP packet arrives.
//
// Fix: PrepareUpstreamQuery builds a fresh struct literal, leaving msgPool
// nil.  Pack therefore allocates its own memory that is never returned to
// the server's pool.
//
// This test verifies that out.Data is nil after PrepareUpstreamQuery (so Pack
// must allocate fresh memory) and that packing out does not touch query.Data
// (confirming no shared backing array between the two messages).
func TestPrepareUpstreamQuery_DataIsNil(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)
	q := makeQuery("example.com.", dns.TypeA)

	// Pack q so q.Data has a known, non-nil backing array.
	if err := q.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	originalDataPtr := &q.Data[0]

	out := m.PrepareUpstreamQuery(q, "1.1.1.1:853", false)

	// out.Data must be nil: any downstream Pack must allocate fresh memory
	// rather than returning a small slice to the server's buffer pool.
	if out.Data != nil {
		t.Errorf("out.Data must be nil after PrepareUpstreamQuery, got %d bytes", len(out.Data))
	}

	// Packing out must not modify q.Data (no shared backing array).
	if err := out.Pack(); err != nil {
		t.Fatalf("Pack out: %v", err)
	}
	if len(out.Data) > 0 && &out.Data[0] == originalDataPtr {
		t.Error("out.Data shares backing array with query.Data (msgPool contamination risk)")
	}
	// q.Data must be unchanged after packing out.
	if &q.Data[0] != originalDataPtr {
		t.Error("q.Data backing array changed after packing out (unexpected mutation)")
	}
}

// TestCookies_Reoriginate_ConcurrentAccess exercises the cookie store under
// concurrent load to verify there are no data races (run with -race).
func TestCookies_Reoriginate_ConcurrentAccess(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	const goroutines = 20
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			upstream := "upstream1"
			q := makeQuery("example.com.", dns.TypeA)
			out := m.PrepareUpstreamQuery(q, upstream, false)
			c := findPseudoType[*dns.COOKIE](out)
			if c != nil && len(c.Cookie) >= 16 {
				// Simulate a server cookie response.
				m.processResponseCookie(&dns.COOKIE{Cookie: c.Cookie + "deadbeefdeadbeef"}, upstream)
			}
		}(i)
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestCookies_Reoriginate_ServerCookieTooShort verifies that a response cookie
// whose server part is shorter than 8 bytes (16 hex chars) is rejected per
// RFC 7873 s4.1 and does not update the cookie store.
func TestCookies_Reoriginate_ServerCookieTooShort(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// Total 17-31 chars: client (16) + server (1-15) -- server part too short.
	// Use 30 chars total: 16 client + 14 server (7 bytes, below the 8-byte min).
	shortTotal := &dns.COOKIE{Cookie: "abcdef0123456789" + "aabbccddeeff00"}
	m.processResponseCookie(shortTotal, "upstream1")

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)
	cookie := findPseudoType[*dns.COOKIE](out)
	if cookie == nil {
		t.Fatal("cookie must be present")
	}
	if len(cookie.Cookie) != 16 {
		t.Errorf("cookie len = %d, want 16 (invalid short server cookie must not be stored)", len(cookie.Cookie))
	}
}

// TestCookies_Reoriginate_ServerCookieTooLong verifies that a response cookie
// whose server part exceeds 32 bytes (64 hex chars) is rejected per
// RFC 7873 s4.1 and does not update the cookie store.
func TestCookies_Reoriginate_ServerCookieTooLong(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// 16 client + 66 server = 82 chars total, exceeds the 80-char maximum.
	oversized := "abcdef0123456789" + "aabbccddeeff001122334455667788990011223344556677889900112233445566778899" // 16+70=86
	m.processResponseCookie(&dns.COOKIE{Cookie: oversized}, "upstream1")

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)
	cookie := findPseudoType[*dns.COOKIE](out)
	if cookie == nil {
		t.Fatal("cookie must be present")
	}
	if len(cookie.Cookie) != 16 {
		t.Errorf("cookie len = %d, want 16 (oversized server cookie must not be stored)", len(cookie.Cookie))
	}
}

// TestProcessResponseCookieOnly_UpdatesStatePerUpstream verifies that
// ProcessResponseCookieOnly stores the server cookie under the correct
// upstream address so that it is returned in subsequent queries to that
// upstream.
func TestProcessResponseCookieOnly_UpdatesStatePerUpstream(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)

	// Prime client cookie for upstream1.
	q := makeQuery("example.com.", dns.TypeA)
	out1 := m.PrepareUpstreamQuery(q, "upstream1", false)
	c1 := findPseudoType[*dns.COOKIE](out1)
	if c1 == nil {
		t.Fatal("initial cookie must be present")
	}

	// Simulate receiving an upstream response that includes a server cookie.
	serverHex := "c0ffee1122334455"
	resp := new(dns.Msg)
	resp.Pseudo = append(resp.Pseudo, &dns.COOKIE{Cookie: c1.Cookie + serverHex})
	m.ProcessResponseCookieOnly(resp, "upstream1")

	// The next query to upstream1 must carry the stored server cookie.
	out2 := m.PrepareUpstreamQuery(q, "upstream1", false)
	c2 := findPseudoType[*dns.COOKIE](out2)
	if c2 == nil {
		t.Fatal("cookie must be present after ProcessResponseCookieOnly")
	}
	if len(c2.Cookie) <= 16 {
		t.Errorf("cookie len = %d, want >16 (server cookie should be appended)", len(c2.Cookie))
	}
	if c2.Cookie[16:] != serverHex {
		t.Errorf("server cookie = %q, want %q", c2.Cookie[16:], serverHex)
	}

	// upstream2 must not have received any server cookie state.
	out3 := m.PrepareUpstreamQuery(q, "upstream2", false)
	c3 := findPseudoType[*dns.COOKIE](out3)
	if c3 == nil {
		t.Fatal("cookie must be present for upstream2")
	}
	if len(c3.Cookie) != 16 {
		t.Errorf("upstream2 cookie len = %d, want 16 (no state for upstream2)", len(c3.Cookie))
	}
}

// TestProcessResponseCookieOnly_NilSafe verifies that ProcessResponseCookieOnly
// does not panic on a nil response.
func TestProcessResponseCookieOnly_NilSafe(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Cookies.Mode = "reoriginate"
	m := NewMiddleware(cfg)
	m.ProcessResponseCookieOnly(nil, "upstream1") // must not panic
}

// --- RFC 6891: EDNS OPT presence rules ---

// TestPrepareClientResponse_NonEDNS_NoOPT verifies that PrepareClientResponse
// does not emit an OPT record when the client query had no OPT (RFC 6891).
func TestPrepareClientResponse_NonEDNS_NoOPT(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	// Simulate a blocked response that pre-populated UDPSize and Pseudo.
	resp.UDPSize = MaxUDPPayload
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{InfoCode: 15, ExtraText: "Blocked"})

	m.PrepareClientResponse(resp, false, false, false) // clientHasEDNS = false

	if resp.UDPSize != 0 {
		t.Errorf("non-EDNS client: UDPSize should be 0, got %d", resp.UDPSize)
	}
	if len(resp.Pseudo) != 0 {
		t.Errorf("non-EDNS client: Pseudo should be empty, got %d options", len(resp.Pseudo))
	}
}

// TestPrepareClientResponse_EDNS_HasOPT verifies that PrepareClientResponse
// sets the UDP payload size when the client query included an OPT record.
func TestPrepareClientResponse_EDNS_HasOPT(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	m.PrepareClientResponse(resp, false, true, false) // clientHasEDNS = true

	if resp.UDPSize != MaxUDPPayload {
		t.Errorf("EDNS client: UDPSize = %d, want %d", resp.UDPSize, MaxUDPPayload)
	}
}

// TestPrepareClientResponse_NonEDNS_NoKeepalive verifies that TCP keepalive
// is not added for non-EDNS clients (TCP keepalive is an EDNS0 option).
func TestPrepareClientResponse_NonEDNS_NoKeepalive(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.TCPKeepalive.ClientTimeoutSec = 60
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	m.PrepareClientResponse(resp, true, false, false) // TCP but not EDNS

	if findPseudoType[*dns.TCPKEEPALIVE](resp) != nil {
		t.Error("non-EDNS client: TCP keepalive must not be included in response")
	}
}

// TestClientHasEDNS_WithOPT verifies that a query with OPT is detected.
func TestClientHasEDNS_WithOPT(t *testing.T) {
	q := makeQueryWithDO("example.com.", dns.TypeA) // includes OPT
	// Pack and unpack to simulate wire round-trip (UDPSize gets set on unpack)
	if err := q.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	unpacked := new(dns.Msg)
	unpacked.Data = q.Data
	if err := unpacked.Unpack(); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !ClientHasEDNS(unpacked) {
		t.Error("query with OPT should be detected as EDNS-capable after wire round-trip")
	}
}

// TestClientHasEDNS_WithoutOPT verifies that a query without OPT is not detected.
func TestClientHasEDNS_WithoutOPT(t *testing.T) {
	q := makeQuery("example.com.", dns.TypeA) // no OPT
	if ClientHasEDNS(q) {
		t.Error("query without OPT should not be detected as EDNS-capable")
	}
}

// TestClientHasEDNS_Nil verifies that nil is handled safely.
func TestClientHasEDNS_Nil(t *testing.T) {
	if ClientHasEDNS(nil) {
		t.Error("nil query should not be detected as EDNS-capable")
	}
}

// --- RFC 9461/9462: DDR SVCB service parameters ---

// TestDDR_DoT_SVCB_HasALPN verifies that a DDR response for DoT contains
// the ALPN parameter set to "dot" per RFC 7858.
func TestDDR_DoT_SVCB_HasALPN(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true
	cfg.Downstream.DoT.Enabled = true
	cfg.Downstream.DoT.Port = 853

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeSVCB)
	resp := HandleDDR(q, cfg)
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("DDR with DoT should return at least one SVCB answer")
	}

	var dotRec *dns.SVCB
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SVCB); ok && s.Priority == 1 {
			dotRec = s
			break
		}
	}
	if dotRec == nil {
		t.Fatal("DDR DoT record (priority 1) not found")
	}

	var foundALPN, foundPort bool
	for _, pair := range dotRec.Value {
		switch p := pair.(type) {
		case *svcb.ALPN:
			if len(p.Alpn) == 1 && p.Alpn[0] == "dot" {
				foundALPN = true
			}
		case *svcb.PORT:
			if p.Port == 853 {
				foundPort = true
			}
		}
	}
	if !foundALPN {
		t.Error("DDR DoT SVCB must contain ALPN=dot (RFC 7858)")
	}
	if !foundPort {
		t.Errorf("DDR DoT SVCB must contain port=853, got value=%v", dotRec.Value)
	}
}

// TestDDR_DoH_SVCB_HasALPNPortAndPath verifies that a DDR response for DoH
// contains ALPN=h2, port, and dohpath per RFC 9461/9462.
func TestDDR_DoH_SVCB_HasALPNPortAndPath(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.Port = 443

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeSVCB)
	resp := HandleDDR(q, cfg)
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("DDR with DoH should return at least one SVCB answer")
	}

	var dohRec *dns.SVCB
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SVCB); ok && s.Priority == 2 {
			dohRec = s
			break
		}
	}
	if dohRec == nil {
		t.Fatal("DDR DoH record (priority 2) not found")
	}

	foundALPN, foundPort, foundPath := inspectDoHSVCB(dohRec, "h2", 443, "/dns-query")
	if !foundALPN {
		t.Error("DDR DoH SVCB must contain ALPN=h2 (RFC 8484)")
	}
	if !foundPort {
		t.Errorf("DDR DoH SVCB must contain port=443, got value=%v", dohRec.Value)
	}
	if !foundPath {
		t.Error("DDR DoH SVCB must contain dohpath with /dns-query template (RFC 9461)")
	}
}

// inspectDoHSVCB scans an SVCB record for the expected ALPN, port, and
// dohpath substring. Returns booleans indicating which were found.
func inspectDoHSVCB(rec *dns.SVCB, wantALPN string, wantPort uint16, wantPathSubstr string) (alpn, port, path bool) {
	for _, pair := range rec.Value {
		switch p := pair.(type) {
		case *svcb.ALPN:
			for _, a := range p.Alpn {
				if a == wantALPN {
					alpn = true
				}
			}
		case *svcb.PORT:
			if p.Port == wantPort {
				port = true
			}
		case *svcb.DOHPATH:
			if strings.Contains(p.Template, wantPathSubstr) {
				path = true
			}
		}
	}
	return
}

// TestDDR_BothDoTAndDoH verifies that a DDR response includes records for
// both DoT (priority 1) and DoH (priority 2) when both are enabled.
func TestDDR_BothDoTAndDoH(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true
	cfg.Downstream.DoT.Enabled = true
	cfg.Downstream.DoT.Port = 853
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.Port = 443

	q := dnsutil.SetQuestion(new(dns.Msg), "_dns.resolver.arpa.", dns.TypeSVCB)
	resp := HandleDDR(q, cfg)
	if resp == nil {
		t.Fatal("DDR should return a response")
	}
	if len(resp.Answer) != 2 {
		t.Errorf("DDR with both DoT and DoH should return 2 SVCB records, got %d", len(resp.Answer))
	}

	priorities := make(map[uint16]bool)
	for _, rr := range resp.Answer {
		if s, ok := rr.(*dns.SVCB); ok {
			priorities[s.Priority] = true
		}
	}
	if !priorities[1] {
		t.Error("DDR should include a SVCB record with priority 1 for DoT")
	}
	if !priorities[2] {
		t.Error("DDR should include a SVCB record with priority 2 for DoH")
	}
}

// TestDDR_CaseInsensitive verifies that DDR queries with mixed-case owner
// names are handled correctly per RFC 4343 (case-insensitive DNS name
// comparison). The query "_DNS.RESOLVER.ARPA." should produce the same
// response as "_dns.resolver.arpa.".
func TestDDR_CaseInsensitive(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.DDR.Enabled = true
	cfg.Downstream.DoT.Enabled = true
	cfg.Downstream.DoT.Port = 853

	// Mixed-case DDR query name -- RFC 4343 s2 requires case-insensitive match.
	q := dnsutil.SetQuestion(new(dns.Msg), "_DNS.RESOLVER.ARPA.", dns.TypeSVCB)
	resp := HandleDDR(q, cfg)

	if resp == nil {
		t.Fatal("HandleDDR should respond to mixed-case _DNS.RESOLVER.ARPA. query")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one SVCB record in DDR response")
	}
}

// TestNeedsTruncation_NonEDNS_UsesDefault512 verifies that non-EDNS clients
// (clientUDPSize == 0) use the RFC 6891 default of 512 bytes for the
// truncation threshold, not an unlimited size.
func TestNeedsTruncation_NonEDNS_UsesDefault512(t *testing.T) {
	// Build a response that exceeds 512 bytes but is under 1232.
	q := makeQuery("example.com.", dns.TypeTXT)
	resp := new(dns.Msg)
	resp.Response = true
	resp.ID = q.ID
	resp.Question = q.Question
	// Add several TXT records totalling > 512 bytes.
	for i := 0; i < 8; i++ {
		txt := &dns.TXT{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			TXT: rdata.TXT{Txt: []string{strings.Repeat("x", 64)}},
		}
		resp.Answer = append(resp.Answer, txt)
	}

	// clientUDPSize == 0 -> non-EDNS -> 512-byte limit.
	if !NeedsTruncation(resp, false, 0) {
		t.Error("response > 512 bytes should require truncation for non-EDNS client (clientUDPSize=0)")
	}

	// clientUDPSize == 1232 -> EDNS -> 1232-byte limit; same response should fit.
	if NeedsTruncation(resp, false, 1232) {
		t.Error("response < 1232 bytes should NOT require truncation for EDNS client (clientUDPSize=1232)")
	}
}

// TestNeedsTruncation_TCP_AlwaysFalse verifies TCP never triggers truncation
// regardless of response size, per RFC 5966.
func TestNeedsTruncation_TCP_AlwaysFalse(t *testing.T) {
	resp := new(dns.Msg)
	resp.Response = true
	for i := 0; i < 20; i++ {
		txt := &dns.TXT{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			TXT: rdata.TXT{Txt: []string{strings.Repeat("y", 64)}},
		}
		resp.Answer = append(resp.Answer, txt)
	}
	if NeedsTruncation(resp, true, 0) {
		t.Error("TCP responses must never be truncated (RFC 5966)")
	}
}

// --- RFC 7830 / RFC 8467: EDNS(0) Padding ---

func makeQueryWithPadding(name string, qtype uint16) *dns.Msg {
	q := makeQuery(name, qtype)
	q.UDPSize = 4096 // must have OPT for PADDING to be carried
	q.Pseudo = append(q.Pseudo, &dns.PADDING{Padding: ""})
	return q
}

// TestClientHasPadding_WithPadding verifies that a query with a PADDING option
// is detected correctly.
func TestClientHasPadding_WithPadding(t *testing.T) {
	q := makeQueryWithPadding("example.com.", dns.TypeA)
	if !ClientHasPadding(q) {
		t.Error("query with PADDING option should be detected")
	}
}

// TestClientHasPadding_WithoutPadding verifies that a query without a PADDING
// option is not detected.
func TestClientHasPadding_WithoutPadding(t *testing.T) {
	q := makeQuery("example.com.", dns.TypeA)
	if ClientHasPadding(q) {
		t.Error("query without PADDING option should not be detected")
	}
}

// TestClientHasPadding_Nil verifies that nil is handled safely.
func TestClientHasPadding_Nil(t *testing.T) {
	if ClientHasPadding(nil) {
		t.Error("nil query should return false")
	}
}

// TestPadding_UpstreamPadding_NotAddedWhenDisabled verifies that no upstream
// padding is added when UpstreamPadding is explicitly set to false.
func TestPadding_UpstreamPadding_NotAddedWhenDisabled(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = false
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true) // isTCP=true

	if findPseudoType[*dns.PADDING](out) != nil {
		t.Error("upstream padding must not be added when UpstreamPadding=false")
	}
}

// TestPadding_UpstreamPadding_NotAddedOnUDP verifies that no upstream padding
// is added on UDP transports even when UpstreamPadding is enabled (RFC 7830 s3.1).
func TestPadding_UpstreamPadding_NotAddedOnUDP(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = true
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false) // isTCP=false (UDP)

	if findPseudoType[*dns.PADDING](out) != nil {
		t.Error("upstream padding must not be added on UDP transport (RFC 7830 s3.1)")
	}
}

// TestPadding_UpstreamPadding_AddedOnTCP verifies that upstream padding is
// added on TCP (encrypted) transports when UpstreamPadding is enabled.
func TestPadding_UpstreamPadding_AddedOnTCP(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = true
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true) // isTCP=true (DoT/DoH)

	pad := findPseudoType[*dns.PADDING](out)
	if pad == nil {
		t.Fatal("upstream padding must be added on TCP transport when UpstreamPadding=true")
	}
}

// TestPadding_UpstreamPadding_BlockSize128 verifies that upstream queries are
// padded to the next multiple of 128 bytes (RFC 8467 s4.1).
func TestPadding_UpstreamPadding_BlockSize128(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = true
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true)

	if err := out.Pack(); err != nil {
		t.Fatalf("pack upstream query: %v", err)
	}
	size := len(out.Data)
	if size%128 != 0 {
		t.Errorf("padded upstream query size = %d, not a multiple of 128", size)
	}
}

// TestPadding_UpstreamPadding_ContentIsZeros verifies that the upstream padding
// bytes are all zeros as recommended by RFC 7830.
func TestPadding_UpstreamPadding_ContentIsZeros(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = true
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true)

	pad := findPseudoType[*dns.PADDING](out)
	if pad == nil {
		t.Fatal("expected PADDING option")
	}
	// Padding hex string should only contain "00" pairs
	for i := 0; i+1 < len(pad.Padding); i += 2 {
		if pad.Padding[i] != '0' || pad.Padding[i+1] != '0' {
			t.Errorf("padding byte at position %d is not zero: %q", i/2, pad.Padding[i:i+2])
		}
	}
}

// TestPadding_ClientPaddingStripped verifies that client PADDING is stripped
// from the upstream query (proxy rebuilds OPT from scratch).
func TestPadding_ClientPaddingStripped(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	q := makeQueryWithPadding("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", false)

	// Client PADDING must not appear in upstream query (OPT is rebuilt from scratch)
	if findPseudoType[*dns.PADDING](out) != nil {
		t.Error("client PADDING must be stripped from upstream query")
	}
}

// TestPadding_UpstreamPaddingStrippedFromResponse verifies that upstream
// PADDING is stripped from the response before it is forwarded to clients.
func TestPadding_UpstreamPaddingStrippedFromResponse(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Pseudo = append(resp.Pseudo, &dns.PADDING{Padding: strings.Repeat("00", 60)})
	m.ProcessUpstreamResponse(resp, "upstream1")

	if findPseudoType[*dns.PADDING](resp) != nil {
		t.Error("upstream PADDING must be stripped from the response forwarded to clients")
	}
}

// TestPadding_ClientResponsePadded_TCP verifies that a padding option is added
// to TCP responses when the client included a PADDING option (RFC 7830/8467).
func TestPadding_ClientResponsePadded_TCP(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Response = true
	resp.UDPSize = 4096
	m.PrepareClientResponse(resp, true, true, true) // isTCP=true, clientHasPadding=true

	if findPseudoType[*dns.PADDING](resp) == nil {
		t.Error("response must contain PADDING when client requested it over TCP")
	}
}

// TestPadding_ClientResponseNotPadded_UDP verifies that no padding is added to
// UDP responses even when the client included a PADDING option (RFC 7830 s3.1).
func TestPadding_ClientResponseNotPadded_UDP(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Response = true
	m.PrepareClientResponse(resp, false, true, true) // isTCP=false (UDP), clientHasPadding=true

	if findPseudoType[*dns.PADDING](resp) != nil {
		t.Error("padding must not be added to UDP responses (RFC 7830 s3.1)")
	}
}

// TestPadding_ClientResponseNotPadded_WhenClientDidNotRequest verifies that
// no padding is added when the client did not include a PADDING option.
func TestPadding_ClientResponseNotPadded_WhenClientDidNotRequest(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Response = true
	m.PrepareClientResponse(resp, true, true, false) // isTCP=true, clientHasPadding=false

	if findPseudoType[*dns.PADDING](resp) != nil {
		t.Error("padding must not be added when client did not request it")
	}
}

// TestPadding_ClientResponseBlockSize468 verifies that responses are padded to
// the next multiple of 468 bytes (RFC 8467 s4.2).
func TestPadding_ClientResponseBlockSize468(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Response = true
	m.PrepareClientResponse(resp, true, true, true) // isTCP=true, clientHasPadding=true

	if err := resp.Pack(); err != nil {
		t.Fatalf("pack response: %v", err)
	}
	size := len(resp.Data)
	if size%468 != 0 {
		t.Errorf("padded response size = %d, not a multiple of 468", size)
	}
}

// TestPadding_ClientResponseContentIsZeros verifies that response padding bytes
// are all zeros as recommended by RFC 7830.
func TestPadding_ClientResponseContentIsZeros(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Response = true
	m.PrepareClientResponse(resp, true, true, true) // isTCP=true, clientHasPadding=true

	pad := findPseudoType[*dns.PADDING](resp)
	if pad == nil {
		t.Fatal("expected PADDING option in response")
	}
	for i := 0; i+1 < len(pad.Padding); i += 2 {
		if pad.Padding[i] != '0' || pad.Padding[i+1] != '0' {
			t.Errorf("response padding byte at position %d is not zero: %q", i/2, pad.Padding[i:i+2])
		}
	}
}

// TestPadding_NonEDNSClient_NoPadding verifies that no padding is added when
// the client did not send an EDNS OPT record (RFC 6891).
func TestPadding_NonEDNSClient_NoPadding(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	resp := new(dns.Msg)
	resp.Response = true
	m.PrepareClientResponse(resp, true, false, false) // clientHasEDNS=false

	if findPseudoType[*dns.PADDING](resp) != nil {
		t.Error("non-EDNS client must not receive a PADDING option")
	}
}

// TestPadding_UpstreamPadding_MultipleBlockSizes verifies that padding keeps
// the message at exactly 128-byte multiples regardless of the initial size.
func TestPadding_UpstreamPadding_MultipleBlockSizes(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = true
	m := NewMiddleware(cfg)

	queries := []struct {
		name  string
		qtype uint16
	}{
		{"a.example.com.", dns.TypeA},
		{"somewhat.longer.domain.name.example.com.", dns.TypeA},
		{"example.com.", dns.TypeAAAA},
		{"example.com.", dns.TypeMX},
	}
	for _, tc := range queries {
		q := makeQuery(tc.name, tc.qtype)
		out := m.PrepareUpstreamQuery(q, "upstream1", true)
		if err := out.Pack(); err != nil {
			t.Fatalf("pack %s %s: %v", tc.name, dns.TypeToString[tc.qtype], err)
		}
		size := len(out.Data)
		if size%128 != 0 {
			t.Errorf("query %s %s: padded size = %d, not a multiple of 128",
				tc.name, dns.TypeToString[tc.qtype], size)
		}
	}
}

// TestPadding_ClientResponse_MultipleBlockSizes verifies that response padding
// keeps the message at exactly 468-byte multiples for different response sizes.
func TestPadding_ClientResponse_MultipleBlockSizes(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	for _, answerCount := range []int{0, 1, 3, 5} {
		resp := new(dns.Msg)
		resp.Response = true
		for i := 0; i < answerCount; i++ {
			a := &dns.A{
				Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			}
			a.Addr = netip.MustParseAddr("192.0.2.1")
			resp.Answer = append(resp.Answer, a)
		}
		m.PrepareClientResponse(resp, true, true, true)
		if err := resp.Pack(); err != nil {
			t.Fatalf("pack response with %d answers: %v", answerCount, err)
		}
		size := len(resp.Data)
		if size%468 != 0 {
			t.Errorf("response with %d answers: padded size = %d, not a multiple of 468",
				answerCount, size)
		}
	}
}

// TestPadding_UpstreamPadding_EnabledByDefault verifies that upstream padding
// is enabled in the default configuration.
func TestPadding_UpstreamPadding_EnabledByDefault(t *testing.T) {
	cfg := defaultTestConfig()
	if !cfg.Privacy.Padding.UpstreamPadding {
		t.Error("upstream padding should be enabled by default")
	}
	m := NewMiddleware(cfg)

	q := makeQuery("example.com.", dns.TypeA)
	out := m.PrepareUpstreamQuery(q, "upstream1", true)

	if findPseudoType[*dns.PADDING](out) == nil {
		t.Error("upstream padding must be present in default config on TCP")
	}
}

// TestPadding_UpstreamPadding_IsNonDeterministic verifies that repeated calls
// with the same message produce at least two distinct padded sizes, demonstrating
// the random jitter recommended by RFC 8467 s3. The probability of all 100
// iterations landing in the same bucket is astronomically small (<2^-49).
func TestPadding_UpstreamPadding_IsNonDeterministic(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Privacy.Padding.UpstreamPadding = true
	m := NewMiddleware(cfg)

	sizes := make(map[int]bool)
	for i := 0; i < 100; i++ {
		q := makeQuery("example.com.", dns.TypeA)
		out := m.PrepareUpstreamQuery(q, "upstream1", true)
		if err := out.Pack(); err != nil {
			t.Fatalf("pack (iteration %d): %v", i, err)
		}
		sizes[len(out.Data)] = true
	}
	if len(sizes) < 2 {
		t.Errorf("RFC 8467 s3: upstream padding should be non-deterministic, got only %d distinct size(s) in 100 iterations", len(sizes))
	}
}

// TestPadding_ClientResponse_IsNonDeterministic verifies that repeated calls
// with the same response produce at least two distinct padded sizes (RFC 8467 s3).
func TestPadding_ClientResponse_IsNonDeterministic(t *testing.T) {
	cfg := defaultTestConfig()
	m := NewMiddleware(cfg)

	sizes := make(map[int]bool)
	for i := 0; i < 100; i++ {
		resp := new(dns.Msg)
		resp.Response = true
		m.PrepareClientResponse(resp, true, true, true)
		if err := resp.Pack(); err != nil {
			t.Fatalf("pack (iteration %d): %v", i, err)
		}
		sizes[len(resp.Data)] = true
		// Reset for next iteration
	}
	if len(sizes) < 2 {
		t.Errorf("RFC 8467 s3: response padding should be non-deterministic, got only %d distinct size(s) in 100 iterations", len(sizes))
	}
}

// TestPrepareUpstreamQueryRandomisesID pins RFC 5452 s9.1: the transaction ID
// sent upstream must be the resolver's own, not the downstream client's.
// Forwarding the client's ID lets any client fix the ID an off-path spoofer
// would otherwise have to guess.
func TestPrepareUpstreamQueryRandomisesID(t *testing.T) {
	m := NewMiddleware(config.DefaultConfig())

	q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	q.ID = 0x4142

	seen := make(map[uint16]int)
	for i := 0; i < 64; i++ {
		out := m.PrepareUpstreamQuery(q, "9.9.9.9:853", false)
		if out.ID == q.ID {
			t.Fatalf("upstream query reused the client transaction ID 0x%04x", q.ID)
		}
		seen[out.ID]++
	}
	// 64 draws from 16 bits should not repeat much; a constant would collapse
	// to a single entry.
	if len(seen) < 32 {
		t.Errorf("upstream IDs look non-random: %d distinct values from 64 draws", len(seen))
	}
}

// TestMakeTruncatedResponseKeepsEDNS pins RFC 6891 s6.2.5 and RFC 3225: a TC=1
// reply to an EDNS client must still carry an OPT record and echo the DO bit.
// The truncated message replaces one PrepareClientResponse had already fitted
// with both, so rebuilding them here is what keeps the reply from looking like
// it came from a resolver with no EDNS support.
func TestMakeTruncatedResponseKeepsEDNS(t *testing.T) {
	wire := func(do bool, udpSize uint16) *dns.Msg {
		q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
		q.UDPSize = udpSize
		q.Security = do
		if err := q.Pack(); err != nil {
			t.Fatalf("pack: %v", err)
		}
		out := new(dns.Msg)
		out.Data = append([]byte(nil), q.Data...)
		if err := out.Unpack(); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		return out
	}

	// The library only emits an OPT record when UDPSize exceeds MinMsgSize
	// (512), so an EDNS client has to advertise more than that.
	t.Run("EDNS client with DO=1", func(t *testing.T) {
		resp := MakeTruncatedResponse(wire(true, 4096))
		if !resp.Truncated {
			t.Error("TC bit must be set")
		}
		if resp.UDPSize == 0 {
			t.Error("response to an EDNS query must carry an OPT record")
		}
		if !resp.Security {
			t.Error("DO bit must be echoed back to the client")
		}
	})

	t.Run("EDNS client with DO=0", func(t *testing.T) {
		resp := MakeTruncatedResponse(wire(false, 4096))
		if resp.UDPSize == 0 {
			t.Error("response to an EDNS query must carry an OPT record")
		}
		if resp.Security {
			t.Error("DO bit must not be set when the client did not ask for it")
		}
	})

	t.Run("non-EDNS client gets no OPT", func(t *testing.T) {
		q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
		resp := MakeTruncatedResponse(q)
		if resp.UDPSize != 0 {
			t.Error("RFC 6891: no OPT in a response to a non-EDNS query")
		}
	})
}

// TestClientRequestsDNSSECFromWire guards the DO-bit detection against
// regressing to a Pseudo scan. Msg.Unpack decomposes the OPT record into the
// message-level Security field, so any implementation that looks for a
// *dns.OPT in Pseudo silently reports false for every real query.
func TestClientRequestsDNSSECFromWire(t *testing.T) {
	for _, do := range []bool{true, false} {
		q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
		q.UDPSize = 4096
		q.Security = do
		if err := q.Pack(); err != nil {
			t.Fatalf("pack: %v", err)
		}
		w := new(dns.Msg)
		w.Data = append([]byte(nil), q.Data...)
		if err := w.Unpack(); err != nil {
			t.Fatalf("unpack: %v", err)
		}
		if len(w.Pseudo) != 0 {
			t.Fatalf("precondition: Unpack should leave no *dns.OPT in Pseudo, got %d entries", len(w.Pseudo))
		}
		if got := ClientRequestsDNSSEC(w); got != do {
			t.Errorf("ClientRequestsDNSSEC() = %v for a wire query with DO=%v", got, do)
		}
	}
}
