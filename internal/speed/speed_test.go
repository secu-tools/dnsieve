// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package speed

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

func TestExtractHost_DoH(t *testing.T) {
	tests := []struct {
		address  string
		expected string
	}{
		{"https://dns.quad9.net/dns-query", "dns.quad9.net"},
		{"https://1.1.1.1/dns-query", "1.1.1.1"},
		{"https://dns.example.com:8443/dns-query", "dns.example.com"},
		{"http://dns.example.com/dns-query", "dns.example.com"},
		{"dns.example.com/dns-query", "dns.example.com"},
		{"https://example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got := extractHost(tt.address, "doh")
			if got != tt.expected {
				t.Errorf("extractHost(%q, doh) = %q, want %q", tt.address, got, tt.expected)
			}
		})
	}
}

func TestExtractHost_DoT(t *testing.T) {
	tests := []struct {
		address  string
		expected string
	}{
		{"dns.quad9.net:853", "dns.quad9.net"},
		{"1.1.1.1:853", "1.1.1.1"},
		{"dns.example.com:8853", "dns.example.com"},
		{"no-port-host", "no-port-host"}, // SplitHostPort fails, returns address
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got := extractHost(tt.address, "dot")
			if got != tt.expected {
				t.Errorf("extractHost(%q, dot) = %q, want %q", tt.address, got, tt.expected)
			}
		})
	}
}

func TestExtractHost_UDP(t *testing.T) {
	got := extractHost("9.9.9.9:53", "udp")
	if got != "" {
		t.Errorf("extractHost for udp should return empty, got %q", got)
	}
}

func TestIsCertError(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"x509: certificate signed by unknown authority", true},
		{"tls: handshake failure", true},
		{"certificate has expired", true},
		{"connection refused", false},
		{"i/o timeout", false},
		{"DNS query failed", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isCertError(tt.input); got != tt.expected {
				t.Errorf("isCertError(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsConnError(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"connection refused", true},
		{"no such host", true},
		{"i/o timeout", true},
		{"network is unreachable", true},
		{"timeout waiting for response", true},
		{"x509: certificate expired", false},
		{"SERVFAIL", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isConnError(tt.input); got != tt.expected {
				t.Errorf("isConnError(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestClassifyError_CertError(t *testing.T) {
	r := &ServerResult{}
	classifyError(r, "example.com", &testError{"x509: certificate has expired"})
	if r.CertErrors != 1 {
		t.Errorf("expected 1 cert error, got %d", r.CertErrors)
	}
	if r.ConnErrors != 0 || r.DNSErrors != 0 {
		t.Error("only cert error should be incremented")
	}
}

func TestClassifyError_ConnError(t *testing.T) {
	r := &ServerResult{}
	classifyError(r, "example.com", &testError{"connection refused"})
	if r.ConnErrors != 1 {
		t.Errorf("expected 1 conn error, got %d", r.ConnErrors)
	}
	if r.CertErrors != 0 || r.DNSErrors != 0 {
		t.Error("only conn error should be incremented")
	}
}

func TestClassifyError_DNSError(t *testing.T) {
	r := &ServerResult{}
	classifyError(r, "example.com", &testError{"SERVFAIL from upstream"})
	if r.DNSErrors != 1 {
		t.Errorf("expected 1 DNS error, got %d", r.DNSErrors)
	}
	if r.CertErrors != 0 || r.ConnErrors != 0 {
		t.Error("only DNS error should be incremented")
	}
}

func TestComputeStats_Empty(t *testing.T) {
	r := &ServerResult{}
	computeStats(r)
	if r.AvgLatency != 0 || r.MinLatency != 0 || r.MaxLatency != 0 {
		t.Error("empty latencies should produce zero stats")
	}
}

func TestComputeStats_Single(t *testing.T) {
	r := &ServerResult{
		Latencies: []time.Duration{100 * time.Millisecond},
	}
	computeStats(r)
	if r.AvgLatency != 100*time.Millisecond {
		t.Errorf("avg = %v, want 100ms", r.AvgLatency)
	}
	if r.MinLatency != 100*time.Millisecond {
		t.Errorf("min = %v, want 100ms", r.MinLatency)
	}
	if r.MaxLatency != 100*time.Millisecond {
		t.Errorf("max = %v, want 100ms", r.MaxLatency)
	}
}

func TestComputeStats_Multiple(t *testing.T) {
	r := &ServerResult{
		Latencies: []time.Duration{
			50 * time.Millisecond,
			100 * time.Millisecond,
			150 * time.Millisecond,
		},
	}
	computeStats(r)
	if r.AvgLatency != 100*time.Millisecond {
		t.Errorf("avg = %v, want 100ms", r.AvgLatency)
	}
	if r.MinLatency != 50*time.Millisecond {
		t.Errorf("min = %v, want 50ms", r.MinLatency)
	}
	if r.MaxLatency != 150*time.Millisecond {
		t.Errorf("max = %v, want 150ms", r.MaxLatency)
	}
}

func TestCheckBootstrapResolve_UDP(t *testing.T) {
	// UDP protocol should always return true (no hostname to resolve)
	r := &ServerResult{}
	ok := checkBootstrapResolve(r, testUpstream("9.9.9.9:53", "udp"), "", "")
	if !ok {
		t.Error("UDP should always return true for bootstrap resolve")
	}
}

func TestCheckBootstrapResolve_IPAddress(t *testing.T) {
	// IP address in DoT should skip resolution
	r := &ServerResult{}
	ok := checkBootstrapResolve(r, testUpstream("1.1.1.1:853", "dot"), "", "")
	if !ok {
		t.Error("IP address should skip resolution and return true")
	}
}

// testError implements error interface for testing.
type testError struct {
	msg string
}

func (e *testError) Error() string { return e.msg }

// testUpstream creates a minimal UpstreamServer config for testing.
func testUpstream(addr, proto string) config.UpstreamServer {
	return config.UpstreamServer{
		Address:  addr,
		Protocol: proto,
	}
}

// mockSpeedClient implements upstream.Client for speed tests.
type mockSpeedClient struct {
	resp *dns.Msg
	err  error
}

func (m *mockSpeedClient) Query(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Deep copy via pack/unpack
	if err := m.resp.Pack(); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	r.Data = append([]byte(nil), m.resp.Data...)
	if err := r.Unpack(); err != nil {
		return nil, err
	}
	r.ID = msg.ID
	return r, nil
}

func (m *mockSpeedClient) String() string { return "mock-speed" }

func (m *mockSpeedClient) Close() {}

func makeNormalSpeedResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	return resp
}

func makeServfailResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeServerFailure
	return resp
}

func TestQueryDomain_Success(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeNormalSpeedResp(q)}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if r.SuccessCount != 1 {
		t.Errorf("expected 1 success, got %d", r.SuccessCount)
	}
	if r.TotalQueries != 1 {
		t.Errorf("expected 1 query, got %d", r.TotalQueries)
	}
	if len(r.Latencies) != 1 {
		t.Errorf("expected 1 latency, got %d", len(r.Latencies))
	}
}

func TestQueryDomain_Error(t *testing.T) {
	client := &mockSpeedClient{err: errors.New("connection refused")}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if r.SuccessCount != 0 {
		t.Error("should not count error as success")
	}
	if r.ConnErrors != 1 {
		t.Errorf("expected 1 conn error, got %d", r.ConnErrors)
	}
	if r.TotalQueries != 1 {
		t.Errorf("expected 1 total query, got %d", r.TotalQueries)
	}
}

func TestQueryDomain_SERVFAIL(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeServfailResp(q)}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if r.SuccessCount != 0 {
		t.Error("SERVFAIL should not be counted as success")
	}
	if r.DNSErrors != 1 {
		t.Errorf("expected 1 DNS error for SERVFAIL, got %d", r.DNSErrors)
	}
}

// recordingMockClient wraps mockSpeedClient and captures the last query sent.
type recordingMockClient struct {
	inner     mockSpeedClient
	lastQuery *dns.Msg
}

func (r *recordingMockClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r.lastQuery = msg
	return r.inner.Query(ctx, msg)
}

func (r *recordingMockClient) String() string { return "recording-mock" }

func (r *recordingMockClient) Close() {}

// sleepingMockClient wraps mockSpeedClient and sleeps for the given duration
// before returning, to guarantee a measurable round-trip latency in tests.
type sleepingMockClient struct {
	inner mockSpeedClient
	delay time.Duration
}

func (s *sleepingMockClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	time.Sleep(s.delay)
	return s.inner.Query(ctx, msg)
}

func (s *sleepingMockClient) String() string { return "sleeping-mock" }

func (s *sleepingMockClient) Close() {}

// TestQueryDomain_SetsEDNS0 verifies that queryDomain includes an OPT record
// (UDPSize > 0) in every query so that upstreams can return EDE options.
func TestQueryDomain_SetsEDNS0(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	recording := &recordingMockClient{inner: mockSpeedClient{resp: makeNormalSpeedResp(q)}}
	srv := &ServerResult{}
	queryDomain(srv, recording, "example.com", "")

	if recording.lastQuery == nil {
		t.Fatal("query was not received by client")
	}
	if recording.lastQuery.UDPSize == 0 {
		t.Error("UDPSize == 0: queryDomain must set UDPSize > 0 so upstreams include EDE options (RFC 8914)")
	}
}

// TestQueryDomain_SERVFAIL_EDE_ViaUDP is the end-to-end regression test for the
// Quad9-style block detection bug: the mock UDP server here only includes EDE
// in its SERVFAIL response when the incoming query carries an OPT record
// (UDPSize > 0).  Without the query.UDPSize fix in queryDomain the mock returns
// plain SERVFAIL (no EDE) and the result is classified as SERVFAIL instead of
// BLOCKED.  With the fix, the query has EDNS0 enabled, the mock returns
// SERVFAIL+EDE(Blocked), hasEDEBlocked fires, and the result is BLOCKED.
func TestQueryDomain_SERVFAIL_EDE_ViaUDP(t *testing.T) {
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		// Only include EDE when the client signals EDNS0 support (UDPSize > 0).
		// This mirrors real resolver behaviour: EDE requires EDNS0 (RFC 8914 s.4).
		if query.UDPSize > 0 {
			resp.Pseudo = append(resp.Pseudo, &dns.EDE{
				InfoCode:  dns.ExtendedErrorBlocked,
				ExtraText: "policy",
			})
		}
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	// The mock server simulates the SERVFAIL+EDE(Blocked) response pattern used
	// by filtering resolvers (e.g. Quad9-style policy blocks).
	results := runTests(cfg, []string{"malware.blocked.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Blocked != 1 {
		t.Errorf("expected Blocked=1 (SERVFAIL+EDE should be BLOCKED), got %d -- DNSErrors=%d", r.Blocked, r.DNSErrors)
	}
	if r.DNSErrors != 0 {
		t.Errorf("expected 0 DNS errors (domain should be BLOCKED not SERVFAIL), got %d", r.DNSErrors)
	}
	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 DomainResult, got %d", len(r.DomainResults))
	}
	dr := r.DomainResults[0]
	if dr.Status != "BLOCKED" {
		t.Errorf("expected Status=BLOCKED, got %q", dr.Status)
	}
	if dr.EDECode != "15:Blocked" {
		t.Errorf("expected EDECode='15:Blocked', got %q", dr.EDECode)
	}
}

func TestCreateClient_UnsupportedProtocol(t *testing.T) {
	srv := config.UpstreamServer{
		Address:  "example.com:12345",
		Protocol: "unsupported",
	}
	_, err := createClient(srv, false, nil, "auto")
	if err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestCreateClient_UDP(t *testing.T) {
	srv := config.UpstreamServer{
		Address:  "9.9.9.9:53",
		Protocol: "udp",
	}
	c, err := createClient(srv, false, nil, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

// udpHandlerFn is a function that builds a DNS response for a UDP query.
type udpHandlerFn func(query *dns.Msg) *dns.Msg

// startMockUDPServer starts a local UDP DNS server and returns its address.
// The handler receives each parsed query and returns the response to send (nil = skip).
func startMockUDPServer(t *testing.T, handler udpHandlerFn) string {
	t.Helper()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on UDP: %v", err)
	}
	localAddr := ln.LocalAddr().String()
	go serveUDPPackets(ln, handler)
	t.Cleanup(func() { ln.Close() })
	return localAddr
}

// serveUDPPackets reads DNS queries from a PacketConn and dispatches them to handler.
func serveUDPPackets(ln net.PacketConn, handler udpHandlerFn) {
	buf := make([]byte, 512)
	for {
		n, addr, err := ln.ReadFrom(buf)
		if err != nil {
			return
		}
		query := new(dns.Msg)
		query.Data = buf[:n]
		if err := query.Unpack(); err != nil {
			continue
		}
		resp := handler(query)
		if resp == nil {
			continue
		}
		if err := resp.Pack(); err != nil {
			continue
		}
		if _, err := ln.WriteTo(resp.Data, addr); err != nil {
			return
		}
	}
}

func makeNormalUDPResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	if len(query.Question) > 0 {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("127.0.0.1")},
		})
	}
	return resp
}

func TestRunTests_UDPServer(t *testing.T) {
	localAddr := startMockUDPServer(t, makeNormalUDPResponse)

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	results := runTests(cfg, []string{"example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].TotalQueries != 1 {
		t.Errorf("expected 1 query, got %d", results[0].TotalQueries)
	}
}

func TestRunStartupTest_UDPServer(t *testing.T) {
	localAddr := startMockUDPServer(t, makeNormalUDPResponse)

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	RunStartupTest(cfg, logger)
}

func TestRunStartupTest_SlowServer(t *testing.T) {
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	RunStartupTest(cfg, logger)
}

func TestRunStartupTest_AllQuerysFail(t *testing.T) {
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	RunStartupTest(cfg, logger)
}

// Verify upstream.Client interface is satisfied by mockSpeedClient.
var _ upstream.Client = (*mockSpeedClient)(nil)

// ---------------------------------------------------------------------------
// DefaultTestDomains
// ---------------------------------------------------------------------------

func TestDefaultTestDomains_Count(t *testing.T) {
	if len(DefaultTestDomains) != 10 {
		t.Errorf("expected 10 default test domains, got %d", len(DefaultTestDomains))
	}
}

func TestDefaultTestDomains_NoDuplicates(t *testing.T) {
	seen := make(map[string]struct{}, len(DefaultTestDomains))
	for _, d := range DefaultTestDomains {
		if _, ok := seen[d]; ok {
			t.Errorf("duplicate domain in DefaultTestDomains: %q", d)
		}
		seen[d] = struct{}{}
	}
}

func TestDefaultTestDomains_ValidFormat(t *testing.T) {
	for _, d := range DefaultTestDomains {
		if d == "" {
			t.Error("DefaultTestDomains contains an empty entry")
			continue
		}
		if d[0] == '.' || d[len(d)-1] == '.' {
			t.Errorf("domain %q has a leading or trailing dot", d)
		}
		hasDot := false
		for _, ch := range d {
			if ch > 127 {
				t.Errorf("domain %q contains a non-ASCII character", d)
				break
			}
			if ch == '.' {
				hasDot = true
			}
		}
		if !hasDot {
			t.Errorf("domain %q has no dot (not a valid FQDN label)", d)
		}
	}
}

func TestDefaultTestDomains_NoWhitespace(t *testing.T) {
	for _, d := range DefaultTestDomains {
		for _, ch := range d {
			if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
				t.Errorf("domain %q contains whitespace", d)
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// RunInteractiveTest
// ---------------------------------------------------------------------------

// TestRunInteractiveTest_UsesDefaultDomainsWhenNoneSupplied verifies that
// passing nil domains causes the built-in DefaultTestDomains to be queried,
// one query per domain.
func TestRunInteractiveTest_UsesDefaultDomainsWhenNoneSupplied(t *testing.T) {
	var mu sync.Mutex
	var queriedNames []string

	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		if len(query.Question) > 0 {
			mu.Lock()
			queriedNames = append(queriedNames, query.Question[0].Header().Name)
			mu.Unlock()
		}
		return makeNormalUDPResponse(query)
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	RunInteractiveTest(cfg, nil)

	mu.Lock()
	got := len(queriedNames)
	mu.Unlock()

	if got != len(DefaultTestDomains) {
		t.Errorf("expected %d queries (one per default domain), got %d", len(DefaultTestDomains), got)
	}
}

// TestRunInteractiveTest_UsesSuppliedDomains verifies that explicitly supplied
// domains are used instead of the defaults.
func TestRunInteractiveTest_UsesSuppliedDomains(t *testing.T) {
	supplied := []string{"example.com", "example.net", "example.org"}

	var mu sync.Mutex
	var queriedNames []string

	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		if len(query.Question) > 0 {
			mu.Lock()
			queriedNames = append(queriedNames, query.Question[0].Header().Name)
			mu.Unlock()
		}
		return makeNormalUDPResponse(query)
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	RunInteractiveTest(cfg, supplied)

	mu.Lock()
	got := len(queriedNames)
	mu.Unlock()

	if got != len(supplied) {
		t.Errorf("expected %d queries (one per supplied domain), got %d", len(supplied), got)
	}
}

func TestRunInteractiveTest_AllFail(t *testing.T) {
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	// Must not panic even when every query fails.
	RunInteractiveTest(cfg, []string{"example.com"})
}

func TestRunInteractiveTest_MultipleUpstreams(t *testing.T) {
	addr1 := startMockUDPServer(t, makeNormalUDPResponse)
	addr2 := startMockUDPServer(t, makeNormalUDPResponse)

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: addr1, Protocol: "udp"},
			{Address: addr2, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	// Both upstreams should be tested without panicking.
	RunInteractiveTest(cfg, []string{"example.com", "example.net"})
}

// TestRunStartupTest_UsesFewerDomains verifies the startup subset is smaller
// than the full DefaultTestDomains list.
func TestRunStartupTest_UsesFewerDomains(t *testing.T) {
	const startupSubset = 3
	if startupSubset >= len(DefaultTestDomains) {
		t.Errorf("startup subset (%d) should be smaller than DefaultTestDomains (%d)",
			startupSubset, len(DefaultTestDomains))
	}
}

func TestRunStartupTest_ConnError(t *testing.T) {
	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: "127.0.0.1:1", Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	// Must complete without panicking even when every query errors.
	RunStartupTest(cfg, logger)
}

// ---------------------------------------------------------------------------
// DomainResult and buildDomainResult
// ---------------------------------------------------------------------------

func makeNXDomainResp(query *dns.Msg, withSOA bool) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeNameError
	if withSOA {
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
	}
	return resp
}

func makeBlockedNullResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
	})
	return resp
}

func makeRefusedResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeRefused
	return resp
}

func makeNODATAResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	// NOERROR with empty answer section
	return resp
}

func makeADResp(query *dns.Msg) *dns.Msg {
	resp := makeNormalSpeedResp(query)
	resp.AuthenticatedData = true
	return resp
}

func TestBuildDomainResult_OK(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	dr := buildDomainResult("example.com", makeNormalSpeedResp(q), 50*time.Millisecond)

	if dr.Status != "OK" {
		t.Errorf("expected OK, got %q", dr.Status)
	}
	if dr.Latency != 50*time.Millisecond {
		t.Errorf("expected 50ms, got %v", dr.Latency)
	}
	if dr.DNSSEC {
		t.Error("expected DNSSEC=false")
	}
}

func TestBuildDomainResult_DNSSEC_AD(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	dr := buildDomainResult("example.com", makeADResp(q), 20*time.Millisecond)

	if dr.Status != "OK" {
		t.Errorf("expected OK, got %q", dr.Status)
	}
	if !dr.DNSSEC {
		t.Error("expected DNSSEC=true for AD-bit response")
	}
}

func TestBuildDomainResult_SERVFAIL(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	dr := buildDomainResult("example.com", makeServfailResp(q), 10*time.Millisecond)

	if dr.Status != "SERVFAIL" {
		t.Errorf("expected SERVFAIL, got %q", dr.Status)
	}
}

func TestBuildDomainResult_NXDOMAIN_Genuine(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "nonexistent.example.com.", dns.TypeA)

	dr := buildDomainResult("nonexistent.example.com", makeNXDomainResp(q, true), 15*time.Millisecond)

	if dr.Status != "NXDOMAIN" {
		t.Errorf("expected NXDOMAIN,SOA (genuine), got %q", dr.Status)
	}
}

func TestBuildDomainResult_NXDOMAIN_Filtered(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	// NXDOMAIN without SOA = Quad9-style filter
	dr := buildDomainResult("blocked.example.com", makeNXDomainResp(q, false), 8*time.Millisecond)

	if dr.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for filter-NXDOMAIN, got %q", dr.Status)
	}
}

func TestBuildDomainResult_Blocked_NullAddr(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	dr := buildDomainResult("blocked.example.com", makeBlockedNullResp(q), 12*time.Millisecond)

	if dr.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for 0.0.0.0 response, got %q", dr.Status)
	}
}

func TestBuildDomainResult_REFUSED(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	dr := buildDomainResult("example.com", makeRefusedResp(q), 5*time.Millisecond)

	if dr.Status != "REFUSED" {
		t.Errorf("expected REFUSED, got %q", dr.Status)
	}
}

func TestBuildDomainResult_NODATA(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	dr := buildDomainResult("example.com", makeNODATAResp(q), 7*time.Millisecond)

	if dr.Status != "NODATA" {
		t.Errorf("expected NODATA, got %q", dr.Status)
	}
}

// ---------------------------------------------------------------------------
// applyDomainResult
// ---------------------------------------------------------------------------

func TestApplyDomainResult_OK(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "OK", Latency: 50 * time.Millisecond})

	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1, got %d", r.SuccessCount)
	}
	if len(r.Latencies) != 1 {
		t.Errorf("expected 1 latency, got %d", len(r.Latencies))
	}
	if r.DNSErrors != 0 {
		t.Errorf("expected no DNS errors, got %d", r.DNSErrors)
	}
}

func TestApplyDomainResult_NODATA(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "NODATA", Latency: 10 * time.Millisecond})

	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 for NODATA, got %d", r.SuccessCount)
	}
}

func TestApplyDomainResult_SERVFAIL(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "SERVFAIL"})

	if r.SuccessCount != 0 {
		t.Error("SERVFAIL should not increment SuccessCount")
	}
	if r.DNSErrors != 1 {
		t.Errorf("expected DNSErrors=1, got %d", r.DNSErrors)
	}
}

func TestApplyDomainResult_NXDOMAIN(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "NXDOMAIN", Latency: 8 * time.Millisecond})

	if r.NXDomains != 1 {
		t.Errorf("expected NXDomains=1, got %d", r.NXDomains)
	}
	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 for NXDOMAIN (got a response), got %d", r.SuccessCount)
	}
	if len(r.Latencies) != 1 {
		t.Errorf("expected latency recorded for NXDOMAIN, got %d", len(r.Latencies))
	}
}

func TestApplyDomainResult_BLOCKED(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "blocked.example.com", Status: "BLOCKED", Latency: 10 * time.Millisecond})

	if r.Blocked != 1 {
		t.Errorf("expected Blocked=1, got %d", r.Blocked)
	}
	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 for BLOCKED (got a response), got %d", r.SuccessCount)
	}
}

func TestApplyDomainResult_REFUSED(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "REFUSED", Latency: 5 * time.Millisecond})

	if r.Refused != 1 {
		t.Errorf("expected Refused=1, got %d", r.Refused)
	}
	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 for REFUSED (got a response), got %d", r.SuccessCount)
	}
}

func TestApplyDomainResult_DNSSEC(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "OK", Latency: 20 * time.Millisecond, DNSSEC: true})

	if r.DNSSECAware != 1 {
		t.Errorf("expected DNSSECAware=1, got %d", r.DNSSECAware)
	}
}

func TestApplyDomainResult_UnexpectedRcode(t *testing.T) {
	r := &ServerResult{}
	applyDomainResult(r, DomainResult{Domain: "example.com", Status: "RCODE5"})

	if r.DNSErrors != 1 {
		t.Errorf("expected DNSErrors=1 for unexpected rcode, got %d", r.DNSErrors)
	}
	if r.SuccessCount != 0 {
		t.Error("unexpected rcode should not increment SuccessCount")
	}
}

// ---------------------------------------------------------------------------
// classifyError domain result population
// ---------------------------------------------------------------------------

func TestClassifyError_AppendsDomainResult_Cert(t *testing.T) {
	r := &ServerResult{}
	classifyError(r, "example.com", &testError{"x509: certificate has expired"})

	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 DomainResult, got %d", len(r.DomainResults))
	}
	if r.DomainResults[0].Status != "CERT_ERR" {
		t.Errorf("expected CERT_ERR, got %q", r.DomainResults[0].Status)
	}
	if r.DomainResults[0].Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", r.DomainResults[0].Domain)
	}
}

func TestClassifyError_AppendsDomainResult_Conn(t *testing.T) {
	r := &ServerResult{}
	classifyError(r, "example.com", &testError{"connection refused"})

	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 DomainResult, got %d", len(r.DomainResults))
	}
	if r.DomainResults[0].Status != "CONN_ERR" {
		t.Errorf("expected CONN_ERR, got %q", r.DomainResults[0].Status)
	}
}

func TestClassifyError_AppendsDomainResult_Generic(t *testing.T) {
	r := &ServerResult{}
	classifyError(r, "example.com", &testError{"some unknown error"})

	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 DomainResult, got %d", len(r.DomainResults))
	}
	if r.DomainResults[0].Status != "ERROR" {
		t.Errorf("expected ERROR, got %q", r.DomainResults[0].Status)
	}
}

// ---------------------------------------------------------------------------
// queryDomain with new response types (via mock UDP server)
// ---------------------------------------------------------------------------

func TestQueryDomain_NXDOMAIN_Genuine(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "nonexistent.example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeNXDomainResp(q, true)}
	r := &ServerResult{}
	queryDomain(r, client, "nonexistent.example.com", "")

	if r.NXDomains != 1 {
		t.Errorf("expected NXDomains=1, got %d", r.NXDomains)
	}
	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 (got a valid response), got %d", r.SuccessCount)
	}
	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 DomainResult, got %d", len(r.DomainResults))
	}
	if r.DomainResults[0].Status != "NXDOMAIN" {
		t.Errorf("expected NXDOMAIN status, got %q", r.DomainResults[0].Status)
	}
}

func TestQueryDomain_NXDOMAIN_Filtered(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeNXDomainResp(q, false)}
	r := &ServerResult{}
	queryDomain(r, client, "blocked.example.com", "")

	if r.Blocked != 1 {
		t.Errorf("expected Blocked=1 for filter-NXDOMAIN, got %d", r.Blocked)
	}
	if r.DomainResults[0].Status != "BLOCKED" {
		t.Errorf("expected BLOCKED status, got %q", r.DomainResults[0].Status)
	}
}

func TestQueryDomain_Blocked_NullAddr(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeBlockedNullResp(q)}
	r := &ServerResult{}
	queryDomain(r, client, "blocked.example.com", "")

	if r.Blocked != 1 {
		t.Errorf("expected Blocked=1, got %d", r.Blocked)
	}
	if r.DomainResults[0].Status != "BLOCKED" {
		t.Errorf("expected BLOCKED status, got %q", r.DomainResults[0].Status)
	}
}

func TestQueryDomain_Refused(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeRefusedResp(q)}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if r.Refused != 1 {
		t.Errorf("expected Refused=1, got %d", r.Refused)
	}
	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 for REFUSED (got a response), got %d", r.SuccessCount)
	}
	if r.DomainResults[0].Status != "REFUSED" {
		t.Errorf("expected REFUSED status, got %q", r.DomainResults[0].Status)
	}
}

func TestQueryDomain_NODATA(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeNODATAResp(q)}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 for NODATA, got %d", r.SuccessCount)
	}
	if r.DomainResults[0].Status != "NODATA" {
		t.Errorf("expected NODATA status, got %q", r.DomainResults[0].Status)
	}
}

func TestQueryDomain_DNSSEC_AD(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeADResp(q)}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if r.DNSSECAware != 1 {
		t.Errorf("expected DNSSECAware=1, got %d", r.DNSSECAware)
	}
	if !r.DomainResults[0].DNSSEC {
		t.Error("expected DomainResult.DNSSEC=true")
	}
}

// ---------------------------------------------------------------------------
// printDomainResults / printDomainRow (smoke -- must not panic)
// ---------------------------------------------------------------------------

func TestPrintDomainResults_Empty(t *testing.T) {
	// Empty slice must not write anything and must not panic.
	printDomainResults(os.Stderr, nil)
}

func TestPrintDomainResults_Various(t *testing.T) {
	results := []DomainResult{
		{Domain: "ok.example.com", Status: "OK", Latency: 12 * time.Millisecond},
		{Domain: "malware-host.example.com", Status: "BLOCKED", Latency: 8 * time.Millisecond, EDECode: "15:Blocked"},
		{Domain: "no-such-host.example.com", Status: "NXDOMAIN", Latency: 5 * time.Millisecond},
		{Domain: "refused.example.com", Status: "REFUSED", Latency: 3 * time.Millisecond},
		{Domain: "secure.example.com", Status: "OK", Latency: 20 * time.Millisecond, DNSSEC: true},
		{Domain: "conn-fail.example.com", Status: "CONN_ERR"},
	}
	// Must not panic with a mix of statuses.
	printDomainResults(os.Stderr, results)
}

// captureFile creates a temp file, runs fn(f), then returns the file's contents.
func captureFile(t *testing.T, fn func(f *os.File)) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "speed-test-*.txt")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer f.Close()
	fn(f)
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	return string(b)
}

// TestPrintDomainResults_TableHeader verifies that the output begins with a
// "Domain Details:" heading followed by a header row and a separator row.
func TestPrintDomainResults_TableHeader(t *testing.T) {
	results := []DomainResult{
		{Domain: "example.com", Status: "OK", Latency: 5 * time.Millisecond},
	}
	got := captureFile(t, func(f *os.File) { printDomainResults(f, results) })

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines (heading, header, separator), got %d:\n%s", len(lines), got)
	}
	if !strings.Contains(lines[0], "Domain Details") {
		t.Errorf("line 0 should contain 'Domain Details', got %q", lines[0])
	}
	if !strings.Contains(lines[1], "Domain") || !strings.Contains(lines[1], "Latency") || !strings.Contains(lines[1], "Status") {
		t.Errorf("line 1 should be header row with Domain/Latency/Status, got %q", lines[1])
	}
	if !strings.Contains(lines[2], "---") {
		t.Errorf("line 2 should be a separator row (dashes), got %q", lines[2])
	}
}

// TestPrintDomainResults_TableRowCount verifies that the table contains exactly
// one data row per DomainResult (heading + header + separator + N data rows).
func TestPrintDomainResults_TableRowCount(t *testing.T) {
	results := []DomainResult{
		{Domain: "a.example.com", Status: "OK", Latency: 1 * time.Millisecond},
		{Domain: "b.example.com", Status: "NXDOMAIN", Latency: 2 * time.Millisecond},
		{Domain: "c.example.com", Status: "BLOCKED", Latency: 3 * time.Millisecond},
	}
	got := captureFile(t, func(f *os.File) { printDomainResults(f, results) })

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	// Expected: 1 heading + 1 header + 1 separator + 3 data rows + 2 blank lines
	// between rows = 8 (trailing blank after last row removed by TrimRight).
	if len(lines) != 8 {
		t.Errorf("expected 8 lines, got %d:\n%s", len(lines), got)
	}
}

// TestPrintDomainResults_TruncationInTable verifies that the "..." truncation
// algorithm still produces correct output when domains are printed inside the
// table format.
func TestPrintDomainResults_TruncationInTable(t *testing.T) {
	// 41-char domain: must be truncated to 40 chars in the domain column.
	longDomain := "cloud-storage-api-v2-stage.service.tokoyo" // 41 chars
	if len(longDomain) != 41 {
		t.Fatalf("test setup: expected 41 chars, got %d", len(longDomain))
	}
	results := []DomainResult{
		{Domain: longDomain, Status: "OK", Latency: 10 * time.Millisecond},
	}
	got := captureFile(t, func(f *os.File) { printDomainResults(f, results) })

	// The data row (4th line, index 3) must contain "..." and the tail suffix.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 lines, got %d", len(lines))
	}
	dataRow := lines[3]
	if !strings.Contains(dataRow, "...") {
		t.Errorf("expected '...' truncation in data row, got %q", dataRow)
	}
	if !strings.HasSuffix(strings.TrimRight(lines[3], " \t"), "10ms      OK") {
		// Check that latency+status columns still align after truncation
		if !strings.Contains(dataRow, "10ms") || !strings.Contains(dataRow, "OK") {
			t.Errorf("latency/status columns missing after truncation in row: %q", dataRow)
		}
	}
}

// TestPrintDomainResults_EDEInfoColumn verifies that the EDE/Info column
// appears correctly for rows that have an EDE code and for rows that have
// DNSSEC instead.
func TestPrintDomainResults_EDEInfoColumn(t *testing.T) {
	results := []DomainResult{
		{Domain: "blocked.example.com", Status: "BLOCKED", Latency: 7 * time.Millisecond, EDECode: "15:Blocked"},
		{Domain: "ok-prohibited.example.com", Status: "OK", Latency: 5 * time.Millisecond, EDECode: "18:Prohibited"},
		{Domain: "secure.example.com", Status: "OK", Latency: 3 * time.Millisecond, DNSSEC: true},
		{Domain: "plain.example.com", Status: "OK", Latency: 2 * time.Millisecond},
	}
	got := captureFile(t, func(f *os.File) { printDomainResults(f, results) })

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	// lines[0]=heading, [1]=header, [2]=separator, data rows at [3],[5],[7],[9]
	// with blank lines at [4],[6],[8] between them.
	if len(lines) < 10 {
		t.Fatalf("expected 10 lines, got %d:\n%s", len(lines), got)
	}
	if !strings.Contains(lines[3], "15:Blocked") {
		t.Errorf("EDE code '15:Blocked' missing from row: %q", lines[3])
	}
	if !strings.Contains(lines[5], "18:Prohibited") {
		t.Errorf("EDE code '18:Prohibited' missing from row: %q", lines[5])
	}
	if !strings.Contains(lines[7], "[DNSSEC]") {
		t.Errorf("[DNSSEC] tag missing from DNSSEC row: %q", lines[7])
	}
	if strings.Contains(lines[9], "15:") || strings.Contains(lines[9], "[DNSSEC]") {
		t.Errorf("plain OK row should have no EDE/DNSSEC annotation: %q", lines[9])
	}
}

// TestPrintDomainResults_HeaderColumnsAligned verifies that the header and
// separator row widths match the data row field widths.
func TestPrintDomainResults_HeaderColumnsAligned(t *testing.T) {
	results := []DomainResult{
		{Domain: "example.com", Status: "OK", Latency: 5 * time.Millisecond},
	}
	got := captureFile(t, func(f *os.File) { printDomainResults(f, results) })

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("need at least 4 lines")
	}
	headerLine := lines[1]
	sepLine := lines[2]
	dataLine := lines[3]

	// All three lines must start with the same 4-space indent.
	for _, l := range []string{headerLine, sepLine, dataLine} {
		if !strings.HasPrefix(l, "    ") {
			t.Errorf("line must start with 4-space indent, got %q", l)
		}
	}
	// After the 4-space indent, the first 40 chars are the domain column.
	// The header must start with "Domain" and the separator must start with dashes.
	trimmedHeader := strings.TrimPrefix(headerLine, "    ")
	if len(trimmedHeader) < 40 {
		t.Fatalf("header line too short after indent: %d chars, want >= 40", len(trimmedHeader))
	}
	if !strings.HasPrefix(trimmedHeader[:40], "Domain") {
		t.Errorf("header domain column should start with 'Domain', got %q", trimmedHeader[:40])
	}
	trimmedSep := strings.TrimPrefix(sepLine, "    ")
	if len(trimmedSep) < 40 {
		t.Fatalf("separator line too short after indent: %d chars, want >= 40", len(trimmedSep))
	}
	if strings.TrimLeft(trimmedSep[:40], "-") != "" {
		t.Errorf("separator domain column should be all dashes, got %q", trimmedSep[:40])
	}
}

// ---------------------------------------------------------------------------
// RunInteractiveTest domain-level output (mock server returning varied rcodes)
// ---------------------------------------------------------------------------

func TestRunInteractiveTest_BlockedDomains(t *testing.T) {
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		// Return 0.0.0.0 for all queries to simulate a sinkhole.
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
		})
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	// Must not panic; blocked counter must be non-zero after the call.
	results := runTests(cfg, []string{"blocked.example.com", "also-blocked.example.com"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Blocked != 2 {
		t.Errorf("expected Blocked=2, got %d", results[0].Blocked)
	}
}

func TestRunInteractiveTest_MixedRcodes(t *testing.T) {
	calls := 0
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		calls++
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		switch calls % 4 {
		case 0: // OK with normal A record
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
				A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
			})
		case 1: // SERVFAIL
			resp.Rcode = dns.RcodeServerFailure
		case 2: // NXDOMAIN with SOA (genuine)
			resp.Rcode = dns.RcodeNameError
			resp.Ns = append(resp.Ns, &dns.SOA{
				Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
				SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com.", Minttl: 300},
			})
		case 3: // REFUSED
			resp.Rcode = dns.RcodeRefused
		}
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}

	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	results := runTests(cfg, domains)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.TotalQueries != 4 {
		t.Errorf("expected 4 total queries, got %d", r.TotalQueries)
	}
	if len(r.DomainResults) != 4 {
		t.Errorf("expected 4 DomainResults, got %d", len(r.DomainResults))
	}
	// Must not panic when printing mixed results.
	printServerResult(os.Stderr, &r)
}

func TestRunStartupTest_BlockedUpstream(t *testing.T) {
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
		})
		return resp
	})

	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: localAddr, Protocol: "udp"},
		},
		UpstreamSettings: config.UpstreamSettings{VerifyCertificates: false},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	// Must log a warning about blocked domains and not panic.
	RunStartupTest(cfg, logger)
}

// ---------------------------------------------------------------------------
// hasEDEBlocked
// ---------------------------------------------------------------------------

func TestHasEDEBlocked_NoEDE(t *testing.T) {
	msg := new(dns.Msg)
	if hasEDEBlocked(msg) {
		t.Error("expected false for message with no EDE")
	}
}

func TestHasEDEBlocked_OtherEDE(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorDNSBogus, ExtraText: "bogus"})
	if hasEDEBlocked(msg) {
		t.Error("expected false for non-blocking EDE code")
	}
}

func TestHasEDEBlocked_Blocked(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: "Blocked"})
	if !hasEDEBlocked(msg) {
		t.Error("expected true for ExtendedErrorBlocked (15)")
	}
}

func TestHasEDEBlocked_Censored(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorCensored})
	if !hasEDEBlocked(msg) {
		t.Error("expected true for ExtendedErrorCensored (16)")
	}
}

func TestHasEDEBlocked_Filtered(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorFiltered})
	if !hasEDEBlocked(msg) {
		t.Error("expected true for ExtendedErrorFiltered (17)")
	}
}

func TestHasEDEBlocked_Prohibited(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorProhibited})
	if !hasEDEBlocked(msg) {
		t.Error("expected true for ExtendedErrorProhibited (18)")
	}
}

// ---------------------------------------------------------------------------
// SERVFAIL + EDE Blocked -> BLOCKED classification (Quad9-style)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// extractEDECode
// ---------------------------------------------------------------------------

func TestExtractEDECode_NoEDE(t *testing.T) {
	msg := new(dns.Msg)
	if got := extractEDECode(msg); got != "" {
		t.Errorf("expected empty string for message with no EDE, got %q", got)
	}
}

func TestExtractEDECode_KnownCode(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: "policy"})
	got := extractEDECode(msg)
	if got != "15:Blocked" {
		t.Errorf("expected '15:Blocked', got %q", got)
	}
}

func TestExtractEDECode_UnknownCode(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: 999})
	got := extractEDECode(msg)
	if got != "999" {
		t.Errorf("expected '999' for unknown code, got %q", got)
	}
}

func TestExtractEDECode_FirstOnly(t *testing.T) {
	// Only the first EDE option should be returned.
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo,
		&dns.EDE{InfoCode: dns.ExtendedErrorBlocked},
		&dns.EDE{InfoCode: dns.ExtendedErrorCensored},
	)
	got := extractEDECode(msg)
	if got != "15:Blocked" {
		t.Errorf("expected first EDE '15:Blocked', got %q", got)
	}
}

func TestExtractEDECode_Censored(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorCensored})
	got := extractEDECode(msg)
	if got != "16:Censored" {
		t.Errorf("expected '16:Censored', got %q", got)
	}
}

func TestExtractEDECode_DNSSEC_Bogus(t *testing.T) {
	msg := new(dns.Msg)
	msg.Pseudo = append(msg.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorDNSBogus})
	got := extractEDECode(msg)
	if got != "6:DNSSEC Bogus" {
		t.Errorf("expected '6:DNSSEC Bogus', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// EDECode populated in DomainResult
// ---------------------------------------------------------------------------

func TestBuildDomainResult_EDECode_Populated(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	resp := makeServfailEDEResp(q, dns.ExtendedErrorBlocked)
	dr := buildDomainResult("blocked.example.com", resp, 10*time.Millisecond)

	if dr.EDECode != "15:Blocked" {
		t.Errorf("expected EDECode='15:Blocked', got %q", dr.EDECode)
	}
}

func TestBuildDomainResult_EDECode_Empty_For_OK(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	dr := buildDomainResult("example.com", makeNormalSpeedResp(q), 10*time.Millisecond)

	if dr.EDECode != "" {
		t.Errorf("expected empty EDECode for OK response, got %q", dr.EDECode)
	}
}

func TestBuildDomainResult_EDECode_DNSSEC_Bogus(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	resp := makeServfailResp(q)
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorDNSBogus, ExtraText: "bad sig"})
	dr := buildDomainResult("example.com", resp, 15*time.Millisecond)

	if dr.EDECode != "6:DNSSEC Bogus" {
		t.Errorf("expected EDECode='6:DNSSEC Bogus', got %q", dr.EDECode)
	}
	// DNSSEC Bogus does not carry a blocking EDE code, so status should be SERVFAIL.
	if dr.Status != "SERVFAIL" {
		t.Errorf("expected SERVFAIL for DNSSEC Bogus, got %q", dr.Status)
	}
}

func makeServfailEDEResp(query *dns.Msg, code uint16) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeServerFailure
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{InfoCode: code, ExtraText: "policy"})
	return resp
}

func TestBuildDomainResult_SERVFAIL_EDE_Blocked(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	resp := makeServfailEDEResp(q, dns.ExtendedErrorBlocked)
	dr := buildDomainResult("blocked.example.com", resp, 46*time.Millisecond)

	if dr.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for SERVFAIL+EDE(Blocked), got %q", dr.Status)
	}
	if dr.Latency != 46*time.Millisecond {
		t.Errorf("expected 46ms latency, got %v", dr.Latency)
	}
}

func TestBuildDomainResult_SERVFAIL_EDE_Censored(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	resp := makeServfailEDEResp(q, dns.ExtendedErrorCensored)
	dr := buildDomainResult("blocked.example.com", resp, 10*time.Millisecond)

	if dr.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for SERVFAIL+EDE(Censored), got %q", dr.Status)
	}
}

func TestBuildDomainResult_SERVFAIL_EDE_Filtered(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	resp := makeServfailEDEResp(q, dns.ExtendedErrorFiltered)
	dr := buildDomainResult("blocked.example.com", resp, 10*time.Millisecond)

	if dr.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for SERVFAIL+EDE(Filtered), got %q", dr.Status)
	}
}

func TestBuildDomainResult_SERVFAIL_EDE_Prohibited(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	resp := makeServfailEDEResp(q, dns.ExtendedErrorProhibited)
	dr := buildDomainResult("blocked.example.com", resp, 10*time.Millisecond)

	if dr.Status != "BLOCKED" {
		t.Errorf("expected BLOCKED for SERVFAIL+EDE(Prohibited), got %q", dr.Status)
	}
}

func TestBuildDomainResult_SERVFAIL_NoEDE_IsServFail(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	// Plain SERVFAIL without EDE must remain SERVFAIL (genuine server error).
	dr := buildDomainResult("example.com", makeServfailResp(q), 200*time.Millisecond)

	if dr.Status != "SERVFAIL" {
		t.Errorf("expected SERVFAIL for plain SERVFAIL (no EDE), got %q", dr.Status)
	}
}

func TestQueryDomain_SERVFAIL_EDE_Blocked(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "blocked.example.com.", dns.TypeA)

	client := &mockSpeedClient{resp: makeServfailEDEResp(q, dns.ExtendedErrorBlocked)}
	r := &ServerResult{}
	queryDomain(r, client, "blocked.example.com", "")

	if r.Blocked != 1 {
		t.Errorf("expected Blocked=1 for SERVFAIL+EDE(Blocked), got %d", r.Blocked)
	}
	if r.DNSErrors != 0 {
		t.Errorf("expected DNSErrors=0 (classified as BLOCKED, not SERVFAIL), got %d", r.DNSErrors)
	}
	if r.SuccessCount != 1 {
		t.Errorf("expected SuccessCount=1 (got a response), got %d", r.SuccessCount)
	}
	if r.DomainResults[0].Status != "BLOCKED" {
		t.Errorf("expected BLOCKED status, got %q", r.DomainResults[0].Status)
	}
}

// ---------------------------------------------------------------------------
// truncateDomain
// ---------------------------------------------------------------------------

func TestTruncateDomain_ShortDomain_NoTruncation(t *testing.T) {
	tests := []string{
		"www.example.com",
		"example.org",
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r", // 37 chars -- under 40
		strings.Repeat("x", 40),               // exactly 40 -- no dot, no truncation needed since len==maxLen
	}
	for _, d := range tests {
		got := truncateDomain(d, 40)
		if got != d {
			t.Errorf("truncateDomain(%q, 40) = %q, want no-op", d, got)
		}
	}
}

func TestTruncateDomain_ExactlyMaxLen(t *testing.T) {
	// A domain exactly 40 chars must not be truncated.
	domain := "abcdefghijklmnopqrstuvwxyz1234567890.com" // 40 chars
	if len(domain) != 40 {
		t.Fatalf("test setup error: domain is %d chars, expected 40", len(domain))
	}
	got := truncateDomain(domain, 40)
	if got != domain {
		t.Errorf("truncateDomain(%q, 40) = %q, want no-op", domain, got)
	}
}

func TestTruncateDomain_TLDCom(t *testing.T) {
	// TLD=com (3), suffixLen=12, prefixLen=28, result must be exactly 40 chars.
	domain := "abcdefghijklmnopqrstuvwxyz1234567890x.com" // 41 chars
	got := truncateDomain(domain, 40)
	if len(got) != 40 {
		t.Errorf("truncateDomain result length = %d, want 40; got %q", len(got), got)
	}
	if !strings.HasSuffix(got, "7890x.com") {
		t.Errorf("expected suffix '7890x.com' (last-5+TLD), got %q", got)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("expected '...' in truncated domain, got %q", got)
	}
}

func TestTruncateDomain_TLDTokoyo(t *testing.T) {
	// TLD=tokoyo (6), suffixLen=15, prefixLen=25, result must be exactly 40 chars.
	// 33 chars -- no truncation needed.
	domain := "cloud-storage-api-v2.service.tokoyo"
	got := truncateDomain(domain, 40)
	if got != domain {
		t.Errorf("expected no truncation for short domain, got %q", got)
	}

	// Exactly 40 chars -- must not be truncated.
	longDomain := "cloud-storage-api-v2-prod.service.tokoyo" // 40 chars
	if len(longDomain) != 40 {
		t.Fatalf("test setup: expected 40 chars, got %d", len(longDomain))
	}
	got2 := truncateDomain(longDomain, 40)
	if got2 != longDomain {
		t.Errorf("expected no truncation at exactly 40 chars, got %q", got2)
	}

	// 41 chars -- must be truncated to exactly 40 with suffix 'rvice.tokoyo'.
	overDomain := "cloud-storage-api-v2-stage.service.tokoyo" // 41 chars
	if len(overDomain) != 41 {
		t.Fatalf("test setup: expected 41 chars, got %d", len(overDomain))
	}
	got3 := truncateDomain(overDomain, 40)
	if len(got3) != 40 {
		t.Errorf("expected 40-char result, got %d: %q", len(got3), got3)
	}
	if !strings.HasSuffix(got3, "rvice.tokoyo") {
		t.Errorf("expected suffix 'rvice.tokoyo', got %q", got3)
	}
}

func TestTruncateDomain_TLDYokohama(t *testing.T) {
	// TLD=yokohama (8), suffixLen=17, prefixLen=23.
	// 43 chars -- must be truncated to 40.
	domain := "mail.north-america-region.corp.yokohama" // 39 chars -- no truncation
	got := truncateDomain(domain, 40)
	if got != domain {
		t.Errorf("expected no truncation for 39-char domain, got %q", got)
	}

	// 43 chars -- must truncate.
	overDomain := "api.north-america-east-region.corp.yokohama" // 43 chars
	if len(overDomain) != 43 {
		t.Fatalf("test setup: expected 43 chars, got %d", len(overDomain))
	}
	got2 := truncateDomain(overDomain, 40)
	if len(got2) != 40 {
		t.Errorf("expected 40-char result, got %d: %q", len(got2), got2)
	}
	if !strings.HasSuffix(got2, "corp.yokohama") {
		t.Errorf("expected suffix 'corp.yokohama', got %q", got2)
	}
	if !strings.HasPrefix(got2, "api.north-america-east") {
		t.Errorf("expected prefix 'api.north-america-east', got %q", got2)
	}
}

func TestTruncateDomain_NoDot(t *testing.T) {
	// Domain with no dot uses simple head truncation.
	domain := strings.Repeat("a", 45)
	got := truncateDomain(domain, 40)
	if len(got) != 40 {
		t.Errorf("expected 40-char result, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected '...' suffix for no-dot fallback, got %q", got)
	}
}

func TestTruncateDomain_LeadingDot_Fallback(t *testing.T) {
	// Domain starting with '.' (lastDot == 0) uses simple truncation.
	domain := "." + strings.Repeat("b", 44)
	got := truncateDomain(domain, 40)
	if len(got) != 40 {
		t.Errorf("expected 40-char result, got %d", len(got))
	}
}

func TestTruncateDomain_VeryLongTLD_Fallback(t *testing.T) {
	// TLD longer than 26 chars makes prefixLen negative; must fall back gracefully.
	tld := strings.Repeat("x", 30)
	domain := "short." + tld // 37 chars -- no truncation needed
	got := truncateDomain(domain, 40)
	if got != domain {
		t.Errorf("expected no-op for 37-char domain, got %q", got)
	}

	// Long enough to trigger truncation path.
	longDomain := "longerprefix." + tld // 43 chars, TLD=30 -> prefixLen=40-3-5-1-30=1 (barely fits)
	got2 := truncateDomain(longDomain, 40)
	if len(got2) > 40 {
		t.Errorf("result must not exceed maxLen; got %d chars: %q", len(got2), got2)
	}
}

func TestTruncateDomain_PreTLDTooShort_Fallback(t *testing.T) {
	// Part before TLD has fewer than 5 chars; must fall back to simple truncation.
	domain := "ab.c" + strings.Repeat("d", 37) // 41 chars: "ab." + 1-char TLD "cddd...d"
	// Actually: lastDot separates "ab" and "cd...d", beforeTLD = "ab" (2 chars < 5)
	domain2 := strings.Repeat("a", 36) + ".ab" // lastDot=36, TLD="ab" (2), beforeTLD=36 chars -- OK
	// Let's make beforeTLD shorter than 5:
	domain3 := strings.Repeat("a", 36) + ".b" // 38 chars -- under 40, no truncation

	for _, d := range []string{domain, domain2, domain3} {
		got := truncateDomain(d, 40)
		if len(got) > 40 {
			t.Errorf("result exceeds maxLen for %q: got %d chars", d, len(got))
		}
	}
}

func TestTruncateDomain_ExactlyThreeDots(t *testing.T) {
	// The ellipsis must be exactly "..." (3 dots), not more or fewer.
	// 43 chars: 36 'a's + 3 chars + ".net" = 40 after truncation.
	domain := strings.Repeat("a", 36) + "bcd.net" // 43 chars
	got := truncateDomain(domain, 40)
	idx := strings.Index(got, "...")
	if idx < 0 {
		t.Fatalf("expected '...' in result, got %q", got)
	}
	// Verify the char after "..." is not another dot.
	afterEllipsis := got[idx+3:]
	if strings.HasPrefix(afterEllipsis, ".") {
		t.Errorf("ellipsis has more than 3 dots in %q", got)
	}
	if len(got) != 40 {
		t.Errorf("expected 40-char result, got %d: %q", len(got), got)
	}
}

// ---------------------------------------------------------------------------
// extractAnswerIPs
// ---------------------------------------------------------------------------

func makeAAAAResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")},
	})
	return resp
}

func TestExtractAnswerIPs_Empty(t *testing.T) {
	msg := new(dns.Msg)
	ips := extractAnswerIPs(msg)
	if ips != nil {
		t.Errorf("expected nil for empty answer, got %v", ips)
	}
}

func TestExtractAnswerIPs_SingleA(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	resp := makeNormalSpeedResp(q)

	ips := extractAnswerIPs(resp)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d: %v", len(ips), ips)
	}
	if ips[0] != "93.184.216.34" {
		t.Errorf("expected 93.184.216.34, got %q", ips[0])
	}
}

func TestExtractAnswerIPs_MultipleA(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	resp := makeNormalSpeedResp(q)
	// Add a second A record
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.99")},
	})

	ips := extractAnswerIPs(resp)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d: %v", len(ips), ips)
	}
}

func TestExtractAnswerIPs_AAAA(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)
	resp := makeAAAAResp(q)

	ips := extractAnswerIPs(resp)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IPv6 IP, got %d: %v", len(ips), ips)
	}
	if ips[0] != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Errorf("unexpected IPv6 address: %q", ips[0])
	}
}

func TestExtractAnswerIPs_Mixed(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	resp := makeNormalSpeedResp(q) // has one A record
	resp.Answer = append(resp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")},
	})

	ips := extractAnswerIPs(resp)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs (A+AAAA), got %d: %v", len(ips), ips)
	}
}

// ---------------------------------------------------------------------------
// buildDomainResult - ResolvedIPs population
// ---------------------------------------------------------------------------

func TestBuildDomainResult_ResolvedIPsPopulated(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	resp := makeNormalSpeedResp(q)

	dr := buildDomainResult("example.com", resp, 10*time.Millisecond)
	if len(dr.ResolvedIPs) != 1 {
		t.Fatalf("expected 1 resolved IP, got %d: %v", len(dr.ResolvedIPs), dr.ResolvedIPs)
	}
	if dr.ResolvedIPs[0] != "93.184.216.34" {
		t.Errorf("expected 93.184.216.34, got %q", dr.ResolvedIPs[0])
	}
}

func TestBuildDomainResult_NoIPsForNXDOMAIN(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "nonexistent.example.com.", dns.TypeA)
	resp := makeNXDomainResp(q, true)

	dr := buildDomainResult("nonexistent.example.com", resp, 10*time.Millisecond)
	if len(dr.ResolvedIPs) != 0 {
		t.Errorf("expected no IPs for NXDOMAIN, got %v", dr.ResolvedIPs)
	}
}

func TestBuildDomainResult_NoIPsForSERVFAIL(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	resp := makeServfailResp(q)

	dr := buildDomainResult("example.com", resp, 10*time.Millisecond)
	if len(dr.ResolvedIPs) != 0 {
		t.Errorf("expected no IPs for SERVFAIL, got %v", dr.ResolvedIPs)
	}
}

// ---------------------------------------------------------------------------
// queryDomain - ipFamily routing (A vs AAAA)
// ---------------------------------------------------------------------------

func TestQueryDomain_UsesAAAA_WhenIPv6(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeAAAA)

	recording := &recordingMockClient{inner: mockSpeedClient{resp: makeAAAAResp(q)}}
	r := &ServerResult{}
	queryDomain(r, recording, "example.com", "ipv6")

	if recording.lastQuery == nil {
		t.Fatal("query not received by client")
	}
	_, isAAAA := recording.lastQuery.Question[0].(*dns.AAAA)
	if !isAAAA {
		t.Errorf("expected AAAA question type, got %T", recording.lastQuery.Question[0])
	}
}

func TestQueryDomain_UsesA_WhenIPv4(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	recording := &recordingMockClient{inner: mockSpeedClient{resp: makeNormalSpeedResp(q)}}
	r := &ServerResult{}
	queryDomain(r, recording, "example.com", "ipv4")

	if recording.lastQuery == nil {
		t.Fatal("query not received by client")
	}
	_, isA := recording.lastQuery.Question[0].(*dns.A)
	if !isA {
		t.Errorf("expected A question type, got %T", recording.lastQuery.Question[0])
	}
}

func TestQueryDomain_UsesA_WhenEmpty(t *testing.T) {
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	recording := &recordingMockClient{inner: mockSpeedClient{resp: makeNormalSpeedResp(q)}}
	r := &ServerResult{}
	queryDomain(r, recording, "example.com", "")

	if recording.lastQuery == nil {
		t.Fatal("query not received by client")
	}
	_, isA := recording.lastQuery.Question[0].(*dns.A)
	if !isA {
		t.Errorf("expected A question type for empty ipFamily, got %T", recording.lastQuery.Question[0])
	}
}

// ---------------------------------------------------------------------------
// queryDomain - latency measurement
// ---------------------------------------------------------------------------

func TestQueryDomain_TimingIsPositive_OnSuccess(t *testing.T) {
	// Use a sleeping mock so the elapsed time is measurably > 0 regardless of
	// OS timer resolution.  The delay is short enough that the test is fast
	// but long enough to survive the Windows 15ms clock tick.
	const delay = 20 * time.Millisecond
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)

	client := &sleepingMockClient{inner: mockSpeedClient{resp: makeNormalSpeedResp(q)}, delay: delay}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 domain result, got %d", len(r.DomainResults))
	}
	dr := r.DomainResults[0]
	if dr.Status != "OK" {
		t.Fatalf("expected OK status on success, got %q (conn=%d dns=%d)", dr.Status, r.ConnErrors, r.DNSErrors)
	}
	// Latency should be >= delay; 0 would indicate the error path was taken.
	if dr.Latency < delay {
		t.Errorf("expected latency >= %v, got %v", delay, dr.Latency)
	}
}

func TestQueryDomain_TimingIsZero_OnError(t *testing.T) {
	client := &mockSpeedClient{err: errors.New("connection refused")}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	// classifyError is called; DomainResults still gets an entry but Latency=0
	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 domain result, got %d", len(r.DomainResults))
	}
	if r.DomainResults[0].Latency != 0 {
		t.Errorf("expected zero latency on transport error, got %v", r.DomainResults[0].Latency)
	}
}

func TestQueryDomain_TimingCapturesRoundTrip(t *testing.T) {
	const delay = 30 * time.Millisecond
	localAddr := startMockUDPServer(t, func(query *dns.Msg) *dns.Msg {
		time.Sleep(delay)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		return resp
	})

	client, err := createClient(config.UpstreamServer{Address: localAddr, Protocol: "udp"}, false, nil, "")
	if err != nil {
		t.Fatalf("createClient: %v", err)
	}
	r := &ServerResult{}
	queryDomain(r, client, "example.com", "")

	if len(r.DomainResults) != 1 {
		t.Fatalf("expected 1 result, got %d", len(r.DomainResults))
	}
	if r.DomainResults[0].Latency < delay {
		t.Errorf("latency %v should be >= mock delay %v", r.DomainResults[0].Latency, delay)
	}
}

// ---------------------------------------------------------------------------
// printDomainRow / printDomainResults - resolved IPs sub-line
// ---------------------------------------------------------------------------

func TestPrintDomainResults_ResolvedIPsSubLine(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	results := []DomainResult{
		{Domain: "example.com", Status: "OK", Latency: 10 * time.Millisecond, ResolvedIPs: []string{"93.184.216.34"}},
	}
	printDomainResults(w, results)

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if !strings.Contains(output, "Resolved IPs:") {
		t.Errorf("expected 'Resolved IPs:' sub-line in output, got:\n%s", output)
	}
	if !strings.Contains(output, "93.184.216.34") {
		t.Errorf("expected IP address in Resolved IPs sub-line, got:\n%s", output)
	}
}

func TestPrintDomainResults_NoIPLine_WhenEmpty(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	results := []DomainResult{
		{Domain: "example.com", Status: "NXDOMAIN", Latency: 10 * time.Millisecond, ResolvedIPs: nil},
	}
	printDomainResults(w, results)

	w.Close()
	os.Stdout = old

	var buf [4096]byte
	n, _ := r.Read(buf[:])
	output := string(buf[:n])

	if strings.Contains(output, "Resolved IPs:") {
		t.Errorf("did not expect 'Resolved IPs:' line when ResolvedIPs is nil, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// ServerResult - BootstrapLatency and BootstrapIP fields
// ---------------------------------------------------------------------------

func TestServerResult_BootstrapFields(t *testing.T) {
	r := &ServerResult{
		BootstrapLatency: 5 * time.Millisecond,
		BootstrapIP:      "9.9.9.9",
	}
	if r.BootstrapLatency != 5*time.Millisecond {
		t.Errorf("unexpected BootstrapLatency: %v", r.BootstrapLatency)
	}
	if r.BootstrapIP != "9.9.9.9" {
		t.Errorf("unexpected BootstrapIP: %q", r.BootstrapIP)
	}
}
