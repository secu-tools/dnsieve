// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package speed

import (
	"context"
	"errors"
	"net"
	"net/netip"
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

func TestServerStatus(t *testing.T) {
	tests := []struct {
		name     string
		result   ServerResult
		expected string
	}{
		{
			name:     "all failed",
			result:   ServerResult{SuccessCount: 0, TotalQueries: 5},
			expected: "FAIL",
		},
		{
			name:     "slow server",
			result:   ServerResult{SuccessCount: 3, AvgLatency: 600 * time.Millisecond},
			expected: "SLOW",
		},
		{
			name:     "cert errors",
			result:   ServerResult{SuccessCount: 3, AvgLatency: 50 * time.Millisecond, CertErrors: 1},
			expected: "WARN",
		},
		{
			name:     "conn errors",
			result:   ServerResult{SuccessCount: 3, AvgLatency: 50 * time.Millisecond, ConnErrors: 2},
			expected: "WARN",
		},
		{
			name:     "healthy",
			result:   ServerResult{SuccessCount: 5, AvgLatency: 50 * time.Millisecond},
			expected: "OK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serverStatus(&tt.result)
			if got != tt.expected {
				t.Errorf("serverStatus() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestCheckBootstrapResolve_UDP(t *testing.T) {
	// UDP protocol should always return true (no hostname to resolve)
	r := &ServerResult{}
	ok := checkBootstrapResolve(r, testUpstream("9.9.9.9:53", "udp"), "")
	if !ok {
		t.Error("UDP should always return true for bootstrap resolve")
	}
}

func TestCheckBootstrapResolve_IPAddress(t *testing.T) {
	// IP address in DoT should skip resolution
	r := &ServerResult{}
	ok := checkBootstrapResolve(r, testUpstream("1.1.1.1:853", "dot"), "")
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
	queryDomain(r, client, "example.com")

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
	queryDomain(r, client, "example.com")

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
	queryDomain(r, client, "example.com")

	if r.SuccessCount != 0 {
		t.Error("SERVFAIL should not be counted as success")
	}
	if r.DNSErrors != 1 {
		t.Errorf("expected 1 DNS error for SERVFAIL, got %d", r.DNSErrors)
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
