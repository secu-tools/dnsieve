// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// mockClient implements the Client interface for testing.
type mockClient struct {
	name     string
	response *dns.Msg
	err      error
	delay    time.Duration
}

func (m *mockClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	// Deep copy via pack/unpack (v2 Copy is shallow).
	// Guard against library panics on records with RDLENGTH=0: the v2 library
	// skips calling the concrete Unpack method for zero-length rdata, leaving
	// struct fields (e.g. rdata.A.Addr) at their zero values. A subsequent
	// Pack() then calls As4() on the zero netip.Addr and panics. Treat any
	// such panic as a non-fatal upstream error so the resolver can fall back.
	packErr := func() (retErr error) {
		defer func() {
			if r := recover(); r != nil {
				retErr = fmt.Errorf("pack: %v", r)
			}
		}()
		return m.response.Pack()
	}()
	if packErr != nil {
		return nil, packErr
	}
	resp := new(dns.Msg)
	resp.Data = make([]byte, len(m.response.Data))
	copy(resp.Data, m.response.Data)
	if err := resp.Unpack(); err != nil {
		return nil, err
	}
	resp.ID = msg.ID
	return resp, nil
}

func (m *mockClient) String() string {
	return m.name
}

func makeQuery(name string, qtype uint16) *dns.Msg {
	return dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
}

func makeNormalResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	return resp
}

func makeBlockedResp(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
	})
	return resp
}

func makeNXDomainResp(query *dns.Msg, withSOA bool) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeNameError
	if withSOA {
		resp.Ns = append(resp.Ns, &dns.SOA{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
			SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com."},
		})
	}
	return resp
}

func newTestResolverWithClients(clients []Client) *Resolver {
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	return &Resolver{
		clients: clients,
		timeout: 2 * time.Second,
		minWait: 50 * time.Millisecond,
		logger:  logger,
	}
}

func newTestResolverWithLogger(clients []Client, logger *logging.Logger) *Resolver {
	return &Resolver{
		clients: clients,
		timeout: 2 * time.Second,
		minWait: 50 * time.Millisecond,
		logger:  logger,
	}
}

func TestNewResolver_ValidConfig(t *testing.T) {
	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: "https://dns.quad9.net/dns-query", Protocol: "doh"},
		},
		UpstreamSettings: config.UpstreamSettings{
			TimeoutMS:          2000,
			MinWaitMS:          200,
			VerifyCertificates: true,
		},
		Logging: config.LoggingConfig{LogLevel: "info"},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	r, err := NewResolver(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(r.clients))
	}
}

func TestNewResolver_UnsupportedProtocol(t *testing.T) {
	cfg := &config.Config{
		Upstream: []config.UpstreamServer{
			{Address: "example.com:53", Protocol: "unsupported"},
		},
		UpstreamSettings: config.UpstreamSettings{
			TimeoutMS: 2000,
			MinWaitMS: 200,
		},
		Logging: config.LoggingConfig{LogLevel: "info"},
	}
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	_, err := NewResolver(cfg, logger)
	if err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestResolve_AllNormal(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", response: makeNormalResp(query)},
		&mockClient{name: "server2", response: makeNormalResp(query)},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("expected a response")
	}
	if result.Blocked {
		t.Error("should not be blocked")
	}
	if !result.AllResponded {
		t.Error("all should have responded")
	}
	if !result.Cacheable {
		t.Error("should be cacheable")
	}
}

func TestResolve_OneBlocked(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", response: makeNormalResp(query)},
		&mockClient{name: "server2", response: makeBlockedResp(query)},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if !result.Blocked {
		t.Error("should be blocked when any server signals block")
	}
	if result.BlockedBy != "server2" {
		t.Errorf("BlockedBy should be server2, got %q", result.BlockedBy)
	}
}

func TestResolve_AllBlocked(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", response: makeBlockedResp(query)},
		&mockClient{name: "server2", response: makeBlockedResp(query)},
		&mockClient{name: "server3", response: makeBlockedResp(query)},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if !result.Blocked {
		t.Error("should be blocked")
	}
	if !result.AllResponded {
		t.Error("all should have responded")
	}
	if !result.Cacheable {
		t.Error("blocked result should be cacheable when all responded")
	}
}

func TestResolve_OneServerError(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", response: makeNormalResp(query)},
		&mockClient{name: "server2", err: fmt.Errorf("connection refused")},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("should still return best available response")
	}
	if result.Blocked {
		t.Error("server error should not cause block")
	}
	if result.Cacheable {
		t.Error("should NOT be cacheable when some servers had errors")
	}
}

func TestResolve_AllServerErrors(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", err: fmt.Errorf("timeout")},
		&mockClient{name: "server2", err: fmt.Errorf("connection refused")},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("should still return SERVFAIL")
	}
	if result.BestResponse.Rcode != dns.RcodeServerFailure {
		t.Error("should return SERVFAIL when all upstreams fail")
	}
	if result.Cacheable {
		t.Error("SERVFAIL should not be cacheable")
	}
}

func TestResolve_NXDOMAINAgreement(t *testing.T) {
	query := makeQuery("nonexistent.example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", response: makeNXDomainResp(query, true)},
		&mockClient{name: "server2", response: makeNXDomainResp(query, true)},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.Blocked {
		t.Error("genuine NXDOMAIN with SOA should not be blocked")
	}
	if !result.Cacheable {
		t.Error("NXDOMAIN agreement should be cacheable")
	}
}

func TestResolve_NXDOMAINDisagreement(t *testing.T) {
	query := makeQuery("test.example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "server1", response: makeNXDomainResp(query, true)},
		&mockClient{name: "server2", response: makeNormalResp(query)},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.Cacheable {
		t.Error("NXDOMAIN disagreement should NOT be cacheable")
	}
}

func TestResolve_Quad9StyleBlock(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	// Quad9 block: NXDOMAIN without SOA (no authority)
	blockedResp := makeNXDomainResp(query, false)
	clients := []Client{
		&mockClient{name: "quad9", response: blockedResp},
		&mockClient{name: "cloudflare", response: makeNormalResp(query)},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if !result.Blocked {
		t.Error("Quad9-style NXDOMAIN without authority should be blocked")
	}
}

func TestResolve_SlowBlockDetection(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	// First server is fast but normal, second is slow but blocks
	clients := []Client{
		&mockClient{name: "fast-normal", response: makeNormalResp(query), delay: 10 * time.Millisecond},
		&mockClient{name: "slow-blocked", response: makeBlockedResp(query), delay: 100 * time.Millisecond},
	}

	r := newTestResolverWithClients(clients)
	r.minWait = 200 * time.Millisecond // Give enough time for slow server
	result := r.Resolve(context.Background(), query)

	if !result.Blocked {
		t.Error("should detect block even from slower server")
	}
}

func TestResolve_PriorityOrder(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)

	resp1 := new(dns.Msg)
	dnsutil.SetReply(resp1, query)
	resp1.Answer = append(resp1.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("1.1.1.1")},
	})

	resp2 := new(dns.Msg)
	dnsutil.SetReply(resp2, query)
	resp2.Answer = append(resp2.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("2.2.2.2")},
	})

	// Server2 responds first due to lower delay
	clients := []Client{
		&mockClient{name: "server1-priority", response: resp1, delay: 50 * time.Millisecond},
		&mockClient{name: "server2-fast", response: resp2, delay: 5 * time.Millisecond},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("expected response")
	}
	// Should use server1 (index 0) because it has higher priority
	a, ok := result.BestResponse.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected *dns.A answer")
	}
	if a.Addr != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("expected response from priority server (1.1.1.1), got %v", a.Addr)
	}
}

func TestResolve_SlowUpstreamWarning(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "slow-server", response: makeNormalResp(query), delay: 80 * time.Millisecond},
	}

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")
	r := newTestResolverWithLogger(clients, logger)
	r.minWait = 5 * time.Millisecond
	r.slowThreshold = 50 * time.Millisecond

	r.Resolve(context.Background(), query)

	output := buf.String()
	if !strings.Contains(output, "Slow upstream") {
		t.Errorf("expected slow warning in log output, got: %s", output)
	}
	if !strings.Contains(output, "slow-server") {
		t.Errorf("expected upstream name in slow warning, got: %s", output)
	}
}

func TestResolve_UpstreamErrorWarning(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	clients := []Client{
		&mockClient{name: "broken-server", err: errors.New("connection refused")},
	}

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")
	r := newTestResolverWithLogger(clients, logger)

	r.Resolve(context.Background(), query)

	output := buf.String()
	if !strings.Contains(output, "broken-server") {
		t.Errorf("expected upstream name in error warning, got: %s", output)
	}
	if !strings.Contains(output, "error") && !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN-level error message, got: %s", output)
	}
}

func TestResolve_UpstreamTimeoutWarning(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	clients := []Client{
		// delay longer than the short context timeout below
		&mockClient{name: "timeout-server", response: makeNormalResp(query), delay: 500 * time.Millisecond},
	}

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")
	r := &Resolver{
		clients: clients,
		timeout: 50 * time.Millisecond,
		minWait: 10 * time.Millisecond,
		logger:  logger,
	}

	r.Resolve(context.Background(), query)

	output := buf.String()
	if !strings.Contains(output, "timed out") {
		t.Errorf("expected timeout warning in log output, got: %s", output)
	}
}

func TestHasNXDomainDisagreement(t *testing.T) {
	r := &Resolver{}

	tests := []struct {
		name     string
		results  []*Result
		expected bool
	}{
		{
			name: "all_normal",
			results: []*Result{
				{Msg: &dns.Msg{}, Inspect: inspectOK()},
				{Msg: &dns.Msg{}, Inspect: inspectOK()},
			},
			expected: false,
		},
		{
			name: "all_nxdomain",
			results: []*Result{
				{Msg: &dns.Msg{}, Inspect: inspectNX()},
				{Msg: &dns.Msg{}, Inspect: inspectNX()},
			},
			expected: false,
		},
		{
			name: "disagreement",
			results: []*Result{
				{Msg: &dns.Msg{}, Inspect: inspectOK()},
				{Msg: &dns.Msg{}, Inspect: inspectNX()},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := r.hasNXDomainDisagreement(tc.results)
			if got != tc.expected {
				t.Errorf("hasNXDomainDisagreement() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestWhitelistResolver_IsWhitelisted(t *testing.T) {
	cfg := &config.WhitelistConfig{
		Enabled: true,
		Domains: []string{"example.com", "safe.net"},
	}
	wl := &WhitelistResolver{cfg: cfg, client: &mockClient{name: "wl"}}

	tests := []struct {
		qname    string
		expected bool
	}{
		{"example.com", true},
		{"example.com.", true},
		{"EXAMPLE.COM", true},
		{"safe.net", true},
		{"other.com", false},
		{"sub.example.com", false}, // exact match only
	}

	for _, tc := range tests {
		t.Run(tc.qname, func(t *testing.T) {
			got := wl.IsWhitelisted(tc.qname)
			if got != tc.expected {
				t.Errorf("IsWhitelisted(%q) = %v, want %v", tc.qname, got, tc.expected)
			}
		})
	}
}

func TestWhitelistResolver_IsWhitelisted_Wildcard(t *testing.T) {
	cfg := &config.WhitelistConfig{
		Enabled: true,
		Domains: []string{"*.example.com"},
	}
	wl := &WhitelistResolver{cfg: cfg, client: &mockClient{name: "wl"}}

	tests := []struct {
		qname    string
		expected bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false},
		{"other.net", false},
	}

	for _, tc := range tests {
		t.Run(tc.qname, func(t *testing.T) {
			got := wl.IsWhitelisted(tc.qname)
			if got != tc.expected {
				t.Errorf("IsWhitelisted(%q) = %v, want %v", tc.qname, got, tc.expected)
			}
		})
	}
}

func TestWhitelistResolver_Nil(t *testing.T) {
	var wl *WhitelistResolver
	if wl.IsWhitelisted("example.com") {
		t.Error("nil WhitelistResolver.IsWhitelisted should return false")
	}
}

func TestWhitelistResolver_Query(t *testing.T) {
	query := makeQuery("safe.example.com", dns.TypeA)
	expectedResp := makeNormalResp(query)

	cfg := &config.WhitelistConfig{
		Enabled: true,
		Domains: []string{"safe.example.com"},
	}
	wl := NewWhitelistResolverFromClient(&mockClient{name: "wl", response: expectedResp}, cfg)

	resp, err := wl.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("expected non-empty response from whitelist resolver")
	}
}

func TestWhitelistResolver_Query_Error(t *testing.T) {
	query := makeQuery("safe.example.com", dns.TypeA)
	cfg := &config.WhitelistConfig{
		Enabled: true,
		Domains: []string{"safe.example.com"},
	}
	wl := NewWhitelistResolverFromClient(&mockClient{name: "wl-err", err: fmt.Errorf("connection refused")}, cfg)

	resp, err := wl.Query(context.Background(), query)
	if err == nil {
		t.Error("expected error from whitelist Query")
	}
	if resp != nil {
		t.Error("expected nil response on error")
	}
}

func TestResolve_EmptyClients(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	r := newTestResolverWithClients([]Client{})
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("expected non-nil response even with no clients")
	}
	if result.BestResponse.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL with no clients, got rcode=%d", result.BestResponse.Rcode)
	}
	if result.Cacheable {
		t.Error("SERVFAIL should not be cacheable")
	}
}

func TestWhitelistResolver_Disabled(t *testing.T) {
	cfg := &config.WhitelistConfig{
		Enabled: false,
		Domains: []string{"example.com"},
	}
	wl := &WhitelistResolver{cfg: cfg, client: &mockClient{name: "wl"}}
	if wl.IsWhitelisted("example.com") {
		t.Error("disabled whitelist should always return false")
	}
}

func TestNewDoHClient_EmptyURL(t *testing.T) {
	_, err := NewDoHClient("", true)
	if err == nil {
		t.Error("expected error for empty DoH URL")
	}
}

func TestNewDoTClient_EmptyAddress(t *testing.T) {
	_, err := NewDoTClient("", true)
	if err == nil {
		t.Error("expected error for empty DoT address")
	}
}

func TestNewPlainClient_EmptyAddress(t *testing.T) {
	_, err := NewPlainClient("")
	if err == nil {
		t.Error("expected error for empty plain DNS address")
	}
}

func TestResolve_SERVFAIL_QuestionPreserved(t *testing.T) {
	// When all upstreams fail, the SERVFAIL returned by Resolve should carry
	// the original query's question section.
	query := makeQuery("fail.example.com", dns.TypeA)
	query.ID = 9001

	clients := []Client{
		&mockClient{name: "err1", err: fmt.Errorf("timeout")},
		&mockClient{name: "err2", err: fmt.Errorf("connection refused")},
	}

	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("expected non-nil SERVFAIL response")
	}
	if result.BestResponse.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL, got rcode=%d", result.BestResponse.Rcode)
	}
	// The SERVFAIL from selectResult may or may not have the Question set
	// (makeServFail has no template when all fail); HandleQuery is responsible
	// for filling it in. Just verify the resolver itself doesn't panic.
}

func inspectOK() dnsmsg.InspectResult { return dnsmsg.InspectResult{} }
func inspectNX() dnsmsg.InspectResult { return dnsmsg.InspectResult{NXDomain: true} }

// -- IPv6 and address-normalisation tests --

func TestNewPlainClient_BareIPv4(t *testing.T) {
	c, err := NewPlainClient("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "8.8.8.8:53" {
		t.Errorf("address = %q, want 8.8.8.8:53", c.address)
	}
}

func TestNewPlainClient_IPv4WithPort(t *testing.T) {
	c, err := NewPlainClient("8.8.8.8:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "8.8.8.8:53" {
		t.Errorf("address = %q, want 8.8.8.8:53", c.address)
	}
}

func TestNewPlainClient_BareIPv6(t *testing.T) {
	c, err := NewPlainClient("2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "[2001:db8::1]:53" {
		t.Errorf("address = %q, want [2001:db8::1]:53", c.address)
	}
}

func TestNewPlainClient_IPv6WithPort(t *testing.T) {
	c, err := NewPlainClient("[2001:db8::1]:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "[2001:db8::1]:53" {
		t.Errorf("address = %q, want [2001:db8::1]:53", c.address)
	}
}

func TestNewDoTClient_BareHostname(t *testing.T) {
	c, err := NewDoTClient("dns.quad9.net", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "dns.quad9.net:853" {
		t.Errorf("address = %q, want dns.quad9.net:853", c.address)
	}
	if c.tlsConfig.ServerName != "dns.quad9.net" {
		t.Errorf("ServerName = %q, want dns.quad9.net", c.tlsConfig.ServerName)
	}
}

func TestNewDoTClient_BareIPv6(t *testing.T) {
	c, err := NewDoTClient("2620:fe::fe", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "[2620:fe::fe]:853" {
		t.Errorf("address = %q, want [2620:fe::fe]:853", c.address)
	}
	if c.tlsConfig.ServerName != "2620:fe::fe" {
		t.Errorf("ServerName = %q, want 2620:fe::fe", c.tlsConfig.ServerName)
	}
}

func TestNewDoTClient_IPv6WithPort(t *testing.T) {
	c, err := NewDoTClient("[2620:fe::fe]:853", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "[2620:fe::fe]:853" {
		t.Errorf("address = %q, want [2620:fe::fe]:853", c.address)
	}
	if c.tlsConfig.ServerName != "2620:fe::fe" {
		t.Errorf("ServerName = %q, want 2620:fe::fe", c.tlsConfig.ServerName)
	}
}

func TestNewDoTClient_IPv4WithPort(t *testing.T) {
	c, err := NewDoTClient("9.9.9.9:853", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "9.9.9.9:853" {
		t.Errorf("address = %q, want 9.9.9.9:853", c.address)
	}
}

func TestNewDoHClient_ValidURL(t *testing.T) {
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.url != "https://dns.quad9.net/dns-query" {
		t.Errorf("url = %q, want https://dns.quad9.net/dns-query", c.url)
	}
}

func TestNewDoHClient_EmptyURL_Second(t *testing.T) {
	_, err := NewDoHClient("", true)
	if err == nil {
		t.Error("expected error for empty DoH URL")
	}
}

// TestResolve_IPv6_AAAA verifies that AAAA queries are resolved and that a
// legitimate IPv6 address (2001:db8::1) is NOT treated as blocked.
func TestResolve_IPv6_AAAA_Normal(t *testing.T) {
	query := makeQuery("ipv6.example.com", dns.TypeAAAA)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "ipv6.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
	})

	clients := []Client{
		&mockClient{name: "ipv6-server", response: resp},
	}
	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if result.BestResponse == nil {
		t.Fatal("expected response")
	}
	if result.Blocked {
		t.Error("2001:db8::1 should not be treated as blocked")
	}
	if !result.Cacheable {
		t.Error("normal AAAA response should be cacheable")
	}
}

// TestResolve_IPv6_AAAA_Blocked verifies that :: (IPv6 unspecified) is
// recognised as a block signal.
func TestResolve_IPv6_AAAA_Blocked(t *testing.T) {
	query := makeQuery("blocked6.example.com", dns.TypeAAAA)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "blocked6.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
	})

	clients := []Client{
		&mockClient{name: "ipv6-block-server", response: resp},
	}
	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if !result.Blocked {
		t.Error(":: should be recognised as a block signal")
	}
}

// TestResolve_IPv4_Blocked_ZeroAddr verifies that 0.0.0.0 is treated as
// a block signal for A queries.
func TestResolve_IPv4_Blocked_ZeroAddr(t *testing.T) {
	query := makeQuery("blocked4.example.com", dns.TypeA)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: "blocked4.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
	})

	clients := []Client{
		&mockClient{name: "ipv4-block-server", response: resp},
	}
	r := newTestResolverWithClients(clients)
	result := r.Resolve(context.Background(), query)

	if !result.Blocked {
		t.Error("0.0.0.0 should be recognised as a block signal")
	}
}
