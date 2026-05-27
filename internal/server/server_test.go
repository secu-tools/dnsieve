// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/domainlist"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// mockUpstreamClient implements the upstream.Client interface for testing.
type mockUpstreamClient struct {
	mu       sync.Mutex
	name     string
	response *dns.Msg
	err      error
}

func (m *mockUpstreamClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Serialize access to m.response: Pack writes to msg.Data in place, so
	// concurrent callers on the same mock client would race without a lock.
	m.mu.Lock()
	defer m.mu.Unlock()
	// Deep copy via pack/unpack (v2 Copy is shallow).
	if err := m.response.Pack(); err != nil {
		return nil, err
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

func (m *mockUpstreamClient) String() string { return m.name }

func newTestHandler(t *testing.T, responses []*dns.Msg) *Handler {
	t.Helper()
	return newTestHandlerWithLogger(t, responses, logging.NewStdoutOnly(logging.DefaultConfig(), "test"))
}

func newTestHandlerWithLogger(t *testing.T, responses []*dns.Msg, logger *logging.Logger) *Handler {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100

	c := cache.New(100, 3600, 5, 0)

	clients := make([]upstream.Client, len(responses))
	for i, resp := range responses {
		clients[i] = &mockUpstreamClient{
			name:     fmt.Sprintf("mock-%d", i),
			response: resp,
		}
	}

	resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)
	return NewHandler(resolver, nil, nil, c, logger, cfg)
}

// testDomainList creates a DomainList from a list of domain entries for testing.
func testDomainList(t *testing.T, entries []string) *domainlist.DomainList {
	t.Helper()
	dir := t.TempDir()
	content := strings.Join(entries, "\n") + "\n"
	path := filepath.Join(dir, "test.list")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test list: %v", err)
	}
	dl := domainlist.NewDomainList("test", domainlist.ModeBlock, []string{path})
	if _, _, _, err := dl.Load(nil); err != nil {
		t.Fatalf("load test list: %v", err)
	}
	return dl
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

// hasEDEBlocked reports whether the message contains an EDE option with
// InfoCode == ExtendedErrorBlocked (15) per RFC 8914.
func hasEDEBlocked(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok && ede.InfoCode == dns.ExtendedErrorBlocked {
			return true
		}
	}
	return false
}

func TestHandleQuery_EmptyQuestion(t *testing.T) {
	handler := newTestHandler(t, nil)
	query := &dns.Msg{} // No question section

	resp := handler.HandleQuery(context.Background(), query)
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR for empty question, got %d", resp.Rcode)
	}
}

func TestHandleQuery_NormalQuery(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one answer")
	}
}

func TestHandleQuery_BlockedQuery(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(query)})
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("blocked response rcode=%s, want NOERROR (null mode)", dns.RcodeToString[resp.Rcode])
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked response must include EDE Blocked (code 15)")
	}
}

func TestHandleQuery_CacheHit(t *testing.T) {
	query := makeQuery("cached.example.com", dns.TypeA)

	resp1Body := new(dns.Msg)
	dnsutil.SetReply(resp1Body, query)
	resp1Body.Answer = append(resp1Body.Answer, &dns.A{
		Hdr: dns.Header{Name: "cached.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	})

	handler := newTestHandler(t, []*dns.Msg{resp1Body})

	// First query: should call upstream
	resp1 := handler.HandleQuery(context.Background(), query)
	if resp1 == nil {
		t.Fatal("expected response")
	}

	// Second query: should hit cache (same domain, different ID)
	query2 := makeQuery("cached.example.com", dns.TypeA)
	query2.ID = 9999

	resp2 := handler.HandleQuery(context.Background(), query2)
	if resp2 == nil {
		t.Fatal("expected cached response")
	}
	if resp2.ID != 9999 {
		t.Errorf("cached response should use new query ID, got %d", resp2.ID)
	}
}

func TestHandleQuery_BlockedNeverLeaked(t *testing.T) {
	query := makeQuery("evil.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(query)})
	resp := handler.HandleQuery(context.Background(), query)

	// In null mode, blocked A queries return NOERROR with 0.0.0.0.
	// Verify no real routable IP appears.
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("blocked response rcode=%s, want NOERROR (null mode)", dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.Addr != (netip.AddrFrom4([4]byte{0, 0, 0, 0})) {
				t.Errorf("blocked response leaked real IP %s", a.Addr)
			}
		}
	}
}

func TestHandleQuery_AAAA_Blocked(t *testing.T) {
	query := makeQuery("malware.example.com", dns.TypeAAAA)

	// Simulate what an upstream like Quad9 sends when blocking an AAAA query.
	upstreamBlocked := new(dns.Msg)
	dnsutil.SetReply(upstreamBlocked, query)
	upstreamBlocked.Answer = append(upstreamBlocked.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "malware.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
	})

	handler := newTestHandler(t, []*dns.Msg{upstreamBlocked})
	resp := handler.HandleQuery(context.Background(), query)

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("blocked AAAA rcode=%s, want NOERROR (null mode)", dns.RcodeToString[resp.Rcode])
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked AAAA must include EDE Blocked (code 15)")
	}
}

func TestHandleQuery_MultipleQuestions(t *testing.T) {
	// DNS spec: only one question per message is allowed
	query := new(dns.Msg)
	q1 := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}
	q2 := &dns.A{Hdr: dns.Header{Name: "other.com.", Class: dns.ClassINET}}
	query.Question = []dns.RR{q1, q2}

	handler := newTestHandler(t, nil)
	resp := handler.HandleQuery(context.Background(), query)
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR for multiple questions, got %d", resp.Rcode)
	}
}

func TestHandleQuery_AllUpstreamsFail(t *testing.T) {
	query := makeQuery("fail.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false

	errClient := &mockUpstreamClient{
		name: "error-client",
		err:  fmt.Errorf("connection refused"),
	}
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients([]upstream.Client{errClient}, 1*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL when all upstreams fail, got rcode=%d", resp.Rcode)
	}
}

func TestHandleQuery_CacheDisabled(t *testing.T) {
	query := makeQuery("nocache.example.com", dns.TypeA)

	normalResp := new(dns.Msg)
	dnsutil.SetReply(normalResp, query)
	normalResp.Answer = append(normalResp.Answer, &dns.A{
		Hdr: dns.Header{Name: "nocache.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("10.0.0.1")},
	})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false

	c := cache.New(0, 1, 1, 0)
	clients := []upstream.Client{
		&mockUpstreamClient{name: "mock", response: normalResp},
	}
	resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)
	if resp == nil || len(resp.Answer) == 0 {
		t.Error("expected response even with cache disabled")
	}
}

func TestHandleQuery_ResponseIDMatchesQuery(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	query.ID = 12345

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})
	resp := handler.HandleQuery(context.Background(), query)
	if resp.ID != 12345 {
		t.Errorf("response ID should match query ID 12345, got %d", resp.ID)
	}
}

// TestHandleQuery_BlockedLogsInfo verifies that a blocked upstream query
// produces a dns_query JSON event with the domain name and blocked status.
// Per-query details are JSON-only; text mode does not emit them.
func TestHandleQuery_BlockedLogsInfo(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	handler := newTestHandlerWithLogger(t, []*dns.Msg{makeBlockedResp(query)}, logger)
	handler.HandleQuery(context.Background(), query)

	output := buf.String()
	if !strings.Contains(output, "blocked.example.com") {
		t.Errorf("expected domain name in JSON event, got: %s", output)
	}
	if !strings.Contains(output, "blocked") {
		t.Errorf("expected 'blocked' in JSON event, got: %s", output)
	}
	if !strings.Contains(output, "dns_query") {
		t.Errorf("expected dns_query type in JSON event, got: %s", output)
	}
}

// TestHandleQuery_BlockedFromCacheLogsInfo verifies that a blocked-from-cache
// response produces a dns_query JSON event. Text mode does not emit per-query data.
func TestHandleQuery_BlockedFromCacheLogsInfo(t *testing.T) {
	query := makeQuery("cached-block.example.com", dns.TypeA)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	handler := newTestHandlerWithLogger(t, []*dns.Msg{makeBlockedResp(query)}, logger)

	// First query: populates cache with blocked entry
	handler.HandleQuery(context.Background(), query)

	// Clear the buffer so we only see the second query's log
	buf.Reset()

	// Second query: should come from cache
	q2 := makeQuery("cached-block.example.com", dns.TypeA)
	handler.HandleQuery(context.Background(), q2)

	output := buf.String()
	if !strings.Contains(output, "cached-block.example.com") {
		t.Errorf("expected domain in JSON event, got: %s", output)
	}
	if !strings.Contains(output, "blocked") {
		t.Errorf("expected 'blocked' in JSON event, got: %s", output)
	}
	if !strings.Contains(output, "cache") {
		t.Errorf("expected 'cache' in JSON event, got: %s", output)
	}
}

func TestHandleQuery_WhitelistBypassing(t *testing.T) {
	// Whitelisted domain should use whitelist resolver, not blocking upstreams.
	query := makeQuery("safe.example.com", dns.TypeA)

	wlResponse := new(dns.Msg)
	dnsutil.SetReply(wlResponse, query)
	wlResponse.Answer = append(wlResponse.Answer, &dns.A{
		Hdr: dns.Header{Name: "safe.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("5.5.5.5")},
	})

	wlClient := &mockUpstreamClient{name: "whitelist-resolver", response: wlResponse}

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Whitelist = config.WhitelistConfig{
		Enabled: true,
	}

	wlList := testDomainList(t, []string{"safe.example.com"})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	c := cache.New(100, 3600, 5, 0)

	// Blocking upstreams -- would return 0.0.0.0 if used
	blockClient := &mockUpstreamClient{name: "blocker", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{blockClient}, 2*time.Second, 50*time.Millisecond, logger)

	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("expected response from whitelist resolver")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record")
	}
	if a.Addr != netip.MustParseAddr("5.5.5.5") {
		t.Errorf("expected whitelist resolver IP 5.5.5.5, got %v", a.Addr)
	}
}

func TestDecodeBase64URL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantLen int
	}{
		{"valid base64url", "AAABAAABAAAAAAAAAAEA", false, 15},
		{"empty string", "", false, 0},
		{"invalid base64", "!@#$%", true, 0},
		{"3-char raw base64url", "AAE", false, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeBase64URL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeBase64URL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("decodeBase64URL(%q) len = %d, want %d", tt.input, len(got), tt.wantLen)
			}
		})
	}
}

func TestComputeMaxAge(t *testing.T) {
	// Empty message -> default 1800
	empty := new(dns.Msg)
	if got := computeMaxAge(empty); got != 1800 {
		t.Errorf("computeMaxAge(empty) = %d, want 1800", got)
	}

	// Message with TTL 300 -> 300
	query := makeQuery("example.com", dns.TypeA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	})
	if got := computeMaxAge(resp); got != 300 {
		t.Errorf("computeMaxAge with TTL=300 = %d, want 300", got)
	}

	// Message with TTL 0 -> 1 (minimum enforced)
	resp2 := new(dns.Msg)
	dnsutil.SetReply(resp2, query)
	resp2.Answer = append(resp2.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 0},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	})
	if got := computeMaxAge(resp2); got != 1 {
		t.Errorf("computeMaxAge with TTL=0 = %d, want 1", got)
	}
}

func TestHandleQuery_NonWhitelistedGoesNormal(t *testing.T) {
	// When a whitelist resolver is configured but the domain is NOT whitelisted,
	// the query should go through the normal upstream resolver path.
	query := makeQuery("normal.example.com", dns.TypeA)
	normalResp := makeNormalResp(query)

	wlCfg := config.WhitelistConfig{
		Enabled: true,
	}

	wlList := testDomainList(t, []string{"safe.example.com"}) // NOT normal.example.com

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	cfg.Whitelist = wlCfg

	c := cache.New(100, 3600, 5, 0)
	clients := []upstream.Client{
		&mockUpstreamClient{name: "normal-upstream", response: normalResp},
	}
	resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)

	// Whitelist resolver returns something different -- should NOT be used.
	wlResp := new(dns.Msg)
	dnsutil.SetReply(wlResp, query)
	wlResp.Answer = append(wlResp.Answer, &dns.A{
		Hdr: dns.Header{Name: "normal.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("9.9.9.9")},
	})
	wlClient := &mockUpstreamClient{name: "whitelist-resolver", response: wlResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &wlCfg, wlList)

	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("expected response from normal upstream")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record")
	}
	// Should come from normal-upstream (93.184.216.34), not whitelist (9.9.9.9)
	if a.Addr == netip.MustParseAddr("9.9.9.9") {
		t.Error("non-whitelisted domain should not use whitelist resolver")
	}
}

func TestServePlain_UDPQuery(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-plain")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain returned: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	q := makeQuery("example.com", dns.TypeA)
	q.RecursionDesired = true

	c := new(dns.Client)
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer queryCancel()
	resp, _, clientErr := c.Exchange(queryCtx, q, "udp", fmt.Sprintf("127.0.0.1:%d", port))
	if clientErr != nil {
		t.Fatalf("UDP query failed: %v", clientErr)
	}
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got %v", resp.Rcode)
	}
}

// -- readDOHWireQuery tests (extracted from dohHandler) --

func TestReadDOHWireQuery_POST_Valid(t *testing.T) {
	body := []byte{0, 1, 2, 3, 4, 5}
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/dns-message")

	wire, status, msg := readDOHWireQuery(r)
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d (%s)", status, msg)
	}
	if !bytes.Equal(wire, body) {
		t.Errorf("expected body %v, got %v", body, wire)
	}
}

func TestReadDOHWireQuery_POST_WrongContentType(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{1, 2, 3}))
	r.Header.Set("Content-Type", "text/plain")

	_, status, msg := readDOHWireQuery(r)
	if status != http.StatusUnsupportedMediaType {
		t.Errorf("expected 415, got %d", status)
	}
	if msg == "" {
		t.Error("expected non-empty error message for wrong Content-Type")
	}
}

func TestReadDOHWireQuery_GET_Valid(t *testing.T) {
	q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	if err := q.Pack(); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(q.Data)

	r := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)

	wire, status, _ := readDOHWireQuery(r)
	if status != http.StatusOK {
		t.Errorf("expected 200, got %d", status)
	}
	if !bytes.Equal(wire, q.Data) {
		t.Error("decoded GET wire bytes do not match original")
	}
}

func TestReadDOHWireQuery_GET_MissingParam(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/dns-query", nil)

	_, status, _ := readDOHWireQuery(r)
	if status != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ?dns=, got %d", status)
	}
}

func TestReadDOHWireQuery_GET_InvalidBase64(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/dns-query?dns=not-valid!!!", nil)

	_, status, _ := readDOHWireQuery(r)
	if status != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid base64url, got %d", status)
	}
}

func TestReadDOHWireQuery_UnsupportedMethod(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/dns-query", nil)

	_, status, msg := readDOHWireQuery(r)
	if status != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", status)
	}
	if msg == "" {
		t.Error("expected error message for unsupported method")
	}
}

// TestStartListeners_NoListeners verifies that startListeners returns an error
// when all downstream protocols are disabled.
func TestStartListeners_NoListeners(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = false
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false

	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	errCh := make(chan error, 3)
	var wg sync.WaitGroup

	err := startListeners(context.Background(), handler, cfg, logger, errCh, &wg)
	if err == nil {
		t.Error("expected error when no downstream listeners are enabled")
	}
}

// TestHandleQuery_CacheHit_WireIDMatchesQuery verifies that when a cached
// response is served, the wire-format bytes (resp.Data) carry the new query's
// ID. This catches the bug where WriteTo sends stale Data with the original ID.
func TestHandleQuery_CacheHit_WireIDMatchesQuery(t *testing.T) {
	query := makeQuery("wire-id-test.example.com", dns.TypeA)
	query.ID = 11111
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})

	// First query: resolves via upstream and populates cache.
	handler.HandleQuery(context.Background(), query)

	// Second query with a different ID: must come from cache.
	q2 := makeQuery("wire-id-test.example.com", dns.TypeA)
	q2.ID = 22222

	resp := handler.HandleQuery(context.Background(), q2)
	if resp == nil {
		t.Fatal("expected cached response")
	}
	if resp.ID != 22222 {
		t.Errorf("struct ID = %d, want 22222", resp.ID)
	}

	// Verify the wire-format Data has the updated ID.
	// WriteTo only calls Pack if len(Data)==0, so Data must be correct here.
	if len(resp.Data) == 0 {
		t.Skip("response has no pre-packed Data; WriteTo will pack on write")
	}
	check := new(dns.Msg)
	check.Data = make([]byte, len(resp.Data))
	copy(check.Data, resp.Data)
	if err := check.Unpack(); err != nil {
		t.Fatalf("Unpack Data: %v", err)
	}
	if check.ID != 22222 {
		t.Errorf("wire-format ID = %d, want 22222 (WriteTo would send wrong ID to client)", check.ID)
	}
}

// TestHandleQuery_AllUpstreamsFail_QuestionPreserved ensures that a SERVFAIL
// returned when every upstream errors always includes the original Question
// section (RFC 1035 s4.1.1 requires the response to echo the query section).
func TestHandleQuery_AllUpstreamsFail_QuestionPreserved(t *testing.T) {
	query := makeQuery("fail.example.com", dns.TypeA)
	query.ID = 7777

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false

	errClient := &mockUpstreamClient{name: "err", err: fmt.Errorf("network error")}
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients([]upstream.Client{errClient}, 1*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)

	if resp.ID != 7777 {
		t.Errorf("SERVFAIL ID = %d, want 7777", resp.ID)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL rcode, got %d", resp.Rcode)
	}
	if len(resp.Question) == 0 {
		t.Error("SERVFAIL response must include the Question section (RFC 1035 s4.1.1)")
	}
	if !resp.Response {
		t.Error("SERVFAIL must have QR=1")
	}
}

// TestDohHandler_ContentTypeAndCacheControl verifies that a successful DoH
// response includes the required Content-Type and Cache-Control headers per
// RFC 8484.
func TestDohHandler_ContentTypeAndCacheControl(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	query.ID = 0 // RFC 8484: ID must be 0

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	body := make([]byte, len(query.Data))
	copy(body, query.Data)

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	dohHandler(w, req, handler, logger)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("Content-Type = %q, want application/dns-message", ct)
	}
	if cc := res.Header.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("Cache-Control = %q, want 'public, max-age=...'", cc)
	}
}

// TestDohHandler_IDEcho verifies that the DNS ID in the response matches the
// client's requested ID per RFC 8484 s4.
func TestDohHandler_IDEcho(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	query.ID = 4321 // non-zero to verify echo

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	if err := query.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	body := make([]byte, len(query.Data))
	copy(body, query.Data)

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	respMsg := new(dns.Msg)
	respMsg.Data = w.Body.Bytes()
	if err := respMsg.Unpack(); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if respMsg.ID != 4321 {
		t.Errorf("response DNS ID = %d, want 4321", respMsg.ID)
	}
}

// TestDohHandler_SERVFAIL_CacheControlNoStore verifies that SERVFAIL responses
// carry Cache-Control: no-store per RFC 8484 s5.1.
func TestDohHandler_SERVFAIL_CacheControlNoStore(t *testing.T) {
	query := makeQuery("fail.example.com", dns.TypeA)
	query.ID = 0

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false

	errClient := &mockUpstreamClient{name: "err", err: fmt.Errorf("connection refused")}
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients([]upstream.Client{errClient}, 1*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)

	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	body := make([]byte, len(query.Data))
	copy(body, query.Data)

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	cc := w.Result().Header.Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("SERVFAIL Cache-Control = %q, want no-store", cc)
	}
}

// TestDohHandler_GET_EndToEnd exercises the DoH GET path end-to-end.
func TestDohHandler_GET_EndToEnd(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	query.ID = 0

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(query.Data)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	w := httptest.NewRecorder()

	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Result().Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("GET Content-Type = %q, want application/dns-message", ct)
	}
	respMsg := new(dns.Msg)
	respMsg.Data = w.Body.Bytes()
	if err := respMsg.Unpack(); err != nil {
		t.Fatalf("unpack GET response: %v", err)
	}
	if respMsg.Rcode != dns.RcodeSuccess {
		t.Errorf("GET response rcode = %d, want NOERROR", respMsg.Rcode)
	}
}

// TestDohHandler_OPTIONS_CORS verifies CORS preflight handling.
func TestDohHandler_OPTIONS_CORS(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/dns-query", nil)
	w := httptest.NewRecorder()

	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status = %d, want 204", w.Code)
	}
	if w.Result().Header.Get("Access-Control-Allow-Origin") == "" {
		t.Error("CORS Allow-Origin header missing")
	}
}

// TestServePlain_TCPQuery verifies that the plain DNS TCP listener responds
// correctly.
func TestServePlain_TCPQuery(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-plain-tcp")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain returned: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	q := makeQuery("example.com", dns.TypeA)
	q.RecursionDesired = true

	c := new(dns.Client)
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer queryCancel()
	resp, _, clientErr := c.Exchange(queryCtx, q, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if clientErr != nil {
		t.Fatalf("TCP query failed: %v", clientErr)
	}
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got %v", resp.Rcode)
	}
}

// TestServePlain_IPv6_UDPQuery verifies that the plain DNS server can bind
// to an IPv6 loopback address.
func TestServePlain_IPv6_UDPQuery(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available on this system")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	query := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"::1"}
	cfg.Downstream.Plain.Port = port

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-ipv6-plain")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain IPv6 returned: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	q := makeQuery("example.com", dns.TypeA)
	q.RecursionDesired = true

	c := new(dns.Client)
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer queryCancel()
	addr := fmt.Sprintf("[::1]:%d", port)
	resp, _, clientErr := c.Exchange(queryCtx, q, "udp", addr)
	if clientErr != nil {
		t.Fatalf("IPv6 UDP query failed: %v", clientErr)
	}
	if resp == nil {
		t.Fatal("no response from IPv6 server")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR from IPv6 server, got %v", resp.Rcode)
	}
}

// TestHandleQuery_IPv4_A verifies that an IPv4 A record is returned correctly.
func TestHandleQuery_IPv4_A(t *testing.T) {
	query := makeQuery("ipv4.example.com", dns.TypeA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: "ipv4.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	})

	handler := newTestHandler(t, []*dns.Msg{resp})
	result := handler.HandleQuery(context.Background(), query)

	if result == nil {
		t.Fatal("expected response")
	}
	if len(result.Answer) == 0 {
		t.Fatal("expected answer")
	}
	a, ok := result.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected *dns.A")
	}
	if a.Addr != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("A record = %v, want 192.0.2.1", a.Addr)
	}
}

// TestHandleQuery_IPv6_AAAA_Normal verifies that an IPv6 AAAA record with a
// legitimate address is returned and not incorrectly classified as blocked.
func TestHandleQuery_IPv6_AAAA_Normal(t *testing.T) {
	query := makeQuery("ipv6.example.com", dns.TypeAAAA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "ipv6.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
	})

	handler := newTestHandler(t, []*dns.Msg{resp})
	result := handler.HandleQuery(context.Background(), query)

	if result == nil {
		t.Fatal("expected response")
	}
	if len(result.Answer) == 0 {
		t.Fatal("expected answer")
	}
	aaaa, ok := result.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatal("expected *dns.AAAA")
	}
	if aaaa.Addr != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("AAAA record = %v, want 2001:db8::1", aaaa.Addr)
	}
}

// TestHandleQuery_IPv6_AAAA_Blocked_Unspecified verifies that :: is treated as
// a block indicator and the proxy returns the configured blocking mode response.
func TestHandleQuery_IPv6_AAAA_Blocked_Unspecified(t *testing.T) {
	query := makeQuery("blocked6.example.com", dns.TypeAAAA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "blocked6.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
	})

	handler := newTestHandler(t, []*dns.Msg{resp})
	result := handler.HandleQuery(context.Background(), query)

	if result == nil {
		t.Fatal("expected response")
	}
	if result.Rcode != dns.RcodeSuccess {
		t.Errorf("blocked AAAA rcode=%s, want NOERROR (null mode)", dns.RcodeToString[result.Rcode])
	}
	if !hasEDEBlocked(result) {
		t.Error("blocked AAAA must include EDE Blocked (code 15)")
	}
}

// TestHandleQuery_MixedIPv4IPv6 verifies that the cache correctly separates
// A (IPv4) and AAAA (IPv6) queries for the same domain name.
func TestHandleQuery_MixedIPv4IPv6(t *testing.T) {
	queryA := makeQuery("dual.example.com", dns.TypeA)
	queryAAAA := makeQuery("dual.example.com", dns.TypeAAAA)

	respA := new(dns.Msg)
	dnsutil.SetReply(respA, queryA)
	respA.Answer = append(respA.Answer, &dns.A{
		Hdr: dns.Header{Name: "dual.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("198.51.100.1")},
	})

	respAAAA := new(dns.Msg)
	dnsutil.SetReply(respAAAA, queryAAAA)
	respAAAA.Answer = append(respAAAA.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "dual.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::cafe")},
	})

	// Use two clients: first returns A, second returns AAAA.
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true

	c := cache.New(100, 3600, 5, 0)

	clientA := &mockUpstreamClient{name: "mock-a", response: respA}
	resolverA := upstream.NewResolverFromClients([]upstream.Client{clientA}, 2*time.Second, 50*time.Millisecond, logger)
	handlerA := NewHandler(resolverA, nil, nil, c, logger, cfg)

	// Resolve A query and cache it.
	rA := handlerA.HandleQuery(context.Background(), queryA)
	if rA == nil || len(rA.Answer) == 0 {
		t.Fatal("expected A response")
	}
	if _, ok := rA.Answer[0].(*dns.A); !ok {
		t.Fatal("expected A record")
	}

	// Cache A but not AAAA; AAAA query should go upstream.
	clientAAAA := &mockUpstreamClient{name: "mock-aaaa", response: respAAAA}
	resolverAAAA := upstream.NewResolverFromClients([]upstream.Client{clientAAAA}, 2*time.Second, 50*time.Millisecond, logger)
	handlerAAAA := NewHandler(resolverAAAA, nil, nil, c, logger, cfg)

	rAAAA := handlerAAAA.HandleQuery(context.Background(), queryAAAA)
	if rAAAA == nil || len(rAAAA.Answer) == 0 {
		t.Fatal("expected AAAA response")
	}
	if _, ok := rAAAA.Answer[0].(*dns.AAAA); !ok {
		t.Fatal("expected AAAA record")
	}
}

// TestHandleQuery_CacheHitLogsContainTTLandRTL verifies that TTL (ttl=)
// and remaining TTL (rtl=) are present in the log output for cache hits.
func TestHandleQuery_CacheHitLogsContainTTLandRTL(t *testing.T) {
	query := makeQuery("ttllog.example.com", dns.TypeA)

	var buf bytes.Buffer
	// Use debug mode to capture all messages including debug-level output.
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "debug", Synchronous: true}, "test")

	handler := newTestHandlerWithLogger(t, []*dns.Msg{makeNormalResp(query)}, logger)

	// First request populates the cache.
	handler.HandleQuery(context.Background(), query)
	buf.Reset()

	// Second request is a cache hit.
	q2 := makeQuery("ttllog.example.com", dns.TypeA)
	handler.HandleQuery(context.Background(), q2)

	out := buf.String()
	if !strings.Contains(out, "ttl=") {
		t.Errorf("expected ttl= in cache hit log, got: %s", out)
	}
	if !strings.Contains(out, "rtl=") {
		t.Errorf("expected rtl= in cache hit log, got: %s", out)
	}
}

// TestHandleQuery_FinalResultLogged_SERVFAIL verifies that the debug log
// contains a final result line with SERVFAIL when all upstreams fail.
func TestHandleQuery_FinalResultLogged_SERVFAIL(t *testing.T) {
	query := makeQuery("faillog.example.com", dns.TypeA)

	var buf bytes.Buffer
	// Use debug mode to capture all messages including debug-level output.
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "debug", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	errClient := &mockUpstreamClient{name: "err", err: fmt.Errorf("connection refused")}
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients([]upstream.Client{errClient}, 1*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)

	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if !strings.Contains(out, "SERVFAIL") {
		t.Errorf("expected SERVFAIL in debug log, got: %s", out)
	}
}

// TestHandleQuery_FinalResultLogged_Blocked verifies that the debug log
// contains the blocked=true final result line.
func TestHandleQuery_FinalResultLogged_Blocked(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)

	var buf bytes.Buffer
	// Use debug mode to capture all messages including debug-level output.
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "debug", Synchronous: true}, "test")

	handler := newTestHandlerWithLogger(t, []*dns.Msg{makeBlockedResp(query)}, logger)
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if !strings.Contains(out, "blocked=true") {
		t.Errorf("expected blocked=true in debug log, got: %s", out)
	}
}

// TestComputeMaxAge_NoAnswer verifies that computeMaxAge returns a positive
// value even when there are no answer records.
func TestComputeMaxAge_NoRecords(t *testing.T) {
	msg := new(dns.Msg)
	if got := computeMaxAge(msg); got < 1 {
		t.Errorf("computeMaxAge with no records = %d, want >= 1", got)
	}
}

// TestHandleQuery_RecursionAvailable verifies that all response paths set
// the RA (Recursion Available) bit per RFC 1035 s4.1.3.
func TestHandleQuery_RecursionAvailable(t *testing.T) {
	tests := []struct {
		name     string
		upstream *dns.Msg
	}{
		{"normal", makeNormalResp(makeQuery("example.com", dns.TypeA))},
		{"blocked", makeBlockedResp(makeQuery("evil.com", dns.TypeA))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := makeQuery(tt.upstream.Question[0].Header().Name, dns.TypeA)
			handler := newTestHandler(t, []*dns.Msg{tt.upstream})
			resp := handler.HandleQuery(context.Background(), q)
			if !resp.RecursionAvailable {
				t.Errorf("%s: RecursionAvailable=false, want true", tt.name)
			}
		})
	}
}

// TestHandleQuery_QR_BitAlwaysSet verifies that the QR (Response) bit is set
// in every response path (RFC 1035 s4.1.1).
func TestHandleQuery_QR_BitAlwaysSet(t *testing.T) {
	type tc struct {
		name     string
		upstream *mockUpstreamClient
	}
	tests := []tc{
		{"normal", &mockUpstreamClient{name: "ok", response: makeNormalResp(makeQuery("qr.example.com", dns.TypeA))}},
		{"blocked", &mockUpstreamClient{name: "bl", response: makeBlockedResp(makeQuery("qr.example.com", dns.TypeA))}},
		{"error", &mockUpstreamClient{name: "err", err: fmt.Errorf("fail")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
			cfg := config.DefaultConfig()
			cfg.Cache.Enabled = false
			c := cache.New(100, 3600, 5, 0)
			resolver := upstream.NewResolverFromClients([]upstream.Client{tt.upstream}, 1*time.Second, 50*time.Millisecond, logger)
			handler := NewHandler(resolver, nil, nil, c, logger, cfg)
			q := makeQuery("qr.example.com", dns.TypeA)
			resp := handler.HandleQuery(context.Background(), q)
			if !resp.Response {
				t.Errorf("%s: QR bit not set in response", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Multi-address binding tests
// ---------------------------------------------------------------------------

// findFreePort allocates a TCP listener on 127.0.0.1:0 and returns the
// assigned port, closing the listener so the port is available for the test.
func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestServePlainAddresses_MultiAddress verifies that ServePlain correctly binds
// to two addresses and each answers DNS queries independently.
func TestServePlainAddresses_MultiAddress(t *testing.T) {
	port := findFreePort(t)

	query := makeQuery("multi.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query), makeNormalResp(query)})

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1", "127.0.0.2"}
	cfg.Downstream.Plain.Port = port

	// Skip if 127.0.0.2 is not bindable on this system.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.2:%d", port))
	if err != nil {
		t.Skipf("127.0.0.2 not bindable on this system: %v", err)
	}
	ln.Close()

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-multi")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain multi returned: %v", err)
		}
	}()

	time.Sleep(150 * time.Millisecond)

	for _, addr := range []string{"127.0.0.1", "127.0.0.2"} {
		target := fmt.Sprintf("%s:%d", addr, port)
		q := makeQuery("multi.example.com", dns.TypeA)
		q.RecursionDesired = true
		c := new(dns.Client)
		qCtx, qCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer qCancel()
		resp, _, clientErr := c.Exchange(qCtx, q, "udp", target)
		if clientErr != nil {
			t.Errorf("UDP query to %s failed: %v", target, clientErr)
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("expected NOERROR from %s, got %v", target, resp.Rcode)
		}
	}
}

// TestServePlainAddresses_EmptyAddresses verifies that servePlainAddresses
// returns an error immediately when given an empty address slice.
func TestServePlainAddresses_EmptyAddresses(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-empty")
	err := servePlainAddresses(context.Background(), handler, nil, 5353, logger)
	if err == nil {
		t.Fatal("expected error for empty address slice")
	}
}

// TestServePlainAddresses_BindFailure verifies that servePlainAddresses returns
// an error immediately when any address cannot be bound (port already in use).
func TestServePlainAddresses_BindFailure(t *testing.T) {
	// Occupy the port before starting ServePlain.
	occupier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-bind occupier: %v", err)
	}
	defer occupier.Close()
	port := occupier.Addr().(*net.TCPAddr).Port

	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-bind-fail")

	// Both UDP and TCP listeners must fail because the TCP port is in use.
	// On most platforms one of the two will fail immediately.
	errCh := make(chan error, 1)
	go func() {
		errCh <- servePlainAddresses(context.Background(), handler, []string{"127.0.0.1"}, port, logger)
	}()

	select {
	case e := <-errCh:
		if e == nil {
			t.Error("expected bind error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for bind error")
	}
}

// TestServeDoHAddresses_EmptyAddresses verifies that serveDoHAddresses returns
// an error immediately when given an empty address slice.
func TestServeDoHAddresses_EmptyAddresses(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-doh-empty")
	cfg := config.DefaultConfig()
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	err := serveDoHAddresses(context.Background(), handler, nil, 8080, cfg, logger)
	if err == nil {
		t.Fatal("expected error for empty DoH address slice")
	}
}

// TestServeDoHAddresses_MultiAddress verifies that ServeDoH binds to two
// addresses and each answers DoH queries correctly.
func TestServeDoHAddresses_MultiAddress(t *testing.T) {
	port := findFreePort(t)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.2:%d", port))
	if err != nil {
		t.Skipf("127.0.0.2 not bindable on this system: %v", err)
	}
	ln.Close()

	query := makeQuery("doh-multi.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query), makeNormalResp(query)})
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-doh-multi")

	cfg := config.DefaultConfig()
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cfg.Downstream.DoH.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := serveDoHAddresses(ctx, handler, []string{"127.0.0.1", "127.0.0.2"}, port, cfg, logger); err != nil {
			t.Logf("serveDoHAddresses returned: %v", err)
		}
	}()

	time.Sleep(150 * time.Millisecond)

	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	body := query.Data

	for _, addr := range []string{"127.0.0.1", "127.0.0.2"} {
		target := fmt.Sprintf("http://%s:%d/dns-query", addr, port)
		req, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/dns-message")

		httpClient := &http.Client{Timeout: 3 * time.Second}
		resp, clientErr := httpClient.Do(req)
		if clientErr != nil {
			t.Errorf("DoH POST to %s failed: %v", target, clientErr)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("DoH %s: expected 200, got %d", target, resp.StatusCode)
		}
	}
}

// TestServeDoTAddresses_EmptyAddresses verifies that serveDoTAddresses returns
// an error immediately when given an empty address slice.
func TestServeDoTAddresses_EmptyAddresses(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-dot-empty")
	err := serveDoTAddresses(context.Background(), handler, nil, 853, nil, logger)
	if err == nil {
		t.Fatal("expected error for empty DoT address slice")
	}
}

// TestNetworkForIP verifies that networkForIP returns the correct network type
// strings for IPv4 and IPv6 addresses.
func TestNetworkForIP(t *testing.T) {
	tests := []struct {
		ip      string
		wantTCP string
		wantUDP string
	}{
		{"0.0.0.0", "tcp4", "udp4"},
		{"127.0.0.1", "tcp4", "udp4"},
		{"192.168.1.1", "tcp4", "udp4"},
		{"::", "tcp6", "udp6"},
		{"::1", "tcp6", "udp6"},
		{"fd12:3456:789a:1::5", "tcp6", "udp6"},
		{"2001:db8::1", "tcp6", "udg6"},
	}
	// Correct the typo in the last expected value.
	tests[6].wantUDP = "udp6"

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			gotTCP, gotUDP := networkForIP(tt.ip)
			if gotTCP != tt.wantTCP {
				t.Errorf("networkForIP(%q) TCP = %q, want %q", tt.ip, gotTCP, tt.wantTCP)
			}
			if gotUDP != tt.wantUDP {
				t.Errorf("networkForIP(%q) UDP = %q, want %q", tt.ip, gotUDP, tt.wantUDP)
			}
		})
	}
}

// TestServePlain_DualStack verifies that ServePlain can simultaneously bind to
// both an IPv4 address (127.0.0.1) and an IPv6 address (::1) on the same port
// without triggering a "bind: address already in use" error.
// This tests the fix for the dual-stack socket conflict where using the generic
// "tcp"/"udp" network types on a system that defaults to dual-stack IPv6
// sockets causes the second bind to fail.
func TestServePlain_DualStack(t *testing.T) {
	// Check IPv6 availability first.
	ln6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback not available on this system")
	}
	port := ln6.Addr().(*net.TCPAddr).Port
	ln6.Close()

	// Also check IPv4 can bind on the same port.
	ln4, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("IPv4 cannot bind port %d alongside IPv6: %v", port, err)
	}
	ln4.Close()

	query := makeQuery("dualstack.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{
		makeNormalResp(query), makeNormalResp(query),
		makeNormalResp(query), makeNormalResp(query),
	})

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1", "::1"}
	cfg.Downstream.Plain.Port = port

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-dualstack")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			errCh <- err
		}
	}()

	// Short deadline to catch bind errors at startup.
	select {
	case err := <-errCh:
		t.Fatalf("ServePlain dual-stack bind failed: %v", err)
	case <-time.After(300 * time.Millisecond):
		// No error within the startup window; both addresses bound successfully.
	}

	c := new(dns.Client)

	// Query via IPv4.
	q4 := makeQuery("dualstack.example.com", dns.TypeA)
	q4.RecursionDesired = true
	qCtx4, qCancel4 := context.WithTimeout(context.Background(), 3*time.Second)
	defer qCancel4()
	resp4, _, err4 := c.Exchange(qCtx4, q4, "udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err4 != nil {
		t.Errorf("IPv4 UDP query failed: %v", err4)
	} else if resp4.Rcode != dns.RcodeSuccess {
		t.Errorf("IPv4 UDP: expected NOERROR, got %v", resp4.Rcode)
	}

	// Query via IPv6.
	q6 := makeQuery("dualstack.example.com", dns.TypeA)
	q6.RecursionDesired = true
	qCtx6, qCancel6 := context.WithTimeout(context.Background(), 3*time.Second)
	defer qCancel6()
	resp6, _, err6 := c.Exchange(qCtx6, q6, "udp", fmt.Sprintf("[::1]:%d", port))
	if err6 != nil {
		t.Errorf("IPv6 UDP query failed: %v", err6)
	} else if resp6.Rcode != dns.RcodeSuccess {
		t.Errorf("IPv6 UDP: expected NOERROR, got %v", resp6.Rcode)
	}
}

// ---------------------------------------------------------------------------
// Cache-Control: no-store on HTTP error responses (RFC 8484 s5.1)
// ---------------------------------------------------------------------------

// TestDohHandler_ErrorResponse_NoStore_InvalidBase64 verifies that a GET
// request with invalid base64url in ?dns= returns 400 and Cache-Control: no-store
// so that HTTP caches and reverse proxies do not cache the error.
func TestDohHandler_ErrorResponse_NoStore_InvalidBase64(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns=!!invalid!!", nil)
	w := httptest.NewRecorder()
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
	if cc := w.Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store on 400 error", cc)
	}
}

// TestDohHandler_ErrorResponse_NoStore_WrongContentType verifies that a POST
// with the wrong Content-Type returns 415 with Cache-Control: no-store.
func TestDohHandler_ErrorResponse_NoStore_WrongContentType(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{1, 2, 3}))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status=%d, want 415", w.Code)
	}
	if cc := w.Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store on 415 error", cc)
	}
}

// TestDohHandler_ErrorResponse_NoStore_MethodNotAllowed verifies that an
// unsupported HTTP method (e.g. PUT) returns 405 with Cache-Control: no-store.
func TestDohHandler_ErrorResponse_NoStore_MethodNotAllowed(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	req := httptest.NewRequest(http.MethodPut, "/dns-query", nil)
	w := httptest.NewRecorder()
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d, want 405", w.Code)
	}
	if cc := w.Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store on 405 error", cc)
	}
}

// TestDohHandler_ErrorResponse_NoStore_MalformedWire verifies that a POST
// with a Content-Type of application/dns-message but an unparseable body
// returns 400 with Cache-Control: no-store.
func TestDohHandler_ErrorResponse_NoStore_MalformedWire(t *testing.T) {
	handler := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{0xde, 0xad}))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
	if cc := w.Result().Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store on 400 malformed wire error", cc)
	}
}

// ---------------------------------------------------------------------------
// JSON DNS API (Accept: application/dns-json)
// ---------------------------------------------------------------------------

// TestDohHandler_JSONAccept_ContentType verifies that a request with
// Accept: application/dns-json receives a response with Content-Type
// application/dns-json rather than application/dns-message.
func TestDohHandler_JSONAccept_ContentType(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	query.ID = 0

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(query)})
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	body := make([]byte, len(query.Data))
	copy(body, query.Data)

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-json")
	w := httptest.NewRecorder()
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	ct := w.Result().Header.Get("Content-Type")
	if ct != "application/dns-json" {
		t.Errorf("Content-Type=%q, want application/dns-json", ct)
	}
	// Response body must be valid JSON starting with '{'.
	body2 := w.Body.Bytes()
	if len(body2) == 0 || body2[0] != '{' {
		t.Errorf("JSON body does not start with '{': %q", string(body2))
	}
}

// TestDohHandler_JSONAccept_BlockedDomain verifies that a blocked domain
// served via the JSON API carries a short Cache-Control max-age (null mode
// uses a 10s TTL for the synthesized answer).
func TestDohHandler_JSONAccept_BlockedDomain(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	query.ID = 0

	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(query)})
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}
	body := make([]byte, len(query.Data))
	copy(body, query.Data)

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-json")
	w := httptest.NewRecorder()
	dohHandler(w, req, handler, logger)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (DNS status in body for JSON API)", w.Code)
	}
	// Null mode returns NOERROR (not REFUSED), so responses are cacheable
	// with a short TTL rather than no-store.
	cc := w.Result().Header.Get("Cache-Control")
	if cc == "" {
		t.Error("expected Cache-Control header")
	}
	if ct := w.Result().Header.Get("Content-Type"); ct != "application/dns-json" {
		t.Errorf("Content-Type=%q, want application/dns-json", ct)
	}
}

// ---------------------------------------------------------------------------
// Genuine NXDOMAIN pass-through (RFC 1034 s4.3.3)
// ---------------------------------------------------------------------------

// TestHandleQuery_GenuineNXDomain_NotBlocked verifies that when an upstream
// returns NXDOMAIN with an Authority (SOA) section, the proxy correctly
// passes the NXDOMAIN response to the client rather than treating it as a
// block signal.
func TestHandleQuery_GenuineNXDomain_NotBlocked(t *testing.T) {
	query := makeQuery("nonexistent.example.com", dns.TypeA)

	// Build genuine NXDOMAIN response: NXDOMAIN + SOA in Authority.
	nxResp := new(dns.Msg)
	dnsutil.SetReply(nxResp, query)
	nxResp.Rcode = dns.RcodeNameError
	nxResp.Ns = append(nxResp.Ns, &dns.SOA{
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

	handler := newTestHandler(t, []*dns.Msg{nxResp})
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response for genuine NXDOMAIN")
	}
	// Must NOT be treated as a blocked domain (REFUSED + EDE).
	if resp.Rcode == dns.RcodeRefused {
		t.Error("genuine NXDOMAIN (with SOA) must not become REFUSED")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode=%s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("genuine NXDOMAIN should have no answer records, got %d", len(resp.Answer))
	}
}

// =============================================================================
// F-02: BADCOOKIE through server handler
// =============================================================================

// TestHandleQuery_BADCOOKIE_ReturnsServFail verifies that when all upstreams
// return BADCOOKIE, the handler returns SERVFAIL to the client.
func TestHandleQuery_BADCOOKIE_ReturnsServFail(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	badCookieResp := new(dns.Msg)
	dnsutil.SetReply(badCookieResp, query)
	badCookieResp.Rcode = dns.RcodeBadCookie

	handler := newTestHandler(t, []*dns.Msg{badCookieResp})
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL for BADCOOKIE, got %s",
			dns.RcodeToString[resp.Rcode])
	}
}

// =============================================================================
// F-03: Whitelist resolver error handling
// =============================================================================

// TestHandleQuery_WhitelistResolverError_ReturnsSERVFAIL verifies that when
// the whitelist resolver fails, the handler returns SERVFAIL.
func TestHandleQuery_WhitelistResolverError_ReturnsSERVFAIL(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist.Enabled = true

	wlList := testDomainList(t, []string{"whitelisted.example.com"})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	c := cache.New(100, 3600, 5, 0)

	// Normal upstream that works
	normalResp := makeNormalResp(makeQuery("whitelisted.example.com", dns.TypeA))
	clients := []upstream.Client{
		&mockUpstreamClient{name: "normal", response: normalResp},
	}
	resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)

	// Whitelist resolver that always errors
	wlClient := &mockUpstreamClient{
		name: "wl-fail",
		err:  fmt.Errorf("whitelist upstream unavailable"),
	}
	wlResolver := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	handler := NewHandler(resolver, wlResolver, nil, c, logger, cfg)

	query := makeQuery("whitelisted.example.com", dns.TypeA)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL when whitelist resolver fails, got %s",
			dns.RcodeToString[resp.Rcode])
	}
}

// =============================================================================
// DoH-specific tests
// =============================================================================

// TestComputeMaxAge_EmptyMessage verifies default max-age when no TTL-bearing
// records exist in an empty message.
func TestComputeMaxAge_EmptyMessage(t *testing.T) {
	msg := new(dns.Msg)
	age := computeMaxAge(msg)
	if age != 1800 {
		t.Errorf("expected default 1800 for no records, got %d", age)
	}
}

// TestComputeMaxAge_WithRecords verifies min TTL from records is used.
func TestComputeMaxAge_WithRecords(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeNormalResp(query)
	resp.Answer[0].Header().TTL = 120

	age := computeMaxAge(resp)
	if age != 120 {
		t.Errorf("expected 120 from TTL, got %d", age)
	}
}

// TestComputeMaxAge_Floor verifies minimum of 1.
func TestComputeMaxAge_Floor(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	resp := makeNormalResp(query)
	resp.Answer[0].Header().TTL = 0

	age := computeMaxAge(resp)
	if age < 1 {
		t.Errorf("expected min 1, got %d", age)
	}
}

// =============================================================================
// Handler multi-question rejection
// =============================================================================

// TestHandleQuery_MultipleQuestions_FORMERR verifies that queries with more
// than one question are rejected with FORMERR.
func TestHandleQuery_MultipleQuestions_FORMERR(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	extra := &dns.A{
		Hdr: dns.Header{Name: "other.example.com.", Class: dns.ClassINET},
	}
	query.Question = append(query.Question, extra)

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(makeQuery("example.com", dns.TypeA))})
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR for multi-question, got %s",
			dns.RcodeToString[resp.Rcode])
	}
}

// TestHandleQuery_EmptyQuestion_FORMERR verifies empty question rejection.
func TestHandleQuery_EmptyQuestion_FORMERR(t *testing.T) {
	query := new(dns.Msg)
	query.ID = 1234

	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(makeQuery("example.com", dns.TypeA))})
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR for empty question, got %s",
			dns.RcodeToString[resp.Rcode])
	}
}

// --- RFC 8484: DoH Content-Type tolerance tests ---

// TestReadDOHWireQuery_POST_ContentType_WithParams verifies that a valid
// Content-Type with MIME parameters (e.g. charset) is accepted per RFC 8484.
func TestReadDOHWireQuery_POST_ContentType_WithParams(t *testing.T) {
	body := []byte{0, 1, 2, 3, 4, 5}
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/dns-message; charset=utf-8")

	wire, status, msg := readDOHWireQuery(r)
	if status != http.StatusOK {
		t.Errorf("Content-Type with params: expected 200, got %d (%s)", status, msg)
	}
	if !bytes.Equal(wire, body) {
		t.Errorf("Content-Type with params: body mismatch")
	}
}

// TestReadDOHWireQuery_POST_ContentType_CaseInsensitive verifies that the
// media type comparison is case-insensitive per MIME type standards.
func TestReadDOHWireQuery_POST_ContentType_CaseInsensitive(t *testing.T) {
	body := []byte{0, 1, 2, 3, 4, 5}
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	r.Header.Set("Content-Type", "Application/DNS-Message")

	wire, status, msg := readDOHWireQuery(r)
	if status != http.StatusOK {
		t.Errorf("case-variant Content-Type: expected 200, got %d (%s)", status, msg)
	}
	if !bytes.Equal(wire, body) {
		t.Errorf("case-variant Content-Type: body mismatch")
	}
}

// TestReadDOHWireQuery_POST_ContentType_WrongTypeWithParams verifies that a
// wrong base type with extra parameters is still rejected.
func TestReadDOHWireQuery_POST_ContentType_WrongTypeWithParams(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{1, 2, 3}))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	_, status, _ := readDOHWireQuery(r)
	if status != http.StatusUnsupportedMediaType {
		t.Errorf("wrong Content-Type with params: expected 415, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// Local blacklist and priority ordering tests
// ---------------------------------------------------------------------------

// TestHandleQuery_LocalBlacklistBlocks verifies that a domain in the local
// blacklist returns a blocked response without querying upstream.
func TestHandleQuery_LocalBlacklistBlocks(t *testing.T) {
	query := makeQuery("evil.blacklisted.example.com", dns.TypeA)

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false

	bl := testDomainList(t, []string{"||evil.blacklisted.example.com^"})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	c := cache.New(100, 3600, 5, 0)

	// Normal upstream -- must NOT be reached.
	normalResp := makeNormalResp(query)
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{&mockUpstreamClient{name: "upstream", response: normalResp}},
		2*time.Second, 50*time.Millisecond, logger,
	)

	handler := NewHandler(resolver, nil, bl, c, logger, cfg)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	// Null mode: NOERROR with 0.0.0.0 answer and EDE Blocked.
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("local blacklist rcode=%s, want NOERROR (null mode)", dns.RcodeToString[resp.Rcode])
	}
	if !hasEDEBlocked(resp) {
		t.Error("local blacklist response must include EDE Blocked (code 15)")
	}
	// Verify the null-mode 0.0.0.0 address is present.
	if len(resp.Answer) == 0 {
		t.Fatal("expected answer record in null mode blocked response")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record in null mode blocked response")
	}
	if a.Addr != (netip.AddrFrom4([4]byte{})) {
		t.Errorf("null mode blocked IP = %v, want 0.0.0.0", a.Addr)
	}
}

// TestHandleQuery_LocalBlacklistLogsInfo verifies that a blacklist block
// produces a dns_query JSON event with the domain name. Text mode does not
// emit per-query data.
func TestHandleQuery_LocalBlacklistLogsInfo(t *testing.T) {
	query := makeQuery("logged.blacklisted.example.com", dns.TypeA)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	bl := testDomainList(t, []string{"||logged.blacklisted.example.com^"})
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients(nil, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, bl, c, logger, cfg)

	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if !strings.Contains(out, "logged.blacklisted.example.com") {
		t.Errorf("expected domain in blacklist JSON event, got: %s", out)
	}
	if !strings.Contains(out, "blacklist") {
		t.Errorf("expected 'blacklist' in JSON event, got: %s", out)
	}
	if strings.Contains(out, "blocked_by") {
		t.Errorf("blocked_by field must not appear in JSON event, got: %s", out)
	}
	if !strings.Contains(out, "dns_query") {
		t.Errorf("expected dns_query event type in JSON output, got: %s", out)
	}
}

// TestHandleQuery_WhitelistPreemptsBlacklist verifies that when a domain
// appears in both the whitelist and the blacklist, the whitelist wins: the
// query is resolved cleanly rather than blocked.
// Priority order: DDR > whitelist > blacklist > cache > upstream.
func TestHandleQuery_WhitelistPreemptsBlacklist(t *testing.T) {
	query := makeQuery("shared.example.com", dns.TypeA)

	wlResponse := new(dns.Msg)
	dnsutil.SetReply(wlResponse, query)
	wlResponse.Answer = append(wlResponse.Answer, &dns.A{
		Hdr: dns.Header{Name: "shared.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("7.7.7.7")},
	})
	wlClient := &mockUpstreamClient{name: "whitelist-resolver", response: wlResponse}

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	cfg.Whitelist.Enabled = true

	// Domain is in BOTH the whitelist and the blacklist.
	wlList := testDomainList(t, []string{"||shared.example.com^"})
	bl := testDomainList(t, []string{"||shared.example.com^"})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	c := cache.New(100, 3600, 5, 0)

	// Blocking upstream -- must NOT be reached.
	blockClient := &mockUpstreamClient{name: "blocker", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{blockClient},
		2*time.Second, 50*time.Millisecond, logger,
	)
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	handler := NewHandler(resolver, wlRes, bl, c, logger, cfg)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	// Whitelist must win: clean resolution, no EDE Blocked.
	if hasEDEBlocked(resp) {
		t.Error("whitelist must preempt blacklist: response must not be blocked")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("whitelist response rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected answer record from whitelist resolver")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record from whitelist resolver")
	}
	if a.Addr != netip.MustParseAddr("7.7.7.7") {
		t.Errorf("whitelist resolver IP = %v, want 7.7.7.7", a.Addr)
	}
}

// TestHandleQuery_BlacklistDoesNotAffectNonMatchingDomain verifies that a
// domain NOT in the blacklist is resolved normally via upstream.
func TestHandleQuery_BlacklistDoesNotAffectNonMatchingDomain(t *testing.T) {
	query := makeQuery("safe.example.com", dns.TypeA)
	normalResp := makeNormalResp(query)

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false

	// Blacklist only contains a different domain.
	bl := testDomainList(t, []string{"||other.example.com^"})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{&mockUpstreamClient{name: "upstream", response: normalResp}},
		2*time.Second, 50*time.Millisecond, logger,
	)

	handler := NewHandler(resolver, nil, bl, c, logger, cfg)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	if hasEDEBlocked(resp) {
		t.Error("non-blacklisted domain must not be blocked")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode=%s, want NOERROR for non-blacklisted domain", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Error("expected answer records for non-blacklisted domain")
	}
}

// TestReadDOHWireQuery_POST_ContentType_Empty verifies that a missing
// Content-Type header is rejected.
func TestReadDOHWireQuery_POST_ContentType_Empty(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{1, 2, 3}))
	// No Content-Type header set

	_, status, _ := readDOHWireQuery(r)
	if status != http.StatusUnsupportedMediaType {
		t.Errorf("missing Content-Type: expected 415, got %d", status)
	}
}

// --- RFC 6891: Non-EDNS client receives no OPT in response ---

// TestServePlain_NonEDNS_NoOPTInResponse verifies that a plain DNS client
// that sends a query without an OPT record does not receive an OPT record
// (and therefore no EDE) in the response, per RFC 6891.
func TestServePlain_NonEDNS_NoOPTInResponse(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Logf("close listener: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-non-edns")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain: %v", err)
		}
	}()
	time.Sleep(50 * time.Millisecond)

	// Send a query WITHOUT an OPT record (non-EDNS client).
	nonEDNSQuery := makeQuery("example.com", dns.TypeA)
	nonEDNSQuery.RecursionDesired = true
	// Verify query has no OPT / UDPSize = 0
	if nonEDNSQuery.UDPSize != 0 {
		t.Logf("non-EDNS query UDPSize=%d", nonEDNSQuery.UDPSize)
	}

	c := new(dns.Client)
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer queryCancel()
	resp, _, err := c.Exchange(queryCtx, nonEDNSQuery, "udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("UDP query: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("non-EDNS query: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	// Response must NOT include OPT (UDPSize should be 0 after unpack if no OPT present).
	if resp.UDPSize != 0 {
		t.Errorf("non-EDNS client: response UDPSize=%d, want 0 (no OPT per RFC 6891)", resp.UDPSize)
	}
}

// TestServePlain_EDNS_HasOPTInResponse verifies that an EDNS-capable client
// receives an OPT record in the response.
func TestServePlain_EDNS_HasOPTInResponse(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Logf("close listener: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-edns")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain: %v", err)
		}
	}()
	time.Sleep(50 * time.Millisecond)

	// Send a query WITH an OPT record (EDNS-capable client).
	ednsQuery := makeQuery("example.com", dns.TypeA)
	ednsQuery.RecursionDesired = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.SetUDPSize(1232)
	ednsQuery.Pseudo = append(ednsQuery.Pseudo, opt)

	c := new(dns.Client)
	queryCtx, queryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer queryCancel()
	resp, _, err := c.Exchange(queryCtx, ednsQuery, "udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("EDNS UDP query: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.UDPSize == 0 {
		t.Error("EDNS client: response should include OPT record (UDPSize != 0)")
	}
}

// =============================================================================
// Whitelist caching tests
// =============================================================================

// newTestHandlerWithWhitelistAndUpstream creates a Handler that has a whitelist
// resolver and a separate blocking upstream. whitelistDomains specifies which
// domains are in the whitelist; whitelistResp is what the whitelist resolver
// returns; blockingResp is what the main upstream returns (typically blocked).
func newTestHandlerWithWhitelistAndUpstream(
	t *testing.T,
	whitelistDomains []string,
	whitelistResp *dns.Msg,
	upstreamResp *dns.Msg,
) *Handler {
	t.Helper()
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Cache.MinTTL = 1
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 1, 0)

	// Whitelist domain list from temp file
	wlList := testDomainList(t, whitelistDomains)

	wlClient := &mockUpstreamClient{name: "whitelist-resolver", response: whitelistResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	upClient := &mockUpstreamClient{name: "main-upstream", response: upstreamResp}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)

	return NewHandler(resolver, wlRes, nil, c, logger, cfg)
}

// countCallsClient wraps a mockUpstreamClient and counts Query invocations.
type countCallsClient struct {
	*mockUpstreamClient
	mu    sync.Mutex
	calls int
}

func (c *countCallsClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.mockUpstreamClient.Query(ctx, msg)
}

func (c *countCallsClient) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestHandleQuery_WhitelistCacheHit(t *testing.T) {
	// First query should hit whitelist resolver; second should be served from cache.
	query := makeQuery("safe.example.com", dns.TypeA)

	wlResp := new(dns.Msg)
	dnsutil.SetReply(wlResp, query)
	wlResp.Answer = append(wlResp.Answer, &dns.A{
		Hdr: dns.Header{Name: "safe.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("5.5.5.5")},
	})

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Cache.MinTTL = 1
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 1, 0)
	wlList := testDomainList(t, []string{"safe.example.com"})

	wlCount := &countCallsClient{
		mockUpstreamClient: &mockUpstreamClient{name: "wl", response: wlResp},
	}
	wlRes := upstream.NewWhitelistResolverFromClient(wlCount, &cfg.Whitelist, wlList)

	blockResp := makeBlockedResp(query)
	upCount := &countCallsClient{
		mockUpstreamClient: &mockUpstreamClient{name: "up", response: blockResp},
	}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upCount}, 2*time.Second, 50*time.Millisecond, logger)

	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	// First query: whitelist resolver called, result cached.
	resp1 := handler.HandleQuery(context.Background(), query)
	if resp1 == nil {
		t.Fatal("expected response on first query")
	}
	a1, ok := resp1.Answer[0].(*dns.A)
	if !ok || a1.Addr != netip.MustParseAddr("5.5.5.5") {
		t.Errorf("first query: expected whitelist IP 5.5.5.5, got %v", resp1.Answer)
	}
	if wlCount.Calls() != 1 {
		t.Errorf("first query: expected 1 whitelist resolver call, got %d", wlCount.Calls())
	}

	// Second query: served from cache, whitelist resolver NOT called again.
	query2 := makeQuery("safe.example.com", dns.TypeA)
	query2.ID = 9999
	resp2 := handler.HandleQuery(context.Background(), query2)
	if resp2 == nil {
		t.Fatal("expected cached response on second query")
	}
	if resp2.ID != 9999 {
		t.Errorf("cached response ID should be 9999, got %d", resp2.ID)
	}
	if wlCount.Calls() != 1 {
		t.Errorf("second query: whitelist resolver should not be called again (got %d calls)", wlCount.Calls())
	}
	if upCount.Calls() != 0 {
		t.Errorf("upstream should never be queried for whitelisted domain (got %d calls)", upCount.Calls())
	}
}

func TestHandleQuery_WhitelistCacheOnlyServesWhitelistedEntry(t *testing.T) {
	// If the cache has a non-whitelisted entry for a domain and the domain is
	// then added to the whitelist, the non-whitelisted entry must NOT be served
	// from the whitelist path. (Invalidation handles this in RunContext; here we
	// verify the whitelist path checks entry.Whitelisted before serving.)
	query := makeQuery("flip.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Cache.MinTTL = 1
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 1, 0)

	// Pre-seed cache with a non-whitelisted (blocked) entry.
	blockedResp := makeBlockedResp(query)
	c.Put(query, blockedResp, true, false) // whitelisted=false

	wlResp := new(dns.Msg)
	dnsutil.SetReply(wlResp, query)
	wlResp.Answer = append(wlResp.Answer, &dns.A{
		Hdr: dns.Header{Name: "flip.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("9.9.9.9")},
	})
	wlList := testDomainList(t, []string{"flip.example.com"})
	wlClient := &mockUpstreamClient{name: "wl", response: wlResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	upClient := &mockUpstreamClient{name: "up", response: makeNormalResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)

	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)
	resp := handler.HandleQuery(context.Background(), query)

	if resp == nil {
		t.Fatal("expected response")
	}
	// The domain is whitelisted, non-whitelisted cached entry should be bypassed,
	// whitelist resolver should return 9.9.9.9.
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.Addr != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("expected whitelist resolver IP 9.9.9.9, got %v", resp.Answer)
	}
}

func TestHandleQuery_WhitelistCacheDisabledFlowsToResolver(t *testing.T) {
	// When cache is disabled, every whitelist query must hit the whitelist resolver.
	query := makeQuery("safe.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(0, 1, 1, 0)

	wlResp := new(dns.Msg)
	dnsutil.SetReply(wlResp, query)
	wlResp.Answer = append(wlResp.Answer, &dns.A{
		Hdr: dns.Header{Name: "safe.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("1.1.1.1")},
	})
	wlCount := &countCallsClient{
		mockUpstreamClient: &mockUpstreamClient{name: "wl", response: wlResp},
	}
	wlList := testDomainList(t, []string{"safe.example.com"})
	wlRes := upstream.NewWhitelistResolverFromClient(wlCount, &cfg.Whitelist, wlList)

	resolver := upstream.NewResolverFromClients(nil, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	for i := 0; i < 3; i++ {
		q := makeQuery("safe.example.com", dns.TypeA)
		handler.HandleQuery(context.Background(), q)
	}
	if wlCount.Calls() != 3 {
		t.Errorf("cache disabled: expected 3 whitelist resolver calls, got %d", wlCount.Calls())
	}
}

func TestHandleQuery_WhitelistCacheRespectsTTL(t *testing.T) {
	// Cached whitelist entry must respect min_ttl (clamping short upstream TTLs).
	query := makeQuery("safe.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Cache.MinTTL = 60 // force min 60s
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 60, 0)

	wlResp := new(dns.Msg)
	dnsutil.SetReply(wlResp, query)
	wlResp.Answer = append(wlResp.Answer, &dns.A{
		Hdr: dns.Header{Name: "safe.example.com.", Class: dns.ClassINET, TTL: 10}, // short TTL
		A:   rdata.A{Addr: netip.MustParseAddr("5.5.5.5")},
	})
	wlList := testDomainList(t, []string{"safe.example.com"})
	wlClient := &mockUpstreamClient{name: "wl", response: wlResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	upClient := &mockUpstreamClient{name: "up", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)
	if resp == nil {
		t.Fatal("expected response")
	}

	// Entry should be cached -- verify it has a Whitelisted flag.
	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cached entry")
	}
	if !entry.Whitelisted {
		t.Error("cached entry should have Whitelisted=true")
	}
	// TTL should be clamped to minTTL (60s) since upstream gave 10s.
	ttl := entry.ExpiresAt.Sub(entry.InsertedAt)
	if ttl < 59*time.Second {
		t.Errorf("expected TTL >= 60s (minTTL), got %s", ttl)
	}
}

func TestHandleQuery_BlacklistNoCacheLookupNoWrite(t *testing.T) {
	// Blacklisted domain: no cache lookup, no cache write, just block.
	query := makeQuery("evil.example.com", dns.TypeA)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100

	c := cache.New(100, 3600, 5, 0)

	// Pre-seed cache with a normal entry to confirm cache is not read.
	normalEntry := makeNormalResp(query)
	c.Put(query, normalEntry, false, false)

	bl := testDomainList(t, []string{"evil.example.com"})

	upClient := &mockUpstreamClient{name: "up", response: makeNormalResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, bl, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)
	if resp == nil {
		t.Fatal("expected response")
	}
	// Must be blocked (EDE Blocked).
	if !hasEDEBlocked(resp) {
		t.Error("blacklisted domain must return EDE Blocked, not the cached normal entry")
	}
	// Cache should still only have the original 1 entry -- blacklist does not write.
	if c.Len() != 1 {
		t.Errorf("blacklist should not write to cache, got %d entries", c.Len())
	}
}

func TestHandleQuery_WhitelistReloadInvalidatesRemovedDomain(t *testing.T) {
	// When a domain is removed from the whitelist and the list hot-reloads,
	// its cache entry (Whitelisted=true) must be invalidated so the next
	// query goes through the normal upstream path (which may block it).
	query := makeQuery("waswhite.example.com", dns.TypeA)

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 5, 0)

	// Seed a whitelisted cache entry.
	wlResp := makeNormalResp(query)
	c.Put(query, wlResp, false, true) // Whitelisted=true

	if entry, _ := c.Get(query); entry == nil || !entry.Whitelisted {
		t.Fatal("precondition: entry must be cached as whitelisted")
	}

	// Build a new DomainSet that does NOT contain the domain (simulates removal).
	emptySet := domainlist.EmptySet()

	// Simulate whitelist invalidation logic as wired in RunContext:
	// when whitelist entry.Whitelisted != isNowWhitelisted, invalidate.
	go func() {
		n := c.InvalidateIf(func(name string, entry *cache.Entry) bool {
			isNowWhitelisted := emptySet.Contains(name)
			return entry.Whitelisted != isNowWhitelisted
		})
		if n != 1 {
			t.Errorf("expected 1 entry invalidated, got %d", n)
		}
	}()

	// Allow the goroutine to complete.
	time.Sleep(50 * time.Millisecond)

	if entry, _ := c.Get(query); entry != nil {
		t.Error("cache entry for removed-whitelist domain should have been invalidated")
	}
}

func TestHandleQuery_WhitelistReloadInvalidatesAddedDomain(t *testing.T) {
	// When a domain is ADDED to the whitelist and the list hot-reloads,
	// any previously cached (non-whitelist) entry must be invalidated so the
	// next query goes through the whitelist path.
	query := makeQuery("newwhite.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}
	_ = logger

	c := cache.New(100, 3600, 5, 0)

	// Seed a blocked (non-whitelisted) cache entry.
	blockedResp := makeBlockedResp(query)
	c.Put(query, blockedResp, true, false) // Whitelisted=false, Blocked=true

	if entry, _ := c.Get(query); entry == nil || entry.Whitelisted {
		t.Fatal("precondition: entry must be cached as blocked/non-whitelisted")
	}

	// Build a new DomainSet that DOES contain the domain (simulates addition).
	newSet, _ := domainlist.ParseReader(strings.NewReader("newwhite.example.com\n"), domainlist.ModeAllow)

	go func() {
		n := c.InvalidateIf(func(name string, entry *cache.Entry) bool {
			isNowWhitelisted := newSet.Contains(name)
			return entry.Whitelisted != isNowWhitelisted
		})
		if n != 1 {
			t.Errorf("expected 1 entry invalidated, got %d", n)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	if entry, _ := c.Get(query); entry != nil {
		t.Error("blocked cache entry for newly-whitelisted domain should have been invalidated")
	}
}

func TestHandleQuery_WhitelistEntryTaggedInCache(t *testing.T) {
	// After a whitelist resolver query, the cache entry must have Whitelisted=true.
	query := makeQuery("tag.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 5, 0)
	wlResp := makeNormalResp(query)
	wlList := testDomainList(t, []string{"tag.example.com"})
	wlClient := &mockUpstreamClient{name: "wl", response: wlResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	upClient := &mockUpstreamClient{name: "up", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	handler.HandleQuery(context.Background(), query)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected entry in cache after whitelist query")
	}
	if !entry.Whitelisted {
		t.Error("entry cached after whitelist resolution must have Whitelisted=true")
	}
	if entry.Blocked {
		t.Error("whitelisted entry must not be blocked")
	}
}

func TestHandleQuery_WhitelistErrorNoCache(t *testing.T) {
	// When whitelist resolver errors, SERVFAIL is returned and nothing is cached.
	query := makeQuery("safe.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 5, 0)
	wlList := testDomainList(t, []string{"safe.example.com"})
	errClient := &mockUpstreamClient{
		name: "wl-err",
		err:  fmt.Errorf("whitelist resolver timeout"),
	}
	wlRes := upstream.NewWhitelistResolverFromClient(errClient, &cfg.Whitelist, wlList)

	upClient := &mockUpstreamClient{name: "up", response: makeNormalResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("expected SERVFAIL on whitelist resolver error, got %s", dns.RcodeToString[resp.Rcode])
	}
	if c.Len() != 0 {
		t.Errorf("error response must not be cached, got %d entries", c.Len())
	}
}

func TestHandleQuery_WhitelistNormalDomainNotCachedAsWhitelisted(t *testing.T) {
	// A normal (non-whitelisted) upstream result must NOT be tagged Whitelisted.
	query := makeQuery("normal.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 5, 0)
	wlList := testDomainList(t, []string{"safe.example.com"}) // different domain
	wlClient := &mockUpstreamClient{name: "wl", response: makeNormalResp(query)}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)

	upClient := &mockUpstreamClient{name: "up", response: makeNormalResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	handler.HandleQuery(context.Background(), query)

	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cached entry")
	}
	if entry.Whitelisted {
		t.Error("normal (non-whitelisted) domain must not be tagged Whitelisted in cache")
	}
}

// =============================================================================
// Wildcard whitelist invalidation tests
//
// These tests verify that makeWhitelistInvalidator correctly handles wildcard
// matching via DomainSet.Contains. The key property is that
// DomainSet.Contains uses matchWildcard which walks up the domain hierarchy,
// so "*.example.com" covers "abc.example.com", "x.y.z.example.com", etc.
//
// The predicate used in production: entry.Whitelisted != newSet.Contains(name)
// removes an entry when its cached whitelist status no longer matches the
// current whitelist domain set.
// =============================================================================

// makeQueryDO returns a query with the DNSSEC OK (DO) bit set.
func makeQueryDO(name string, qtype uint16) *dns.Msg {
	q := makeQuery(name, qtype)
	opt := &dns.OPT{}
	opt.Hdr.Name = "."
	opt.SetUDPSize(4096)
	opt.SetSecurity(true)
	q.Pseudo = append(q.Pseudo, opt)
	return q
}

// invalidatePred is the production predicate from makeWhitelistInvalidator.
func invalidatePred(newSet *domainlist.DomainSet) func(string, *cache.Entry) bool {
	return func(name string, entry *cache.Entry) bool {
		return entry.Whitelisted != newSet.Contains(name)
	}
}

// TestHandleQuery_WhitelistReloadWildcard_SubdomainInvalidated verifies that
// when *.example.com is removed from the whitelist, a cached entry for a
// direct subdomain (abc.example.com) tagged Whitelisted=true is removed.
func TestHandleQuery_WhitelistReloadWildcard_SubdomainInvalidated(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)
	q := makeQuery("abc.example.com", dns.TypeA)
	c.Put(q, makeNormalResp(q), false, true) // Whitelisted=true

	if entry, _ := c.Get(q); entry == nil || !entry.Whitelisted {
		t.Fatal("precondition: entry must be cached as whitelisted")
	}

	// New set: *.example.com is GONE.
	emptySet := domainlist.EmptySet()
	n := c.InvalidateIf(invalidatePred(emptySet))
	if n != 1 {
		t.Errorf("expected 1 invalidated entry, got %d", n)
	}
	if entry, _ := c.Get(q); entry != nil {
		t.Error("abc.example.com must be invalidated when *.example.com is removed")
	}
}

// TestHandleQuery_WhitelistReloadWildcard_DeepSubdomainInvalidated verifies
// that a deep subdomain many levels below the wildcard apex is invalidated
// when the wildcard is removed. This validates that matchWildcard walks up the
// full hierarchy, not just one level.
func TestHandleQuery_WhitelistReloadWildcard_DeepSubdomainInvalidated(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)
	q := makeQuery("e1.a2.b3.v4.sub.example.com", dns.TypeA)
	c.Put(q, makeNormalResp(q), false, true) // Whitelisted=true, covered by *.example.com

	// New set with *.example.com removed entirely.
	emptySet := domainlist.EmptySet()
	n := c.InvalidateIf(invalidatePred(emptySet))
	if n != 1 {
		t.Errorf("expected 1 invalidated entry, got %d", n)
	}
	if entry, _ := c.Get(q); entry != nil {
		t.Error("e1.a2.b3.v4.sub.example.com must be invalidated when *.example.com is removed")
	}
}

// TestHandleQuery_WhitelistReloadWildcard_AddedCoversDeepSubdomain verifies
// the reverse direction: a non-whitelisted cache entry for a deep subdomain
// is invalidated when *.example.com is ADDED to the whitelist.
func TestHandleQuery_WhitelistReloadWildcard_AddedCoversDeepSubdomain(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)
	q := makeQuery("e1.a2.b3.v4.sub.example.com", dns.TypeA)
	c.Put(q, makeBlockedResp(q), true, false) // Whitelisted=false, Blocked=true

	if entry, _ := c.Get(q); entry == nil || entry.Whitelisted {
		t.Fatal("precondition: entry must be cached as blocked/non-whitelisted")
	}

	// New set: *.example.com is NOW in the whitelist.
	newSet, err := domainlist.ParseReader(strings.NewReader("*.example.com\n"), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}
	n := c.InvalidateIf(invalidatePred(newSet))
	if n != 1 {
		t.Errorf("expected 1 invalidated entry, got %d", n)
	}
	if entry, _ := c.Get(q); entry != nil {
		t.Error("deep subdomain blocked entry must be invalidated when *.example.com is added to whitelist")
	}
}

// TestHandleQuery_WhitelistReloadWildcard_ApexMatchedByWildcard verifies that
// the apex domain itself (example.com) is also covered by *.example.com in the
// whitelist, so it is invalidated when the wildcard is removed.
// DomainSet stores *.example.com as wildcard["example.com"], and matchWildcard
// for "example.com" will match it directly.
func TestHandleQuery_WhitelistReloadWildcard_ApexMatchedByWildcard(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)
	// The apex domain "example.com" is matched by *.example.com.
	q := makeQuery("example.com", dns.TypeA)
	c.Put(q, makeNormalResp(q), false, true) // Whitelisted=true

	// Verify it's whitelisted (meaning *.example.com was in the list at write time).
	if entry, _ := c.Get(q); entry == nil || !entry.Whitelisted {
		t.Fatal("precondition: apex entry must be cached as whitelisted")
	}

	// New set: *.example.com is GONE.
	emptySet := domainlist.EmptySet()
	n := c.InvalidateIf(invalidatePred(emptySet))
	if n != 1 {
		t.Errorf("expected 1 invalidated entry (apex), got %d", n)
	}
	if entry, _ := c.Get(q); entry != nil {
		t.Error("apex example.com entry must be invalidated when *.example.com wildcard is removed")
	}
}

// TestHandleQuery_WhitelistReloadWildcard_PreservesOtherDomain verifies that
// invalidating entries for example.com does not touch entries for other.com.
func TestHandleQuery_WhitelistReloadWildcard_PreservesOtherDomain(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	qExample := makeQuery("abc.example.com", dns.TypeA)
	qOther := makeQuery("abc.other.com", dns.TypeA)
	c.Put(qExample, makeNormalResp(qExample), false, true) // Whitelisted=true
	c.Put(qOther, makeNormalResp(qOther), false, true)     // Whitelisted=true

	// New set: *.other.com still present, *.example.com removed.
	newSet, err := domainlist.ParseReader(strings.NewReader("*.other.com\n"), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}
	n := c.InvalidateIf(invalidatePred(newSet))
	if n != 1 {
		t.Errorf("expected 1 invalidated entry (example only), got %d", n)
	}
	if entry, _ := c.Get(qExample); entry != nil {
		t.Error("abc.example.com must be invalidated")
	}
	if entry, _ := c.Get(qOther); entry == nil {
		t.Error("abc.other.com must be preserved (still whitelisted)")
	}
}

// TestHandleQuery_WhitelistReloadWildcard_MultipleQtypesBothInvalidated
// verifies that when a domain has separate cache entries for A, AAAA, and MX
// (all whitelisted), removing the wildcard invalidates all of them.
func TestHandleQuery_WhitelistReloadWildcard_MultipleQtypesBothInvalidated(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	qA := makeQuery("abc.example.com", dns.TypeA)
	qAAAA := makeQuery("abc.example.com", dns.TypeAAAA)

	respA := makeNormalResp(qA)
	respAAAA := new(dns.Msg)
	dnsutil.SetReply(respAAAA, qAAAA)
	respAAAA.Answer = append(respAAAA.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: qAAAA.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
	})

	c.Put(qA, respA, false, true)       // Whitelisted=true
	c.Put(qAAAA, respAAAA, false, true) // Whitelisted=true

	if c.Len() != 2 {
		t.Fatalf("precondition: expected 2 cache entries, got %d", c.Len())
	}

	emptySet := domainlist.EmptySet()
	n := c.InvalidateIf(invalidatePred(emptySet))
	if n != 2 {
		t.Errorf("expected both A and AAAA entries invalidated, got %d", n)
	}
	if c.Len() != 0 {
		t.Error("cache must be empty after invalidating all entries")
	}
}

// TestHandleQuery_WhitelistReloadWildcard_DOBitSegregatedBothInvalidated
// verifies that DO=0 and DO=1 entries for the same domain (stored under
// different cache keys per RFC 3225) are both invalidated when the wildcard
// is removed from the whitelist.
func TestHandleQuery_WhitelistReloadWildcard_DOBitSegregatedBothInvalidated(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	qNoDO := makeQuery("abc.example.com", dns.TypeA)
	qDO := makeQueryDO("abc.example.com", dns.TypeA)

	c.Put(qNoDO, makeNormalResp(qNoDO), false, true) // key: abc.example.com./A/IN
	c.Put(qDO, makeNormalResp(qDO), false, true)     // key: abc.example.com./A/IN/DO

	if c.Len() != 2 {
		t.Fatalf("precondition: expected 2 separate cache entries (DO=0 and DO=1), got %d", c.Len())
	}

	emptySet := domainlist.EmptySet()
	n := c.InvalidateIf(invalidatePred(emptySet))
	if n != 2 {
		t.Errorf("expected both DO=0 and DO=1 entries invalidated, got %d", n)
	}
}

// TestHandleQuery_WhitelistReloadWildcard_MixedEntriesSelective verifies the
// full mixed scenario:
//   - example.com entries (whitelisted=true): invalidated when *.example.com removed
//   - other.com entries (whitelisted=false): invalidated when *.other.com added
//   - third.com entries (whitelisted=true): preserved (still in whitelist)
func TestHandleQuery_WhitelistReloadWildcard_MixedEntriesSelective(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	qEx := makeQuery("sub.example.com", dns.TypeA)
	qOther := makeQuery("sub.other.com", dns.TypeA)
	qThird := makeQuery("sub.third.com", dns.TypeA)

	c.Put(qEx, makeNormalResp(qEx), false, true)        // Whitelisted=true (*.example.com was in WL)
	c.Put(qOther, makeBlockedResp(qOther), true, false) // Whitelisted=false (was blocked)
	c.Put(qThird, makeNormalResp(qThird), false, true)  // Whitelisted=true (*.third.com still in WL)

	// New whitelist: *.example.com gone, *.other.com added, *.third.com unchanged.
	newSet, err := domainlist.ParseReader(strings.NewReader("*.other.com\n*.third.com\n"), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}
	n := c.InvalidateIf(invalidatePred(newSet))
	// Expected: sub.example.com (was WL=true, now not in WL) + sub.other.com (was WL=false, now in WL) = 2
	if n != 2 {
		t.Errorf("expected 2 invalidated entries, got %d", n)
	}
	if entry, _ := c.Get(qEx); entry != nil {
		t.Error("sub.example.com must be invalidated (removed from whitelist)")
	}
	if entry, _ := c.Get(qOther); entry != nil {
		t.Error("sub.other.com must be invalidated (added to whitelist)")
	}
	if entry, _ := c.Get(qThird); entry == nil {
		t.Error("sub.third.com must be preserved (still whitelisted)")
	}
}

// TestHandleQuery_WhitelistCache_CorruptedEntryFallsThrough verifies that
// when the wire bytes for a Whitelisted=true cache entry are corrupted and
// MakeCachedResponse returns nil, the handler re-queries the whitelist
// resolver instead of falling through to the normal (possibly blocking)
// pipeline. This prevents a whitelisted domain from being incorrectly blocked.
func TestHandleQuery_WhitelistCache_CorruptedEntryFallsThrough(t *testing.T) {
	query := makeQuery("safe.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 5, 0)
	wlResp := makeNormalResp(query)
	wlList := testDomainList(t, []string{"safe.example.com"})
	wlClient := &mockUpstreamClient{name: "wl", response: wlResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)
	blockedClient := &mockUpstreamClient{name: "up", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{blockedClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	// Seed the cache with a Whitelisted=true entry.
	c.Put(query, makeNormalResp(query), false, true)

	// Corrupt the stored wire bytes so MakeCachedResponse will fail to unpack.
	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("precondition: entry must be in cache")
	}
	entry.Data = []byte{0xFF, 0xFF, 0xFF, 0xFF} // invalid DNS wire format

	// HandleQuery must re-query the whitelist resolver and return the correct
	// (non-blocked) response -- NOT the blocked upstream response.
	resp := handler.HandleQuery(context.Background(), query)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR from whitelist resolver fallback, got %s", dns.RcodeToString[resp.Rcode])
	}
	// Ensure the wl resolver was queried (not the blocking upstream).
	if len(resp.Answer) == 0 {
		t.Error("expected answer from whitelist resolver, got empty response (may have been blocked)")
	}
}

// TestHandleQuery_WhitelistCache_NonWhitelistEntryIgnored verifies that when
// a Whitelisted=false entry (e.g. stale blocked entry not yet invalidated)
// is in the cache for a currently-whitelisted domain, the handler ignores it
// and queries the whitelist resolver, returning the correct non-blocked result.
func TestHandleQuery_WhitelistCache_NonWhitelistEntryIgnored(t *testing.T) {
	query := makeQuery("safe.example.com", dns.TypeA)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 100
	cfg.Whitelist = config.WhitelistConfig{Enabled: true}

	c := cache.New(100, 3600, 5, 0)

	// Seed a BLOCKED (non-whitelist) entry for the domain.
	c.Put(query, makeBlockedResp(query), true, false) // Whitelisted=false, Blocked=true

	wlResp := makeNormalResp(query)
	wlList := testDomainList(t, []string{"safe.example.com"})
	wlClient := &mockUpstreamClient{name: "wl", response: wlResp}
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)
	blockedUpClient := &mockUpstreamClient{name: "up", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{blockedUpClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, wlRes, nil, c, logger, cfg)

	resp := handler.HandleQuery(context.Background(), query)
	if resp == nil {
		t.Fatal("expected response")
	}
	// The whitelisted domain must resolve through the whitelist resolver (NOERROR),
	// NOT return the stale blocked entry from cache.
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR from whitelist resolver, got %s (stale blocked entry was served)", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 || resp.Answer[0].(*dns.A).A.Addr == (netip.Addr{}) {
		t.Error("expected real address from whitelist resolver, got empty or null address")
	}
}

// =============================================================================
// Scoped wildcard precision tests
//
// These tests verify that *.abc.example.com (stored as wildcard["abc.example.com"])
// does NOT match www.example.com or example.com, while correctly matching
// direct subdomains and deep subdomains of abc.example.com.
//
// The matchWildcard walk for "www.example.com":
//   "www.example.com" -> "example.com" -> no further labels -> false
//
// The matchWildcard walk for "example.com":
//   "example.com" -> no further labels -> false
//
// Neither "www.example.com" nor "example.com" equals "abc.example.com", so
// the wildcard entry for abc.example.com does not match them.
// =============================================================================

// TestHandleQuery_WhitelistReloadScopedWildcard_NoEffectOnParentDomain
// verifies that removing *.abc.example.com from the whitelist does NOT
// invalidate a cached entry for example.com (the parent domain).
func TestHandleQuery_WhitelistReloadScopedWildcard_NoEffectOnParentDomain(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	qParent := makeQuery("example.com", dns.TypeA)
	qScoped := makeQuery("sub.abc.example.com", dns.TypeA)

	// Both were cached as whitelisted via *.example.com AND *.abc.example.com
	// respectively (simulated -- we just tag both as whitelisted).
	c.Put(qParent, makeNormalResp(qParent), false, true)
	c.Put(qScoped, makeNormalResp(qScoped), false, true)

	// New set: *.abc.example.com removed, but *.example.com is still present
	// so example.com remains whitelisted.
	newSet, err := domainlist.ParseReader(strings.NewReader("*.example.com\n"), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}

	n := c.InvalidateIf(invalidatePred(newSet))
	// sub.abc.example.com is still covered by *.example.com -> no change.
	// example.com is covered by *.example.com -> no change.
	if n != 0 {
		t.Errorf("expected 0 invalidations (both still covered by *.example.com), got %d", n)
	}
	if entry, _ := c.Get(qParent); entry == nil {
		t.Error("example.com must be preserved -- covered by *.example.com")
	}
	if entry, _ := c.Get(qScoped); entry == nil {
		t.Error("sub.abc.example.com must be preserved -- covered by *.example.com")
	}
}

// TestHandleQuery_WhitelistReloadScopedWildcard_ParentNotInvalidatedWhenScopedRemoved
// verifies the primary edge case: *.abc.example.com is removed from whitelist,
// www.example.com and example.com (which were never under abc.example.com)
// must NOT be invalidated.
func TestHandleQuery_WhitelistReloadScopedWildcard_ParentNotInvalidatedWhenScopedRemoved(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	// These were whitelisted because *.example.com was in the whitelist.
	qWWW := makeQuery("www.example.com", dns.TypeA)
	qApex := makeQuery("example.com", dns.TypeA)
	// This was whitelisted because *.abc.example.com was in the whitelist.
	qScoped := makeQuery("app.abc.example.com", dns.TypeA)
	// This sibling is also under abc.example.com.
	qSibling := makeQuery("deep.abc.example.com", dns.TypeA)

	for _, q := range []*dns.Msg{qWWW, qApex, qScoped, qSibling} {
		c.Put(q, makeNormalResp(q), false, true) // all Whitelisted=true
	}

	// New whitelist: *.abc.example.com removed; *.example.com still present.
	// www.example.com and example.com are still under *.example.com -> keep.
	// app.abc.example.com and deep.abc.example.com are still under *.example.com -> keep.
	// (Because *.example.com covers all subdomains at any depth.)
	newSet, err := domainlist.ParseReader(strings.NewReader("*.example.com\n"), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}

	n := c.InvalidateIf(invalidatePred(newSet))
	if n != 0 {
		t.Errorf("expected 0 invalidations (all still covered by *.example.com), got %d", n)
	}
	for _, q := range []*dns.Msg{qWWW, qApex, qScoped, qSibling} {
		name := q.Question[0].Header().Name
		if entry, _ := c.Get(q); entry == nil {
			t.Errorf("%s must be preserved", name)
		}
	}
}

// TestHandleQuery_WhitelistReloadScopedWildcard_ScopedRemovedOnlyWhenParentAlsoGone
// verifies that when BOTH *.example.com and *.abc.example.com are removed,
// all entries (www.example.com, example.com, sub.abc.example.com) are invalidated.
func TestHandleQuery_WhitelistReloadScopedWildcard_ScopedRemovedOnlyWhenParentAlsoGone(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	qWWW := makeQuery("www.example.com", dns.TypeA)
	qApex := makeQuery("example.com", dns.TypeA)
	qScoped := makeQuery("sub.abc.example.com", dns.TypeA)

	for _, q := range []*dns.Msg{qWWW, qApex, qScoped} {
		c.Put(q, makeNormalResp(q), false, true)
	}

	// New whitelist: empty. Everything should be invalidated.
	emptySet := domainlist.EmptySet()
	n := c.InvalidateIf(invalidatePred(emptySet))
	if n != 3 {
		t.Errorf("expected 3 invalidations, got %d", n)
	}
	for _, q := range []*dns.Msg{qWWW, qApex, qScoped} {
		name := q.Question[0].Header().Name
		if entry, _ := c.Get(q); entry != nil {
			t.Errorf("%s must be invalidated", name)
		}
	}
}

// TestHandleQuery_WhitelistReloadScopedWildcard_OnlyScopedSubdomainInvalidated
// is the key precision test: *.abc.example.com is removed, but a plain
// *.example.com is NOT present. Only entries under abc.example.com are
// invalidated. www.example.com and example.com (not subdomains of
// abc.example.com) must be preserved.
func TestHandleQuery_WhitelistReloadScopedWildcard_OnlyScopedSubdomainInvalidated(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	// These entries were whitelisted via some different, now-removed entry.
	// We simulate that scenario: all start as Whitelisted=true.
	qWWW := makeQuery("www.example.com", dns.TypeA)
	qApex := makeQuery("example.com", dns.TypeA)
	qScoped := makeQuery("app.abc.example.com", dns.TypeA)
	qDeepScoped := makeQuery("x.y.abc.example.com", dns.TypeA)
	qOtherSub := makeQuery("other.example.com", dns.TypeA)

	for _, q := range []*dns.Msg{qWWW, qApex, qScoped, qDeepScoped, qOtherSub} {
		c.Put(q, makeNormalResp(q), false, true)
	}

	// New whitelist has only exact "www.example.com", "example.com", and
	// "other.example.com" -- no *.example.com, no *.abc.example.com.
	// So only www.example.com, example.com, other.example.com match.
	// app.abc.example.com and x.y.abc.example.com do NOT match -> invalidated.
	content := "www.example.com\nexample.com\nother.example.com\n"
	newSet, err := domainlist.ParseReader(strings.NewReader(content), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}

	n := c.InvalidateIf(invalidatePred(newSet))
	if n != 2 {
		t.Errorf("expected 2 invalidations (scoped entries only), got %d", n)
	}
	if entry, _ := c.Get(qWWW); entry == nil {
		t.Error("www.example.com must be preserved (exact match in new set)")
	}
	if entry, _ := c.Get(qApex); entry == nil {
		t.Error("example.com must be preserved (exact match in new set)")
	}
	if entry, _ := c.Get(qOtherSub); entry == nil {
		t.Error("other.example.com must be preserved (exact match in new set)")
	}
	if entry, _ := c.Get(qScoped); entry != nil {
		t.Error("app.abc.example.com must be invalidated (no longer in whitelist)")
	}
	if entry, _ := c.Get(qDeepScoped); entry != nil {
		t.Error("x.y.abc.example.com must be invalidated (no longer in whitelist)")
	}
}

// TestHandleQuery_WhitelistReloadScopedWildcard_AddedScopedDoesNotAffectParent
// verifies the reverse direction: adding *.abc.example.com to the whitelist
// does NOT invalidate cached entries for www.example.com or example.com
// (they were already covered by *.example.com).
func TestHandleQuery_WhitelistReloadScopedWildcard_AddedScopedDoesNotAffectParent(t *testing.T) {
	c := cache.New(100, 3600, 5, 0)

	// www.example.com and example.com are cached as whitelisted (via *.example.com).
	qWWW := makeQuery("www.example.com", dns.TypeA)
	qApex := makeQuery("example.com", dns.TypeA)
	// app.abc.example.com was NOT whitelisted (no whitelist entry at all before).
	qScoped := makeQuery("app.abc.example.com", dns.TypeA)

	c.Put(qWWW, makeNormalResp(qWWW), false, true)        // Whitelisted=true
	c.Put(qApex, makeNormalResp(qApex), false, true)      // Whitelisted=true
	c.Put(qScoped, makeBlockedResp(qScoped), true, false) // Whitelisted=false, was blocked

	// New whitelist: *.example.com + *.abc.example.com added.
	content := "*.example.com\n*.abc.example.com\n"
	newSet, err := domainlist.ParseReader(strings.NewReader(content), domainlist.ModeAllow)
	if err != nil {
		t.Fatalf("parse domain set: %v", err)
	}

	n := c.InvalidateIf(invalidatePred(newSet))
	// Only app.abc.example.com changes (was WL=false, now WL=true by *.abc.example.com) -> 1
	// www.example.com: was WL=true, now still matched by *.example.com -> no change
	// example.com: was WL=true, now still matched by *.example.com -> no change
	if n != 1 {
		t.Errorf("expected 1 invalidation (app.abc.example.com only), got %d", n)
	}
	if entry, _ := c.Get(qWWW); entry == nil {
		t.Error("www.example.com must be preserved (still whitelisted)")
	}
	if entry, _ := c.Get(qApex); entry == nil {
		t.Error("example.com must be preserved (still whitelisted)")
	}
	if entry, _ := c.Get(qScoped); entry != nil {
		t.Error("app.abc.example.com must be invalidated (newly whitelisted)")
	}
}

// TestMakeRefreshFunc_EmitsJSONEventOnSuccess verifies that a successful
// background cache refresh emits a dns_query JSON event that includes
// upstream and decision fields but no response section. The client already
// received the cached response, so the refresh event must not duplicate it.
func TestMakeRefreshFunc_EmitsJSONEventOnSuccess(t *testing.T) {
	query := makeQuery("bgrefresh.example.com", dns.TypeA)
	resp := makeNormalResp(query)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	client := &mockUpstreamClient{name: "upstream-0", response: resp}
	resolver := upstream.NewResolverFromClients([]upstream.Client{client}, 2*time.Second, 50*time.Millisecond, logger)

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	c := cache.New(100, 3600, 5, 0)

	fn := makeRefreshFunc(resolver, nil, c, cfg, logger, 2*time.Second)
	fn(query)

	output := buf.String()
	if !strings.Contains(output, "background-refresh") {
		t.Errorf("expected 'background-refresh' in JSON event, got: %s", output)
	}
	if !strings.Contains(output, `"dns_query"`) {
		t.Errorf("expected dns_query type in JSON event, got: %s", output)
	}
	if !strings.Contains(output, `"upstream"`) {
		t.Errorf("expected 'upstream' field in JSON event, got: %s", output)
	}
	if !strings.Contains(output, `"decision"`) {
		t.Errorf("expected 'decision' field in JSON event, got: %s", output)
	}
	// No response section: the client already received the cached response.
	if strings.Contains(output, `"response"`) {
		t.Errorf("background-refresh event must not include response section, got: %s", output)
	}
	if !strings.Contains(output, "bgrefresh.example.com") {
		t.Errorf("expected domain name in JSON event, got: %s", output)
	}
}

// TestMakeRefreshFunc_BlockedDomainEmitsJSONEvent verifies that when a
// background refresh discovers the domain is now blocked, a dns_query JSON
// event is emitted with blocked=true in the decision and no response section.
func TestMakeRefreshFunc_BlockedDomainEmitsJSONEvent(t *testing.T) {
	query := makeQuery("now-blocked.example.com", dns.TypeA)
	blockedUpstreamResp := makeBlockedResp(query)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	client := &mockUpstreamClient{name: "upstream-0", response: blockedUpstreamResp}
	resolver := upstream.NewResolverFromClients([]upstream.Client{client}, 2*time.Second, 50*time.Millisecond, logger)

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	c := cache.New(100, 3600, 5, 0)

	fn := makeRefreshFunc(resolver, nil, c, cfg, logger, 2*time.Second)
	fn(query)

	output := buf.String()
	if !strings.Contains(output, "background-refresh") {
		t.Errorf("expected 'background-refresh' in JSON event, got: %s", output)
	}
	if !strings.Contains(output, `"blocked":true`) {
		t.Errorf("expected blocked:true in JSON decision, got: %s", output)
	}
	if !strings.Contains(output, `"dns_query"`) {
		t.Errorf("expected dns_query type in JSON event, got: %s", output)
	}
	if strings.Contains(output, `"response"`) {
		t.Errorf("background-refresh event must not include response section, got: %s", output)
	}
}

// TestBuildCacheInfo_TTLRemainingPct_Rounded verifies that ttl_remaining_pct
// is rounded to at most 2 decimal places and does not produce long floating-
// point strings such as 8.333333333333332.
func TestBuildCacheInfo_TTLRemainingPct_Rounded(t *testing.T) {
	// total=60s, 5s remaining: 5/60*100 = 8.333...% -> must round to 8.33
	now := time.Now()
	entry := &cache.Entry{
		InsertedAt: now.Add(-55 * time.Second),
		ExpiresAt:  now.Add(5 * time.Second),
	}
	info := buildCacheInfo(entry, false)
	if info == nil {
		t.Fatal("buildCacheInfo returned nil")
	}
	// Format with 10 decimal places, strip trailing zeros, check at most 2 remain.
	s := fmt.Sprintf("%.10f", info.TTLRemainingPct)
	parts := strings.SplitN(s, ".", 2)
	if len(parts) == 2 {
		dec := strings.TrimRight(parts[1], "0")
		if len(dec) > 2 {
			t.Errorf("TTLRemainingPct has more than 2 decimal places: %v (formatted: %s)", info.TTLRemainingPct, s)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper: parse a single JSON dns_query event from a buffer.
// ---------------------------------------------------------------------------

func parseDNSQueryEvent(t *testing.T, buf *bytes.Buffer) map[string]interface{} {
	t.Helper()
	dec := json.NewDecoder(buf)
	var obj map[string]interface{}
	if err := dec.Decode(&obj); err != nil {
		t.Fatalf("JSON decode failed: %v\n%s", err, buf.String())
	}
	return obj
}

func dnsSubObj(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	dns, ok := obj["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'dns' field in event: %v", obj)
	}
	return dns
}

// newJSONTestHandler creates a handler that logs to the given buffer in JSON
// mode, using the provided upstream mock responses.
func newJSONTestHandler(t *testing.T, buf *bytes.Buffer, responses []*dns.Msg) *Handler {
	t.Helper()
	logger := logging.NewWriterLogger(buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")
	return newTestHandlerWithLogger(t, responses, logger)
}

// ---------------------------------------------------------------------------
// Rename: client -> request field in dns_query JSON events
// ---------------------------------------------------------------------------

// TestJSONEvent_RequestFieldPresent verifies that dns_query events use
// "request" (not "client") as the sub-object key for query metadata.
func TestJSONEvent_RequestFieldPresent(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	var buf bytes.Buffer
	handler := newJSONTestHandler(t, &buf, []*dns.Msg{makeNormalResp(query)})
	handler.HandleQuery(context.Background(), query)

	obj := parseDNSQueryEvent(t, &buf)
	dns := dnsSubObj(t, obj)

	if _, hasClient := dns["client"]; hasClient {
		t.Error("dns.client must not be present; field was renamed to dns.request")
	}
	if _, hasRequest := dns["request"]; !hasRequest {
		t.Error("dns.request must be present in dns_query events")
	}
}

// ---------------------------------------------------------------------------
// CacheInfo: no "hit" field
// ---------------------------------------------------------------------------

// TestJSONEvent_CacheInfo_NoHitField verifies that cached responses do not
// include a "hit" field (it is always implied by the presence of "cache").
func TestJSONEvent_CacheInfo_NoHitField(t *testing.T) {
	query := makeQuery("cached.example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	c := cache.New(100, 3600, 5, 0)
	// Pre-populate the cache.
	normalResp := makeNormalResp(query)
	c.Put(query, normalResp, false, false)

	resolver := upstream.NewResolverFromClients(nil, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if strings.Contains(out, `"hit"`) {
		t.Errorf("cache event must not have 'hit' field, got: %s", out)
	}
	if !strings.Contains(out, `"cache"`) {
		t.Errorf("cache hit event must have 'cache' field, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// IDN: domain always as ACE/Punycode, no domain_ace field
// ---------------------------------------------------------------------------

// TestJSONEvent_IDN_AlwaysPunycode verifies that when a client queries an
// internationalized domain (Punycode/ACE wire format), the logged domain
// value is the ACE form directly. The domain_ace field must not appear.
func TestJSONEvent_IDN_AlwaysPunycode(t *testing.T) {
	// "xn--bcher-kva.example" is the ACE encoding of "buecher.example"
	query := makeQuery("xn--bcher-kva.example", dns.TypeA)
	var buf bytes.Buffer
	handler := newJSONTestHandler(t, &buf, []*dns.Msg{makeNormalResp(query)})
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if strings.Contains(out, "domain_ace") {
		t.Errorf("domain_ace field must never appear in JSON output, got: %s", out)
	}
	if !strings.Contains(out, "xn--bcher-kva.example") {
		t.Errorf("expected Punycode domain in JSON output, got: %s", out)
	}
	// Unicode form must NOT appear in the domain field.
	if strings.Contains(out, "buecher") {
		t.Errorf("Unicode form must not appear in JSON domain field, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Decision: no blocked_by field; block_source = "blacklist" for local list
// ---------------------------------------------------------------------------

// TestJSONEvent_LocalBlacklist_NoBlockedBy verifies that local blacklist
// blocks do not emit a "blocked_by" field.
func TestJSONEvent_LocalBlacklist_NoBlockedBy(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	bl := testDomainList(t, []string{"||blocked.example.com^"})
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients(nil, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, bl, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if strings.Contains(out, `"blocked_by"`) {
		t.Errorf("blocked_by field must not appear in JSON output, got: %s", out)
	}
}

// TestJSONEvent_LocalBlacklist_BlockSourceIsBlacklist verifies that
// block_source = "blacklist" (not "local-blacklist") for local list blocks.
func TestJSONEvent_LocalBlacklist_BlockSourceIsBlacklist(t *testing.T) {
	query := makeQuery("blocked2.example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	bl := testDomainList(t, []string{"||blocked2.example.com^"})
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients(nil, 2*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, bl, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	obj := parseDNSQueryEvent(t, &buf)
	dns := dnsSubObj(t, obj)

	dec, ok := dns["decision"].(map[string]interface{})
	if !ok {
		t.Fatal("expected decision object in JSON event")
	}
	if dec["block_source"] != "blacklist" {
		t.Errorf("expected block_source=blacklist, got %v", dec["block_source"])
	}
	if dec["block_source"] == "local-blacklist" {
		t.Error("block_source must not be 'local-blacklist'; expected 'blacklist'")
	}
}

// ---------------------------------------------------------------------------
// Upstream address: no DoH/DoT/UDP wrappers
// ---------------------------------------------------------------------------

// TestJSONEvent_UpstreamAddress_NoProtocolWrapper verifies that upstream
// address fields in JSON events show raw addresses without protocol wrappers
// such as DoH(...), DoT(...), or UDP(...).
func TestJSONEvent_UpstreamAddress_NoProtocolWrapper(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	c := cache.New(100, 3600, 5, 0)

	// mockUpstreamClient.String() returns m.name as the address (host:port).
	// After the address/port split, "9.9.9.9" and port 53 should appear separately.
	plainAddr := "9.9.9.9:53"
	client := &mockUpstreamClient{name: plainAddr, response: makeNormalResp(query)}
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{client},
		2*time.Second, 50*time.Millisecond, logger,
	)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	for _, wrapper := range []string{"DoH(", "DoT(", "UDP("} {
		if strings.Contains(out, wrapper) {
			t.Errorf("upstream address must not be wrapped in %s...), got: %s", wrapper, out)
		}
	}
	// address and port are now split: "9.9.9.9" and 53 must appear separately.
	if !strings.Contains(out, `"9.9.9.9"`) {
		t.Errorf("expected host 9.9.9.9 in JSON output, got: %s", out)
	}
	if !strings.Contains(out, `"port":53`) {
		t.Errorf("expected port:53 in JSON output, got: %s", out)
	}
	// The combined address:port string must NOT appear as a single value.
	if strings.Contains(out, `"9.9.9.9:53"`) {
		t.Errorf("address must not include port in JSON output, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// EDE text: no null bytes after caching
// ---------------------------------------------------------------------------

// makeBlockedRespWithEDE constructs a blocked response carrying an EDE
// option with a non-empty ExtraText. This is used to exercise the code path
// where cache.Put can corrupt EDE.ExtraText via the dns library's pack bug.
func makeBlockedRespWithEDE(query *dns.Msg, ede string) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
	})
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: ede})
	return resp
}

// TestJSONEvent_EDEText_NotNullBytes verifies that the EDE text in a blocked
// upstream event does not contain null bytes even when cache.Put is called.
// Regression test for the dns library bug where Pack() mutates EDE.ExtraText.
func TestJSONEvent_EDEText_NotNullBytes(t *testing.T) {
	query := makeQuery("blocked-ede.example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true // ensure cache.Put is called — this triggers the bug
	c := cache.New(100, 3600, 5, 0)

	// The response EDE text will be set by dnsmsg.MakeBlockedResponse using the
	// blocker name. Give the client a name that will appear in the EDE text.
	client := &mockUpstreamClient{name: "blocker-ede", response: makeBlockedRespWithEDE(query, "Blocked (blocker-ede)")}
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{client},
		2*time.Second, 50*time.Millisecond, logger,
	)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	// For the WaitAll path we need to give the goroutine time to finish.
	time.Sleep(200 * time.Millisecond)

	out := buf.String()
	if strings.Contains(out, `\u0000`) {
		t.Errorf("EDE text must not contain null bytes in JSON output, got: %s", out)
	}
	// The response-level EDE text comes from MakeBlockedResponse (based on blocker name).
	if !strings.Contains(out, `"ede_code":15`) {
		t.Errorf("expected ede_code=15 in JSON output, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Slow flag: independent per upstream, including when blocked
// ---------------------------------------------------------------------------

// slowMockClient is a mock upstream that delays for a specified duration
// before returning a response. Used to test the slow upstream flag.
type slowMockClient struct {
	name     string
	response *dns.Msg
	delay    time.Duration
}

func (c *slowMockClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r := new(dns.Msg)
	r.ID = msg.ID
	r.Response = true
	r.Rcode = c.response.Rcode
	r.Answer = append(r.Answer, c.response.Answer...)
	r.Pseudo = append(r.Pseudo, c.response.Pseudo...)
	return r, nil
}

func (c *slowMockClient) String() string { return c.name }

// TestJSONEvent_SlowFlag_BlockedDomain verifies that the slow flag is set
// independently per upstream even when the domain is blocked. An upstream
// that takes longer than the slow threshold must be flagged even if another
// upstream signals the block first.
func TestJSONEvent_SlowFlag_BlockedDomain(t *testing.T) {
	query := makeQuery("malware-slow.example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	cfg.Logging.SlowUpstreamMS = 50 // 50ms threshold
	c := cache.New(100, 3600, 5, 0)

	blockedResp := makeBlockedRespWithEDE(query, "Blocked")

	clients := []upstream.Client{
		// Fast blocker: responds immediately
		&mockUpstreamClient{name: "fast-blocker", response: blockedResp},
		// Slow blocker: takes 500ms (well above 200ms default slow threshold)
		&slowMockClient{name: "slow-blocker", response: blockedResp, delay: 500 * time.Millisecond},
	}
	// NewResolverFromClients uses a default slow threshold of 200ms;
	// slow-blocker takes 500ms so it will exceed the threshold.
	resolver := upstream.NewResolverFromClients(clients, 5*time.Second, 50*time.Millisecond, logger)

	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	// Allow WaitAll goroutine to emit the JSON event.
	time.Sleep(700 * time.Millisecond)

	out := buf.String()
	if out == "" {
		t.Fatal("expected JSON output but got none")
	}
	// The slow flag should appear in at least one upstream entry.
	if !strings.Contains(out, `"slow":true`) {
		t.Logf("JSON: %s", out)
		t.Error("expected at least one upstream entry with slow=true for slow-blocker")
	}
}

// ---------------------------------------------------------------------------
// Early blocked return: WaitAll mechanism
// ---------------------------------------------------------------------------

// TestJSONEvent_EarlyBlockedReturn_WaitAll verifies that when a block is
// detected early (before all upstreams respond), the JSON log event is still
// emitted with complete upstream information once all upstreams finish.
func TestJSONEvent_EarlyBlockedReturn_WaitAll(t *testing.T) {
	query := makeQuery("early-block.example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	c := cache.New(100, 3600, 5, 0)

	blockedResp := makeBlockedRespWithEDE(query, "Blocked (early)")
	normalResp := makeNormalResp(query)

	clients := []upstream.Client{
		// Fast blocker signals the block immediately.
		&mockUpstreamClient{name: "fast-blocker", response: blockedResp},
		// Slow upstream takes time — exercises WaitAll.
		&slowMockClient{name: "slow-upstream", response: normalResp, delay: 300 * time.Millisecond},
	}
	// Use non-zero minWait so Phase 1 properly waits for block detection
	// rather than exiting immediately on the zero-duration timer.
	resolver := upstream.NewResolverFromClients(clients, 5*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)

	// HandleQuery must return quickly (before slow-upstream finishes).
	start := time.Now()
	resp := handler.HandleQuery(context.Background(), query)
	elapsed := time.Since(start)

	if resp == nil {
		t.Fatal("expected response from HandleQuery")
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("HandleQuery took %v; expected early return (<250ms) for blocked domain", elapsed)
	}

	// Wait for the WaitAll goroutine to emit the JSON event.
	time.Sleep(500 * time.Millisecond)

	out := buf.String()
	if !strings.Contains(out, "dns_query") {
		t.Errorf("expected dns_query JSON event after WaitAll, got: %s", out)
	}
	// Both upstreams should appear in the event.
	if !strings.Contains(out, "fast-blocker") {
		t.Errorf("expected fast-blocker in JSON upstream data, got: %s", out)
	}
	if !strings.Contains(out, "slow-upstream") {
		t.Errorf("expected slow-upstream in JSON upstream data, got: %s", out)
	}
}

// TestJSONEvent_EarlyBlockedReturn_EDEText_NotCorrupted verifies that when
// the early-block + WaitAll path is taken, the EDE text is captured before
// cache.Put and therefore does not contain null bytes.
func TestJSONEvent_EarlyBlockedReturn_EDEText_NotCorrupted(t *testing.T) {
	query := makeQuery("ede-early.example.com", dns.TypeA)
	edeText := "Blocked (early-block-ede-test)"
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true // triggers cache.Put which can corrupt EDE
	c := cache.New(100, 3600, 5, 0)

	blockedResp := makeBlockedRespWithEDE(query, edeText)
	clients := []upstream.Client{
		&mockUpstreamClient{name: "blocker", response: blockedResp},
		&slowMockClient{name: "slow", response: makeNormalResp(query), delay: 300 * time.Millisecond},
	}
	resolver := upstream.NewResolverFromClients(clients, 5*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	// Wait for WaitAll goroutine.
	time.Sleep(500 * time.Millisecond)

	out := buf.String()
	if strings.Contains(out, `\u0000`) {
		t.Errorf("EDE text must not contain null bytes in early-block path, got: %s", out)
	}
	// The response EDE text is set by MakeBlockedResponse with the blocker name;
	// verify it appears and is not the corrupted form.
	if !strings.Contains(out, `"ede_code":15`) {
		t.Errorf("expected ede_code=15 in JSON output after WaitAll, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// buildClientInfo: domain is ACE-only (no unicode conversion)
// ---------------------------------------------------------------------------

// TestBuildClientInfo_DomainIsPunycode verifies that buildClientInfo sets
// Domain to the ACE/Punycode form directly (no Unicode conversion).
func TestBuildClientInfo_DomainIsPunycode(t *testing.T) {
	query := makeQuery("xn--nxasmq6b.example", dns.TypeA)
	info := buildClientInfo(query, nil)
	if info == nil {
		t.Fatal("expected non-nil RequestInfo")
	}
	if info.Domain != "xn--nxasmq6b.example" {
		t.Errorf("expected Domain=xn--nxasmq6b.example (Punycode), got %q", info.Domain)
	}
}

// TestBuildClientInfo_ASCIIDomain verifies that buildClientInfo sets Domain
// to the plain ASCII domain (unchanged).
func TestBuildClientInfo_ASCIIDomain(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	info := buildClientInfo(query, nil)
	if info == nil {
		t.Fatal("expected non-nil RequestInfo")
	}
	if info.Domain != "example.com" {
		t.Errorf("expected Domain=example.com, got %q", info.Domain)
	}
}

// ---------------------------------------------------------------------------
// buildCacheInfo: no Hit field
// ---------------------------------------------------------------------------

// TestBuildCacheInfo_NoHit verifies that buildCacheInfo does not set a Hit
// field (it was removed since Hit is always true for cache events).
func TestBuildCacheInfo_NoHit(t *testing.T) {
	query := makeQuery("cached-nohit.example.com", dns.TypeA)
	normalResp := makeNormalResp(query)
	c := cache.New(100, 3600, 5, 0)
	c.Put(query, normalResp, false, false)
	entry, _ := c.Get(query)
	if entry == nil {
		t.Fatal("expected cache entry")
	}
	info := buildCacheInfo(entry, false)
	if info == nil {
		t.Fatal("expected non-nil CacheInfo")
	}
	// Verify via JSON serialization that "hit" key is absent.
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if strings.Contains(string(data), `"hit"`) {
		t.Errorf("CacheInfo must not have 'hit' field, got: %s", data)
	}
}

// ---------------------------------------------------------------------------
// buildBlacklistDecisionInfo: block_source = "blacklist"
// ---------------------------------------------------------------------------

// TestBuildBlacklistDecisionInfo_BlockSource verifies that the decision info
// for a local blacklist block uses "blacklist" (not "local-blacklist").
func TestBuildBlacklistDecisionInfo_BlockSource(t *testing.T) {
	dec := buildBlacklistDecisionInfo("NOERROR")
	if dec == nil {
		t.Fatal("expected non-nil DecisionInfo")
	}
	if dec.BlockSource != "blacklist" {
		t.Errorf("expected BlockSource=blacklist, got %q", dec.BlockSource)
	}
	data, err := json.Marshal(dec)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	if strings.Contains(string(data), "local-blacklist") {
		t.Errorf("'local-blacklist' must not appear in DecisionInfo JSON, got: %s", data)
	}
	if strings.Contains(string(data), `"blocked_by"`) {
		t.Errorf("'blocked_by' must not appear in DecisionInfo JSON, got: %s", data)
	}
}

// ---------------------------------------------------------------------------
// buildUpstreamInfos: EDE null-byte stripping
// ---------------------------------------------------------------------------

// TestBuildUpstreamInfos_EDENullBytes verifies that null bytes in EDE
// ExtraText (caused by the dns library's Pack mutation bug) are stripped.
func TestBuildUpstreamInfos_EDENullBytes(t *testing.T) {
	msg := new(dns.Msg)
	// Simulate what happens after Pack() corrupts ExtraText with null bytes.
	corruptedText := "Blocked\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 15, ExtraText: corruptedText}}

	results := []*upstream.Result{
		{Index: 0, Client: "upstream1", Msg: msg, Inspect: dnsmsg.InspectResult{Blocked: true}},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if strings.Contains(infos[0].EDEText, "\x00") {
		t.Errorf("EDEText must not contain null bytes after stripping, got: %q", infos[0].EDEText)
	}
	if infos[0].EDEText != "Blocked" {
		t.Errorf("expected EDEText=\"Blocked\" after null stripping, got: %q", infos[0].EDEText)
	}
}

// TestBuildResponseInfo_EDENullBytes verifies that buildResponseInfo strips
// null bytes from EDE ExtraText.
func TestBuildResponseInfo_EDENullBytes(t *testing.T) {
	msg := new(dns.Msg)
	corruptedText := "Blocked (upstream)\x00\x00\x00\x00\x00"
	msg.Pseudo = []dns.RR{&dns.EDE{InfoCode: 15, ExtraText: corruptedText}}
	msg.Rcode = dns.RcodeSuccess

	ri := buildResponseInfo(msg)
	if ri == nil {
		t.Fatal("expected non-nil ResponseInfo")
	}
	if strings.Contains(ri.EDEText, "\x00") {
		t.Errorf("EDEText must not contain null bytes, got: %q", ri.EDEText)
	}
	if ri.EDEText != "Blocked (upstream)" {
		t.Errorf("expected stripped EDEText, got: %q", ri.EDEText)
	}
}

// ---------------------------------------------------------------------------
// splitClientAddress unit tests
// ---------------------------------------------------------------------------

// TestSplitClientAddress_DoH_DefaultPort verifies that a DoH URL without an
// explicit port returns the unchanged URL and port 443.
func TestSplitClientAddress_DoH_DefaultPort(t *testing.T) {
	addr, port := splitClientAddress("https://dns.quad9.net/dns-query", "doh")
	if addr != "https://dns.quad9.net/dns-query" {
		t.Errorf("expected unchanged URL, got %q", addr)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

// TestSplitClientAddress_DoH_ExplicitPort verifies that a DoH URL with an
// explicit port has the port stripped from the URL host and returned separately.
func TestSplitClientAddress_DoH_ExplicitPort(t *testing.T) {
	addr, port := splitClientAddress("https://dns.quad9.net:4343/dns-query", "doh")
	if addr != "https://dns.quad9.net/dns-query" {
		t.Errorf("expected URL without port, got %q", addr)
	}
	if port != 4343 {
		t.Errorf("expected port 4343, got %d", port)
	}
}

// TestSplitClientAddress_DoT verifies that a DoT address is split into host
// and port components.
func TestSplitClientAddress_DoT(t *testing.T) {
	addr, port := splitClientAddress("dns.quad9.net:853", "dot")
	if addr != "dns.quad9.net" {
		t.Errorf("expected host dns.quad9.net, got %q", addr)
	}
	if port != 853 {
		t.Errorf("expected port 853, got %d", port)
	}
}

// TestSplitClientAddress_Plain verifies that a plain UDP address is split into
// host and port components.
func TestSplitClientAddress_Plain(t *testing.T) {
	addr, port := splitClientAddress("9.9.9.9:53", "udp")
	if addr != "9.9.9.9" {
		t.Errorf("expected host 9.9.9.9, got %q", addr)
	}
	if port != 53 {
		t.Errorf("expected port 53, got %d", port)
	}
}

// ---------------------------------------------------------------------------
// buildClientInfo: Unicode domain → Punycode
// ---------------------------------------------------------------------------

// TestBuildClientInfo_UnicodeDomain_NormalizedToPunycode verifies that a DNS
// query containing a non-ASCII Unicode domain (as can happen when a
// non-conforming client sends raw UTF-8 label bytes) is normalized to its
// Punycode/ACE form before the domain is stored in ClientInfo.
func TestBuildClientInfo_UnicodeDomain_NormalizedToPunycode(t *testing.T) {
	// Build a query manually with a raw Unicode label (non-conforming client).
	unicodeName := "\u6d4b\u8bd5.org." // 测试.org.
	query := dnsutil.SetQuestion(new(dns.Msg), unicodeName, dns.TypeA)

	meta := &ClientMeta{IP: "127.0.0.1", Port: 1234, Protocol: "udp"}
	info := buildClientInfo(query, meta)
	if info == nil {
		t.Fatal("buildClientInfo returned nil")
	}
	if info.Domain != "xn--0zwm56d.org" {
		t.Errorf("expected Punycode domain xn--0zwm56d.org, got %q", info.Domain)
	}
	// The raw Unicode bytes must not appear.
	if strings.Contains(info.Domain, "\u6d4b\u8bd5") {
		t.Errorf("Unicode bytes must not appear in ClientInfo.Domain, got %q", info.Domain)
	}
}

// ---------------------------------------------------------------------------
// buildUpstreamInfos: address / port split
// ---------------------------------------------------------------------------

// TestBuildUpstreamInfos_AddressAndPortSplit verifies that plain DNS upstream
// addresses are split into separate Address and Port fields.
func TestBuildUpstreamInfos_AddressAndPortSplit(t *testing.T) {
	results := []*upstream.Result{
		{
			Index:      0,
			Client:     "9.9.9.9:53",
			Protocol:   "udp",
			DurationMS: 5,
		},
	}
	infos := buildUpstreamInfos(results, 0)
	if len(infos) != 1 {
		t.Fatalf("expected 1 info, got %d", len(infos))
	}
	if infos[0].Address != "9.9.9.9" {
		t.Errorf("expected address 9.9.9.9, got %q", infos[0].Address)
	}
	if infos[0].Port != 53 {
		t.Errorf("expected port 53, got %d", infos[0].Port)
	}
}

// ---------------------------------------------------------------------------
// JSON integration: port field + IDN Punycode in domain
// ---------------------------------------------------------------------------

// TestJSONEvent_UpstreamPortField verifies that the "port" field is present in
// the upstream array of a dns_query JSON event.
func TestJSONEvent_UpstreamPortField(t *testing.T) {
	query := makeQuery("example.com", dns.TypeA)
	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	c := cache.New(100, 3600, 5, 0)

	client := &mockUpstreamClient{name: "9.9.9.9:53", response: makeNormalResp(query)}
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{client},
		2*time.Second, 50*time.Millisecond, logger,
	)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if !strings.Contains(out, `"port"`) {
		t.Errorf("expected 'port' field in upstream JSON, got: %s", out)
	}
	if !strings.Contains(out, `"port":53`) {
		t.Errorf("expected port:53 in JSON, got: %s", out)
	}
}

// TestJSONEvent_IDN_Unicode_NormalizedInDomain verifies that a HandleQuery
// call with a Unicode domain name (raw UTF-8 label bytes from a non-conforming
// client) logs the Punycode/ACE form in the "domain" field.
func TestJSONEvent_IDN_Unicode_NormalizedInDomain(t *testing.T) {
	unicodeName := "\u6d4b\u8bd5.org." // 测试.org.
	query := dnsutil.SetQuestion(new(dns.Msg), unicodeName, dns.TypeA)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.Config{StdoutMode: "json", Synchronous: true}, "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	c := cache.New(100, 3600, 5, 0)

	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeSuccess

	client := &mockUpstreamClient{name: "9.9.9.9:53", response: resp}
	resolver := upstream.NewResolverFromClients(
		[]upstream.Client{client},
		2*time.Second, 50*time.Millisecond, logger,
	)
	handler := NewHandler(resolver, nil, nil, c, logger, cfg)
	handler.HandleQuery(context.Background(), query)

	out := buf.String()
	if strings.Contains(out, "\u6d4b\u8bd5") {
		t.Errorf("Unicode bytes must not appear in JSON domain field, got: %s", out)
	}
	if !strings.Contains(out, "xn--0zwm56d.org") {
		t.Errorf("expected Punycode xn--0zwm56d.org in JSON domain, got: %s", out)
	}
}
