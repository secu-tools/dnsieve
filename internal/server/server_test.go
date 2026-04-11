// SPDX-License-Identifier: MIT
package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/config"
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
	return NewHandler(resolver, nil, c, logger, cfg)
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
	handler := NewHandler(resolver, nil, c, logger, cfg)

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
	handler := NewHandler(resolver, nil, c, logger, cfg)

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

func TestHandleQuery_BlockedLogsInfo(t *testing.T) {
	query := makeQuery("blocked.example.com", dns.TypeA)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")

	handler := newTestHandlerWithLogger(t, []*dns.Msg{makeBlockedResp(query)}, logger)
	handler.HandleQuery(context.Background(), query)

	output := buf.String()
	if !strings.Contains(output, "blocked.example.com.") {
		t.Errorf("expected domain name in blocked log, got: %s", output)
	}
	if !strings.Contains(output, "is blocked by") {
		t.Errorf("expected 'is blocked by' in log, got: %s", output)
	}
}

func TestHandleQuery_BlockedFromCacheLogsInfo(t *testing.T) {
	query := makeQuery("cached-block.example.com", dns.TypeA)

	var buf bytes.Buffer
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")

	handler := newTestHandlerWithLogger(t, []*dns.Msg{makeBlockedResp(query)}, logger)

	// First query: populates cache with blocked entry
	handler.HandleQuery(context.Background(), query)

	// Clear the buffer so we only see the second query's log
	buf.Reset()

	// Second query: should come from cache
	q2 := makeQuery("cached-block.example.com", dns.TypeA)
	handler.HandleQuery(context.Background(), q2)

	output := buf.String()
	if !strings.Contains(output, "is blocked (from cache") {
		t.Errorf("expected 'is blocked (from cache' in log, got: %s", output)
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
		Domains: []string{"safe.example.com"},
	}

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")
	c := cache.New(100, 3600, 5, 0)

	// Blocking upstreams -- would return 0.0.0.0 if used
	blockClient := &mockUpstreamClient{name: "blocker", response: makeBlockedResp(query)}
	resolver := upstream.NewResolverFromClients([]upstream.Client{blockClient}, 2*time.Second, 50*time.Millisecond, logger)

	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist)

	handler := NewHandler(resolver, wlRes, c, logger, cfg)
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
		Domains: []string{"safe.example.com"}, // NOT normal.example.com
	}

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
	wlRes := upstream.NewWhitelistResolverFromClient(wlClient, &wlCfg)

	handler := NewHandler(resolver, wlRes, c, logger, cfg)
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
	handler := NewHandler(resolver, nil, c, logger, cfg)

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
	handler := NewHandler(resolver, nil, c, logger, cfg)

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
	handlerA := NewHandler(resolverA, nil, c, logger, cfg)

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
	handlerAAAA := NewHandler(resolverAAAA, nil, c, logger, cfg)

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
	// NewWriterLogger uses LevelDebug, so debug messages are captured.
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")

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
	// NewWriterLogger uses LevelDebug, so debug messages are captured.
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")

	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = false
	errClient := &mockUpstreamClient{name: "err", err: fmt.Errorf("connection refused")}
	c := cache.New(100, 3600, 5, 0)
	resolver := upstream.NewResolverFromClients([]upstream.Client{errClient}, 1*time.Second, 50*time.Millisecond, logger)
	handler := NewHandler(resolver, nil, c, logger, cfg)

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
	// NewWriterLogger uses LevelDebug, so debug messages are captured.
	logger := logging.NewWriterLogger(&buf, logging.DefaultConfig(), "test")

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
			handler := NewHandler(resolver, nil, c, logger, cfg)
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
	cfg.Whitelist.Domains = []string{"whitelisted.example.com"}

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
	wlResolver := upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist)

	handler := NewHandler(resolver, wlResolver, c, logger, cfg)

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
