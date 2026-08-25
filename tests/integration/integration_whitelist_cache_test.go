// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
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
	"github.com/secu-tools/dnsieve/internal/domainlist"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/server"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// mockIntegrationClient is a DNS Client that returns a pre-configured response.
type mockIntegrationClient struct {
	mu       sync.Mutex
	name     string
	response *dns.Msg
	err      error
	calls    int
}

func (m *mockIntegrationClient) Query(_ context.Context, msg *dns.Msg) (*dns.Msg, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
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

func (m *mockIntegrationClient) String() string { return m.name }

func (m *mockIntegrationClient) Close() {}
func (m *mockIntegrationClient) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// writeIntegrationListFile writes a domain list to a temp file and returns its path.
func writeIntegrationListFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write list file: %v", err)
	}
	return path
}

// startMockServer starts a plain-DNS server with mock whitelist and upstream
// clients. Returns the port and a cancel function.
func startMockServer(
	t *testing.T,
	wlDomains []string,
	wlClient upstream.Client,
	upClient upstream.Client,
) (int, context.CancelFunc) {
	t.Helper()
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "integration-mock")

	port := findFreePort(t)
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 1000
	cfg.Cache.MinTTL = 1
	cfg.Cache.BlockedTTL = 3600
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false
	cfg.Whitelist = config.WhitelistConfig{Enabled: len(wlDomains) > 0}

	c := cache.New(cfg.Cache.MaxEntries, cfg.Cache.BlockedTTL, cfg.Cache.MinTTL, cfg.Cache.RenewPercent)

	var wlRes *upstream.WhitelistResolver
	if len(wlDomains) > 0 && wlClient != nil {
		listPath := writeIntegrationListFile(t, strings.Join(wlDomains, "\n")+"\n")
		wlList := domainlist.NewDomainList("whitelist", domainlist.ModeAllow, []string{listPath})
		if _, _, _, err := wlList.Load(nil); err != nil {
			t.Fatalf("load whitelist: %v", err)
		}
		wlRes = upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)
	}

	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := server.NewHandler(resolver, wlRes, nil, c, logger, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := server.ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	waitForServer(t, port)
	return port, cancel
}

// makeIntegrationResp returns a real-looking DNS A response.
func makeIntegrationResp(name string, ip string, ttl uint32) *dns.Msg {
	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), dns.TypeA)
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: dnsutil.Fqdn(name), Class: dns.ClassINET, TTL: ttl},
		A:   rdata.A{Addr: netip.MustParseAddr(ip)},
	})
	return resp
}

// queryUDPIntegration sends a plain UDP A query to port on localhost.
func queryUDPIntegration(t *testing.T, port int, name string) *dns.Msg {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c := dns.NewClient()
	c.Transport.ReadTimeout = 5 * time.Second
	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), dns.TypeA)
	q.RecursionDesired = true
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp, _, err := c.Exchange(ctx, q, "udp", addr)
	if err != nil {
		t.Fatalf("UDP query %s: %v", name, err)
	}
	return resp
}

// startMockServerWithPort starts with a given port (for reload tests).
func startMockServerWithCache(
	t *testing.T,
	wlDomains []string,
	wlClient upstream.Client,
	upClient upstream.Client,
) (int, context.CancelFunc, *cache.Cache) {
	t.Helper()
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "integration-mock-cache")

	port := findFreePort(t)
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	cfg.Cache.MaxEntries = 1000
	cfg.Cache.MinTTL = 1
	cfg.Cache.BlockedTTL = 3600
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false
	cfg.Whitelist = config.WhitelistConfig{Enabled: len(wlDomains) > 0}

	c := cache.New(cfg.Cache.MaxEntries, cfg.Cache.BlockedTTL, cfg.Cache.MinTTL, cfg.Cache.RenewPercent)

	var wlRes *upstream.WhitelistResolver
	if len(wlDomains) > 0 && wlClient != nil {
		listPath := writeIntegrationListFile(t, strings.Join(wlDomains, "\n")+"\n")
		wlList := domainlist.NewDomainList("whitelist", domainlist.ModeAllow, []string{listPath})
		if _, _, _, err := wlList.Load(nil); err != nil {
			t.Fatalf("load whitelist: %v", err)
		}
		wlRes = upstream.NewWhitelistResolverFromClient(wlClient, &cfg.Whitelist, wlList)
	}

	resolver := upstream.NewResolverFromClients([]upstream.Client{upClient}, 2*time.Second, 50*time.Millisecond, logger)
	handler := server.NewHandler(resolver, wlRes, nil, c, logger, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := server.ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	waitForServer(t, port)
	return port, cancel, c
}

// ============================================================
// Whitelist cache integration tests
// ============================================================

func TestIntegration_Whitelist_CacheHit(t *testing.T) {
	// First query should call whitelist resolver; second must be served from cache.
	wlClient := &mockIntegrationClient{
		name:     "wl-resolver",
		response: makeIntegrationResp("safe.example.com", "5.5.5.5", 300),
	}
	upBlockedResp := makeIntegrationResp("safe.example.com", "0.0.0.0", 300)
	upClient := &mockIntegrationClient{
		name:     "blocking-upstream",
		response: upBlockedResp,
	}

	port, cancel := startMockServer(t, []string{"safe.example.com"}, wlClient, upClient)
	defer cancel()

	// First query -- whitelist resolver must be called once.
	resp1 := queryUDPIntegration(t, port, "safe.example.com")
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("first query: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}
	if wlClient.Calls() != 1 {
		t.Errorf("first query: expected 1 whitelist call, got %d", wlClient.Calls())
	}

	// Second query -- must come from cache, whitelist resolver NOT called again.
	resp2 := queryUDPIntegration(t, port, "safe.example.com")
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("second query: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	if wlClient.Calls() != 1 {
		t.Errorf("second query: whitelist resolver called %d times, expected 1 (cache should serve)", wlClient.Calls())
	}
	if upClient.Calls() != 0 {
		t.Errorf("upstream should never be queried for a whitelisted domain, got %d calls", upClient.Calls())
	}
	t.Logf("whitelist cache hit: rcode=%s wl_calls=%d up_calls=%d",
		dns.RcodeToString[resp2.Rcode], wlClient.Calls(), upClient.Calls())
}

func TestIntegration_Whitelist_CacheTaggedCorrectly(t *testing.T) {
	// Cache entry for a whitelisted domain must have Whitelisted=true.
	wlClient := &mockIntegrationClient{
		name:     "wl-resolver",
		response: makeIntegrationResp("tagged.example.com", "1.2.3.4", 300),
	}
	upClient := &mockIntegrationClient{
		name:     "upstream",
		response: makeIntegrationResp("tagged.example.com", "9.9.9.9", 300),
	}

	port, cancel, c := startMockServerWithCache(t, []string{"tagged.example.com"}, wlClient, upClient)
	defer cancel()

	queryUDPIntegration(t, port, "tagged.example.com")

	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn("tagged.example.com"), dns.TypeA)
	entry, _ := c.Get(q)
	if entry == nil {
		t.Fatal("expected cache entry after whitelist resolution")
	}
	if !entry.Whitelisted {
		t.Error("cache entry for whitelisted domain must have Whitelisted=true")
	}
	if entry.Blocked {
		t.Error("whitelisted cache entry must not be Blocked")
	}
}

func TestIntegration_Whitelist_NonWhitelistedDomainNotTagged(t *testing.T) {
	// A domain NOT in the whitelist must be cached with Whitelisted=false.
	wlClient := &mockIntegrationClient{
		name:     "wl-resolver",
		response: makeIntegrationResp("other.example.com", "1.1.1.1", 300),
	}
	upClient := &mockIntegrationClient{
		name:     "upstream",
		response: makeIntegrationResp("other.example.com", "9.9.9.9", 300),
	}

	// Whitelist only contains "safe.example.com"; "other.example.com" is not in it.
	port, cancel, c := startMockServerWithCache(t, []string{"safe.example.com"}, wlClient, upClient)
	defer cancel()

	queryUDPIntegration(t, port, "other.example.com")

	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn("other.example.com"), dns.TypeA)
	entry, _ := c.Get(q)
	if entry == nil {
		t.Fatal("expected cache entry for non-whitelisted domain")
	}
	if entry.Whitelisted {
		t.Error("non-whitelisted domain must not be tagged Whitelisted in cache")
	}
}

func TestIntegration_Whitelist_InvalidateOnReload(t *testing.T) {
	// Simulate the cache invalidation that RunContext wires up when the
	// whitelist reloads and a domain is removed.
	//
	// We directly exercise the InvalidateIf -> OnReload plumbing without
	// needing the file-watch hot-reload, since the hot-reload path is
	// already covered by unit tests.
	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn("was-white.example.com"), dns.TypeA)

	c := cache.New(100, 3600, 5, 0)
	// Seed a whitelisted entry.
	resp := makeIntegrationResp("was-white.example.com", "5.5.5.5", 300)
	c.Put(q, resp, false, true) // Whitelisted=true

	if entry, _ := c.Get(q); entry == nil || !entry.Whitelisted {
		t.Fatal("precondition: entry must be cached as whitelisted")
	}

	// Simulate whitelist reload with an empty new set (domain removed).
	emptySet := domainlist.EmptySet()
	go func() {
		c.InvalidateIf(func(name string, entry *cache.Entry) bool {
			return entry.Whitelisted != emptySet.Contains(name)
		})
	}()

	time.Sleep(50 * time.Millisecond)

	if entry, _ := c.Get(q); entry != nil {
		t.Error("removed-whitelist entry must be invalidated from cache")
	}
}

func TestIntegration_Whitelist_InvalidateOnReloadNewDomainAdded(t *testing.T) {
	// Simulate cache invalidation when a domain is added to the whitelist.
	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn("new-white.example.com"), dns.TypeA)

	c := cache.New(100, 3600, 5, 0)
	// Seed a blocked (non-whitelisted) entry.
	blockedResp := makeIntegrationResp("new-white.example.com", "0.0.0.0", 300)
	c.Put(q, blockedResp, true, false) // Blocked=true, Whitelisted=false

	if entry, _ := c.Get(q); entry == nil || entry.Whitelisted {
		t.Fatal("precondition: entry must be cached as blocked/non-whitelisted")
	}

	// Simulate whitelist reload with the domain now included.
	newSet, err := domainlist.ParseReader(
		strings.NewReader("new-white.example.com\n"),
		domainlist.ModeAllow,
	)
	if err != nil {
		t.Fatalf("ParseReader: %v", err)
	}

	go func() {
		c.InvalidateIf(func(name string, entry *cache.Entry) bool {
			return entry.Whitelisted != newSet.Contains(name)
		})
	}()

	time.Sleep(50 * time.Millisecond)

	if entry, _ := c.Get(q); entry != nil {
		t.Error("blocked entry for newly-whitelisted domain must be invalidated")
	}
}

func TestIntegration_Whitelist_MultipleQueriesReduceUpstreamCalls(t *testing.T) {
	// 10 queries for the same whitelisted domain should only result in 1
	// whitelist resolver call (all subsequent served from cache).
	wlClient := &mockIntegrationClient{
		name:     "wl-resolver",
		response: makeIntegrationResp("popular.example.com", "8.8.8.8", 300),
	}
	upClient := &mockIntegrationClient{
		name:     "upstream",
		response: makeIntegrationResp("popular.example.com", "0.0.0.0", 300),
	}

	port, cancel := startMockServer(t, []string{"popular.example.com"}, wlClient, upClient)
	defer cancel()

	for i := 0; i < 10; i++ {
		resp := queryUDPIntegration(t, port, "popular.example.com")
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("query %d: rcode=%s", i+1, dns.RcodeToString[resp.Rcode])
		}
	}

	if wlClient.Calls() != 1 {
		t.Errorf("10 identical queries should result in 1 whitelist call, got %d", wlClient.Calls())
	}
	if upClient.Calls() != 0 {
		t.Errorf("upstream should never be called for whitelisted domain, got %d", upClient.Calls())
	}
}

func waitForPort(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("warning: server at %s may not be ready", addr)
}
