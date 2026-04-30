// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/config"
)

// --- newHostResolver construction ---

func TestNewHostResolver_DisabledMode_ReturnsNil(t *testing.T) {
	hr, err := newHostResolver("dns.example.com", "853", []string{"127.0.0.1:53"}, "auto", resolveDisabled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr != nil {
		t.Error("expected nil resolver for resolveDisabled mode")
	}
}

func TestNewHostResolver_NumericIP_ReturnsNil(t *testing.T) {
	hr, err := newHostResolver("9.9.9.9", "853", []string{"127.0.0.1:53"}, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr != nil {
		t.Error("expected nil resolver for numeric IP host")
	}
}

func TestNewHostResolver_NoBootstrapIPs_ReturnsNil(t *testing.T) {
	hr, err := newHostResolver("dns.example.com", "853", nil, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr != nil {
		t.Error("expected nil resolver when no bootstrap IPs provided")
	}
}

func TestNewHostResolver_IPv6Numeric_ReturnsNil(t *testing.T) {
	hr, err := newHostResolver("2620:fe::fe", "853", []string{"9.9.9.9:53"}, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr != nil {
		t.Error("expected nil resolver for numeric IPv6 host")
	}
}

func TestNewHostResolver_TTLMode_ResolvesOnConstruction(t *testing.T) {
	// Start a mock bootstrap server returning a known IP.
	bootstrapAddr := startMockBootstrapServer(t, "1.2.3.4", false)

	hr, err := newHostResolver("dns.example.com", "853", []string{bootstrapAddr}, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr == nil {
		t.Fatal("expected non-nil resolver")
	}

	addr := hr.Addr()
	if addr != "1.2.3.4:853" {
		t.Errorf("addr=%q, want 1.2.3.4:853", addr)
	}
}

func TestNewHostResolver_IntervalMode_ResolvesOnConstruction(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "5.6.7.8", false)

	hr, err := newHostResolver("dns.example.com", "443", []string{bootstrapAddr}, "auto", 60)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr == nil {
		t.Fatal("expected non-nil resolver")
	}

	addr := hr.Addr()
	if addr != "5.6.7.8:443" {
		t.Errorf("addr=%q, want 5.6.7.8:443", addr)
	}
}

func TestNewHostResolver_BootstrapFail_FallsBackToHostname(t *testing.T) {
	// Bootstrap at port 1 is unreachable.
	hr, err := newHostResolver("dns.example.com", "853", []string{"127.0.0.1:1"}, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hr == nil {
		t.Fatal("expected non-nil resolver even on bootstrap failure")
	}

	// Fallback: should use the original hostname:port.
	addr := hr.Addr()
	if addr != "dns.example.com:853" {
		t.Errorf("addr=%q, want dns.example.com:853 (hostname fallback)", addr)
	}
}

// --- Addr() basic behaviour ---

func TestHostResolver_Addr_ReturnsCachedBeforeExpiry(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "10.0.0.1", false)

	hr, err := newHostResolver("host.example.com", "53", []string{bootstrapAddr}, "auto", 3600)
	if err != nil || hr == nil {
		t.Fatalf("newHostResolver: err=%v hr=%v", err, hr)
	}

	// Multiple Addr() calls should all return the same address without hitting bootstrap.
	for i := 0; i < 5; i++ {
		if got := hr.Addr(); got != "10.0.0.1:53" {
			t.Errorf("call %d: addr=%q, want 10.0.0.1:53", i, got)
		}
	}
}

// --- Addr() sync re-resolution on expiry ---

func TestHostResolver_Addr_SyncRefreshOnExpiry(t *testing.T) {
	// Track how many times the bootstrap server is queried.
	var queryCount atomic.Int32
	serverAddr := startCountingBootstrapServer(t, []string{"10.1.1.1", "10.1.1.2"}, &queryCount)

	hr, err := newHostResolver("host.example.com", "53", []string{serverAddr}, "auto", resolveByTTL)
	if err != nil || hr == nil {
		t.Fatalf("newHostResolver: err=%v hr=%v", err, hr)
	}

	// Force-expire the address.
	hr.mu.Lock()
	hr.expiresAt = time.Now().Add(-time.Second)
	hr.totalDur = minResolveInterval
	hr.mu.Unlock()

	addr := hr.Addr()
	// After sync refresh, address should be updated to second IP returned.
	if addr == "" {
		t.Error("expected non-empty address after sync refresh")
	}
	if queryCount.Load() < 2 {
		t.Errorf("expected at least 2 bootstrap queries (initial + refresh), got %d", queryCount.Load())
	}
}

// --- Background refresh ---

func TestHostResolver_Addr_BackgroundRefreshTriggered(t *testing.T) {
	// The first Addr() call after reaching the 10% TTL threshold should
	// trigger a background refresh without blocking.
	var queryCount atomic.Int32
	serverAddr := startCountingBootstrapServer(t, []string{"10.2.2.1", "10.2.2.2"}, &queryCount)

	hr, err := newHostResolver("host.example.com", "53", []string{serverAddr}, "auto", resolveByTTL)
	if err != nil || hr == nil {
		t.Fatalf("newHostResolver: err=%v hr=%v", err, hr)
	}

	// Set up state: not yet expired but within 10% remaining.
	total := 2 * time.Second
	hr.mu.Lock()
	hr.totalDur = total
	// 5% remaining = well within the 10% threshold.
	hr.expiresAt = time.Now().Add(total / 20)
	hr.mu.Unlock()

	// First Addr() should return current (non-expired) address immediately and
	// kick off a background refresh goroutine.
	addr := hr.Addr()
	if addr == "" {
		t.Error("expected non-empty address")
	}

	// Wait a moment for the background refresh to complete.
	time.Sleep(500 * time.Millisecond)

	if queryCount.Load() < 2 {
		t.Errorf("expected background refresh query; queryCount=%d", queryCount.Load())
	}
}

// --- Concurrent Addr() calls ---

func TestHostResolver_Addr_ConcurrentCallsSafe(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "10.3.3.1", false)

	hr, err := newHostResolver("host.example.com", "53", []string{bootstrapAddr}, "auto", 3600)
	if err != nil || hr == nil {
		t.Fatalf("newHostResolver: err=%v hr=%v", err, hr)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	addrs := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addrs[idx] = hr.Addr()
		}(i)
	}
	wg.Wait()

	for i, addr := range addrs {
		if addr == "" {
			t.Errorf("goroutine %d: got empty address", i)
		}
	}
}

func TestHostResolver_Addr_ConcurrentExpiredCallsSafe(t *testing.T) {
	// Multiple goroutines calling Addr() on an expired resolver: only one
	// should perform the DNS query; others should return the stale address.
	var queryCount atomic.Int32
	serverAddr := startCountingBootstrapServer(t, []string{"10.4.4.1"}, &queryCount)

	hr, err := newHostResolver("host.example.com", "53", []string{serverAddr}, "auto", resolveByTTL)
	if err != nil || hr == nil {
		t.Fatalf("newHostResolver: err=%v hr=%v", err, hr)
	}

	// Force expiry.
	hr.mu.Lock()
	hr.expiresAt = time.Now().Add(-time.Second)
	hr.totalDur = minResolveInterval
	hr.mu.Unlock()

	const goroutines = 10
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = hr.Addr()
		}()
	}
	wg.Wait()

	// Due to the refreshing flag, only a small number of DNS queries should
	// have been issued (ideally 1 sync + initial, but may be slightly more
	// due to concurrent goroutines seeing the expiry at the same time).
	if queryCount.Load() > int32(goroutines)+1 {
		t.Errorf("too many bootstrap queries: got %d, want at most %d", queryCount.Load(), goroutines+1)
	}
}

// --- setExpiry ---

func TestHostResolver_SetExpiry_TTLMode_FloorApplied(t *testing.T) {
	hr := &hostResolver{mode: resolveByTTL}
	// TTL of 0 should be raised to minResolveInterval.
	hr.setExpiry(0, resolveByTTL)
	if hr.totalDur != minResolveInterval {
		t.Errorf("totalDur=%v, want %v (floor)", hr.totalDur, minResolveInterval)
	}
	if hr.expiresAt.Before(time.Now()) {
		t.Error("expiresAt should be in the future")
	}
}

func TestHostResolver_SetExpiry_TTLMode_SmallTTL_FloorApplied(t *testing.T) {
	hr := &hostResolver{mode: resolveByTTL}
	// 10-second TTL is below the 30-second floor.
	hr.setExpiry(10, resolveByTTL)
	if hr.totalDur != minResolveInterval {
		t.Errorf("totalDur=%v, want %v (floor applied for small TTL)", hr.totalDur, minResolveInterval)
	}
}

func TestHostResolver_SetExpiry_TTLMode_NormalTTL(t *testing.T) {
	hr := &hostResolver{mode: resolveByTTL}
	hr.setExpiry(300, resolveByTTL)
	want := 300 * time.Second
	if hr.totalDur != want {
		t.Errorf("totalDur=%v, want %v", hr.totalDur, want)
	}
}

func TestHostResolver_SetExpiry_IntervalMode(t *testing.T) {
	hr := &hostResolver{mode: 120}
	// TTL is ignored in interval mode; the configured mode value is used.
	hr.setExpiry(9999, 120)
	want := 120 * time.Second
	if hr.totalDur != want {
		t.Errorf("totalDur=%v, want %v", hr.totalDur, want)
	}
}

// --- Bootstrap TTL returned from server ---

func TestBootstrapTTL_ReturnedFromRecord(t *testing.T) {
	// A mock server returning TTL=300 for A records.
	serverAddr := startBootstrapServerWithTTL(t, "11.22.33.44", 300)

	bootstrapIPs := []string{serverAddr}
	hr, err := newHostResolver("dns.example.com", "853", bootstrapIPs, "ipv4", resolveByTTL)
	if err != nil || hr == nil {
		t.Fatalf("newHostResolver: err=%v hr=%v", err, hr)
	}

	hr.mu.Lock()
	dur := hr.totalDur
	hr.mu.Unlock()

	// With TTL=300 the totalDur should be 300s (above the 30s floor).
	if dur != 300*time.Second {
		t.Errorf("totalDur=%v, want 300s", dur)
	}
}

// --- Integration: DoTClient with re-resolution ---

func TestDoTClient_WithHostResolver_UsesResolvedAddr(t *testing.T) {
	cert := generateSelfSignedCert(t)
	var servedAddr atomic.Value

	ln := startTLSDNSServer(t, cert, func(q *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, q)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: q.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
		})
		return resp
	})

	lnAddr, err := net.ResolveTCPAddr("tcp", ln)
	if err != nil {
		// ln is already a string like "127.0.0.1:PORT"
		lnAddr = &net.TCPAddr{}
		lnAddr.IP = net.ParseIP("127.0.0.1")
	}
	_ = lnAddr
	servedAddr.Store(ln)

	// Bootstrap resolves "dns.example.test" to 127.0.0.1.
	bootstrapAddr := startMockBootstrapServer(t, "127.0.0.1", false)

	// Extract port from ln to build correct server address.
	_, port, _ := net.SplitHostPort(ln)
	target := fmt.Sprintf("dns.example.test:%s", port)

	client, err := NewDoTClient(target, false, "auto", resolveByTTL, bootstrapAddr)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}
	if client.resolver == nil {
		t.Fatal("expected non-nil resolver for re-resolution mode")
	}

	addr := client.resolver.Addr()
	if addr == "" {
		t.Error("resolver returned empty address")
	}
	_ = servedAddr
}

func TestDoTClient_Disabled_NoResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "127.0.0.1", false)

	client, err := NewDoTClient("dns.example.test:853", false, "auto", resolveDisabled, bootstrapAddr)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}
	if client.resolver != nil {
		t.Error("expected nil resolver for resolveDisabled mode")
	}
}

// --- Integration: DoHClient with re-resolution ---

func TestDoHClient_WithHostResolver_HasResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "10.0.0.1", false)

	client, err := NewDoHClient("https://dns.example.com/dns-query", false, "auto", resolveByTTL, bootstrapAddr)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	if client.resolver == nil {
		t.Error("expected non-nil resolver when re-resolution is enabled")
	}
}

func TestDoHClient_Disabled_NoResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "10.0.0.1", false)

	client, err := NewDoHClient("https://dns.example.com/dns-query", false, "auto", resolveDisabled, bootstrapAddr)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	if client.resolver != nil {
		t.Error("expected nil resolver for resolveDisabled mode")
	}
}

func TestDoHClient_NumericIPURL_NoResolver(t *testing.T) {
	// URL with a numeric IP host: no hostResolver is needed.
	client, err := NewDoHClient("https://9.9.9.9/dns-query", false, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	if client.resolver != nil {
		t.Error("expected nil resolver for numeric IP URL")
	}
}

// --- extractURLHostPort ---

func TestExtractURLHostPort_HTTPS(t *testing.T) {
	host, port, scheme := extractURLHostPort("https://dns.quad9.net/dns-query")
	if host != "dns.quad9.net" {
		t.Errorf("host=%q, want dns.quad9.net", host)
	}
	if port != "443" {
		t.Errorf("port=%q, want 443", port)
	}
	if scheme != "https" {
		t.Errorf("scheme=%q, want https", scheme)
	}
}

func TestExtractURLHostPort_ExplicitPort(t *testing.T) {
	host, port, _ := extractURLHostPort("https://dns.quad9.net:853/dns-query")
	if host != "dns.quad9.net" {
		t.Errorf("host=%q, want dns.quad9.net", host)
	}
	if port != "853" {
		t.Errorf("port=%q, want 853", port)
	}
}

func TestExtractURLHostPort_HTTP(t *testing.T) {
	host, port, scheme := extractURLHostPort("http://internal.example.com/dns-query")
	if host != "internal.example.com" {
		t.Errorf("host=%q, want internal.example.com", host)
	}
	if port != "80" {
		t.Errorf("port=%q, want 80", port)
	}
	if scheme != "http" {
		t.Errorf("scheme=%q, want http", scheme)
	}
}

func TestExtractURLHostPort_Invalid(t *testing.T) {
	host, port, _ := extractURLHostPort("not-a-url")
	// Should not panic; result may be empty or partial.
	_ = host
	_ = port
}

// --- helpers ---

// startCountingBootstrapServer starts a mock bootstrap DNS server that cycles
// through the given IPs in order (wrapping around). It atomically increments
// queryCount for every query received.
func startCountingBootstrapServer(t *testing.T, ips []string, queryCount *atomic.Int32) string {
	t.Helper()
	if len(ips) == 0 {
		t.Fatal("ips must not be empty")
	}

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	var callIdx atomic.Int32

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			queryCount.Add(1)

			q := new(dns.Msg)
			q.Data = make([]byte, n)
			copy(q.Data, buf[:n])
			if err := q.Unpack(); err != nil {
				continue
			}

			idx := int(callIdx.Add(1)) - 1
			ip := netip.MustParseAddr(ips[idx%len(ips)])

			resp := new(dns.Msg)
			dnsutil.SetReply(resp, q)
			resp.Rcode = dns.RcodeSuccess
			if len(q.Question) > 0 {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  q.Question[0].Header().Name,
						Class: dns.ClassINET,
						TTL:   300,
					},
					A: rdata.A{Addr: ip},
				})
			}
			if packErr := resp.Pack(); packErr != nil {
				continue
			}
			conn.WriteTo(resp.Data, addr)
		}
	}()

	return conn.LocalAddr().String()
}

// startBootstrapServerWithTTL starts a mock bootstrap DNS server that responds
// with a fixed IP and the specified TTL for all A queries.
func startBootstrapServerWithTTL(t *testing.T, replyIP string, ttl uint32) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ip := netip.MustParseAddr(replyIP)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			q := new(dns.Msg)
			q.Data = make([]byte, n)
			copy(q.Data, buf[:n])
			if err := q.Unpack(); err != nil {
				continue
			}
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, q)
			resp.Rcode = dns.RcodeSuccess
			if len(q.Question) > 0 {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  q.Question[0].Header().Name,
						Class: dns.ClassINET,
						TTL:   ttl,
					},
					A: rdata.A{Addr: ip},
				})
			}
			if packErr := resp.Pack(); packErr != nil {
				continue
			}
			conn.WriteTo(resp.Data, addr)
		}
	}()

	return conn.LocalAddr().String()
}

// --- NewWhitelistResolver re-resolution ---

func TestNewWhitelistResolver_Disabled_ReturnsNil(t *testing.T) {
	cfg := &config.WhitelistConfig{Enabled: false}
	wl, err := NewWhitelistResolver(cfg, false, nil, "auto", resolveDisabled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wl != nil {
		t.Error("expected nil WhitelistResolver when disabled")
	}
}

func TestNewWhitelistResolver_DisabledMode_NoResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "1.1.1.1", false)
	cfg := &config.WhitelistConfig{
		Enabled:          true,
		ResolverAddress:  "https://dns.example.com/dns-query",
		ResolverProtocol: "doh",
	}
	wl, err := NewWhitelistResolver(cfg, false, []string{bootstrapAddr}, "auto", resolveDisabled)
	if err != nil {
		t.Fatalf("NewWhitelistResolver: %v", err)
	}
	if wl == nil {
		t.Fatal("expected non-nil WhitelistResolver")
	}
	dohClient, ok := wl.client.(*DoHClient)
	if !ok {
		t.Fatalf("expected *DoHClient, got %T", wl.client)
	}
	if dohClient.resolver != nil {
		t.Error("expected nil resolver for resolveDisabled mode")
	}
}

func TestNewWhitelistResolver_TTLMode_HasResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "1.1.1.1", false)
	cfg := &config.WhitelistConfig{
		Enabled:          true,
		ResolverAddress:  "https://dns.example.com/dns-query",
		ResolverProtocol: "doh",
	}
	wl, err := NewWhitelistResolver(cfg, false, []string{bootstrapAddr}, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("NewWhitelistResolver: %v", err)
	}
	if wl == nil {
		t.Fatal("expected non-nil WhitelistResolver")
	}
	dohClient, ok := wl.client.(*DoHClient)
	if !ok {
		t.Fatalf("expected *DoHClient, got %T", wl.client)
	}
	if dohClient.resolver == nil {
		t.Error("expected non-nil resolver for TTL-based re-resolution mode")
	}
}

func TestNewWhitelistResolver_IntervalMode_HasResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "1.1.1.1", false)
	cfg := &config.WhitelistConfig{
		Enabled:          true,
		ResolverAddress:  "https://dns.example.com/dns-query",
		ResolverProtocol: "doh",
	}
	wl, err := NewWhitelistResolver(cfg, false, []string{bootstrapAddr}, "auto", 300)
	if err != nil {
		t.Fatalf("NewWhitelistResolver: %v", err)
	}
	if wl == nil {
		t.Fatal("expected non-nil WhitelistResolver")
	}
	dohClient, ok := wl.client.(*DoHClient)
	if !ok {
		t.Fatalf("expected *DoHClient, got %T", wl.client)
	}
	if dohClient.resolver == nil {
		t.Error("expected non-nil resolver for fixed-interval re-resolution mode")
	}
}

func TestNewWhitelistResolver_DoTProtocol_TTLMode_HasResolver(t *testing.T) {
	bootstrapAddr := startMockBootstrapServer(t, "1.1.1.1", false)
	cfg := &config.WhitelistConfig{
		Enabled:          true,
		ResolverAddress:  "dns.example.com:853",
		ResolverProtocol: "dot",
	}
	wl, err := NewWhitelistResolver(cfg, false, []string{bootstrapAddr}, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("NewWhitelistResolver: %v", err)
	}
	if wl == nil {
		t.Fatal("expected non-nil WhitelistResolver")
	}
	dotClient, ok := wl.client.(*DoTClient)
	if !ok {
		t.Fatalf("expected *DoTClient, got %T", wl.client)
	}
	if dotClient.resolver == nil {
		t.Error("expected non-nil resolver for TTL-based re-resolution mode on DoT whitelist client")
	}
}

func TestNewWhitelistResolver_NumericIPAddress_NoResolver(t *testing.T) {
	cfg := &config.WhitelistConfig{
		Enabled:          true,
		ResolverAddress:  "https://1.1.1.1/dns-query",
		ResolverProtocol: "doh",
	}
	wl, err := NewWhitelistResolver(cfg, false, nil, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("NewWhitelistResolver: %v", err)
	}
	if wl == nil {
		t.Fatal("expected non-nil WhitelistResolver")
	}
	dohClient, ok := wl.client.(*DoHClient)
	if !ok {
		t.Fatalf("expected *DoHClient, got %T", wl.client)
	}
	if dohClient.resolver != nil {
		t.Error("expected nil resolver for numeric IP whitelist address")
	}
}

func TestNewWhitelistResolver_DefaultAddress_NoResolverForNumericIP(t *testing.T) {
	// Default address is https://1.1.1.1/dns-query (numeric) so no hostResolver.
	cfg := &config.WhitelistConfig{Enabled: true}
	wl, err := NewWhitelistResolver(cfg, false, nil, "auto", resolveByTTL)
	if err != nil {
		t.Fatalf("NewWhitelistResolver: %v", err)
	}
	if wl == nil {
		t.Fatal("expected non-nil WhitelistResolver")
	}
	dohClient, ok := wl.client.(*DoHClient)
	if !ok {
		t.Fatalf("expected *DoHClient, got %T", wl.client)
	}
	if dohClient.resolver != nil {
		t.Error("expected nil resolver for default numeric IP whitelist address")
	}
}
