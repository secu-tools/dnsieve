// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// --- ParseBootstrapDNSAddrs ---

func TestParseBootstrapDNSAddrs_Empty(t *testing.T) {
	if got := ParseBootstrapDNSAddrs(""); len(got) != 0 {
		t.Errorf("empty string should return nil/empty, got %v", got)
	}
}

func TestParseBootstrapDNSAddrs_Single(t *testing.T) {
	got := ParseBootstrapDNSAddrs("9.9.9.9:53")
	if len(got) != 1 || got[0] != "9.9.9.9:53" {
		t.Errorf("got %v, want [9.9.9.9:53]", got)
	}
}

func TestParseBootstrapDNSAddrs_MultipleComma(t *testing.T) {
	got := ParseBootstrapDNSAddrs("9.9.9.9:53,149.112.112.112:53")
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0] != "9.9.9.9:53" {
		t.Errorf("got[0] = %q, want 9.9.9.9:53", got[0])
	}
	if got[1] != "149.112.112.112:53" {
		t.Errorf("got[1] = %q, want 149.112.112.112:53", got[1])
	}
}

func TestParseBootstrapDNSAddrs_SpacePadding(t *testing.T) {
	got := ParseBootstrapDNSAddrs("  9.9.9.9:53 , 149.112.112.112:53  ")
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
}

func TestParseBootstrapDNSAddrs_NoPort(t *testing.T) {
	got := ParseBootstrapDNSAddrs("9.9.9.9")
	if len(got) != 1 || got[0] != "9.9.9.9:53" {
		t.Errorf("got %v, want [9.9.9.9:53]", got)
	}
}

func TestParseBootstrapDNSAddrs_IPv6NoPort(t *testing.T) {
	got := ParseBootstrapDNSAddrs("2620:fe::fe")
	if len(got) != 1 || got[0] != "[2620:fe::fe]:53" {
		t.Errorf("got %v, want [[2620:fe::fe]:53]", got)
	}
}

func TestParseBootstrapDNSAddrs_IPv6WithPort(t *testing.T) {
	got := ParseBootstrapDNSAddrs("[2620:fe::fe]:53")
	if len(got) != 1 || got[0] != "[2620:fe::fe]:53" {
		t.Errorf("got %v, want [[2620:fe::fe]:53]", got)
	}
}

func TestParseBootstrapDNSAddrs_EmptySegments(t *testing.T) {
	got := ParseBootstrapDNSAddrs(",9.9.9.9:53,,149.112.112.112:53,")
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
}

// --- lookupHostViaBootstrap (using a mock UDP DNS server) ---

// startMockBootstrapServer starts a local UDP DNS server that responds to A
// queries with the given IP. Returns the server address.
func startMockBootstrapServer(t *testing.T, replyIP string, srvFail bool) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
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
			resp.Response = true
			if srvFail {
				resp.Rcode = dns.RcodeServerFailure
			} else {
				resp.Rcode = dns.RcodeSuccess
				if len(q.Question) > 0 && dns.RRToType(q.Question[0]) == dns.TypeA {
					ip := netip.MustParseAddr(replyIP)
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.Header{
							Name:  q.Question[0].Header().Name,
							Class: dns.ClassINET,
							TTL:   300,
						},
						A: rdata.A{Addr: ip},
					})
				}
			}
			if err := resp.Pack(); err != nil {
				continue
			}
			conn.WriteTo(resp.Data, addr)
		}
	}()

	return conn.LocalAddr().String()
}

func TestLookupHostViaBootstrap_Success(t *testing.T) {
	addr := startMockBootstrapServer(t, "9.9.9.9", false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := lookupHostViaBootstrap(ctx, "dns.quad9.net", addr, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "9.9.9.9" {
		t.Errorf("got IP %q, want 9.9.9.9", ip)
	}
}

func TestLookupHostViaBootstrap_ServerFail(t *testing.T) {
	addr := startMockBootstrapServer(t, "", true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := lookupHostViaBootstrap(ctx, "dns.quad9.net", addr, "auto")
	if err == nil {
		t.Error("expected error for SERVFAIL response")
	}
}

func TestLookupHostViaBootstrap_BadAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := lookupHostViaBootstrap(ctx, "example.com", "127.0.0.1:1", "auto")
	if err == nil {
		t.Error("expected error for unreachable bootstrap server")
	}
}

// --- resolveViaBootstrap ---

func TestResolveViaBootstrap_FirstWins(t *testing.T) {
	fast := startMockBootstrapServer(t, "1.2.3.4", false)
	slow := startMockBootstrapServer(t, "5.6.7.8", false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := resolveViaBootstrap(ctx, "example.com", []string{fast, slow}, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "1.2.3.4" && ip != "5.6.7.8" {
		t.Errorf("unexpected IP %q", ip)
	}
}

func TestResolveViaBootstrap_FallbackToSecond(t *testing.T) {
	// First server fails, second succeeds.
	bad := "127.0.0.1:1"
	good := startMockBootstrapServer(t, "9.9.9.9", false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := resolveViaBootstrap(ctx, "example.com", []string{bad, good}, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "9.9.9.9" {
		t.Errorf("got IP %q, want 9.9.9.9", ip)
	}
}

func TestResolveViaBootstrap_AllFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := resolveViaBootstrap(ctx, "example.com", []string{"127.0.0.1:1", "127.0.0.1:2"}, "auto")
	if err == nil {
		t.Error("expected error when all bootstrap servers fail")
	}
}

func TestResolveViaBootstrap_NoAddrs(t *testing.T) {
	ctx := context.Background()
	_, err := resolveViaBootstrap(ctx, "example.com", nil, "auto")
	if err == nil {
		t.Error("expected error for empty bootstrap list")
	}
}

// --- makeBootstrapDialer ---

func TestMakeBootstrapDialer_NumericIP(t *testing.T) {
	// Numeric IP addresses should not trigger bootstrap resolution.
	dialer := makeBootstrapDialer([]string{"127.0.0.1:1"}, "auto") // unreachable bootstrap

	// Connecting to a numeric IP should NOT query the (unreachable) bootstrap.
	// Use a local listener to prove the connection goes through.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialer(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Errorf("expected connection to succeed without bootstrap: %v", err)
		return
	}
	conn.Close()
}

func TestMakeBootstrapDialer_HostnameLookup(t *testing.T) {
	// Bootstrap server resolves to a local listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	lnAddr := ln.Addr().(*net.TCPAddr)
	bootstrap := startMockBootstrapServer(t, lnAddr.IP.String(), false)

	dialer := makeBootstrapDialer([]string{bootstrap}, "auto")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Dial using a hostname; bootstrap resolves it to the local listener IP.
	addr := fmt.Sprintf("fake-hostname.local:%d", lnAddr.Port)
	conn, err := dialer(ctx, "tcp", addr)
	if err != nil {
		t.Errorf("expected dial to succeed via bootstrap: %v", err)
		return
	}
	conn.Close()
}

// TestMakeBootstrapDialer_FallbackOnBootstrapFailure verifies that when
// bootstrap DNS is unreachable, the dialer falls back to the system resolver
// (i.e. returns an error from the system resolver, not from bootstrap itself).
func TestMakeBootstrapDialer_FallbackOnBootstrapFailure(t *testing.T) {
	// Bootstrap at port 1 is unreachable; dialer must NOT return a bootstrap
	// error — it falls back to the system resolver, which may return "no such
	// host" for a non-existent domain (acceptable) but must not return a
	// "bootstrap" error message.
	dialer := makeBootstrapDialer([]string{"127.0.0.1:1"}, "auto")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := dialer(ctx, "tcp", "nonexistent.invalid:443")
	if err == nil {
		t.Fatal("expected error for non-existent host, got nil")
	}
	if strings.Contains(err.Error(), "bootstrap") {
		t.Errorf("expected system-resolver error (not bootstrap error) after fallback, got: %v", err)
	}
}

// --- Integration: NewDoHClient with bootstrap ---

func TestNewDoHClient_WithBootstrap_Accepted(t *testing.T) {
	// Ensure NewDoHClient accepts bootstrap IPs without error.
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true, "auto", "9.9.9.9:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
	if c.String() == "" {
		t.Error("client String() should not be empty")
	}
}

func TestNewDoHClient_NoBootstrap_Accepted(t *testing.T) {
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

func TestNewDoHClient_MultipleBootstrap_Accepted(t *testing.T) {
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true, "auto", "9.9.9.9:53", "149.112.112.112:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

// --- Integration: NewDoTClient with bootstrap ---

func TestNewDoTClient_NoBootstrap_Accepted(t *testing.T) {
	c, err := NewDoTClient("dns.quad9.net:853", true, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

func TestNewDoTClient_WithBootstrap_NumericHost(t *testing.T) {
	// When address is already a numeric IP, bootstrap lookup is skipped.
	c, err := NewDoTClient("9.9.9.9:853", true, "auto", "9.9.9.9:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

func TestNewDoTClient_WithBootstrap_FallsBackOnFail(t *testing.T) {
	// Bootstrap lookup fails (port 1 is unreachable); client creation should
	// succeed and fall back to the original address.
	c, err := NewDoTClient("dns.quad9.net:853", true, "auto", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("client creation should not fail if bootstrap lookup fails: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

// =============================================================================
// F-06: Bootstrap A-only resolution tests
// =============================================================================

// TestLookupHostViaBootstrap_ARecordQuery verifies that the bootstrap lookup
// sends an A query and returns the first A record IP.
func TestLookupHostViaBootstrap_ARecordQuery(t *testing.T) {
	// Start a mock UDP DNS server that responds to A queries.
	addr, cleanup := startCustomBootstrapServer(t, func(msg *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
		})
		return resp
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := lookupHostViaBootstrap(ctx, "test.example.com", addr, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

// TestLookupHostViaBootstrap_NoARecord verifies that an error is returned
// when no A record exists for the queried host.
func TestLookupHostViaBootstrap_NoARecord(t *testing.T) {
	addr, cleanup := startCustomBootstrapServer(t, func(msg *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		// Return empty answer (no A records)
		return resp
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := lookupHostViaBootstrap(ctx, "norecord.example.com", addr, "auto")
	if err == nil {
		t.Error("expected error when no A record returned")
	}
}

// TestLookupHostViaBootstrap_ServerError verifies that bootstrap returns an
// error when the DNS server responds with a non-success rcode.
func TestLookupHostViaBootstrap_ServerError(t *testing.T) {
	addr, cleanup := startCustomBootstrapServer(t, func(msg *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		resp.Rcode = dns.RcodeServerFailure
		return resp
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := lookupHostViaBootstrap(ctx, "fail.example.com", addr, "auto")
	if err == nil {
		t.Error("expected error when server returns SERVFAIL")
	}
}

// TestResolveViaBootstrap_MultipleAddrs verifies that resolveViaBootstrap
// fans out to all bootstrap addresses and returns the first successful result.
func TestResolveViaBootstrap_MultipleAddrs(t *testing.T) {
	// First server fails, second succeeds.
	addr1, cleanup1 := startCustomBootstrapServer(t, func(msg *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		resp.Rcode = dns.RcodeServerFailure
		return resp
	})
	defer cleanup1()

	addr2, cleanup2 := startCustomBootstrapServer(t, func(msg *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 60},
			A:   rdata.A{Addr: netip.MustParseAddr("5.6.7.8")},
		})
		return resp
	})
	defer cleanup2()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := resolveViaBootstrap(ctx, "test.example.com", []string{addr1, addr2}, "auto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", ip)
	}
}

// TestResolveViaBootstrap_EmptyAddrs verifies error on empty bootstrap list.
func TestResolveViaBootstrap_EmptyAddrs(t *testing.T) {
	ctx := context.Background()
	_, err := resolveViaBootstrap(ctx, "test.example.com", nil, "auto")
	if err == nil {
		t.Error("expected error with empty bootstrap addresses")
	}
}

// startCustomBootstrapServer starts a local UDP DNS server for testing
// with a custom handler function.
func startCustomBootstrapServer(t *testing.T, handler func(*dns.Msg) *dns.Msg) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := new(dns.Msg)
			msg.Data = buf[:n]
			if err := msg.Unpack(); err != nil {
				continue
			}
			resp := handler(msg)
			if err := resp.Pack(); err != nil {
				continue
			}
			pc.WriteTo(resp.Data, raddr)
		}
	}()

	cleanup := func() {
		pc.Close()
		<-done
	}
	return addr, cleanup
}

// startMockBootstrapServerAAAA starts a local UDP DNS server that responds to
// AAAA queries with the given IPv6 address and returns NXDOMAIN for A queries,
// simulating an IPv6-only environment.
func startMockBootstrapServerAAAA(t *testing.T, replyIPv6 string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
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
			resp.Response = true
			if len(q.Question) > 0 {
				switch dns.RRToType(q.Question[0]) {
				case dns.TypeAAAA:
					resp.Rcode = dns.RcodeSuccess
					ip := netip.MustParseAddr(replyIPv6)
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr: dns.Header{
							Name:  q.Question[0].Header().Name,
							Class: dns.ClassINET,
							TTL:   300,
						},
						AAAA: rdata.AAAA{Addr: ip},
					})
				default:
					resp.Rcode = dns.RcodeNameError // A queries fail
				}
			}
			if err := resp.Pack(); err != nil {
				continue
			}
			conn.WriteTo(resp.Data, addr)
		}
	}()

	return conn.LocalAddr().String()
}

// TestLookupHostViaBootstrap_AAAAOnly verifies that bootstrap lookup succeeds
// when the server only responds to AAAA queries (IPv6-only environment).
func TestLookupHostViaBootstrap_AAAAOnly(t *testing.T) {
	addr := startMockBootstrapServerAAAA(t, "2001:db8::1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := lookupHostViaBootstrap(ctx, "ipv6host.example.com", addr, "auto")
	if err != nil {
		t.Fatalf("AAAA-only bootstrap: unexpected error: %v", err)
	}
	if ip != "2001:db8::1" {
		t.Errorf("AAAA-only bootstrap: got IP %q, want 2001:db8::1", ip)
	}
}

// startMockBootstrapServerAOnly starts a local UDP DNS server that only
// responds to A queries (no AAAA support).
func startMockBootstrapServerAOnly(t *testing.T, replyIP string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
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
			resp.Response = true
			if len(q.Question) > 0 && dns.RRToType(q.Question[0]) == dns.TypeA {
				resp.Rcode = dns.RcodeSuccess
				ip := netip.MustParseAddr(replyIP)
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  q.Question[0].Header().Name,
						Class: dns.ClassINET,
						TTL:   300,
					},
					A: rdata.A{Addr: ip},
				})
			} else {
				resp.Rcode = dns.RcodeNameError
			}
			if err := resp.Pack(); err != nil {
				continue
			}
			conn.WriteTo(resp.Data, addr)
		}
	}()

	return conn.LocalAddr().String()
}

// TestLookupHostViaBootstrap_AOnly verifies that bootstrap lookup still
// succeeds when the server only responds to A queries.
func TestLookupHostViaBootstrap_AOnly(t *testing.T) {
	addr := startMockBootstrapServerAOnly(t, "192.0.2.1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := lookupHostViaBootstrap(ctx, "example.com", addr, "auto")
	if err != nil {
		t.Fatalf("A-only bootstrap: unexpected error: %v", err)
	}
	if ip != "192.0.2.1" {
		t.Errorf("A-only bootstrap: got IP %q, want 192.0.2.1", ip)
	}
}

// TestLookupHostViaBootstrap_BothRespond verifies that bootstrap lookup
// returns a valid IP when both A and AAAA answer (race, first wins).
func TestLookupHostViaBootstrap_BothRespond(t *testing.T) {
	// Server responds to both A and AAAA.
	addr, cleanup := startCustomBootstrapServer(t, func(msg *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		resp.Response = true
		if len(msg.Question) > 0 {
			switch dns.RRToType(msg.Question[0]) {
			case dns.TypeA:
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
					A:   rdata.A{Addr: netip.MustParseAddr("198.51.100.1")},
				})
			case dns.TypeAAAA:
				resp.Rcode = dns.RcodeSuccess
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
					AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::2")},
				})
			}
		}
		return resp
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := lookupHostViaBootstrap(ctx, "dual.example.com", addr, "auto")
	if err != nil {
		t.Fatalf("dual A/AAAA bootstrap: unexpected error: %v", err)
	}
	// Either A or AAAA is valid.
	if ip != "198.51.100.1" && ip != "2001:db8::2" {
		t.Errorf("dual A/AAAA bootstrap: got unexpected IP %q", ip)
	}
}

// --- queryBootstrapRecord unit tests ---

// startMockBootstrapForRecord starts a minimal UDP DNS server that returns a
// configured rcode and optional A record. Used to test queryBootstrapRecord
// directly. Returns the server address and a cleanup function.
func startMockBootstrapForRecord(t *testing.T, rcode uint16, ip string) (addr string, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, remote, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			req := new(dns.Msg)
			req.Data = buf[:n]
			if unpackErr := req.Unpack(); unpackErr != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.Response = true
			resp.ID = req.ID
			resp.Question = req.Question
			resp.Rcode = rcode
			if rcode == dns.RcodeSuccess && ip != "" {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  dnsutil.Fqdn("example.com"),
						Class: dns.ClassINET,
						TTL:   60,
					},
					A: rdata.A{Addr: netip.MustParseAddr(ip)},
				})
			}
			if packErr := resp.Pack(); packErr != nil {
				continue
			}
			_, _ = pc.WriteTo(resp.Data, remote)
		}
	}()
	cleanup = func() {
		pc.Close()
		<-done
	}
	return pc.LocalAddr().String(), cleanup
}

// TestQueryBootstrapRecord_Success verifies that a successful A query returns
// the IP address from the answer section.
func TestQueryBootstrapRecord_Success(t *testing.T) {
	addr, cleanup := startMockBootstrapForRecord(t, dns.RcodeSuccess, "192.0.2.1")
	defer cleanup()

	transport := &dns.Transport{
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Dialer:       &net.Dialer{Timeout: 2 * time.Second},
	}
	client := &dns.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ip, err := queryBootstrapRecord(ctx, client, "example.com", addr, dns.TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "192.0.2.1" {
		t.Errorf("ip=%q, want 192.0.2.1", ip)
	}
}

// TestQueryBootstrapRecord_RcodeError verifies that a non-NOERROR rcode from
// the bootstrap server is returned as an error.
func TestQueryBootstrapRecord_RcodeError(t *testing.T) {
	addr, cleanup := startMockBootstrapForRecord(t, dns.RcodeNameError, "")
	defer cleanup()

	transport := &dns.Transport{
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Dialer:       &net.Dialer{Timeout: 2 * time.Second},
	}
	client := &dns.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := queryBootstrapRecord(ctx, client, "example.com", addr, dns.TypeA)
	if err == nil {
		t.Error("expected error for NXDOMAIN rcode, got nil")
	}
}

// TestQueryBootstrapRecord_NoAnswer verifies that an empty answer section
// is returned as an error (no A/AAAA records found).
func TestQueryBootstrapRecord_NoAnswer(t *testing.T) {
	addr, cleanup := startMockBootstrapForRecord(t, dns.RcodeSuccess, "")
	defer cleanup()

	transport := &dns.Transport{
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Dialer:       &net.Dialer{Timeout: 2 * time.Second},
	}
	client := &dns.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := queryBootstrapRecord(ctx, client, "example.com", addr, dns.TypeA)
	if err == nil {
		t.Error("expected error for empty answer section, got nil")
	}
}
