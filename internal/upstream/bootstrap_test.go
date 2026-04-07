// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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

	ip, err := lookupHostViaBootstrap(ctx, "dns.quad9.net", addr)
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

	_, err := lookupHostViaBootstrap(ctx, "dns.quad9.net", addr)
	if err == nil {
		t.Error("expected error for SERVFAIL response")
	}
}

func TestLookupHostViaBootstrap_BadAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := lookupHostViaBootstrap(ctx, "example.com", "127.0.0.1:1")
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

	ip, err := resolveViaBootstrap(ctx, "example.com", []string{fast, slow})
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

	ip, err := resolveViaBootstrap(ctx, "example.com", []string{bad, good})
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

	_, err := resolveViaBootstrap(ctx, "example.com", []string{"127.0.0.1:1", "127.0.0.1:2"})
	if err == nil {
		t.Error("expected error when all bootstrap servers fail")
	}
}

func TestResolveViaBootstrap_NoAddrs(t *testing.T) {
	ctx := context.Background()
	_, err := resolveViaBootstrap(ctx, "example.com", nil)
	if err == nil {
		t.Error("expected error for empty bootstrap list")
	}
}

// --- makeBootstrapDialer ---

func TestMakeBootstrapDialer_NumericIP(t *testing.T) {
	// Numeric IP addresses should not trigger bootstrap resolution.
	dialer := makeBootstrapDialer([]string{"127.0.0.1:1"}) // unreachable bootstrap

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

	dialer := makeBootstrapDialer([]string{bootstrap})

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

// --- Integration: NewDoHClient with bootstrap ---

func TestNewDoHClient_WithBootstrap_Accepted(t *testing.T) {
	// Ensure NewDoHClient accepts bootstrap IPs without error.
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true, "9.9.9.9:53")
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
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

func TestNewDoHClient_MultipleBootstrap_Accepted(t *testing.T) {
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", true, "9.9.9.9:53", "149.112.112.112:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

// --- Integration: NewDoTClient with bootstrap ---

func TestNewDoTClient_NoBootstrap_Accepted(t *testing.T) {
	c, err := NewDoTClient("dns.quad9.net:853", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}

func TestNewDoTClient_WithBootstrap_NumericHost(t *testing.T) {
	// When address is already a numeric IP, bootstrap lookup is skipped.
	c, err := NewDoTClient("9.9.9.9:853", true, "9.9.9.9:53")
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
	c, err := NewDoTClient("dns.quad9.net:853", true, "127.0.0.1:1")
	if err != nil {
		t.Fatalf("client creation should not fail if bootstrap lookup fails: %v", err)
	}
	if c == nil {
		t.Error("expected non-nil client")
	}
}
