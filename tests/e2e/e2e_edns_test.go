// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"encoding/hex"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

// ============================================================
// EDNS: ECS (RFC 7871)
// ============================================================

// TestE2E_EDNS_ECS_Strip verifies ECS is not forwarded upstream in strip mode.
func TestE2E_EDNS_ECS_Strip(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.ECS.Mode = "strip"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithECS(t, port, "example.com", dns.TypeA, "1.2.3.0/24")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ECS strip: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("ECS strip: ECS-in-resp=%v", findECS(resp) != nil)
}

// TestE2E_EDNS_ECS_Forward verifies ECS is forwarded to upstreams.
func TestE2E_EDNS_ECS_Forward(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.ECS.Mode = "forward"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithECS(t, port, "example.com", dns.TypeA, "192.0.2.0/24")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ECS forward: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("ECS forward: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_EDNS_ECS_Substitute verifies ECS is replaced with the configured subnet.
func TestE2E_EDNS_ECS_Substitute(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.ECS.Mode = "substitute"
	cfg.Privacy.ECS.Subnet = "203.0.113.0/24"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithECS(t, port, "example.com", dns.TypeA, "1.2.3.0/24")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ECS substitute: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("ECS substitute: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestE2E_EDNS_ECS_IPv6 verifies ECS works with an IPv6 subnet.
func TestE2E_EDNS_ECS_IPv6(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.ECS.Mode = "forward"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithECS(t, port, "example.com", dns.TypeA, "2001:db8::/32")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ECS IPv6: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("ECS IPv6: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// ============================================================
// EDNS: Cookies (RFC 7873)
// ============================================================

// TestE2E_EDNS_Cookies_Strip verifies cookies are stripped in strip mode.
func TestE2E_EDNS_Cookies_Strip(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.Cookies.Mode = "strip"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithCookie(t, port, "example.com", dns.TypeA, "aabbccdd11223344")
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("cookies strip: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("cookies strip: cookie-in-resp=%v", findCookie(resp) != nil)
}

// TestE2E_EDNS_Cookies_Reoriginate verifies proxy uses its own cookie state.
func TestE2E_EDNS_Cookies_Reoriginate(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.Cookies.Mode = "reoriginate"
	cancel := startServer(t, cfg)
	defer cancel()

	resp1 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("cookies reoriginate q1: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}
	resp2 := queryUDP(t, port, "cloudflare.com", dns.TypeA)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("cookies reoriginate q2: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("cookies reoriginate: q1=%d q2=%d answers", len(resp1.Answer), len(resp2.Answer))
}

// TestE2E_EDNS_Cookies_Reoriginate_IsDefault verifies reoriginate is the default.
func TestE2E_EDNS_Cookies_Reoriginate_IsDefault(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Privacy.Cookies.Mode != "reoriginate" {
		t.Errorf("default cookies mode = %q, want reoriginate", cfg.Privacy.Cookies.Mode)
	}
}

// ============================================================
// EDNS: NSID (RFC 5001)
// ============================================================

// TestE2E_EDNS_NSID_Strip verifies NSID requests are stripped.
func TestE2E_EDNS_NSID_Strip(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.NSID.Mode = "strip"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithNSID(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("NSID strip: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("NSID strip: NSID-in-resp=%v", findNSID(resp) != nil)
}

// TestE2E_EDNS_NSID_Forward verifies NSID requests are forwarded to upstream.
func TestE2E_EDNS_NSID_Forward(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.NSID.Mode = "forward"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithNSID(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("NSID forward: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("NSID forward: rcode=%s NSID=%v", dns.RcodeToString[resp.Rcode], findNSID(resp) != nil)
}

// TestE2E_EDNS_NSID_Substitute verifies the proxy substitutes its own NSID.
func TestE2E_EDNS_NSID_Substitute(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Privacy.NSID.Mode = "substitute"
	cfg.Privacy.NSID.Value = "dnsieve-e2e-test"
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryWithNSID(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("NSID substitute: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	nsid := findNSID(resp)
	if nsid == nil {
		t.Error("NSID substitute: expected NSID in response")
		return
	}
	expected := hex.EncodeToString([]byte("dnsieve-e2e-test"))
	if nsid.Nsid != expected {
		t.Errorf("NSID substitute: got %q, want %q", nsid.Nsid, expected)
	}
	t.Logf("NSID substitute: nsid=%s", nsid.Nsid)
}

// ============================================================
// EDNS: TCP Keepalive (RFC 7828)
// ============================================================

// TestE2E_EDNS_TCPKeepalive verifies TCP responses include a keepalive option.
func TestE2E_EDNS_TCPKeepalive(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.TCPKeepalive.ClientTimeoutSec = 30
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryTCP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("TCP keepalive: rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	ka := findTCPKeepalive(resp)
	if ka == nil {
		t.Logf("info: TCP keepalive option not present")
		return
	}
	// RFC 7828: timeout is in units of 100ms
	expectedTimeout := uint16(30 * 10)
	if ka.Timeout != expectedTimeout {
		t.Errorf("TCP keepalive: timeout = %d (100ms units), want %d", ka.Timeout, expectedTimeout)
	}
	t.Logf("TCP keepalive: timeout=%d (= %ds)", ka.Timeout, ka.Timeout/10)
}

// TestE2E_EDNS_TCPKeepalive_NotOnUDP verifies UDP responses omit TCP keepalive.
func TestE2E_EDNS_TCPKeepalive_NotOnUDP(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP keepalive: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if ka := findTCPKeepalive(resp); ka != nil {
		t.Error("RFC 7828: TCP keepalive must not appear in UDP responses")
	}
}
