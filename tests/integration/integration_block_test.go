// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
)

// isBlockedResponse reports whether a DNS response represents a blocked domain.
// In default "null" mode: NOERROR with 0.0.0.0 (A) or :: (AAAA) and EDE Blocked.
// In other modes: checks for EDE Blocked regardless of rcode.
func isBlockedResponse(resp *dns.Msg) bool {
	return hasEDEBlocked(resp)
}

// isBlockedNull reports whether a response uses null blocking mode:
// NOERROR with 0.0.0.0 for A or :: for AAAA, and EDE Blocked.
func isBlockedNull(resp *dns.Msg) bool {
	if resp.Rcode != dns.RcodeSuccess || !hasEDEBlocked(resp) {
		return false
	}
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if a.Addr == netip.AddrFrom4([4]byte{0, 0, 0, 0}) {
				return true
			}
		case *dns.AAAA:
			if a.Addr == netip.IPv6Unspecified() {
				return true
			}
		}
	}
	return false
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

func TestIntegration_BlockedDomain_IPv4(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if isBlockedNull(resp) {
		t.Logf("block IPv4: confirmed NOERROR + 0.0.0.0 + EDE Blocked (null mode)")
		return
	}
	if isBlockedResponse(resp) {
		t.Logf("block IPv4: confirmed EDE Blocked (rcode=%s)", dns.RcodeToString[resp.Rcode])
		return
	}
	t.Log("warning: test domain was not blocked by any configured upstream")
}

func TestIntegration_BlockedDomain_IPv6(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeAAAA)
	if isBlockedNull(resp) {
		t.Logf("block IPv6: confirmed NOERROR + :: + EDE Blocked (null mode)")
		return
	}
	if isBlockedResponse(resp) {
		t.Logf("block IPv6: confirmed EDE Blocked (rcode=%s)", dns.RcodeToString[resp.Rcode])
		return
	}
	t.Log("warning: AAAA block not observed (may not be blocked by configured upstreams)")
}

func TestIntegration_BlockedNeverLeaked(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	for i := 0; i < 5; i++ {
		resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
		if isBlockedResponse(resp) {
			// In null mode: answer should only contain 0.0.0.0
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					if a.Addr != netip.AddrFrom4([4]byte{0, 0, 0, 0}) {
						t.Errorf("attempt %d: blocked response leaked real IP %s", i+1, a.Addr)
					}
				}
			}
		}
	}
}

func TestIntegration_BlockedDomain_EDE(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if hasEDEBlocked(resp) {
		t.Logf("block EDE: confirmed EDE Blocked (code %d)", dns.ExtendedErrorBlocked)
		// Verify EDE extra text contains upstream info
		for _, rr := range resp.Pseudo {
			if ede, ok := rr.(*dns.EDE); ok && ede.InfoCode == dns.ExtendedErrorBlocked {
				t.Logf("block EDE extra text: %q", ede.ExtraText)
			}
		}
	} else {
		t.Logf("info: blocked EDE not observed (rcode=%s, may not be blocked by upstream)",
			dns.RcodeToString[resp.Rcode])
	}
}

func TestIntegration_BlockedDomain_NXDomainMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Blocking.Mode = dnsmsg.BlockingModeNXDomain
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if hasEDEBlocked(resp) {
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("nxdomain mode: rcode=%s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 {
			t.Errorf("nxdomain mode: expected no answers, got %d", len(resp.Answer))
		}
		t.Logf("block nxdomain: confirmed NXDOMAIN + EDE Blocked")
	} else {
		t.Log("info: domain not blocked by upstream in nxdomain mode test")
	}
}

func TestIntegration_BlockedDomain_NODATAMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Blocking.Mode = dnsmsg.BlockingModeNODATA
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if hasEDEBlocked(resp) {
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("nodata mode: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 {
			t.Errorf("nodata mode: expected no answers, got %d", len(resp.Answer))
		}
		t.Logf("block nodata: confirmed NOERROR + empty answer + EDE Blocked")
	} else {
		t.Log("info: domain not blocked by upstream in nodata mode test")
	}
}

func TestIntegration_BlockedDomain_RefusedMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Blocking.Mode = dnsmsg.BlockingModeRefused
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if hasEDEBlocked(resp) {
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("refused mode: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 {
			t.Errorf("refused mode: expected no answers, got %d", len(resp.Answer))
		}
		t.Logf("block refused: confirmed REFUSED + EDE Blocked")
	} else {
		t.Log("info: domain not blocked by upstream in refused mode test")
	}
}
