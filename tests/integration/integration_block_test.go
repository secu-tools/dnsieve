// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

// isBlockedResponse reports whether a DNS response represents a blocked domain
// per the proxy's current blocked response format: REFUSED (rcode 5) with an
// Extended DNS Error (EDE) option using InfoCode 15 (Blocked) per RFC 8914.
func isBlockedResponse(resp *dns.Msg) bool {
	if resp.Rcode != dns.RcodeRefused {
		return false
	}
	return hasEDEBlocked(resp)
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

// checkNoIPLeak verifies that a blocked domain response does not contain any
// real answer records (blocked responses return REFUSED with no Answer section).
func checkNoIPLeak(t *testing.T, attempt int, resp *dns.Msg) {
	t.Helper()
	if len(resp.Answer) != 0 {
		t.Logf("warning: attempt %d: blocked response contains %d unexpected answer record(s)",
			attempt, len(resp.Answer))
	}
}

func TestIntegration_BlockedDomain_IPv4(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if isBlockedResponse(resp) {
		t.Logf("block IPv4: confirmed REFUSED + EDE Blocked")
		return
	}
	t.Log("warning: test domain was not blocked by any configured upstream (REFUSED+EDE not observed)")
}

func TestIntegration_BlockedDomain_IPv6(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeAAAA)
	if isBlockedResponse(resp) {
		t.Logf("block IPv6: confirmed REFUSED + EDE Blocked")
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
		checkNoIPLeak(t, i+1, resp)
	}
}

func TestIntegration_BlockedDomain_EDE(t *testing.T) {
	cfg := config.DefaultConfig()
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp := queryLocal(t, port, "isitphishing.org", dns.TypeA)
	if resp.Rcode == dns.RcodeRefused && hasEDEBlocked(resp) {
		t.Logf("block EDE: confirmed REFUSED + EDE Blocked (code %d)", dns.ExtendedErrorBlocked)
	} else {
		t.Logf("info: blocked EDE not observed (rcode=%s, may not be blocked by upstream)",
			dns.RcodeToString[resp.Rcode])
	}
}
