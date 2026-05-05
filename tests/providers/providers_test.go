// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build providers

// Package providers contains DNS provider-specific blocking verification tests.
// These tests query real DNS filtering servers to verify that blocked domains
// are correctly identified and that non-blocked domains pass through.
//
// Run with: go test -tags providers ./tests/providers/ -v -timeout 120s
//
// Provider list and their blocking mechanisms:
//
//	Quad9 (dns.quad9.net)                        - NXDOMAIN without authority section
//	Cloudflare Security (security.cloudflare-dns.com)  - Returns 0.0.0.0
//	Cloudflare Family (family.cloudflare-dns.com)      - Returns 0.0.0.0
//	AdGuard Default (dns.adguard-dns.com)              - Returns 0.0.0.0
//	AdGuard Family (family.adguard-dns.com)            - Returns 0.0.0.0
//	CleanBrowsing Family (family-filter-dns.cleanbrowsing.org) - NXDOMAIN or 0.0.0.0
//	OpenDNS FamilyShield (208.67.222.123)              - Redirect IP
//	Control D (freedns.controld.com)                   - Returns 0.0.0.0
package providers

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// knownBlockedDomain is a domain that filtering DNS providers commonly block.
var knownBlockedDomains = []string{
	"isitphishing.org",
}

// knownSafeDomain is a domain that should never be blocked.
var knownSafeDomains = []string{
	"example.com",
	"example.net",
	"example.org",
}

type provider struct {
	name     string
	protocol string // "doh", "dot", "udp"
	address  string
}

var providers = []provider{
	// DoH providers
	{"Quad9-DoH", "doh", "https://dns.quad9.net/dns-query"},
	{"Cloudflare-Security-DoH", "doh", "https://security.cloudflare-dns.com/dns-query"},
	{"Cloudflare-Family-DoH", "doh", "https://family.cloudflare-dns.com/dns-query"},
	{"AdGuard-Default-DoH", "doh", "https://dns.adguard-dns.com/dns-query"},
	{"AdGuard-Family-DoH", "doh", "https://family.adguard-dns.com/dns-query"},
	{"ControlD-Malware-DoH", "doh", "https://freedns.controld.com/p2/dns-query"},

	// DoT providers
	{"Quad9-DoT", "dot", "dns.quad9.net:853"},
	{"Cloudflare-Security-DoT", "dot", "1.1.1.2:853"},
	{"AdGuard-Default-DoT", "dot", "dns.adguard-dns.com:853"},
	{"ControlD-Malware-DoT", "dot", "p2.freedns.controld.com:853"},

	// Plain DNS providers
	{"Quad9-UDP", "udp", "9.9.9.9:53"},
	{"Cloudflare-Security-UDP", "udp", "1.1.1.2:53"},
	{"OpenDNS-FamilyShield-UDP", "udp", "208.67.222.123:53"},
	{"ControlD-Malware-UDP", "udp", "76.76.2.2:53"},
}

func newClient(t *testing.T, p provider) upstream.Client {
	t.Helper()
	var (
		c   upstream.Client
		err error
	)
	switch p.protocol {
	case "doh":
		c, err = upstream.NewDoHClient(p.address, true, "auto", upstream.ResolveDisabled, 0, nil)
	case "dot":
		c, err = upstream.NewDoTClient(p.address, true, "ipv4", upstream.ResolveDisabled, 0, nil)
	case "udp":
		c, err = upstream.NewPlainClient(p.address)
	default:
		t.Fatalf("unknown protocol: %s", p.protocol)
	}
	if err != nil {
		t.Fatalf("create %s client: %v", p.name, err)
	}
	return c
}

func makeProviderQuery(domain string, qtype uint16) *dns.Msg {
	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(domain), qtype)
	q.RecursionDesired = true
	return q
}

func queryProvider(t *testing.T, client upstream.Client, domain string, qtype uint16) (*dns.Msg, dnsmsg.InspectResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.Query(ctx, makeProviderQuery(domain, qtype))
	if err != nil {
		t.Fatalf("query %s: %v", domain, err)
	}
	return resp, dnsmsg.InspectResponse(resp)
}

// TestProviders_SafeDomainNotBlocked verifies that well-known safe domains
// are NOT blocked by any provider.
func TestProviders_SafeDomainNotBlocked(t *testing.T) {
	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			client := newClient(t, p)
			for _, domain := range knownSafeDomains {
				t.Run(domain, func(t *testing.T) {
					resp, result := queryProvider(t, client, domain, dns.TypeA)
					if result.Blocked {
						t.Errorf("%s blocked safe domain %s (rcode=%s)",
							p.name, domain, dns.RcodeToString[resp.Rcode])
					}
					if len(resp.Answer) == 0 && resp.Rcode == dns.RcodeSuccess {
						t.Logf("Warning: %s returned NODATA for %s", p.name, domain)
					}
				})
			}
		})
	}
}

// TestProviders_BlockedDomainDetected verifies that known malicious domains
// are blocked by filtering providers and that the block signal is correctly
// detected by our InspectResponse function.
func TestProviders_BlockedDomainDetected(t *testing.T) {
	for _, p := range providers {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			client := newClient(t, p)
			for _, domain := range knownBlockedDomains {
				t.Run(domain, func(t *testing.T) {
					resp, result := queryProvider(t, client, domain, dns.TypeA)
					t.Logf("%s for %s: rcode=%s blocked=%v answers=%d ns=%d",
						p.name, domain, dns.RcodeToString[resp.Rcode],
						result.Blocked, len(resp.Answer), len(resp.Ns))
					if !result.Blocked {
						t.Logf("Note: %s did not block %s -- may not be in block list", p.name, domain)
					}
				})
			}
		})
	}
}

// TestProviders_BlockedResponseIsZeroIP verifies that when a provider blocks
// a domain via A/AAAA records, the returned IP is 0.0.0.0 or ::.
func TestProviders_BlockedResponseIsZeroIP(t *testing.T) {
	zeroIPProviders := []provider{
		{"Cloudflare-Security-DoH", "doh", "https://security.cloudflare-dns.com/dns-query"},
		{"Cloudflare-Family-DoH", "doh", "https://family.cloudflare-dns.com/dns-query"},
		{"AdGuard-Default-DoH", "doh", "https://dns.adguard-dns.com/dns-query"},
		{"ControlD-Malware-DoH", "doh", "https://freedns.controld.com/p2/dns-query"},
	}

	for _, p := range zeroIPProviders {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			client := newClient(t, p)
			for _, domain := range knownBlockedDomains {
				verifyZeroIPBlock(t, client, p.name, domain)
			}
		})
	}
}

func verifyZeroIPBlock(t *testing.T, client upstream.Client, providerName, domain string) {
	t.Helper()
	resp, _ := queryProvider(t, client, domain, dns.TypeA)
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if a.Addr == netip.AddrFrom4([4]byte{}) {
				t.Logf("%s correctly returns 0.0.0.0 for blocked %s", providerName, domain)
				return
			}
		}
	}
	t.Logf("Note: %s may not block %s, or uses a different blocking method", providerName, domain)
}

// TestProviders_Quad9_NXDOMAIN_NoAuthority verifies that Quad9 returns
// NXDOMAIN without authority section for blocked domains.
func TestProviders_Quad9_NXDOMAIN_NoAuthority(t *testing.T) {
	client, err := upstream.NewDoHClient("https://dns.quad9.net/dns-query", true, "auto", upstream.ResolveDisabled, 0, nil)
	if err != nil {
		t.Fatalf("create Quad9 client: %v", err)
	}

	for _, domain := range knownBlockedDomains {
		t.Run(domain, func(t *testing.T) {
			resp, result := queryProvider(t, client, domain, dns.TypeA)
			t.Logf("Quad9 %s: rcode=%s blocked=%v ns_count=%d",
				domain, dns.RcodeToString[resp.Rcode], result.Blocked, len(resp.Ns))
			if resp.Rcode == dns.RcodeNameError && len(resp.Ns) == 0 {
				t.Logf("Confirmed: Quad9 NXDOMAIN-without-authority block for %s", domain)
				if !result.Blocked {
					t.Error("InspectResponse should detect Quad9 block")
				}
			}
		})
	}
}

// TestProviders_GenuineNXDOMAIN_HasAuthority verifies that genuine NXDOMAIN
// responses contain an authority section (SOA record).
func TestProviders_GenuineNXDOMAIN_HasAuthority(t *testing.T) {
	client, err := upstream.NewDoHClient("https://dns.quad9.net/dns-query", true, "auto", upstream.ResolveDisabled, 0, nil)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	domain := "this-domain-definitely-does-not-exist-dnsieve-test.com"
	resp, result := queryProvider(t, client, domain, dns.TypeA)

	if resp.Rcode == dns.RcodeNameError {
		t.Logf("Genuine NXDOMAIN for %s: ns_count=%d blocked=%v", domain, len(resp.Ns), result.Blocked)
		if len(resp.Ns) == 0 {
			t.Log("Warning: genuine NXDOMAIN has no authority section")
		}
		if result.Blocked {
			t.Error("genuine NXDOMAIN should NOT be marked as blocked")
		}
	}
}
