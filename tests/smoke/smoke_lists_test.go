// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/miekg/dns"
)

// writeListFile writes domain list content to a file inside dir and returns
// the absolute path.
func writeListFile(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write list file: %v", err)
	}
	return path
}

// whitelistConfig returns a TOML config string that enables the whitelist
// with the given list file and uses Cloudflare as the whitelist resolver.
func whitelistConfig(port int, listFile string) string {
	return fmt.Sprintf(`[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 200
verify_certificates = true
%s
[downstream.plain]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.dot]
enabled = false

[downstream.doh]
enabled = false

[cache]
enabled = true
max_entries = 1000
min_ttl = 30

[whitelist]
enabled = true
list_files = ["%s"]
resolver_address = "https://cloudflare-dns.com/dns-query"
resolver_protocol = "doh"
`, bootstrapIPFamilyTOML(), port, filepath.ToSlash(listFile))
}

// blacklistConfig returns a TOML config string that enables the blacklist
// with the given list file.
func blacklistConfig(port int, listFile string) string {
	return fmt.Sprintf(`[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 200
verify_certificates = true
%s
[downstream.plain]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.dot]
enabled = false

[downstream.doh]
enabled = false

[cache]
enabled = true
max_entries = 1000
min_ttl = 30

[blacklist]
enabled = true
list_files = ["%s"]
`, bootstrapIPFamilyTOML(), port, filepath.ToSlash(listFile))
}

// TestSmoke_Whitelist_ResolvesWhitelistedDomain verifies that a domain
// present in the whitelist file resolves successfully through the dedicated
// whitelist resolver (Cloudflare).
func TestSmoke_Whitelist_ResolvesWhitelistedDomain(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	listFile := writeListFile(t, dir, "whitelist.txt", "example.com\n")
	cfgPath := writeConfig(t, dir, whitelistConfig(port, listFile))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("whitelisted domain: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("whitelisted domain: expected at least one answer")
	}
	t.Logf("whitelist A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestSmoke_Whitelist_WildcardMatch verifies that a wildcard whitelist entry
// (*.example.com) matches subdomains and the base domain.
func TestSmoke_Whitelist_WildcardMatch(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	listFile := writeListFile(t, dir, "whitelist.txt", "*.example.com\n")
	cfgPath := writeConfig(t, dir, whitelistConfig(port, listFile))
	startBinary(t, cfgPath, port)

	// Subdomain should match the wildcard.
	resp := queryUDP(t, port, "www.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("wildcard subdomain: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("wildcard subdomain A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))

	// Base domain should also match (*.example.com matches example.com).
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("wildcard base: rcode=%s, want NOERROR", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("wildcard base A: rcode=%s answers=%d", dns.RcodeToString[resp2.Rcode], len(resp2.Answer))
}

// TestSmoke_Blacklist_BlockedDomain verifies that a blacklisted domain returns
// a blocked response (0.0.0.0 for A in null mode) without contacting upstream.
func TestSmoke_Blacklist_BlockedDomain(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	listFile := writeListFile(t, dir, "blacklist.txt", "blocked.example.com\n")
	cfgPath := writeConfig(t, dir, blacklistConfig(port, listFile))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "blocked.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("blacklisted domain A: rcode=%s, want NOERROR (null mode)", dns.RcodeToString[resp.Rcode])
	}
	// In null blocking mode, the answer should be 0.0.0.0.
	if len(resp.Answer) == 0 {
		t.Fatal("blacklisted domain A: expected answer with 0.0.0.0")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("blacklisted domain A: answer is %T, want *dns.A", resp.Answer[0])
	}
	if a.Addr != netip.AddrFrom4([4]byte{}) {
		t.Fatalf("blacklisted domain A: got %s, want 0.0.0.0", a.Addr)
	}
	t.Logf("blacklist A: blocked with 0.0.0.0 as expected")
}

// TestSmoke_Blacklist_AAAA_BlockedDomain verifies that a blacklisted domain
// returns :: for AAAA queries in null blocking mode.
func TestSmoke_Blacklist_AAAA_BlockedDomain(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	listFile := writeListFile(t, dir, "blacklist.txt", "blocked.example.com\n")
	cfgPath := writeConfig(t, dir, blacklistConfig(port, listFile))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "blocked.example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("blacklisted AAAA: rcode=%s, want NOERROR (null mode)", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("blacklisted AAAA: expected answer with ::")
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("blacklisted AAAA: answer is %T, want *dns.AAAA", resp.Answer[0])
	}
	if aaaa.Addr != netip.IPv6Unspecified() {
		t.Fatalf("blacklisted AAAA: got %s, want ::", aaaa.Addr)
	}
	t.Logf("blacklist AAAA: blocked with :: as expected")
}

// TestSmoke_Blacklist_NonBlocked_Resolves verifies that domains NOT in the
// blacklist still resolve normally.
func TestSmoke_Blacklist_NonBlocked_Resolves(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	listFile := writeListFile(t, dir, "blacklist.txt", "blocked.example.com\n")
	cfgPath := writeConfig(t, dir, blacklistConfig(port, listFile))
	startBinary(t, cfgPath, port)

	// example.com is NOT in the blacklist and should resolve normally.
	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("non-blacklisted domain: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("non-blacklisted domain: expected at least one answer")
	}
	// The answer should NOT be 0.0.0.0 (it should be a real IP).
	a, ok := resp.Answer[0].(*dns.A)
	if ok && a.Addr == netip.AddrFrom4([4]byte{}) {
		t.Fatal("non-blacklisted domain: got 0.0.0.0, expected real IP")
	}
	t.Logf("non-blacklisted A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestSmoke_Blacklist_WildcardMatch verifies that wildcard blacklist entries
// block all subdomains.
func TestSmoke_Blacklist_WildcardMatch(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	listFile := writeListFile(t, dir, "blacklist.txt", "*.blocked-test-domain.example.com\n")
	cfgPath := writeConfig(t, dir, blacklistConfig(port, listFile))
	startBinary(t, cfgPath, port)

	// Subdomain of wildcard should be blocked.
	resp := queryUDP(t, port, "sub.blocked-test-domain.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("blacklist wildcard subdomain: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("blacklist wildcard subdomain: expected blocked answer")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("blacklist wildcard subdomain: answer is %T, want *dns.A", resp.Answer[0])
	}
	if a.Addr != netip.AddrFrom4([4]byte{}) {
		t.Fatalf("blacklist wildcard subdomain: got %s, want 0.0.0.0", a.Addr)
	}
	t.Logf("blacklist wildcard: sub.blocked-test-domain.example.com blocked as expected")

	// Base domain should also be blocked by *.blocked-test-domain.example.com
	resp2 := queryUDP(t, port, "blocked-test-domain.example.com", dns.TypeA)
	if len(resp2.Answer) > 0 {
		a2, ok := resp2.Answer[0].(*dns.A)
		if ok && a2.Addr == netip.AddrFrom4([4]byte{}) {
			t.Logf("blacklist wildcard: base domain also blocked as expected")
		}
	}
}
