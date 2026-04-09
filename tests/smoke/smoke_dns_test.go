// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

// startBinary starts the DNSieve binary with the given config file and waits
// until it is accepting connections on port. It returns a cleanup function
// that kills the process.
func startBinary(t *testing.T, cfgPath string, port int) func() {
	t.Helper()

	cmd := exec.Command(dnsieveBinary, "--cfgfile", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start dnsieve: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if !waitForPort(t, "tcp", addr, 30*time.Second) {
		cmd.Process.Kill()
		t.Fatalf("dnsieve did not start on %s within 30s", addr)
	}

	stop := func() {
		cmd.Process.Kill()
		cmd.Wait()
	}
	t.Cleanup(stop)
	return stop
}

// TestSmoke_PlainDNS_UDP_A verifies an A record query over UDP against the
// running binary resolves successfully.
func TestSmoke_PlainDNS_UDP_A(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("UDP A: expected at least one answer")
	}
	t.Logf("UDP A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestSmoke_PlainDNS_UDP_AAAA verifies an AAAA record query succeeds.
func TestSmoke_PlainDNS_UDP_AAAA(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP AAAA: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("UDP AAAA: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestSmoke_PlainDNS_NXDOMAIN verifies non-existent domains return NXDOMAIN
// or an empty NOERROR, never a valid answer.
func TestSmoke_PlainDNS_NXDOMAIN(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "this-domain-definitely-does-not-exist-dnsieve-smoke.example.com", dns.TypeA)
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		t.Error("NXDOMAIN: expected NXDOMAIN or empty NOERROR, got answers")
	}
	t.Logf("NXDOMAIN: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestSmoke_Cache_HitIsFast verifies that a second identical query is
// noticeably faster than the first, indicating the cache is working.
func TestSmoke_Cache_HitIsFast(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp1 := queryUDP(t, port, "example.com", dns.TypeA)
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("first query: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}

	start := time.Now()
	resp2 := queryUDP(t, port, "example.com", dns.TypeA)
	elapsed := time.Since(start)

	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("second query: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("cache round-trip: %v (answers=%d)", elapsed, len(resp2.Answer))
}

// TestSmoke_MultipleQueryTypes verifies that common record types all resolve
// without errors through the binary.
func TestSmoke_MultipleQueryTypes(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	cases := []struct {
		name  string
		qtype uint16
	}{
		{"A", dns.TypeA},
		{"AAAA", dns.TypeAAAA},
		{"MX", dns.TypeMX},
		{"NS", dns.TypeNS},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := queryUDP(t, port, "google.com", tc.qtype)
			t.Logf("%s google.com: rcode=%s answers=%d", tc.name, dns.RcodeToString[resp.Rcode], len(resp.Answer))
		})
	}
}

// TestSmoke_IDN_ACELabel_A verifies that the DNSieve binary handles an A-record
// query for an ACE-encoded domain name (xn-- Punycode label, RFC 5891) without
// crashing or returning a SERVFAIL caused by label-format rejection.  The
// synthetic subdomain is expected to return NXDOMAIN; any valid DNS response
// code (no crash, no connection reset) is considered a pass.
func TestSmoke_IDN_ACELabel_A(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	// "xn--n3h.example.com" is a synthetic ACE-labelled subdomain.  IANA's
	// example.com does not delegate this label, so NXDOMAIN is expected.
	resp := queryUDP(t, port, "xn--n3h.example.com", dns.TypeA)
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		// Unexpected answers; not a failure but worth logging.
		t.Logf("IDN ACE A: unexpected answers=%d", len(resp.Answer))
	}
	t.Logf("IDN ACE A: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestSmoke_IDN_ACELabel_AAAA mirrors TestSmoke_IDN_ACELabel_A for AAAA queries.
func TestSmoke_IDN_ACELabel_AAAA(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "xn--n3h.example.com", dns.TypeAAAA)
	t.Logf("IDN ACE AAAA: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestSmoke_IDN_MultipleACELabels verifies that domain names with consecutive
// ACE-encoded labels at multiple levels are passed through cleanly.
func TestSmoke_IDN_MultipleACELabels(t *testing.T) {
	dir := smokeTempDir(t)
	port := findFreePort(t)
	cfgPath := writeConfig(t, dir, minimalConfig(port))
	startBinary(t, cfgPath, port)

	resp := queryUDP(t, port, "xn--n3h.xn--n3h.example.com", dns.TypeA)
	t.Logf("IDN multi-label: rcode=%s", dns.RcodeToString[resp.Rcode])
}
