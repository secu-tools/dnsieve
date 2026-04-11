// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// smokeTempDir creates a subdirectory inside smokeTmpDir for a single test.
// It is NOT registered as t.Cleanup because the global cleanup in TestMain
// handles removal of the entire smokeTmpDir tree.
func smokeTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(smokeTmpDir, t.Name())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("create test temp dir: %v", err)
	}
	return dir
}

// findFreePort returns an available local TCP port for use as a DNS listener.
// It retries up to 10 times to minimise the TOCTOU race between closing the
// probe listener and the binary binding the port: if the chosen port is
// grabbed by another process between the two calls the next candidate is used.
func findFreePort(t *testing.T) int {
	t.Helper()
	for range 10 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		// Quick check: try to re-bind briefly to confirm the port is still free.
		check, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			// Port was snatched; try again.
			continue
		}
		check.Close()
		return port
	}
	t.Fatal("find free port: could not find an available port after 10 attempts")
	return 0
}

// waitForPort probes addr over network until it accepts connections or
// the deadline elapses.
func waitForPort(t *testing.T, network, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout(network, addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// queryUDP sends a DNS query for name to 127.0.0.1:<port> over UDP.
// It retries up to 3 times (with 1 s / 2 s backoff) on transport errors
// and on SERVFAIL responses, which can occur when upstream resolvers are
// momentarily unreachable during the server's speed-test phase.
func queryUDP(t *testing.T, port int, name string, qtype uint16) *dns.Msg {
	t.Helper()
	const maxAttempts = 3
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c := dns.NewClient()
		c.Transport.ReadTimeout = 20 * time.Second

		msg := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
		msg.RecursionDesired = true
		// Advertise EDNS0 so the receive buffer is large enough for
		// responses that carry DNSSEC records (NSEC + RRSIG can exceed
		// the legacy 512-byte non-EDNS limit).
		msg.UDPSize = dns.DefaultMsgSize

		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		resp, _, err := c.Exchange(ctx, msg, "udp", addr)
		cancel()
		if err != nil {
			lastErr = err
			t.Logf("UDP query %s (attempt %d/%d): %v", name, attempt, maxAttempts, err)
		} else if resp.Rcode == dns.RcodeServerFailure && attempt < maxAttempts {
			lastResp = resp
			t.Logf("UDP query %s (attempt %d/%d): SERVFAIL, retrying", name, attempt, maxAttempts)
		} else {
			return resp
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if lastErr != nil {
		t.Fatalf("UDP query %s: all %d attempts failed: %v", name, maxAttempts, lastErr)
	}
	return lastResp
}

// minimalConfig returns a minimal DNSieve TOML config for the given port.
// It uses Quad9 and Cloudflare Security as upstreams (same as the default).
func minimalConfig(port int) string {
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
`, port)
}

// writeConfig writes config content to a file named config.toml inside dir
// and returns the full path.
func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
