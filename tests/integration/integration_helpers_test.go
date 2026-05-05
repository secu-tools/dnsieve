// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/server"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// findFreePort returns an available local port.
func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// startTestServer starts a DNSieve server with the given config in-process
// and returns the port it is listening on and a cancel function to stop it.
// It probes upstream reachability using three bootstrap IP-family strategies
// in order: "auto" (RFC 6555 race, exercises the default code path), "ipv4"
// (A records only, works on IPv4-only CI runners), then "ipv6" (AAAA only).
// The server is restarted with each strategy until a probe query returns
// NOERROR. If all strategies fail the test fails immediately (t.Fatal).
func startTestServer(t *testing.T, cfg *config.Config) (int, context.CancelFunc) {
	t.Helper()

	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "integration")

	for _, family := range []string{"auto", "ipv4", "ipv6"} {
		port := findFreePort(t)

		cfgCopy := *cfg
		cfgCopy.UpstreamSettings = cfg.UpstreamSettings
		cfgCopy.Downstream.Plain.Port = port
		cfgCopy.UpstreamSettings.BootstrapIPFamily = family

		resolver, err := upstream.NewResolver(&cfgCopy, logger)
		if err != nil {
			t.Logf("bootstrap_ip_family=%q: resolver error: %v", family, err)
			continue
		}

		c := cache.New(
			cfgCopy.Cache.MaxEntries,
			cfgCopy.Cache.BlockedTTL,
			cfgCopy.Cache.MinTTL,
			cfgCopy.Cache.RenewPercent,
		)

		handler := server.NewHandler(resolver, nil, nil, c, logger, &cfgCopy)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			if serveErr := server.ServePlain(ctx, handler, &cfgCopy, logger); serveErr != nil {
				t.Logf("server stopped: %v", serveErr)
			}
		}()

		waitForServer(t, port)

		// Probe upstream reachability. ReadTimeout (7 s) must remain greater
		// than the proxy's upstream TimeoutMS (5 s) to avoid a tie-race.
		probeQ := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn("example.com"), dns.TypeA)
		probeQ.RecursionDesired = true
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		reachable := false
		for probe := 1; probe <= 3; probe++ {
			c2 := dns.NewClient()
			c2.Transport.ReadTimeout = 7 * time.Second
			ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
			resp, _, probeErr := c2.Exchange(ctx2, probeQ, "udp", addr)
			cancel2()
			if probeErr == nil && resp != nil && resp.Rcode != dns.RcodeServerFailure {
				t.Logf("upstream reachable (bootstrap_ip_family=%q, probe %d/3)", family, probe)
				reachable = true
				break
			}
			t.Logf("bootstrap_ip_family=%q probe %d/3: upstream not yet reachable", family, probe)
			if probe < 3 {
				time.Sleep(time.Duration(probe) * time.Second)
			}
		}

		if reachable {
			return port, cancel
		}

		cancel()
		t.Logf("bootstrap_ip_family=%q: upstream unreachable after 3 probes, trying next strategy", family)
	}

	t.Fatal("upstream unreachable with all bootstrap IP family strategies (auto, ipv4, ipv6)")
	return 0, nil
}

// waitForServer probes the given TCP port until it accepts connections or
// the 3-second deadline is reached.
func waitForServer(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("warning: server at %s may not be ready", addr)
}

// queryLocal sends a DNS query to 127.0.0.1:<port> over UDP.
// It retries up to 3 times (with 1 s / 2 s backoff) on transport errors
// and transient SERVFAIL responses from upstreams.
func queryLocal(t *testing.T, port int, name string, qtype uint16) *dns.Msg {
	t.Helper()
	const maxAttempts = 3
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		c := dns.NewClient()
		c.Transport.ReadTimeout = 15 * time.Second
		query := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
		query.RecursionDesired = true
		// Advertise EDNS0 so the receive buffer is large enough for
		// responses that carry DNSSEC records (NSEC + RRSIG can exceed
		// the legacy 512-byte non-EDNS limit).
		query.UDPSize = dns.DefaultMsgSize

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		resp, _, err := c.Exchange(ctx, query, "udp", addr)
		cancel()
		if err != nil {
			lastErr = err
			t.Logf("query %s %s (attempt %d/%d): %v", name, dns.TypeToString[qtype], attempt, maxAttempts, err)
		} else if resp.Rcode == dns.RcodeServerFailure && attempt < maxAttempts {
			lastResp = resp
			t.Logf("query %s %s (attempt %d/%d): SERVFAIL, retrying", name, dns.TypeToString[qtype], attempt, maxAttempts)
		} else {
			return resp
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if lastErr != nil {
		t.Fatalf("query %s %s: all %d attempts failed: %v", name, dns.TypeToString[qtype], maxAttempts, lastErr)
	}
	return lastResp
}
