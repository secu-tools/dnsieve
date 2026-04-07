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
func startTestServer(t *testing.T, cfg *config.Config) (int, context.CancelFunc) {
	t.Helper()

	port := findFreePort(t)
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "integration")

	resolver, err := upstream.NewResolver(cfg, logger)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	c := cache.New(
		cfg.Cache.MaxEntries,
		cfg.Cache.BlockedTTL,
		cfg.Cache.MinTTL,
		cfg.Cache.RenewPercent,
	)

	handler := server.NewHandler(resolver, nil, c, logger, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := server.ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	waitForServer(t, port)

	return port, cancel
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
