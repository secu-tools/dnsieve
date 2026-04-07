// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

func TestIntegration_CacheHit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Cache.Enabled = true
	port, cancel := startTestServer(t, cfg)
	defer cancel()

	resp1 := queryLocal(t, port, "example.com", dns.TypeA)
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("first query failed: %s", dns.RcodeToString[resp1.Rcode])
	}

	start := time.Now()
	resp2 := queryLocal(t, port, "example.com", dns.TypeA)
	elapsed := time.Since(start)

	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("second query failed: %s", dns.RcodeToString[resp2.Rcode])
	}
	if elapsed > 500*time.Millisecond {
		t.Logf("warning: cached query took %v, expected < 500ms", elapsed)
	}
}
