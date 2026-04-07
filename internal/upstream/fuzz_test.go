// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// FuzzWhitelistIsWhitelisted fuzz-tests domain name matching in the whitelist
// resolver to ensure no panics on arbitrary input.
func FuzzWhitelistIsWhitelisted(f *testing.F) {
	f.Add("example.com.")
	f.Add("*.example.com.")
	f.Add("sub.example.com.")
	f.Add(".")
	f.Add("")
	f.Add("a")
	f.Add("xn--n3h.example.com.")
	f.Add("very-long-label-that-exceeds-normal-dns-limits.example.com.")

	cfg := &config.WhitelistConfig{
		Enabled: true,
		Domains: []string{
			"example.com",
			"*.safe.net",
			"*",
		},
	}
	wl := &WhitelistResolver{cfg: cfg, client: &mockClient{name: "fuzz"}}

	f.Fuzz(func(t *testing.T, domain string) {
		// Must never panic regardless of input
		_ = wl.IsWhitelisted(domain)
	})
}

// FuzzResolveWithMockResponses fuzz-tests the Resolver's fan-out and
// block-consensus logic with arbitrary DNS wire responses from a single mock
// upstream. This exercises InspectResponse, TTL extraction, and NXDOMAIN
// disambiguation on arbitrary wire bytes.
func FuzzResolveWithMockResponses(f *testing.F) {
	// Seed with valid blocked response (0.0.0.0)
	q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	blocked := new(dns.Msg)
	dnsutil.SetReply(blocked, q)
	blocked.Answer = append(blocked.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.AddrFrom4([4]byte{})},
	})
	if err := blocked.Pack(); err == nil {
		f.Add(blocked.Data)
	}

	// Seed with NXDOMAIN (no authority)
	nx := new(dns.Msg)
	dnsutil.SetReply(nx, q)
	nx.Rcode = dns.RcodeNameError
	if err := nx.Pack(); err == nil {
		f.Add(nx.Data)
	}

	// Seed with SERVFAIL
	sf := new(dns.Msg)
	dnsutil.SetReply(sf, q)
	sf.Rcode = dns.RcodeServerFailure
	if err := sf.Pack(); err == nil {
		f.Add(sf.Data)
	}

	// Seed with normal response
	normal := new(dns.Msg)
	dnsutil.SetReply(normal, q)
	normal.Answer = append(normal.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	if err := normal.Pack(); err == nil {
		f.Add(normal.Data)
	}

	// Seed with empty
	f.Add([]byte{})

	// Seed with garbage
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, wireResp []byte) {
		// Parse the wire bytes as a DNS message to use as a mock response.
		// If they're not valid DNS, skip (we're testing the resolver logic, not
		// the parser -- parser fuzz coverage is in dnsmsg/fuzz_test.go).
		mockMsg := new(dns.Msg)
		mockMsg.Data = wireResp
		if err := mockMsg.Unpack(); err != nil {
			return
		}

		query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
		query.RecursionDesired = true
		mockMsg.ID = query.ID

		logger := logging.NewStdoutOnly(logging.DefaultConfig(), "fuzz")
		clients := []Client{
			&mockClient{name: "fuzz-mock", response: mockMsg},
		}
		r := &Resolver{
			clients:       clients,
			timeout:       500 * time.Millisecond,
			minWait:       10 * time.Millisecond,
			slowThreshold: 0,
			logger:        logger,
		}

		// Must never panic
		result := r.Resolve(context.Background(), query)

		if result.BestResponse == nil {
			t.Error("Resolve must always return a non-nil BestResponse")
		}
		// Blocked and ServFail cannot both be true simultaneously
		if result.Blocked && result.BestResponse != nil &&
			result.BestResponse.Rcode == dns.RcodeServerFailure {
			t.Error("result cannot be both blocked and SERVFAIL")
		}
	})
}
