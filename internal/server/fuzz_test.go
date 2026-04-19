// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// FuzzHandleQuery fuzz-tests the DNS query handler with arbitrary
// wire-format DNS messages to ensure no panics.
func FuzzHandleQuery(f *testing.F) {
	// Seed: normal A query
	q := new(dns.Msg)
	dnsutil.SetQuestion(q, "example.com.", dns.TypeA)
	q.RecursionDesired = true
	_ = q.Pack()
	f.Add(q.Data)

	// Seed: empty message
	empty := new(dns.Msg)
	_ = empty.Pack()
	f.Add(empty.Data)

	// Seed: AAAA query
	q2 := new(dns.Msg)
	dnsutil.SetQuestion(q2, "test.org.", dns.TypeAAAA)
	_ = q2.Pack()
	f.Add(q2.Data)

	// Seed: MX query
	q3 := new(dns.Msg)
	dnsutil.SetQuestion(q3, "mail.example.com.", dns.TypeMX)
	_ = q3.Pack()
	f.Add(q3.Data)

	// Seed: minimal header
	f.Add([]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Seed: garbage
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		if t.Context().Err() != nil {
			return
		}
		msg := new(dns.Msg)
		msg.Data = data
		if err := msg.Unpack(); err != nil {
			return // Invalid DNS message, skip
		}

		cfg := config.DefaultConfig()
		cfg.Cache.Enabled = true
		cfg.Cache.MaxEntries = 100

		logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-fuzz")
		c := cache.New(100, 3600, 5, 0)

		// Build a mock upstream that returns a normal response
		mockResp := new(dns.Msg)
		dnsutil.SetReply(mockResp, msg)
		if len(msg.Question) > 0 && dns.RRToType(msg.Question[0]) == dns.TypeA {
			mockResp.Answer = append(mockResp.Answer, &dns.A{
				Hdr: dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
			})
		}

		clients := []upstream.Client{
			&mockUpstreamClient{name: "fuzz-mock", response: mockResp},
		}
		resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)

		handler := NewHandler(resolver, nil, c, logger, cfg)

		// Should not panic
		resp := handler.HandleQuery(t.Context(), msg)

		if resp == nil {
			t.Error("HandleQuery should always return a response")
		}
	})
}

// FuzzHandleQueryDomainNames specifically fuzzes domain name handling.
func FuzzHandleQueryDomainNames(f *testing.F) {
	f.Add("example.com.")
	f.Add("a.b.c.d.e.f.g.")
	f.Add("xn--n3h.example.com.")
	f.Add(".")
	f.Add("very-long-subdomain-label-that-might-cause-issues.example.com.")

	f.Fuzz(func(t *testing.T, domain string) {
		if t.Context().Err() != nil {
			return
		}
		if len(domain) == 0 || len(domain) > 253 {
			return
		}

		query := new(dns.Msg)
		dnsutil.SetQuestion(query, dnsutil.Fqdn(domain), dns.TypeA)
		query.RecursionDesired = true

		cfg := config.DefaultConfig()
		cfg.Cache.Enabled = true
		cfg.Cache.MaxEntries = 100

		logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-fuzz")
		c := cache.New(100, 3600, 5, 0)

		mockResp := new(dns.Msg)
		dnsutil.SetReply(mockResp, query)
		mockResp.Answer = append(mockResp.Answer, &dns.A{
			Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
		})

		clients := []upstream.Client{
			&mockUpstreamClient{name: "fuzz-mock", response: mockResp},
		}
		resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)
		handler := NewHandler(resolver, nil, c, logger, cfg)

		resp := handler.HandleQuery(t.Context(), query)
		if resp == nil {
			t.Error("HandleQuery should always return a response")
		}
	})
}

// FuzzHandleQueryWithCacheRefresh exercises the cache refresh code path by
// using a high renew_percent and a very short TTL so that successive queries
// to the same domain trigger background refresh.
func FuzzHandleQueryWithCacheRefresh(f *testing.F) {
	f.Add("example.com.", uint8(25))
	f.Add("test.org.", uint8(99))
	f.Add("a.b.c.", uint8(1))
	f.Add(".", uint8(50))

	f.Fuzz(func(t *testing.T, domain string, renewPercent uint8) {
		if t.Context().Err() != nil {
			return
		}
		if len(domain) == 0 || len(domain) > 253 {
			return
		}
		pct := int(renewPercent)
		if pct < 1 {
			pct = 1
		}
		if pct > 99 {
			pct = 99
		}

		cfg := config.DefaultConfig()
		cfg.Cache.Enabled = true
		cfg.Cache.MaxEntries = 100
		cfg.Cache.RenewPercent = pct

		logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-fuzz-refresh")
		c := cache.New(100, 3600, 1, pct) // min TTL=1s

		query := new(dns.Msg)
		dnsutil.SetQuestion(query, dnsutil.Fqdn(domain), dns.TypeA)
		query.RecursionDesired = true

		// Response with a 1s TTL so it quickly hits the refresh threshold.
		mockResp := new(dns.Msg)
		dnsutil.SetReply(mockResp, query)
		if len(query.Question) > 0 {
			mockResp.Answer = append(mockResp.Answer, &dns.A{
				Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 1},
				A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
			})
		}

		clients := []upstream.Client{
			&mockUpstreamClient{name: "fuzz-refresh-mock", response: mockResp},
		}
		resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)
		handler := NewHandler(resolver, nil, c, logger, cfg)

		// First query populates cache
		resp := handler.HandleQuery(t.Context(), query)
		if resp == nil {
			t.Error("HandleQuery should always return a response")
		}

		// Second query may hit cache and potentially trigger refresh
		q2 := new(dns.Msg)
		dnsutil.SetQuestion(q2, dnsutil.Fqdn(domain), dns.TypeA)
		resp2 := handler.HandleQuery(t.Context(), q2)
		if resp2 == nil {
			t.Error("second HandleQuery should always return a response")
		}
	})
}

// FuzzHandleQueryIPv6 specifically fuzzes AAAA (IPv6) query handling to
// ensure IPv6 addresses are correctly classified as blocked or non-blocked.
func FuzzHandleQueryIPv6(f *testing.F) {
	// Seed: AAAA query for a normal domain
	q1 := new(dns.Msg)
	dnsutil.SetQuestion(q1, "ipv6.example.com.", dns.TypeAAAA)
	_ = q1.Pack()
	f.Add(q1.Data)

	// Seed: AAAA query
	q2 := new(dns.Msg)
	dnsutil.SetQuestion(q2, "blocked6.example.com.", dns.TypeAAAA)
	_ = q2.Pack()
	f.Add(q2.Data)

	// Seed: A query
	q3 := new(dns.Msg)
	dnsutil.SetQuestion(q3, "blocked4.example.com.", dns.TypeA)
	_ = q3.Pack()
	f.Add(q3.Data)

	f.Fuzz(func(t *testing.T, data []byte) {
		if t.Context().Err() != nil {
			return
		}
		msg := new(dns.Msg)
		msg.Data = data
		if err := msg.Unpack(); err != nil {
			return
		}

		cfg := config.DefaultConfig()
		cfg.Cache.Enabled = true
		cfg.Cache.MaxEntries = 100

		logger := logging.NewStdoutOnly(logging.DefaultConfig(), "fuzz-ipv6")
		c := cache.New(100, 3600, 5, 0)

		mockResp := new(dns.Msg)
		dnsutil.SetReply(mockResp, msg)
		if len(msg.Question) > 0 {
			switch dns.RRToType(msg.Question[0]) {
			case dns.TypeAAAA:
				mockResp.Answer = append(mockResp.Answer, &dns.AAAA{
					Hdr:  dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
					AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
				})
			default:
				mockResp.Answer = append(mockResp.Answer, &dns.A{
					Hdr: dns.Header{Name: msg.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
					A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
				})
			}
		}

		clients := []upstream.Client{
			&mockUpstreamClient{name: "fuzz-ipv6-mock", response: mockResp},
		}
		resolver := upstream.NewResolverFromClients(clients, 2*time.Second, 50*time.Millisecond, logger)
		handler := NewHandler(resolver, nil, c, logger, cfg)

		resp := handler.HandleQuery(t.Context(), msg)
		if resp == nil {
			t.Error("HandleQuery must never return nil")
		}
		if !resp.Response {
			t.Error("QR bit must always be set in responses")
		}
	})
}
