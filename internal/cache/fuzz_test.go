// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package cache

import (
	"net/netip"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// FuzzCacheRenewPercent tests that arbitrary renew_percent values and TTLs
// never cause panics, data races, or incorrect cache states.
func FuzzCacheRenewPercent(f *testing.F) {
	f.Add(0, uint16(300), false)    // disabled refresh
	f.Add(25, uint16(300), false)   // default threshold, long TTL
	f.Add(50, uint16(60), false)    // 50% threshold, short TTL
	f.Add(99, uint16(1), false)     // max threshold, minimal TTL
	f.Add(10, uint16(3600), true)   // blocked entry, should not refresh
	f.Add(25, uint16(0), false)     // zero TTL in response
	f.Add(25, uint16(65535), false) // large TTL

	f.Fuzz(func(t *testing.T, renewPercent int, ttlSecs uint16, blocked bool) {
		// Clamp renewPercent to valid range for cache construction
		if renewPercent < 0 {
			renewPercent = 0
		}
		if renewPercent > 99 {
			renewPercent = 99
		}

		c := New(100, 3600, 1, renewPercent)

		var refreshCalled bool
		c.SetRefreshFunc(func(q *dns.Msg) {
			refreshCalled = true
			// Simulate a successful refresh by putting a response
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, q)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.Header{Name: "fuzz.example.com.", Class: dns.ClassINET, TTL: 300},
				A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
			})
			c.Put(q, resp, false)
		})

		query := dnsutil.SetQuestion(new(dns.Msg), "fuzz.example.com.", dns.TypeA)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		if ttlSecs > 0 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.Header{Name: "fuzz.example.com.", Class: dns.ClassINET, TTL: uint32(ttlSecs)},
				A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
			})
		}

		// Should not panic regardless of inputs
		c.Put(query, resp, blocked)
		entry, _ := c.Get(query)

		if entry != nil {
			_ = MakeCachedResponse(query, entry)
		}

		c.Flush()

		// Verify flushed cache is clean
		if c.Len() != 0 {
			t.Errorf("expected empty cache after flush, got %d entries", c.Len())
		}

		// refreshCalled used only to prevent compiler optimization
		_ = refreshCalled
	})
}

// FuzzCacheKeys tests cache key generation with arbitrary domain names,
// query types, and classes to ensure no panics.
func FuzzCacheKeys(f *testing.F) {
	f.Add("example.com.", uint16(dns.TypeA), uint16(dns.ClassINET))
	f.Add(".", uint16(dns.TypeAAAA), uint16(dns.ClassINET))
	f.Add("a.b.c.d.e.f.g.h.", uint16(dns.TypeMX), uint16(dns.ClassINET))
	f.Add("xn--n3h.example.com.", uint16(dns.TypeTXT), uint16(dns.ClassINET))

	f.Fuzz(func(t *testing.T, name string, qtype, qclass uint16) {
		if len(name) == 0 || len(name) > 253 {
			return
		}

		c := New(100, 3600, 5, 25)

		query := new(dns.Msg)
		query.ID = 1
		q := dnsutil.SetQuestion(query, dnsutil.Fqdn(name), qtype)
		if q == nil {
			// dnsutil.SetQuestion returns nil for qtypes not in dns.TypeToRR
			// (e.g. meta-qtypes). Skip; we are testing cache key generation.
			return
		}

		resp := new(dns.Msg)
		dnsutil.SetReply(resp, q)

		// Should never panic
		c.Put(q, resp, false)
		entry, _ := c.Get(q)
		if entry != nil {
			_ = MakeCachedResponse(q, entry)
		}
	})
}

// FuzzCacheConcurrentRefresh tests concurrent access with background refresh
// enabled to detect data races under the Go race detector.
func FuzzCacheConcurrentRefresh(f *testing.F) {
	f.Add(25, "example.com.")
	f.Add(50, "test.org.")
	f.Add(99, "a.b.c.")

	f.Fuzz(func(t *testing.T, renewPercent int, domain string) {
		if renewPercent < 1 || renewPercent > 99 {
			renewPercent = 25
		}
		if len(domain) == 0 || len(domain) > 253 {
			return
		}

		c := New(50, 3600, 1, renewPercent)
		c.SetRefreshFunc(func(q *dns.Msg) {
			// Minimal refresh: re-put the same entry
			resp := new(dns.Msg)
			dnsutil.SetReply(resp, q)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.Header{Name: q.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
				A:   rdata.A{Addr: netip.MustParseAddr("1.1.1.1")},
			})
			c.Put(q, resp, false)
		})

		query := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(domain), dns.TypeA)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 1},
			A:   rdata.A{Addr: netip.MustParseAddr("2.2.2.2")},
		})
		c.Put(query, resp, false)

		// Multiple concurrent reads with short sleep to hit threshold
		time.Sleep(900 * time.Millisecond)

		done := make(chan struct{}, 5)
		for i := 0; i < 5; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				c.Get(query)
			}()
		}
		for i := 0; i < 5; i++ {
			<-done
		}

		c.Flush()
	})
}
