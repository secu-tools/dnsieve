// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package edns

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/config"
)

// FuzzPrepareUpstreamQuery fuzzes the EDNS middleware with random DNS messages.
func FuzzPrepareUpstreamQuery(f *testing.F) {
	cfg := config.DefaultConfig()
	m := NewMiddleware(cfg)

	// Seed corpus
	seeds := []struct {
		name  string
		qtype uint16
	}{
		{"example.com.", dns.TypeA},
		{"example.com.", dns.TypeAAAA},
		{"example.com.", dns.TypeMX},
		{"_dns.resolver.arpa.", dns.TypeSVCB},
		{".", dns.TypeNS},
	}
	for _, s := range seeds {
		q := dnsutil.SetQuestion(new(dns.Msg), s.name, s.qtype)
		q.RecursionDesired = true
		if err := q.Pack(); err == nil {
			f.Add(q.Data)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := new(dns.Msg)
		msg.Data = data
		if err := msg.Unpack(); err != nil {
			return
		}
		// Should not panic
		out := m.PrepareUpstreamQuery(msg, "test", false)
		if out == nil {
			t.Error("PrepareUpstreamQuery returned nil")
		}
		_ = m.PrepareUpstreamQuery(msg, "test", true)
	})
}

// FuzzProcessUpstreamResponse fuzzes response processing.
func FuzzProcessUpstreamResponse(f *testing.F) {
	cfg := config.DefaultConfig()
	m := NewMiddleware(cfg)

	q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	q.RecursionDesired = true
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)
	if err := resp.Pack(); err == nil {
		f.Add(resp.Data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := new(dns.Msg)
		msg.Data = data
		if err := msg.Unpack(); err != nil {
			return
		}
		// Should not panic
		m.ProcessUpstreamResponse(msg, "test")
	})
}

// FuzzSynthesizeDNAME fuzzes DNAME synthesis.
func FuzzSynthesizeDNAME(f *testing.F) {
	q := dnsutil.SetQuestion(new(dns.Msg), "x.example.com.", dns.TypeA)
	q.RecursionDesired = true
	if err := q.Pack(); err == nil {
		f.Add(q.Data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := new(dns.Msg)
		msg.Data = data
		if err := msg.Unpack(); err != nil {
			return
		}
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, msg)
		dname := &dns.DNAME{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		}
		dname.Target = "example.net."
		resp.Answer = append(resp.Answer, dname)
		// Should not panic
		SynthesizeDNAME(msg, resp)
	})
}
