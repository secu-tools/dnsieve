// SPDX-License-Identifier: MIT
package dnsmsg

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// FuzzInspectWireResponse fuzz-tests the DNS wire format parser and
// block inspection logic to ensure no panics on malformed input.
func FuzzInspectWireResponse(f *testing.F) {
	// Seed corpus with valid DNS messages
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	if err := query.Pack(); err == nil {
		wire := make([]byte, len(query.Data))
		copy(wire, query.Data)
		f.Add(wire)
	}

	// Response message
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
	})
	if err := resp.Pack(); err == nil {
		wireResp := make([]byte, len(resp.Data))
		copy(wireResp, resp.Data)
		f.Add(wireResp)
	}

	// NXDOMAIN with SOA
	nxResp := new(dns.Msg)
	dnsutil.SetReply(nxResp, query)
	nxResp.Rcode = dns.RcodeNameError
	nxResp.Ns = append(nxResp.Ns, &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900},
		SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com."},
	})
	if err := nxResp.Pack(); err == nil {
		wireNX := make([]byte, len(nxResp.Data))
		copy(wireNX, nxResp.Data)
		f.Add(wireNX)
	}

	// Minimal valid DNS header only
	f.Add([]byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Empty
	f.Add([]byte{})

	// Some garbage
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		// This should never panic regardless of input
		msg, result := InspectWireResponse(data)

		// If the message was unpacked, inspect it individually
		if msg != nil {
			_ = InspectResponse(msg)
			_ = ExtractMinTTL(msg)
		}
		// The result should always be valid
		if result.Blocked && result.ServFail {
			t.Error("result cannot be both blocked and servfail")
		}
	})
}
