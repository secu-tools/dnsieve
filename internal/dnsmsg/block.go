// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package dnsmsg provides DNS response inspection and block-signal
// detection for multiple upstream provider conventions.
package dnsmsg

import (
	"fmt"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// blockedUDPSize is the EDNS0 UDP payload size advertised in blocked
// responses. It matches the proxy's default (RFC 9715) and ensures the
// OPT record -- which carries the EDE option -- is always included in the
// wire format even before PrepareClientResponse assigns the final value.
const blockedUDPSize uint16 = 1232

// Blocking mode constants. These correspond to the blocking.mode config value.
const (
	// BlockingModeNull returns NOERROR with 0.0.0.0 for A queries and ::
	// for AAAA queries. Other query types receive NODATA (NOERROR with
	// empty answer). Both Pi-hole and Technitium recommend this mode.
	// Connections to blocked domains fail immediately without timeout.
	BlockingModeNull = "null"

	// BlockingModeNXDomain returns NXDOMAIN with empty answer section.
	// Signals the domain does not exist. Some clients retry more
	// aggressively than with null mode.
	BlockingModeNXDomain = "nxdomain"

	// BlockingModeNODATA returns NOERROR with empty answer section.
	// Signals the domain exists but has no records of the requested type.
	// Better client acceptance than NXDOMAIN in some environments.
	BlockingModeNODATA = "nodata"

	// BlockingModeRefused returns REFUSED with empty answer section.
	// Caution: some clients may fall back to another DNS resolver.
	BlockingModeRefused = "refused"
)

// blockedTTL is the TTL used for synthesized answer records in null mode.
// Short TTL (10 seconds) since the cache layer handles long-term storage
// with its own blocked_ttl setting.
const blockedTTL uint32 = 10

// blockedSOATTL is the TTL used for the synthesized SOA record added to
// NXDOMAIN and NODATA blocked responses. Per RFC 2308, the SOA MINIMUM
// field governs the negative caching TTL seen by downstream resolvers.
const blockedSOATTL uint32 = blockedTTL

// makeSynthesizedSOA builds a minimal SOA record for inclusion in the
// Authority section of synthesized NXDOMAIN/NODATA blocked responses.
// Per RFC 2308 Section 5, the MINIMUM field of the SOA controls how long
// downstream resolvers cache the negative answer.
//
// The SOA uses a static synthetic zone identity because the proxy acts as
// an authoritative blocking resolver and does not know the real upstream
// zone. Downstream caches that honour the SOA MINIMUM will cache the
// negative answer for blockedSOATTL seconds.
func makeSynthesizedSOA(ownerName string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.Header{
			Name:  ownerName,
			Class: dns.ClassINET,
			TTL:   blockedSOATTL,
		},
		SOA: rdata.SOA{
			Ns:      "ns.dnsieve.invalid.",
			Mbox:    "hostmaster.dnsieve.invalid.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  blockedSOATTL,
		},
	}
}

// InspectResult holds the outcome of inspecting a DNS response.
type InspectResult struct {
	Blocked   bool // A blocking signal was detected
	ServFail  bool // Server failure (SERVFAIL rcode)
	NXDomain  bool // NXDOMAIN rcode (may or may not be block)
	HasDNSSEC bool // Response contains DNSSEC data (RRSIG in Answer/Authority, or AD=1)
	Rcode     int  // Raw DNS rcode
}

// InspectResponse examines a parsed DNS message and returns whether it
// represents a blocked domain, a server failure, or a normal response.
//
// Block signals recognised:
//   - A / AAAA answer containing 0.0.0.0, ::, or ::0
//   - NXDOMAIN (rcode 3) with no Authority section (Quad9-style block)
//   - NODATA with REFUSED rcode (some providers)
//
// NOT treated as blocked:
//   - NXDOMAIN with Authority section (contains SOA) = genuine NXDOMAIN
//   - SERVFAIL = server error (not a block signal)
func InspectResponse(msg *dns.Msg) InspectResult {
	if msg == nil {
		return InspectResult{ServFail: true, Rcode: dns.RcodeServerFailure}
	}

	result := InspectResult{Rcode: int(msg.Rcode)}

	// SERVFAIL
	if msg.Rcode == dns.RcodeServerFailure {
		result.ServFail = true
		return result
	}

	// BADCOOKIE (RFC 7873 Section 5.4): treat as a retryable server error.
	// Must not be cached or selected as a valid upstream response.
	if msg.Rcode == dns.RcodeBadCookie {
		result.ServFail = true
		return result
	}

	// Detect DNSSEC: AD=1 means upstream validated the chain;
	// RRSIG records mean the upstream provided signed data.
	result.HasDNSSEC = hasDNSSECData(msg)

	// REFUSED -- some providers use this as a block signal
	if msg.Rcode == dns.RcodeRefused {
		result.Blocked = true
		return result
	}

	// NXDOMAIN disambiguation (Quad9 convention):
	//   NXDOMAIN + no Authority records (NSCOUNT=0) = resolver block
	//   NXDOMAIN + Authority records (SOA)          = genuine NXDOMAIN
	if msg.Rcode == dns.RcodeNameError {
		result.NXDomain = true
		if len(msg.Ns) == 0 {
			result.Blocked = true
		}
		return result
	}

	// Check answer records for block indicators
	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if isBlockedIPv4(a.Addr) {
				result.Blocked = true
				return result
			}
		case *dns.AAAA:
			if isBlockedIPv6(a.Addr) {
				result.Blocked = true
				return result
			}
		}
	}

	return result
}

// InspectWireResponse parses raw wire-format DNS bytes and inspects them.
// Returns the parsed message (if successful) and the inspection result.
func InspectWireResponse(buf []byte) (*dns.Msg, InspectResult) {
	msg := new(dns.Msg)
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, InspectResult{ServFail: true, Rcode: dns.RcodeServerFailure}
	}
	return msg, InspectResponse(msg)
}

// hasDNSSECData returns true if the response carries DNSSEC data: either the
// AD (Authenticated Data) bit is set (upstream has validated the chain), or
// RRSIG records are present in the Answer or Authority section (upstream
// returned signed data for a validating client to verify).
func hasDNSSECData(msg *dns.Msg) bool {
	if msg.AuthenticatedData {
		return true
	}
	for _, rr := range msg.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}
	for _, rr := range msg.Ns {
		if _, ok := rr.(*dns.RRSIG); ok {
			return true
		}
	}
	return false
}

// isBlockedIPv4 checks whether an IPv4 address is a known block indicator.
// Known block IPs: 0.0.0.0
func isBlockedIPv4(addr netip.Addr) bool {
	return addr.Is4() && addr == netip.AddrFrom4([4]byte{})
}

// isBlockedIPv6 checks whether an IPv6 address is a known block indicator.
// Known block IPs: ::
func isBlockedIPv6(addr netip.Addr) bool {
	return addr.Is6() && addr == netip.IPv6Unspecified()
}

// MakeBlockedResponse creates a DNS response that signals a blocked domain
// to the client using the specified blocking mode.
//
// Modes (following Pi-hole and Technitium conventions):
//
//   - "null" (default, recommended): NOERROR with 0.0.0.0 for A / :: for AAAA.
//     Other query types get NODATA (NOERROR, empty answer). Clients see an
//     immediate connection failure. 0.0.0.0 is "this host on this network"
//     (RFC 1122 Section 3.2.1.3); :: is the unspecified address (RFC 4291
//     Section 2.5.2). Both Pi-hole and Technitium default to this mode.
//
//   - "nxdomain": NXDOMAIN with empty answer. Domain does not exist.
//
//   - "nodata": NOERROR with empty answer. Domain exists but no records.
//
//   - "refused": REFUSED with empty answer. Server refuses the query.
//
// All modes include Extended DNS Error (EDE) code 15 (Blocked) per RFC 8914
// section 4.16. The extraText includes which upstream detected the block.
//
// The blockedBy parameter identifies the upstream that signalled the block
// (e.g., "dns.quad9.net"). Pass empty string for cached blocked responses.
func MakeBlockedResponse(query *dns.Msg, mode string, blockedBy string) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Authoritative = false
	resp.RecursionAvailable = true

	// Ensure the OPT record is emitted during Pack even if PrepareClientResponse
	// has not yet run. The EDE option is carried inside the OPT record.
	resp.UDPSize = blockedUDPSize

	// Build EDE extra text with upstream identification.
	edeText := "Blocked"
	if blockedBy != "" {
		edeText = fmt.Sprintf("Blocked (%s)", blockedBy)
	}

	// RFC 8914 EDE code 15 (Blocked): informs the client that the upstream
	// filter deliberately blocked this domain.
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{
		InfoCode:  dns.ExtendedErrorBlocked,
		ExtraText: edeText,
	})

	switch mode {
	case BlockingModeNXDomain:
		resp.Rcode = dns.RcodeNameError
		// RFC 2308: include a synthesized SOA in the Authority section so
		// that downstream resolvers cache the negative answer correctly and
		// interpret the MINIMUM field as the negative TTL.
		if len(query.Question) > 0 {
			resp.Ns = append(resp.Ns, makeSynthesizedSOA(query.Question[0].Header().Name))
		}

	case BlockingModeNODATA:
		resp.Rcode = dns.RcodeSuccess
		// RFC 2308: include a synthesized SOA in the Authority section for
		// NODATA responses so downstream caches observe the negative TTL.
		if len(query.Question) > 0 {
			resp.Ns = append(resp.Ns, makeSynthesizedSOA(query.Question[0].Header().Name))
		}

	case BlockingModeRefused:
		resp.Rcode = dns.RcodeRefused
		// No answer section -- server refuses

	default: // BlockingModeNull (default, recommended)
		resp.Rcode = dns.RcodeSuccess
		if len(query.Question) > 0 {
			qtype := dns.RRToType(query.Question[0])
			qname := query.Question[0].Header().Name
			switch qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.Header{
						Name:  qname,
						Class: dns.ClassINET,
						TTL:   blockedTTL,
					},
					A: rdata.A{Addr: netip.AddrFrom4([4]byte{0, 0, 0, 0})},
				})
			case dns.TypeAAAA:
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr: dns.Header{
						Name:  qname,
						Class: dns.ClassINET,
						TTL:   blockedTTL,
					},
					AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
				})
			default:
				// NODATA for all other types -- domain exists, no records
			}
		}
	}

	return resp
}

// AllServersAgree checks whether all non-error responses agree on being
// NXDOMAIN. Returns true only if every result has NXDomain=true and
// Blocked=false (genuine NXDOMAIN, not a block).
func AllServersAgree(results []InspectResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if r.ServFail {
			continue // skip server errors
		}
		if !r.NXDomain || r.Blocked {
			return false // either not NXDOMAIN or a blocked NXDOMAIN (e.g. Quad9)
		}
	}
	return true
}

// ExtractMinTTL returns the minimum TTL from all answer and authority
// records in a DNS message. Returns 0 if no records are found.
func ExtractMinTTL(msg *dns.Msg) uint32 {
	if msg == nil {
		return 0
	}
	var minTTL uint32
	first := true
	for _, rr := range msg.Answer {
		ttl := rr.Header().TTL
		if first || ttl < minTTL {
			minTTL = ttl
			first = false
		}
	}
	for _, rr := range msg.Ns {
		ttl := rr.Header().TTL
		if first || ttl < minTTL {
			minTTL = ttl
			first = false
		}
	}
	if first {
		return 0
	}
	return minTTL
}
