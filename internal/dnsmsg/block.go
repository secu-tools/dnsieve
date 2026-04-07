// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package dnsmsg provides DNS response inspection and block-signal
// detection for multiple upstream provider conventions.
package dnsmsg

import (
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// blockedUDPSize is the EDNS0 UDP payload size advertised in blocked
// responses. It matches the proxy's default (RFC 9715) and ensures the
// OPT record -- which carries the EDE option -- is always included in the
// wire format even before PrepareClientResponse assigns the final value.
const blockedUDPSize uint16 = 1232

// InspectResult holds the outcome of inspecting a DNS response.
type InspectResult struct {
	Blocked  bool // A blocking signal was detected
	ServFail bool // Server failure (SERVFAIL rcode)
	NXDomain bool // NXDOMAIN rcode (may or may not be block)
	Rcode    int  // Raw DNS rcode
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
// to the client.
//
// The response uses REFUSED (rcode 5) with no Answer section and includes an
// Extended DNS Error (EDE) option with InfoCode 15 (Blocked) per RFC 8914
// section 4.16. REFUSED is semantically correct for policy-based denial and
// avoids DNSSEC validation problems caused by NXDOMAIN and spoofed addresses:
// DNSSEC-validating resolvers such as Pi-hole/dnsmasq only validate NOERROR
// and NXDOMAIN responses; REFUSED is returned to the downstream client
// immediately without DNSSEC processing (dnsmasq forward.c process_reply).
// The EDE Blocked (15) code signals to supporting clients that the upstream
// filter intentionally blocked the domain, as opposed to a network error.
//
// Note: Pi-hole with --dnssec validation will still log the query as BOGUS
// because dnsmasq retries the query once on REFUSED, then classifies the
// result as STAT_ABANDONED. The actual DNS response forwarded to the end
// client is REFUSED + EDE 15. Correct behavior for clients that do not
// perform their own DNSSEC validation, or for Pi-hole in --proxy-dnssec mode.
func MakeBlockedResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Rcode = dns.RcodeRefused
	resp.Authoritative = false
	resp.RecursionAvailable = true

	// Ensure the OPT record is emitted during Pack even if PrepareClientResponse
	// has not yet run. The EDE option is carried inside the OPT record.
	resp.UDPSize = blockedUDPSize

	// RFC 8914 EDE code 15 (Blocked): informs the client that the upstream
	// filter deliberately blocked this domain, as opposed to a genuine error.
	resp.Pseudo = append(resp.Pseudo, &dns.EDE{
		InfoCode:  dns.ExtendedErrorBlocked,
		ExtraText: "Blocked",
	})

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
