// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package server

import (
	"encoding/hex"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/idna"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// toPunycode normalizes a bare domain name (no trailing dot) to its
// ASCII/Punycode representation. Unicode labels (e.g. those received
// verbatim in DNS wire bytes from a non-conforming client) are converted
// to their ACE form. On error the input is returned unchanged.
func toPunycode(name string) string {
	if ascii, err := idna.Lookup.ToASCII(name); err == nil {
		return ascii
	}
	return name
}

// normalizeQueryName converts a DNS question name (which may contain
// non-ASCII labels from non-conforming clients) to its Punycode/ACE form
// while preserving the trailing dot used in FQDN format.
func normalizeQueryName(name string) string {
	bare := strings.TrimSuffix(name, ".")
	if ascii, err := idna.Lookup.ToASCII(bare); err == nil {
		return ascii + "."
	}
	return name
}

// splitClientAddress parses an upstream client address string into a
// normalized address (without port) and port number for structured JSON output.
//
//   - DoH: "https://dns.quad9.net/dns-query" -> ("https://dns.quad9.net/dns-query", 443)
//   - DoH with explicit port: "https://dns.quad9.net:4343/dns-query" -> ("https://dns.quad9.net/dns-query", 4343)
//   - DoT/plain: "dns.quad9.net:853" -> ("dns.quad9.net", 853)
//
// If the address cannot be parsed, the original is returned with port 0.
func splitClientAddress(address string, protocol string) (string, int) {
	if protocol == "doh" {
		u, err := url.Parse(address)
		if err != nil {
			return address, 443
		}
		portStr := u.Port()
		port := 443
		if u.Scheme == "http" {
			port = 80
		}
		if portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
			// Rebuild URL without the explicit port in the host component.
			u.Host = u.Hostname()
		}
		return u.String(), port
	}
	// "dot", "udp", or other: address is expected to be host:port.
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return address, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// extractResolvedIPs returns the IP address strings from A and AAAA records
// in the Answer section of a DNS message. Returns nil when no address records
// are present or when msg is nil.
func extractResolvedIPs(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}
	var ips []string
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if v.Addr.IsValid() {
				ips = append(ips, v.Addr.String())
			}
		case *dns.AAAA:
			if v.Addr.IsValid() {
				ips = append(ips, v.Addr.String())
			}
		}
	}
	return ips
}

// buildRequestInfo constructs a RequestInfo from a DNS query message and the
// client transport details supplied via ClientMeta. meta may be nil (e.g.
// for internally generated queries such as cache refresh).
func buildClientInfo(query *dns.Msg, meta *ClientMeta) *logging.RequestInfo {
	if len(query.Question) == 0 {
		return nil
	}
	q := query.Question[0]
	// Always use the wire-format name stripped of trailing dot and normalized
	// to Punycode/ACE form (some clients send Unicode labels directly).
	ace := toPunycode(strings.TrimSuffix(q.Header().Name, "."))

	ci := &logging.RequestInfo{
		Domain: ace,
		QType:  dns.TypeToString[dns.RRToType(q)],
		QClass: dns.ClassToString[q.Header().Class],
	}
	if ci.QType == "" {
		ci.QType = "UNKNOWN"
	}
	if ci.QClass == "" {
		ci.QClass = "UNKNOWN"
	}
	if meta != nil {
		ci.IP = meta.IP
		ci.Port = meta.Port
		ci.Protocol = meta.Protocol
	}

	// Parse EDNS0 options from the OPT pseudo-section.
	edns := &logging.ClientEDNS{Present: false}
	for _, rr := range query.Pseudo {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		edns.Present = true
		edns.UDPSize = opt.UDPSize()
		ci.DOBit = opt.Security()
		for _, o := range opt.Options {
			if _, ok := o.(*dns.PADDING); ok {
				edns.PaddingRequested = true
			}
		}
		break
	}
	ci.EDNS = edns
	return ci
}

// buildUpstreamInfos converts the per-upstream Result slice from a fan-out
// into the UpstreamInfo slice used in structured log events.
// slowThreshold is the duration above which a result is marked as slow.
func buildUpstreamInfos(results []*upstream.Result, slowThreshold time.Duration) []*logging.UpstreamInfo {
	if len(results) == 0 {
		return nil
	}
	infos := make([]*logging.UpstreamInfo, 0, len(results))
	for _, res := range results {
		if res == nil {
			continue
		}
		info := &logging.UpstreamInfo{
			Index:      res.Index,
			Protocol:   res.Protocol,
			DurationMS: res.DurationMS,
		}
		addr, port := splitClientAddress(res.Client, res.Protocol)
		info.Address = addr
		info.Port = port
		if slowThreshold > 0 && time.Duration(res.DurationMS)*time.Millisecond > slowThreshold {
			info.Slow = true
		}
		if res.Err != nil {
			info.ServFail = true
			info.Error = res.Err.Error()
		} else if res.Msg != nil {
			info.RCode = rcodeString(uint16(res.Inspect.Rcode))
			info.Blocked = res.Inspect.Blocked
			info.ServFail = res.Inspect.ServFail
			info.HasDNSSEC = res.Inspect.HasDNSSEC
			info.ResolvedIPs = extractResolvedIPs(res.Msg)
			info.AnswerCount = len(res.Msg.Answer)
			// Extract EDNS options from the upstream response pseudo-section.
			for _, rr := range res.Msg.Pseudo {
				switch o := rr.(type) {
				case *dns.EDE:
					code := int(o.InfoCode)
					info.EDECode = &code
					info.EDEText = strings.TrimRight(o.ExtraText, "\x00")
				case *dns.NSID:
					info.NSID = decodeNSID(o.Nsid)
				}
			}
		}
		infos = append(infos, info)
	}
	return infos
}

// buildDecisionInfo builds a DecisionInfo from a FanOutResult.
// rcode is the DNS response code string returned to the client.
// cached indicates whether the result was stored in the cache.
func buildDecisionInfo(result *upstream.FanOutResult, rcode string, cached bool) *logging.DecisionInfo {
	d := &logging.DecisionInfo{
		Blocked:      result.Blocked,
		Cacheable:    cached,
		AllResponded: result.AllResponded,
		RCode:        rcode,
	}
	if result.Blocked {
		d.BlockSource = "upstream"
	}
	return d
}

// buildBlacklistDecisionInfo builds a DecisionInfo for a local blacklist block.
func buildBlacklistDecisionInfo(rcode string) *logging.DecisionInfo {
	return &logging.DecisionInfo{
		Blocked:     true,
		BlockSource: "blacklist",
		Cacheable:   false,
		RCode:       rcode,
	}
}

// buildResponseInfo constructs a ResponseInfo describing the DNS response
// that was sent to the client. Returns nil when resp is nil.
func buildResponseInfo(resp *dns.Msg) *logging.ResponseInfo {
	if resp == nil {
		return nil
	}
	ri := &logging.ResponseInfo{
		AnswerCount:    len(resp.Answer),
		Truncated:      resp.Truncated,
		AD:             resp.AuthenticatedData,
		AuthorityCount: len(resp.Ns),
	}
	ri.RCode = rcodeString(uint16(resp.Rcode))
	ri.IPs = extractResolvedIPs(resp)
	// Check for RRSIG records in Answer and Authority sections.
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			ri.HasRRSIG = true
			break
		}
	}
	if !ri.HasRRSIG {
		for _, rr := range resp.Ns {
			if _, ok := rr.(*dns.RRSIG); ok {
				ri.HasRRSIG = true
				break
			}
		}
	}
	// Extract EDE from the pseudo-section of the response.
	for _, rr := range resp.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok {
			code := int(ede.InfoCode)
			ri.EDECode = &code
			ri.EDEText = strings.TrimRight(ede.ExtraText, "\x00")
			break
		}
	}
	return ri
}

// decodeNSID decodes a hex-encoded NSID value to its UTF-8 text form.
// If the raw bytes are valid UTF-8, the decoded string is returned; otherwise
// the original lowercase hex string is returned unchanged.
func decodeNSID(hexStr string) string {
	b, err := hex.DecodeString(hexStr)
	if err != nil || !utf8.Valid(b) {
		return hexStr
	}
	return string(b)
}

// entryTTLs derives the full TTL and the remaining TTL (floored at zero) for a
// cache entry. Shared by the cache-hit log paths so they cannot report
// different numbers for the same entry.
func entryTTLs(entry *cache.Entry) (ttlSec, rtlSec int64) {
	ttlSec = int64(entry.ExpiresAt.Sub(entry.InsertedAt).Seconds())
	rtlSec = int64(time.Until(entry.ExpiresAt).Seconds())
	if rtlSec < 0 {
		rtlSec = 0
	}
	return ttlSec, rtlSec
}

// ttlRemainingPct is the remaining TTL as a percentage of the full TTL,
// rounded to two decimals. Kept separate from entryTTLs so the text-log paths
// do not pay for it.
func ttlRemainingPct(ttlSec, rtlSec int64) float64 {
	if ttlSec <= 0 {
		return 0
	}
	return math.Round(float64(rtlSec)/float64(ttlSec)*100.0*100) / 100
}

// buildCacheInfo builds a CacheInfo from a cache entry and the refresh flag.
func buildCacheInfo(entry *cache.Entry, refreshTriggered bool) *logging.CacheInfo {
	if entry == nil {
		return nil
	}
	ttlSec, rtlSec := entryTTLs(entry)
	pct := ttlRemainingPct(ttlSec, rtlSec)
	return &logging.CacheInfo{
		TTLSec:                     ttlSec,
		TTLRemainingSec:            rtlSec,
		TTLRemainingPct:            pct,
		Blocked:                    entry.Blocked,
		Whitelisted:                entry.Whitelisted,
		BackgroundRefreshTriggered: refreshTriggered,
		DNSSEC:                     entry.DNSSEC,
	}
}

// rcodeString renders a DNS rcode as its mnemonic, falling back to "UNKNOWN"
// for codes the library does not name.
func rcodeString(rcode uint16) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return "UNKNOWN"
}
