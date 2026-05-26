// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package server

import (
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/idna"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// aceToUnicode converts an ACE-encoded domain name (e.g. "xn--bcher-kva.example")
// to its Unicode representation (e.g. "buecher.example"). The trailing DNS dot
// is stripped before conversion and not re-added. If conversion fails or the
// label is already ASCII-only, the original value is returned unchanged.
func aceToUnicode(ace string) string {
	clean := strings.TrimSuffix(ace, ".")
	u, err := idna.ToUnicode(clean)
	if err != nil {
		return clean
	}
	return u
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

// buildClientInfo constructs a ClientInfo from a DNS query message and the
// client transport details supplied via ClientMeta. meta may be nil (e.g.
// for internally generated queries such as cache refresh).
func buildClientInfo(query *dns.Msg, meta *ClientMeta) *logging.ClientInfo {
	if len(query.Question) == 0 {
		return nil
	}
	q := query.Question[0]
	ace := strings.TrimSuffix(q.Header().Name, ".")
	unicode := aceToUnicode(ace)

	ci := &logging.ClientInfo{
		Domain: unicode,
		QType:  dns.TypeToString[dns.RRToType(q)],
		QClass: dns.ClassToString[q.Header().Class],
	}
	if ci.QType == "" {
		ci.QType = "UNKNOWN"
	}
	if ci.QClass == "" {
		ci.QClass = "UNKNOWN"
	}
	if unicode != ace {
		ci.DomainACE = ace
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
			Address:    res.Client,
			Protocol:   res.Protocol,
			DurationMS: res.DurationMS,
		}
		if slowThreshold > 0 && time.Duration(res.DurationMS)*time.Millisecond > slowThreshold {
			info.Slow = true
		}
		if res.Err != nil {
			info.ServFail = true
			info.Error = res.Err.Error()
		} else if res.Msg != nil {
			if rcode, ok := dns.RcodeToString[uint16(res.Inspect.Rcode)]; ok {
				info.RCode = rcode
			} else {
				info.RCode = "UNKNOWN"
			}
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
					info.EDEText = o.ExtraText
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
		d.BlockedBy = result.BlockedBy
		d.BlockSource = "upstream"
	}
	return d
}

// buildBlacklistDecisionInfo builds a DecisionInfo for a local-blacklist block.
func buildBlacklistDecisionInfo(rcode string) *logging.DecisionInfo {
	return &logging.DecisionInfo{
		Blocked:     true,
		BlockedBy:   "local-blacklist",
		BlockSource: "local-blacklist",
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
	if rcode, ok := dns.RcodeToString[uint16(resp.Rcode)]; ok {
		ri.RCode = rcode
	} else {
		ri.RCode = "UNKNOWN"
	}
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
			ri.EDEText = ede.ExtraText
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

// buildCacheInfo builds a CacheInfo from a cache entry and the refresh flag.
func buildCacheInfo(entry *cache.Entry, refreshTriggered bool) *logging.CacheInfo {
	if entry == nil {
		return nil
	}
	ttlSec := int64(entry.ExpiresAt.Sub(entry.InsertedAt).Seconds())
	rtlSec := int64(time.Until(entry.ExpiresAt).Seconds())
	if rtlSec < 0 {
		rtlSec = 0
	}
	var pct float64
	if ttlSec > 0 {
		pct = float64(rtlSec) / float64(ttlSec) * 100.0
	}
	return &logging.CacheInfo{
		Hit:                        true,
		TTLSec:                     ttlSec,
		TTLRemainingSec:            rtlSec,
		TTLRemainingPct:            pct,
		Blocked:                    entry.Blocked,
		Whitelisted:                entry.Whitelisted,
		BackgroundRefreshTriggered: refreshTriggered,
		DNSSEC:                     entry.DNSSEC,
	}
}

// inspectToRCode converts an InspectResult rcode int to its string form.
func inspectToRCode(inspect dnsmsg.InspectResult) string {
	if s, ok := dns.RcodeToString[uint16(inspect.Rcode)]; ok {
		return s
	}
	return "UNKNOWN"
}
