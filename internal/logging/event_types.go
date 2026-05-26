// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package logging

import "time"

// TypeGeneral is used for informational or operational messages that are not
// tied to a specific DNS query (e.g. startup, config loaded, errors).
const TypeGeneral = "general"

// TypeDNSQuery is used for structured DNS query resolution events. It covers
// upstream fan-out, cache hits, blocked domains, and whitelist/blacklist
// decisions. Rich structured sub-fields (Client, Upstream, Decision, Cache)
// carry all available per-query detail.
const TypeDNSQuery = "dns_query"

// Event is the top-level structure for all structured JSON log lines.
// Fields that do not apply to a given event type are omitted (nil pointers
// or zero values are dropped by json.Marshal with omitempty).
type Event struct {
	// Timestamp is the RFC 3339 Nano UTC time when the event was recorded.
	Timestamp string `json:"timestamp"`
	// Level is the log severity: "DEBUG", "INFO", "WARN", "ERROR", "FATAL".
	Level string `json:"level"`
	// Type classifies the event: TypeGeneral or TypeDNSQuery.
	Type string `json:"type"`
	// Message is a human-readable summary of the event.
	Message string `json:"message"`
	// Module identifies the subsystem that produced the event (e.g. "server").
	Module string `json:"module,omitempty"`

	// DNS is populated only when Type == TypeDNSQuery. It groups all
	// per-query structured detail so that general events remain compact.
	DNS *DNSInfo `json:"dns,omitempty"`
}

// DNSInfo groups all structured fields for a single DNS query resolution
// event. It is always non-nil when Event.Type == TypeDNSQuery.
type DNSInfo struct {
	// Client describes the DNS client that sent the query.
	Client *ClientInfo `json:"client,omitempty"`
	// Upstream lists per-upstream resolution results (fan-out).
	// Empty when the response was served entirely from cache.
	Upstream []*UpstreamInfo `json:"upstream,omitempty"`
	// Decision describes what DNSieve decided to return to the client.
	// Nil when the response came from the cache (see Cache instead).
	Decision *DecisionInfo `json:"decision,omitempty"`
	// Cache describes a cache hit. Nil when the query went to upstream.
	Cache *CacheInfo `json:"cache,omitempty"`
	// Response describes the DNS response that was actually sent to the client.
	// It is always populated for dns_query events, regardless of whether the
	// response came from cache, upstream, or a local block decision. This is
	// the authoritative record of what the client received.
	Response *ResponseInfo `json:"response,omitempty"`
}

// ResponseInfo describes the DNS response that was sent back to the client.
// Unlike the upstream results (which may differ per-server in a fan-out),
// this reflects the single, final answer the client actually received.
type ResponseInfo struct {
	// RCode is the DNS response code returned to the client,
	// e.g. "NOERROR", "NXDOMAIN", "SERVFAIL".
	RCode string `json:"rcode,omitempty"`
	// AnswerCount is the number of records in the answer section of the
	// response sent to the client.
	AnswerCount int `json:"answer_count,omitempty"`
	// IPs contains IPv4 and IPv6 addresses from A and AAAA records in the
	// answer section of the response sent to the client.
	// Only present for address queries with at least one resolved address.
	IPs []string `json:"ips,omitempty"`
	// Truncated is true when the TC (Truncated) bit was set in the response,
	// indicating the client should retry over TCP to retrieve the full answer.
	Truncated bool `json:"truncated,omitempty"`
}

// ClientInfo describes the DNS client that sent the query.
type ClientInfo struct {
	// IP is the client's remote IP address (IPv4 or IPv6).
	IP string `json:"ip,omitempty"`
	// Port is the client's source port number.
	Port int `json:"port,omitempty"`
	// Protocol is the downstream transport used by the client:
	// "plain" (UDP/TCP), "dot" (DNS-over-TLS), or "doh" (DNS-over-HTTPS).
	Protocol string `json:"protocol,omitempty"`
	// Domain is the requested name in Unicode form.
	// Internationalized labels (xn-- ACE) are decoded to their Unicode
	// representation so that e.g. "xn--bcher-kva.example" appears as
	// "buecher.example" in the log.
	Domain string `json:"domain"`
	// DomainACE is the ACE/Punycode form of the domain name as it appears
	// in the DNS wire format. Populated only when it differs from Domain
	// (i.e. when the name contains one or more internationalized labels).
	DomainACE string `json:"domain_ace,omitempty"`
	// QType is the DNS query type string, e.g. "A", "AAAA", "MX", "TXT".
	QType string `json:"qtype"`
	// QClass is the DNS query class string, e.g. "IN".
	QClass string `json:"qclass"`
	// DOBit is true when the client set the DNSSEC OK bit in its OPT record.
	DOBit bool `json:"do_bit,omitempty"`
	// EDNS summarises EDNS0 options present in the client query.
	EDNS *ClientEDNS `json:"edns,omitempty"`
}

// ClientEDNS summarises EDNS0 options present in the client query.
type ClientEDNS struct {
	// Present is true when the client sent an OPT record.
	Present bool `json:"present"`
	// UDPSize is the client-advertised UDP payload size (from OPT record).
	// Zero when Present is false.
	UDPSize uint16 `json:"udp_size,omitempty"`
	// PaddingRequested is true when the client included an EDNS Padding
	// option (RFC 7830), requesting that the server add padding to the reply.
	PaddingRequested bool `json:"padding_requested,omitempty"`
}

// UpstreamInfo describes one upstream server's result for a fan-out query.
type UpstreamInfo struct {
	// Index is the zero-based priority position of this upstream in the
	// configured upstream list (lower = higher priority).
	Index int `json:"index"`
	// Address is the configured upstream address, e.g.
	// "https://dns.quad9.net/dns-query" or "dns.quad9.net:853".
	Address string `json:"address"`
	// Protocol is the transport used to reach this upstream:
	// "doh", "dot", or "udp".
	Protocol string `json:"protocol,omitempty"`
	// DurationMS is the wall-clock time taken for this upstream query in
	// milliseconds, measured from just before sending to just after receiving.
	DurationMS int64 `json:"duration_ms"`
	// Slow is true when DurationMS exceeded the configured slow_upstream_ms
	// threshold, indicating a potentially degraded upstream.
	Slow bool `json:"slow,omitempty"`
	// RCode is the DNS response code string returned by this upstream,
	// e.g. "NOERROR", "NXDOMAIN", "SERVFAIL".
	// Empty when the upstream returned an error (see Error).
	RCode string `json:"rcode,omitempty"`
	// Blocked is true when this upstream signalled that the domain is blocked.
	Blocked bool `json:"blocked,omitempty"`
	// ServFail is true when this upstream returned SERVFAIL or an error.
	ServFail bool `json:"servfail,omitempty"`
	// HasDNSSEC is true when the response includes DNSSEC data (RRSIG
	// records in the answer/authority or AD=1).
	HasDNSSEC bool `json:"dnssec,omitempty"`
	// ResolvedIPs lists IP addresses extracted from the A and AAAA records
	// in the upstream Answer section. Empty for non-address query types.
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
	// AnswerCount is the total number of records in the upstream Answer section.
	AnswerCount int `json:"answer_count,omitempty"`
	// Error contains the upstream error message when the query failed.
	// Empty on success.
	Error string `json:"error,omitempty"`
}

// DecisionInfo describes the resolution decision made by DNSieve and returned
// to the client. Populated when the query was resolved via upstream servers
// (not from cache). For cache hits use CacheInfo instead.
type DecisionInfo struct {
	// Blocked is true when the domain was blocked, either by an upstream
	// server or by the local blacklist.
	Blocked bool `json:"blocked"`
	// BlockedBy is the upstream address that signalled the block (e.g.
	// "https://dns.quad9.net/dns-query") or "local-blacklist" for local
	// blacklist matches. Empty when Blocked is false.
	BlockedBy string `json:"blocked_by,omitempty"`
	// BlockSource is "upstream" when a remote server signalled the block,
	// or "local-blacklist" when the local blacklist triggered the block.
	// Empty when Blocked is false.
	BlockSource string `json:"block_source,omitempty"`
	// Cacheable is true when the result was stored in the cache.
	Cacheable bool `json:"cacheable"`
	// AllResponded is true when every configured upstream server returned
	// a valid (non-error) response. False indicates partial upstream failure.
	AllResponded bool `json:"all_responded,omitempty"`
	// RCode is the DNS response code string returned to the client, e.g.
	// "NOERROR", "NXDOMAIN", "SERVFAIL".
	RCode string `json:"rcode,omitempty"`
}

// CacheInfo describes a response that was served from the local cache without
// querying any upstream server.
type CacheInfo struct {
	// Hit is always true for CacheInfo (included for schema clarity in
	// queries where either cache or upstream may be present).
	Hit bool `json:"hit"`
	// TTLSec is the original total TTL of the cached entry in seconds,
	// measured from the time the entry was first inserted.
	TTLSec int64 `json:"ttl_sec"`
	// TTLRemainingSec is the time remaining until the cache entry expires,
	// in seconds, measured at the moment the entry was served.
	TTLRemainingSec int64 `json:"ttl_remaining_sec"`
	// TTLRemainingPct is the remaining TTL expressed as a percentage of the
	// original TTL (0-100, two decimal places of precision).
	TTLRemainingPct float64 `json:"ttl_remaining_pct"`
	// Blocked is true when the cached entry is a blocked-domain response.
	Blocked bool `json:"blocked,omitempty"`
	// Whitelisted is true when the cached entry was stored from a query
	// resolved via the whitelist resolver rather than the standard upstreams.
	Whitelisted bool `json:"whitelisted,omitempty"`
	// BackgroundRefreshTriggered is true when a proactive background cache
	// refresh was started because the remaining TTL fell below the configured
	// renew_percent threshold. The current (still valid) entry is returned
	// while the refresh runs in the background.
	BackgroundRefreshTriggered bool `json:"background_refresh_triggered,omitempty"`
	// DNSSEC is true when the cached entry was stored from a DO=1 query.
	DNSSEC bool `json:"dnssec,omitempty"`
}

// NewGeneralEvent returns an Event of TypeGeneral with the timestamp set to
// the current UTC time. It is used by Infof/Warnf/etc. to wrap plain-text
// log messages as JSON when JSON output is enabled.
func NewGeneralEvent(level Level, module, message string) *Event {
	return &Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Type:      TypeGeneral,
		Message:   message,
		Module:    module,
	}
}

// NewDNSQueryEvent returns an Event of TypeDNSQuery with the timestamp set to
// the current UTC time. Callers should populate the DNS sub-fields
// (DNS.Client, DNS.Upstream, DNS.Decision, DNS.Cache) as appropriate before
// passing to LogEvent.
func NewDNSQueryEvent(level Level, module, message string) *Event {
	return &Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Type:      TypeDNSQuery,
		Message:   message,
		Module:    module,
		DNS:       &DNSInfo{},
	}
}
