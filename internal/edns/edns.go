// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package edns handles EDNS0 option processing for the DNSieve proxy.
// It rebuilds the OPT record from scratch when forwarding queries to
// upstream servers (RFC 6891), handles ECS stripping/substitution
// (RFC 7871), cookie management (RFC 7873), NSID (RFC 5001), TCP
// keepalive (RFC 7828), buffer size limits (RFC 9715), DO bit
// forwarding (RFC 3225), and EDE pass-through (RFC 8914).
package edns

import (
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/svcb"

	"github.com/secu-tools/dnsieve/internal/config"
)

// MaxUDPPayload is the recommended maximum UDP payload size per RFC 9715.
const MaxUDPPayload = 1232

// Middleware processes EDNS0 options on queries and responses according
// to the configured privacy policy.
type Middleware struct {
	cfg     *config.Config
	cookies *cookieStore
}

// NewMiddleware creates an EDNS middleware from config.
func NewMiddleware(cfg *config.Config) *Middleware {
	m := &Middleware{cfg: cfg}
	if cfg.Privacy.Cookies.Mode == "reoriginate" {
		m.cookies = newCookieStore()
	}
	return m
}

// --- Query Processing (client -> proxy -> upstream) ---

// PrepareUpstreamQuery rebuilds the OPT record from scratch for forwarding
// to an upstream server. The client's OPT record is NOT copied.
// Per RFC 6891: proxies should build their own OPT record.
//
// Parameters:
//   - query: the original client query (will not be modified)
//   - upstreamAddr: address of the target upstream (for cookie state)
//   - isTCP: whether the upstream connection uses TCP
//
// Returns a new query message ready to send upstream.
func (m *Middleware) PrepareUpstreamQuery(query *dns.Msg, upstreamAddr string, isTCP bool) *dns.Msg {
	// Build a fresh upstream message instead of query.Copy().
	// query.Copy() propagates the unexported msgPool field from the original
	// request, which is the server's buffer pool.  When the upstream client
	// later calls WriteTo on the copy, the library returns the packed-query
	// slice (small, exact-fit allocation) back to that pool.  The next UDP
	// recvmmsg call then draws a too-small buffer from the pool and panics
	// with "slice bounds out of range" when a larger packet arrives.
	// Creating a clean struct literal leaves msgPool nil, preventing the leak.
	out := &dns.Msg{
		MsgHeader: query.MsgHeader,
		Question:  query.Question,
	}
	// Data is nil in the struct literal above - Pack will allocate fresh
	// memory when the message is sent.  No need to nil it explicitly.

	// Strip the client's entire OPT/Pseudo section - we rebuild from scratch
	out.Pseudo = nil

	// Set message-level EDNS flags that the library uses to construct the OPT RR.
	// RFC 9715: advertise 1232 bytes for UDP, max for TCP
	if isTCP {
		out.UDPSize = 65535
	} else {
		out.UDPSize = MaxUDPPayload
	}

	// RFC 3225: always request DNSSEC data from upstream so that validated
	// responses (with AD=1) are returned. Clients that did not set DO=1 will
	// receive the correct AD bit and can verify the chain; any RRSIG records
	// in the response are benign for clients that did not request them.
	out.Security = true

	// RFC 7871: ECS handling
	m.addECSOption(query, out)

	// RFC 7873: Cookie handling
	m.addCookieOption(out, upstreamAddr)

	// RFC 5001: NSID handling
	m.addNSIDOption(query, out)

	// RFC 7828: TCP keepalive
	if isTCP {
		m.addKeepaliveOption(out, true)
	}

	return out
}

// ProcessUpstreamResponse processes an upstream response before returning
// it to the client. Handles cookie state, EDE forwarding, NSID, etc.
//
// The response is modified in-place.
func (m *Middleware) ProcessUpstreamResponse(resp *dns.Msg, upstreamAddr string) {
	if resp == nil {
		return
	}

	// Process each EDNS0 option in the response
	var kept []dns.RR
	for _, rr := range resp.Pseudo {
		switch o := rr.(type) {
		case *dns.COOKIE:
			// Strip cookies from the response sent to clients. Per-upstream
			// cookie state is updated at the resolver layer via
			// ProcessResponseCookieOnly, which uses the correct upstream address.
			continue
		case *dns.NSID:
			if m.cfg.Privacy.NSID.Mode == "strip" {
				continue
			}
			if m.cfg.Privacy.NSID.Mode == "substitute" {
				o.Nsid = hex.EncodeToString([]byte(m.cfg.Privacy.NSID.Value))
			}
			// "forward" mode: keep as-is
			kept = append(kept, o)
		case *dns.SUBNET:
			if m.cfg.Privacy.ECS.Mode == "strip" {
				continue
			}
			kept = append(kept, o)
		case *dns.TCPKEEPALIVE:
			// Strip upstream keepalive; we set our own for clients
			continue
		case *dns.EDE:
			// RFC 8914: forward EDE as-is
			kept = append(kept, o)
		case *dns.OPT:
			// Drop the upstream's OPT record; the proxy manages its own OPT
			// via message-level UDPSize and Security fields (PrepareClientResponse).
			continue
		default:
			kept = append(kept, rr)
		}
	}
	resp.Pseudo = kept
}

// PrepareClientResponse adds proxy-specific EDNS0 options to a response
// being sent to a client (e.g., TCP keepalive, buffer size).
// clientHasEDNS must be true when the originating query contained an OPT
// record; per RFC 6891, an OPT RR must not be added to the response if the
// client did not send one. When false, any EDNS0 options already present on
// resp (such as EDE from MakeBlockedResponse) are cleared before sending.
func (m *Middleware) PrepareClientResponse(resp *dns.Msg, isTCP bool, clientHasEDNS bool) {
	if resp == nil {
		return
	}

	if !clientHasEDNS {
		// RFC 6891: do not include OPT in the response to a non-EDNS query.
		// Clear UDPSize so the library does not emit an OPT record, and remove
		// any EDNS0 options already attached (e.g. EDE from blocked responses).
		resp.UDPSize = 0
		resp.Security = false
		resp.Pseudo = nil
		return
	}

	// RFC 9715: advertise the proxy's UDP payload size.
	resp.UDPSize = MaxUDPPayload

	// RFC 7828: TCP keepalive for client connections.
	if isTCP {
		m.addKeepaliveOption(resp, false)
	}
}

// ClientHasEDNS reports whether the client query contained an OPT record.
// After a full Unpack(), UDPSize is non-zero whenever the query carried OPT.
func ClientHasEDNS(query *dns.Msg) bool {
	if query == nil {
		return false
	}
	return query.UDPSize > 0
}

// --- DO Bit Helpers ---

// ClientRequestsDNSSEC returns true if the client query has DO=1.
func ClientRequestsDNSSEC(query *dns.Msg) bool {
	return clientRequestsDNSSEC(query)
}

func clientRequestsDNSSEC(query *dns.Msg) bool {
	if query == nil {
		return false
	}
	for _, rr := range query.Pseudo {
		if opt, ok := rr.(*dns.OPT); ok {
			return opt.Security()
		}
	}
	return false
}

// --- ECS Handling (RFC 7871) ---

func (m *Middleware) addECSOption(clientQuery *dns.Msg, out *dns.Msg) {
	switch m.cfg.Privacy.ECS.Mode {
	case "strip":
		// Do not add ECS
		return
	case "forward":
		// Copy client's ECS if present
		if ecs := findECS(clientQuery); ecs != nil {
			out.Pseudo = append(out.Pseudo, ecs.Clone().(dns.EDNS0))
		}
	case "substitute":
		ecs := buildSubstituteECS(m.cfg.Privacy.ECS.Subnet)
		if ecs != nil {
			out.Pseudo = append(out.Pseudo, ecs)
		}
	}
}

func findECS(msg *dns.Msg) *dns.SUBNET {
	if msg == nil {
		return nil
	}
	for _, rr := range msg.Pseudo {
		if s, ok := rr.(*dns.SUBNET); ok {
			return s
		}
	}
	return nil
}

func buildSubstituteECS(subnet string) *dns.SUBNET {
	if subnet == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil
	}
	ecs := &dns.SUBNET{
		Address: prefix.Addr(),
		Netmask: uint8(prefix.Bits()),
		Scope:   0,
	}
	if prefix.Addr().Is4() {
		ecs.Family = 1
	} else {
		ecs.Family = 2
	}
	return ecs
}

// --- Cookie Handling (RFC 7873) ---

// cookieStore maintains per-upstream cookie state for reoriginate mode.
type cookieStore struct {
	mu      sync.RWMutex
	clients map[string]string // upstreamAddr -> our client cookie (hex, 16 chars = 8 bytes)
	servers map[string]string // upstreamAddr -> server cookie (hex)
}

func newCookieStore() *cookieStore {
	return &cookieStore{
		clients: make(map[string]string),
		servers: make(map[string]string),
	}
}

func (cs *cookieStore) getClientCookie(upstream string) string {
	cs.mu.RLock()
	c, ok := cs.clients[upstream]
	cs.mu.RUnlock()
	if ok {
		return c
	}

	// Generate new 8-byte client cookie
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	cookie := hex.EncodeToString(b)

	cs.mu.Lock()
	cs.clients[upstream] = cookie
	cs.mu.Unlock()
	return cookie
}

func (cs *cookieStore) getServerCookie(upstream string) string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.servers[upstream]
}

func (cs *cookieStore) setServerCookie(upstream, cookie string) {
	cs.mu.Lock()
	cs.servers[upstream] = cookie
	cs.mu.Unlock()
}

func (m *Middleware) addCookieOption(out *dns.Msg, upstreamAddr string) {
	switch m.cfg.Privacy.Cookies.Mode {
	case "strip":
		return
	case "reoriginate":
		if m.cookies == nil {
			return
		}
		clientCookie := m.cookies.getClientCookie(upstreamAddr)
		serverCookie := m.cookies.getServerCookie(upstreamAddr)
		cookie := &dns.COOKIE{Cookie: clientCookie + serverCookie}
		out.Pseudo = append(out.Pseudo, cookie)
	}
}

// ProcessResponseCookieOnly extracts the server cookie from an upstream
// response and stores it for the given upstream address. This must be
// called per-upstream immediately after each response is received so that
// the correct upstream address is associated with the cookie state. It does
// NOT strip the cookie from the message (that is done by
// ProcessUpstreamResponse when the best response is assembled for the client).
func (m *Middleware) ProcessResponseCookieOnly(resp *dns.Msg, upstreamAddr string) {
	if resp == nil {
		return
	}
	for _, rr := range resp.Pseudo {
		if cookie, ok := rr.(*dns.COOKIE); ok {
			m.processResponseCookie(cookie, upstreamAddr)
			return
		}
	}
}

func (m *Middleware) processResponseCookie(cookie *dns.COOKIE, upstreamAddr string) {
	if m.cfg.Privacy.Cookies.Mode != "reoriginate" || m.cookies == nil {
		return
	}
	// RFC 7873 s4.1: the client cookie is exactly 8 bytes (16 hex chars).
	// Server cookies must be 8-32 bytes (16-64 hex chars). Reject anything
	// outside that range; an oversized cookie from a rogue upstream is dropped.
	// Total valid range: 32 (16 client + 16 server min) to 80 (16+64 server max).
	if len(cookie.Cookie) < 32 || len(cookie.Cookie) > 80 {
		return
	}
	m.cookies.setServerCookie(upstreamAddr, cookie.Cookie[16:])
}

// --- NSID Handling (RFC 5001) ---

func (m *Middleware) addNSIDOption(clientQuery *dns.Msg, out *dns.Msg) {
	switch m.cfg.Privacy.NSID.Mode {
	case "strip":
		return
	case "forward":
		// Forward only if client requested NSID
		if hasNSID(clientQuery) {
			out.Pseudo = append(out.Pseudo, &dns.NSID{})
		}
	case "substitute":
		// Do not forward NSID to upstream; we handle it ourselves
		return
	}
}

// HandleNSIDSubstitute checks if the client requested NSID and we are in
// substitute mode. If so, adds our NSID to the response.
func (m *Middleware) HandleNSIDSubstitute(clientQuery, resp *dns.Msg) {
	if m.cfg.Privacy.NSID.Mode != "substitute" {
		return
	}
	if !hasNSID(clientQuery) {
		return
	}
	nsid := &dns.NSID{Nsid: hex.EncodeToString([]byte(m.cfg.Privacy.NSID.Value))}
	resp.Pseudo = append(resp.Pseudo, nsid)
}

func hasNSID(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Pseudo {
		if _, ok := rr.(*dns.NSID); ok {
			return true
		}
	}
	return false
}

// --- TCP Keepalive (RFC 7828) ---

func (m *Middleware) addKeepaliveOption(out *dns.Msg, forUpstream bool) {
	var timeoutSec int
	if forUpstream {
		timeoutSec = m.cfg.TCPKeepalive.UpstreamTimeoutSec
	} else {
		timeoutSec = m.cfg.TCPKeepalive.ClientTimeoutSec
	}
	// RFC 7828: timeout in units of 100 milliseconds
	ka := &dns.TCPKEEPALIVE{Timeout: uint16(timeoutSec * 10)}
	out.Pseudo = append(out.Pseudo, ka)
}

// --- DNAME Synthesis (RFC 6672) ---

// SynthesizeDNAME checks whether a DNS response contains a DNAME record
// that requires CNAME synthesis. Per RFC 6672, when a DNAME record matches
// a query, a synthetic CNAME must be present. If the upstream did not
// include it, this function synthesizes one.
func SynthesizeDNAME(query, resp *dns.Msg) {
	if resp == nil || len(query.Question) == 0 {
		return
	}
	qname := strings.ToLower(query.Question[0].Header().Name)

	for _, rr := range resp.Answer {
		dname, ok := rr.(*dns.DNAME)
		if !ok {
			continue
		}
		owner := strings.ToLower(dname.Header().Name)

		// Check if qname is under the DNAME owner
		if !isDNAMEMatch(qname, owner) {
			continue
		}

		// Check if a CNAME for qname already exists in the answer
		if hasCNAMEFor(resp, qname) {
			return
		}

		// Synthesize: replace owner suffix with DNAME target
		target := synthesizeCNAMETarget(qname, owner, dname.Target)
		if target == "" {
			continue
		}

		cname := &dns.CNAME{
			Hdr: dns.Header{
				Name:  query.Question[0].Header().Name,
				Class: dns.ClassINET,
				TTL:   dname.Header().TTL,
			},
		}
		cname.Target = target

		// Insert CNAME right after the DNAME in the answer section
		newAnswer := make([]dns.RR, 0, len(resp.Answer)+1)
		for _, a := range resp.Answer {
			newAnswer = append(newAnswer, a)
			if a == rr {
				newAnswer = append(newAnswer, cname)
			}
		}
		resp.Answer = newAnswer
		return
	}
}

func isDNAMEMatch(qname, owner string) bool {
	if qname == owner {
		return false // DNAME doesn't match the owner itself
	}
	return strings.HasSuffix(qname, "."+owner)
}

func hasCNAMEFor(resp *dns.Msg, qname string) bool {
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			if strings.ToLower(rr.Header().Name) == qname {
				return true
			}
		}
	}
	return false
}

func synthesizeCNAMETarget(qname, owner, target string) string {
	// qname = "x.example.com.", owner = "example.com.", target = "example.net."
	// result = "x.example.net."
	prefix := qname[:len(qname)-len(owner)]
	return prefix + target
}

// --- DDR (RFC 9461/9462) ---

// HandleDDR checks if the query is for _dns.resolver.arpa and generates
// a SVCB response advertising the proxy's encrypted endpoints.
func HandleDDR(query *dns.Msg, cfg *config.Config) *dns.Msg {
	if !cfg.DDR.Enabled {
		return nil
	}
	if len(query.Question) == 0 {
		return nil
	}
	qname := strings.ToLower(query.Question[0].Header().Name)
	qtype := dns.RRToType(query.Question[0])

	if qname != "_dns.resolver.arpa." {
		return nil
	}
	if qtype != dns.TypeSVCB {
		return nil
	}

	resp := new(dns.Msg)
	resp.Response = true
	resp.ID = query.ID
	resp.Question = query.Question
	resp.RecursionAvailable = true
	resp.Rcode = dns.RcodeSuccess

	// Advertise DoT if enabled
	if cfg.Downstream.DoT.Enabled {
		rec := &dns.SVCB{
			Hdr: dns.Header{
				Name:  "_dns.resolver.arpa.",
				Class: dns.ClassINET,
				TTL:   300,
			},
		}
		rec.Priority = 1
		rec.Target = "."
		// RFC 9461/9462: include ALPN and port so DDR clients can connect.
		// "dot" is the ALPN identifier for DNS-over-TLS (RFC 7858).
		rec.Value = []svcb.Pair{
			&svcb.ALPN{Alpn: []string{"dot"}},
			&svcb.PORT{Port: uint16(cfg.Downstream.DoT.Port)},
		}
		resp.Answer = append(resp.Answer, rec)
	}

	// Advertise DoH if enabled
	if cfg.Downstream.DoH.Enabled {
		rec := &dns.SVCB{
			Hdr: dns.Header{
				Name:  "_dns.resolver.arpa.",
				Class: dns.ClassINET,
				TTL:   300,
			},
		}
		rec.Priority = 2
		rec.Target = "."
		// RFC 9461/9462: include ALPN, port, and dohpath so DDR clients can
		// perform zero-config upgrade to DNS-over-HTTPS.
		// "h2" is HTTP/2 (RFC 7540), the mandatory transport for RFC 8484.
		rec.Value = []svcb.Pair{
			&svcb.ALPN{Alpn: []string{"h2"}},
			&svcb.PORT{Port: uint16(cfg.Downstream.DoH.Port)},
			&svcb.DOHPATH{Template: "/dns-query{?dns}"},
		}
		resp.Answer = append(resp.Answer, rec)
	}

	if len(resp.Answer) == 0 {
		resp.Rcode = dns.RcodeNameError
	}

	return resp
}

// --- RFC 9715: Truncation Check ---

// NeedsTruncation checks if a response exceeds the client's advertised EDNS0
// UDP buffer size, capped at the RFC 9715 recommended 1232-byte maximum.
// clientUDPSize is taken from the client query's UDPSize field (0 means no
// EDNS0 OPT was sent; falls back to the RFC 6891 default of 512 bytes).
func NeedsTruncation(resp *dns.Msg, isTCP bool, clientUDPSize uint16) bool {
	if isTCP {
		return false
	}
	if resp == nil {
		return false
	}
	limit := int(clientUDPSize)
	if limit <= 0 {
		limit = 512 // RFC 6891 default for non-EDNS clients
	}
	if limit > MaxUDPPayload {
		limit = MaxUDPPayload
	}
	if err := resp.Pack(); err != nil {
		return false
	}
	return len(resp.Data) > limit
}

// MakeTruncatedResponse creates a minimal response with TC=1.
func MakeTruncatedResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.ID = query.ID
	resp.Response = true
	resp.Truncated = true
	resp.Question = query.Question
	resp.RecursionDesired = query.RecursionDesired
	resp.RecursionAvailable = true
	return resp
}
