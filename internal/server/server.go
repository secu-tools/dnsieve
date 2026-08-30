// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package server orchestrates the DNSieve downstream listeners and
// upstream resolution pipeline.
package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/domainlist"
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// Handler processes DNS queries using the cache and upstream resolver.
type Handler struct {
	resolver          *upstream.Resolver
	whitelistResolver *upstream.WhitelistResolver
	blacklist         *domainlist.DomainList
	cache             *cache.Cache
	logger            *logging.Logger
	cfg               *config.Config
	edns              *edns.Middleware
}

// NewHandler creates a new DNS query handler.
// wlResolver may be nil when the whitelist is disabled.
// blacklist may be nil when the blacklist is disabled.
func NewHandler(resolver *upstream.Resolver, wlResolver *upstream.WhitelistResolver, blacklist *domainlist.DomainList, c *cache.Cache, logger *logging.Logger, cfg *config.Config) *Handler {
	return &Handler{
		resolver:          resolver,
		whitelistResolver: wlResolver,
		blacklist:         blacklist,
		cache:             c,
		logger:            logger,
		cfg:               cfg,
		edns:              edns.NewMiddleware(cfg),
	}
}

// handleWhitelistedQuery checks whether qname is whitelisted. When it is:
//  1. The cache is checked first for a prior Whitelisted=true entry and
//     returned immediately on a hit, avoiding an upstream round-trip.
//  2. On a miss the whitelist resolver is queried, the result is stored in
//     the cache with Whitelisted=true, and the response is returned.
//
// Returning nil continues processing through the normal pipeline (blacklist,
// general cache, upstreams).
func (h *Handler) handleWhitelistedQuery(ctx context.Context, query *dns.Msg, qname, qtype string) *dns.Msg {
	if h.whitelistResolver == nil || !h.whitelistResolver.IsWhitelisted(qname) {
		return nil
	}
	h.logger.Debugf("Query %s %s -> whitelisted", qname, qtype)
	if resp := h.checkWhitelistCache(ctx, query, qname, qtype); resp != nil {
		return resp
	}
	return h.resolveWhitelistUpstream(ctx, query, qname, qtype)
}

// checkWhitelistCache looks for a whitelisted cache entry and returns it if
// found. Returns nil on a miss, when the cache is disabled, or when
// MakeCachedResponse fails (caller must fall through to the resolver).
func (h *Handler) checkWhitelistCache(ctx context.Context, query *dns.Msg, qname, qtype string) *dns.Msg {
	if !h.cfg.Cache.Enabled {
		return nil
	}
	entry, refreshTriggered := h.cache.Get(query)
	if entry == nil {
		return nil
	}
	if !entry.Whitelisted {
		// A non-whitelist entry exists (e.g. stale blocked entry not yet
		// invalidated after a whitelist reload). The whitelist always wins,
		// so we ignore it and re-query the resolver.
		h.logger.Debugf("Query %s %s -> whitelisted (non-whitelist cache entry present, querying resolver)", qname, qtype)
		return nil
	}
	ttlSec, rtlSec := entryTTLs(entry)
	if refreshTriggered {
		h.logger.Debugf("Query %s %s -> whitelisted (cached, background-refresh queued, ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
	} else {
		h.logger.Debugf("Query %s %s -> whitelisted (cached, ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
	}
	resp := cache.MakeCachedResponse(query, entry)
	if resp == nil {
		// Corrupted wire bytes in stored entry; caller will re-query the
		// whitelist resolver.
		h.logger.Warnf("Whitelist cache entry for %s %s could not be unpacked, re-querying whitelist resolver", qname, qtype)
		return nil
	}
	if h.logger.IsJSONEnabled() {
		ttlPct := ttlRemainingPct(ttlSec, rtlSec)
		ev := logging.NewDNSQueryEvent(logging.LevelDebug, "server",
			qname+" "+qtype+" -> whitelisted (cached)")
		ev.DNS.Request = buildClientInfo(query, ClientMetaFrom(ctx))
		ev.DNS.Cache = &logging.CacheInfo{
			TTLSec:                     ttlSec,
			TTLRemainingSec:            rtlSec,
			TTLRemainingPct:            ttlPct,
			Whitelisted:                true,
			BackgroundRefreshTriggered: refreshTriggered,
		}
		ev.DNS.Response = buildResponseInfo(resp)
		h.logger.LogEvent(logging.LevelInfo, ev)
	}
	return resp
}

// resolveWhitelistUpstream queries the whitelist resolver, stores the result
// in the cache (if enabled), and returns the response.
func (h *Handler) resolveWhitelistUpstream(ctx context.Context, query *dns.Msg, qname, qtype string) *dns.Msg {
	h.logger.Debugf("Query %s %s -> whitelisted (querying resolver)", qname, qtype)
	resp, err := h.whitelistResolver.Query(ctx, query)
	if err != nil {
		h.logger.Warnf("Whitelist resolver error for %s %s: %v", qname, qtype, err)
		resp = new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	resp.ID = query.ID
	resp.RecursionAvailable = true
	// A transport error is already handled above, but the resolver can still
	// answer SERVFAIL or BADCOOKIE. dnsmsg treats both as retryable server
	// errors that must not be cached; the main fan-out drops them via
	// Result.OK, and caching them here would pin a transient upstream failure
	// for min_ttl.
	cacheable := !dnsmsg.InspectResponse(resp).ServFail
	cached := false
	if h.cfg.Cache.Enabled && cacheable {
		h.cache.Put(query, resp, false, true) // whitelisted=true
		cached = true
		h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=false cached=true (whitelist resolver)", qname, qtype, dns.RcodeToString[resp.Rcode])
	} else {
		h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=false cached=false (whitelist resolver)", qname, qtype, dns.RcodeToString[resp.Rcode])
	}
	if h.logger.IsJSONEnabled() {
		rcode := dns.RcodeToString[resp.Rcode]
		ev := logging.NewDNSQueryEvent(logging.LevelInfo, "server",
			qname+" "+qtype+" -> rcode="+rcode+" (whitelist resolver)")
		ev.DNS.Request = buildClientInfo(query, ClientMetaFrom(ctx))
		ev.DNS.Decision = &logging.DecisionInfo{
			Blocked:      false,
			BlockSource:  "whitelist",
			Cacheable:    cached,
			AllResponded: true,
			RCode:        rcode,
		}
		ev.DNS.Response = buildResponseInfo(resp)
		h.logger.LogEvent(logging.LevelInfo, ev)
	}
	return resp
}

// handleBlacklistedQuery checks whether qname is blacklisted and, if so,
// returns a blocked response immediately without querying upstream.
// Returns nil when the query is not blacklisted (normal path continues).
func (h *Handler) handleBlacklistedQuery(ctx context.Context, query *dns.Msg, qname, qtype string) *dns.Msg {
	if h.blacklist == nil || !h.blacklist.Contains(qname) {
		return nil
	}
	resp := dnsmsg.MakeBlockedResponse(query, h.cfg.Blocking.Mode, "local-blacklist")
	h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=true (blacklist)",
		qname, qtype, dns.RcodeToString[resp.Rcode])
	if h.logger.IsJSONEnabled() {
		rcode := dns.RcodeToString[resp.Rcode]
		ev := logging.NewDNSQueryEvent(logging.LevelInfo, "server",
			qname+" "+qtype+" -> blocked by blacklist")
		ev.DNS.Request = buildClientInfo(query, ClientMetaFrom(ctx))
		ev.DNS.Decision = buildBlacklistDecisionInfo(rcode)
		ev.DNS.Response = buildResponseInfo(resp)
		h.logger.LogEvent(logging.LevelInfo, ev)
	}
	return resp
}

// handleCacheHit looks up the query in the cache and returns a cached
// response if available. Returns nil on a cache miss or when disabled.
func (h *Handler) handleCacheHit(ctx context.Context, query *dns.Msg, qname, qtype string) *dns.Msg {
	if !h.cfg.Cache.Enabled {
		return nil
	}
	entry, refreshTriggered := h.cache.Get(query)
	if entry == nil {
		return nil
	}

	ttlSec, rtlSec := entryTTLs(entry)

	if entry.Blocked {
		if refreshTriggered {
			h.logger.Debugf("Query %s %s -> blocked (cached, background-refresh queued, ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
		} else {
			h.logger.Debugf("Query %s %s -> blocked (cached, ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
		}
	} else {
		if refreshTriggered {
			h.logger.Debugf("Query %s %s -> stale cache (background-refresh queued, ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
		} else {
			h.logger.Debugf("Query %s %s -> cached (ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
		}
	}
	resp := cache.MakeCachedResponse(query, entry)
	if resp != nil && h.logger.IsJSONEnabled() {
		h.emitCacheHitEvent(ctx, query, qname, qtype, entry, refreshTriggered, resp)
	}
	return resp
}

// emitCacheHitEvent builds and logs a structured JSON event for a cache hit.
func (h *Handler) emitCacheHitEvent(ctx context.Context, query *dns.Msg, qname, qtype string, entry *cache.Entry, refreshTriggered bool, resp *dns.Msg) {
	level := logging.LevelInfo
	msg := qname + " " + qtype + " -> cache hit"
	if entry.Blocked {
		msg = qname + " " + qtype + " -> blocked (cached)"
	}
	ev := logging.NewDNSQueryEvent(level, "server", msg)
	ev.DNS.Request = buildClientInfo(query, ClientMetaFrom(ctx))
	ev.DNS.Cache = buildCacheInfo(entry, refreshTriggered)
	ev.DNS.Response = buildResponseInfo(resp)
	h.logger.LogEvent(level, ev)
}

// HandleQuery processes a single DNS query and returns the response.
// This is the core logic shared by all downstream listeners.
//
// Flow:
//  1. Handle DDR (RFC 9461/9462) if applicable
//  2. Whitelist check -> if whitelisted: check whitelist cache -> hit: return; miss: resolve via whitelist resolver, cache(Whitelisted=true), return
//  3. Blacklist check -> return blocked response if matched (no cache read or write)
//  4. Check general cache -> return cached if hit
//  5. Fan out to all upstreams concurrently (with EDNS middleware)
//  6. If any upstream signals blocked -> cache blocked, return 0.0.0.0/::
//  7. If not blocked and all responded -> cache from 1st priority, return
//  8. If some failed -> don't cache, return best available
//  9. Process DNAME synthesis (RFC 6672)
//  10. Process EDNS response options
func (h *Handler) HandleQuery(ctx context.Context, query *dns.Msg) *dns.Msg {
	if len(query.Question) == 0 {
		resp := new(dns.Msg)
		resp.Response = true
		resp.Rcode = dns.RcodeFormatError
		resp.ID = query.ID
		return resp
	}

	// Reject queries with excessive questions (DNS spec allows 1).
	// Only echo the first question back; the library cannot pack multi-question
	// responses, so a FORMERR with all questions would be silently dropped.
	if len(query.Question) > 1 {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Question = resp.Question[:1]
		resp.Rcode = dns.RcodeFormatError
		return resp
	}

	qname := normalizeQueryName(query.Question[0].Header().Name)
	qtype := dns.TypeToString[dns.RRToType(query.Question[0])]

	h.logger.Debugf("Query %s %s from client", qname, qtype)

	// Step 0: DDR (RFC 9461/9462)
	if ddrResp := edns.HandleDDR(query, h.cfg); ddrResp != nil {
		h.logger.Debugf("Query %s %s -> DDR response", qname, qtype)
		return ddrResp
	}

	// Step 1: Whitelist check -- bypass all blocking upstreams
	if resp := h.handleWhitelistedQuery(ctx, query, qname, qtype); resp != nil {
		// RFC 5001: inject proxy NSID for substitute mode even on whitelist hits.
		h.edns.HandleNSIDSubstitute(query, resp)
		return resp
	}

	// Step 2: Blacklist check -- block immediately without upstream query
	if resp := h.handleBlacklistedQuery(ctx, query, qname, qtype); resp != nil {
		h.edns.HandleNSIDSubstitute(query, resp)
		return resp
	}

	// Step 3: Cache lookup
	if resp := h.handleCacheHit(ctx, query, qname, qtype); resp != nil {
		// RFC 5001: inject proxy NSID for substitute mode even on cache hits.
		// NSID is per-client-request and must not be baked into the cached entry.
		h.edns.HandleNSIDSubstitute(query, resp)
		return resp
	}

	// Step 4: Resolve via upstreams
	result := h.resolver.Resolve(ctx, query)

	if result.BestResponse == nil {
		h.logger.Warnf("All upstreams failed for %s %s", qname, qtype)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		resp.RecursionAvailable = true
		h.logger.Debugf("Query %s %s -> final: rcode=SERVFAIL blocked=false cached=false", qname, qtype)
		if h.logger.IsJSONEnabled() {
			ev := logging.NewDNSQueryEvent(logging.LevelWarn, "server",
				qname+" "+qtype+" -> SERVFAIL (all upstreams failed)")
			ev.DNS.Request = buildClientInfo(query, ClientMetaFrom(ctx))
			ev.DNS.Upstream = buildUpstreamInfos(result.Results, h.resolver.SlowThreshold())
			ev.DNS.Decision = &logging.DecisionInfo{
				Blocked:      false,
				Cacheable:    false,
				AllResponded: false,
				RCode:        "SERVFAIL",
			}
			ev.DNS.Response = buildResponseInfo(resp)
			h.logger.LogEvent(logging.LevelWarn, ev)
		}
		// RFC 5001: substitute mode applies to every response the proxy
		// originates, including this one. Every other return path in
		// HandleQuery does this, and omitting it here made NSID depend on
		// whether the upstreams happened to answer.
		h.edns.HandleNSIDSubstitute(query, resp)
		return resp
	}

	// Step 5: If blocked, return blocked response to client.
	if result.Blocked {
		blockedResp := dnsmsg.MakeBlockedResponse(query, h.cfg.Blocking.Mode, result.BlockedBy)
		rcode := dns.RcodeToString[blockedResp.Rcode]
		// For an early block (upstreams still pending), one upstream signalling
		// a block is sufficient to cache. For the normal path, respect result.Cacheable.
		var cached bool
		if result.WaitAll != nil {
			cached = h.cfg.Cache.Enabled
		} else {
			cached = h.cfg.Cache.Enabled && result.Cacheable
		}
		h.emitBlockedQueryEvent(ctx, query, qname, qtype, result, rcode, cached, blockedResp)
		h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=true cached=%v",
			qname, qtype, rcode, cached)
		return blockedResp
	}

	// Step 6: Process upstream response through EDNS middleware
	h.edns.ProcessUpstreamResponse(result.BestResponse, "")

	// Step 7: DNAME synthesis (RFC 6672)
	edns.SynthesizeDNAME(query, result.BestResponse)

	// Step 8: NSID substitute (RFC 5001)
	h.edns.HandleNSIDSubstitute(query, result.BestResponse)

	// Step 9: Return best response, cache if appropriate.
	// Emit JSON log BEFORE caching to preserve EDE ExtraText -- the dns
	// library's pack mutation corrupts EDE.ExtraText on Pack (triggered
	// internally by cache.Put).
	h.logger.Debugf("Query %s %s -> rcode=%s cacheable=%v allResponded=%v",
		qname, qtype, dns.RcodeToString[result.BestResponse.Rcode], result.Cacheable, result.AllResponded)

	cached := h.cfg.Cache.Enabled && result.Cacheable
	if h.logger.IsJSONEnabled() {
		rcode := dns.RcodeToString[result.BestResponse.Rcode]
		h.emitUpstreamQueryEvent(ctx, query, qname, qtype, result, rcode, cached, result.BestResponse)
	}
	if cached {
		h.cache.Put(query, result.BestResponse, false, false)
	}
	result.BestResponse.ID = query.ID
	// Set RA (Recursion Available) since we perform recursive resolution for
	// clients. Required by RFC 1035 s4.1.1 for recursive servers.
	result.BestResponse.RecursionAvailable = true
	// Ensure the Question section is always echoed back (RFC 1035 s4.1.1).
	// makeServFail may return a minimal response with no Question when all
	// upstream clients returned errors and no template was available.
	if len(result.BestResponse.Question) == 0 {
		result.BestResponse.Question = query.Question
		result.BestResponse.Response = true
		result.BestResponse.RecursionDesired = query.RecursionDesired
		result.BestResponse.RecursionAvailable = true
	}
	h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=false cached=%v",
		qname, qtype, dns.RcodeToString[result.BestResponse.Rcode], cached)
	return result.BestResponse
}

// emitBlockedQueryEvent handles JSON logging for a blocked upstream result.
// When result.WaitAll is non-nil (early-block path), it caches immediately
// and spawns a background goroutine to wait for all upstream results before
// emitting the dns_query event. When WaitAll is nil all upstreams already
// responded and the event is logged synchronously before caching.
func (h *Handler) emitBlockedQueryEvent(ctx context.Context, query *dns.Msg, qname, qtype string, result *upstream.FanOutResult, rcode string, cached bool, blockedResp *dns.Msg) {
	if !h.logger.IsJSONEnabled() {
		if cached {
			h.cache.Put(query, blockedResp, true, false)
		}
		return
	}
	if result.WaitAll != nil {
		// Early block: capture response info before cache.Put can corrupt
		// EDE ExtraText via the dns library's pack mutation.
		respInfo := buildResponseInfo(blockedResp)
		if cached {
			h.cache.Put(query, blockedResp, true, false)
		}
		h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=true cached=%v (early, waiting for upstreams)", qname, qtype, rcode, cached)
		blockedBy := result.BlockedBy
		slowThr := h.resolver.SlowThreshold()
		clientInfo := buildClientInfo(query, ClientMetaFrom(ctx))
		go func() {
			allResults := result.WaitAll()
			allResponded := countOKResults(allResults) == len(allResults)
			ev := logging.NewDNSQueryEvent(logging.LevelInfo, "server",
				qname+" "+qtype+" -> blocked by "+blockedBy)
			ev.DNS.Request = clientInfo
			ev.DNS.Upstream = buildUpstreamInfos(allResults, slowThr)
			ev.DNS.Decision = &logging.DecisionInfo{
				Blocked:      true,
				BlockSource:  "upstream",
				Cacheable:    cached,
				AllResponded: allResponded,
				RCode:        rcode,
			}
			ev.DNS.Response = respInfo
			h.logger.LogEvent(logging.LevelInfo, ev)
		}()
		return
	}
	// All upstreams already responded: log before caching to preserve EDE
	// ExtraText (cache.Put triggers Pack which mutates EDE.ExtraText in the
	// dns v2 library).
	h.emitUpstreamQueryEvent(ctx, query, qname, qtype, result, rcode, cached, blockedResp)
	if cached {
		h.cache.Put(query, blockedResp, true, false)
	}
}

// countOKResults returns the number of non-nil OK results.
func countOKResults(results []*upstream.Result) int {
	n := 0
	for _, r := range results {
		if r != nil && r.OK() {
			n++
		}
	}
	return n
}

// emitUpstreamQueryEvent builds and logs a structured JSON event for a query
// resolved via upstream servers. resp is the response that was sent to the client.
func (h *Handler) emitUpstreamQueryEvent(ctx context.Context, query *dns.Msg, qname, qtype string, result *upstream.FanOutResult, rcode string, cached bool, resp *dns.Msg) {
	level := logging.LevelInfo
	msg := qname + " " + qtype + " -> rcode=" + rcode
	if result.Blocked {
		msg = qname + " " + qtype + " -> blocked by " + result.BlockedBy
	}
	ev := logging.NewDNSQueryEvent(level, "server", msg)
	ev.DNS.Request = buildClientInfo(query, ClientMetaFrom(ctx))
	ev.DNS.Upstream = buildUpstreamInfos(result.Results, h.resolver.SlowThreshold())
	ev.DNS.Decision = buildDecisionInfo(result, rcode, cached)
	ev.DNS.Response = buildResponseInfo(resp)
	h.logger.LogEvent(level, ev)
}

// makeRefreshFunc returns the background-refresh callback for the cache.
// Whitelisted entries are refreshed via wlResolver (keeping Whitelisted=true).
// Normal entries fan out to all upstreams with block-consensus.
func makeRefreshFunc(
	resolver *upstream.Resolver,
	wlResolver *upstream.WhitelistResolver,
	c *cache.Cache,
	cfg *config.Config,
	logger *logging.Logger,
	timeoutDur time.Duration,
) func(*dns.Msg) {
	return func(query *dns.Msg) {
		qname, qtype := refreshQueryInfo(query)
		logger.Debugf("Cache background-refresh started: %s %s", qname, qtype)

		refreshCtx, refreshCancel := context.WithTimeout(context.Background(), timeoutDur)
		defer refreshCancel()

		if wlResolver != nil && wlResolver.IsWhitelisted(qname) {
			resp, err := wlResolver.Query(refreshCtx, query)
			if err != nil {
				logger.Debugf("Cache background-refresh (whitelist) failed: %s %s: %v", qname, qtype, err)
				return
			}
			resp.ID = query.ID
			resp.RecursionAvailable = true
			c.Put(query, resp, false, true)
			rcode := dns.RcodeToString[resp.Rcode]
			logger.Debugf("Cache background-refresh (whitelist) success: %s %s (rcode=%s)", qname, qtype, rcode)
			if logger.IsJSONEnabled() {
				ev := logging.NewDNSQueryEvent(logging.LevelInfo, "server",
					qname+" "+qtype+" -> background-refresh rcode="+rcode+" (whitelist resolver)")
				ev.DNS.Request = buildClientInfo(query, nil)
				ev.DNS.Decision = &logging.DecisionInfo{
					Blocked:      false,
					BlockSource:  "whitelist",
					Cacheable:    true,
					AllResponded: true,
					RCode:        rcode,
				}
				logger.LogEvent(logging.LevelInfo, ev)
			}
			return
		}

		result := resolver.Resolve(refreshCtx, query)
		if result.BestResponse == nil {
			logger.Debugf("Cache background-refresh failed (no response): %s %s", qname, qtype)
			return
		}
		// An early block returns before every upstream has answered, so
		// Cacheable is false even though one upstream positively signalled a
		// block. HandleQuery caches that case deliberately; without the same
		// exception here a newly blocked domain is never refreshed into the
		// cache and keeps being re-resolved until the entry expires.
		if !result.Cacheable && !(result.Blocked && result.WaitAll != nil) {
			logger.Debugf("Cache background-refresh skipped (not cacheable): %s %s", qname, qtype)
			return
		}
		var rcode string
		if result.Blocked {
			logger.Debugf("Cache background-refresh: %s %s is now blocked, updating cache", qname, qtype)
			blockedResp := dnsmsg.MakeBlockedResponse(query, cfg.Blocking.Mode, result.BlockedBy)
			c.Put(query, blockedResp, true, false)
			rcode = dns.RcodeToString[blockedResp.Rcode]
		} else {
			rcode = dns.RcodeToString[result.BestResponse.Rcode]
			logger.Debugf("Cache background-refresh success: %s %s (rcode=%s)", qname, qtype, rcode)
			c.Put(query, result.BestResponse, false, false)
		}
		if logger.IsJSONEnabled() {
			msg := qname + " " + qtype + " -> background-refresh rcode=" + rcode
			if result.Blocked {
				msg = qname + " " + qtype + " -> background-refresh blocked by " + result.BlockedBy
			}
			ev := logging.NewDNSQueryEvent(logging.LevelInfo, "server", msg)
			ev.DNS.Request = buildClientInfo(query, nil)
			ev.DNS.Upstream = buildUpstreamInfos(result.Results, resolver.SlowThreshold())
			ev.DNS.Decision = buildDecisionInfo(result, rcode, true)
			logger.LogEvent(logging.LevelInfo, ev)
		}
	}
}

// makeWhitelistInvalidator returns a reload callback that invalidates cache
// entries whose whitelist membership has changed.
//
//   - Whitelisted=true but no longer in whitelist: remove so next query
//     re-evaluates through normal pipeline (may be blocked by upstreams).
//   - Not whitelisted but now in whitelist: remove so next query is routed
//     to the whitelist resolver and re-cached with Whitelisted=true.
//
// Invalidation runs in a background goroutine to avoid blocking the watcher.
func makeWhitelistInvalidator(c *cache.Cache, logger *logging.Logger) func(*domainlist.DomainSet) {
	return func(newSet *domainlist.DomainSet) {
		go func() {
			n := c.InvalidateIf(func(name string, entry *cache.Entry) bool {
				isNowWhitelisted := newSet.Contains(name)
				return entry.Whitelisted != isNowWhitelisted
			})
			if n > 0 {
				logger.Infof("whitelist reload: invalidated %d cache entries whose whitelist membership changed", n)
			}
		}()
	}
}

// startListeners starts all enabled downstream protocol listeners as
// background goroutines, sending any fatal errors to errCh.
// Returns an error immediately if no listeners are enabled.
func startListeners(ctx context.Context, handler *Handler, cfg *config.Config, logger *logging.Logger, errCh chan<- error, wg *sync.WaitGroup) error {
	var serves []func(context.Context, *Handler, *config.Config, *logging.Logger) error
	if cfg.Downstream.Plain.Enabled {
		serves = append(serves, ServePlain)
	}
	if cfg.Downstream.DoT.Enabled {
		serves = append(serves, ServeDoT)
	}
	if cfg.Downstream.DoH.Enabled {
		serves = append(serves, ServeDoH)
	}

	if len(serves) == 0 {
		return fmt.Errorf("no downstream listeners enabled. Enable at least one of: plain, dot, doh")
	}

	for _, serve := range serves {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serve(ctx, handler, cfg, logger); err != nil {
				errCh <- err
			}
		}()
	}
	return nil
}

// Run starts all configured downstream listeners and blocks until
// a shutdown signal is received.
func Run(cfg *config.Config, logger *logging.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigCh:
			logger.Infof("Received signal %v, shutting down...", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	return RunContext(ctx, cfg, logger)
}

// RunContext starts all configured downstream listeners and blocks until
// ctx is cancelled or a fatal listener error occurs.
// Callers that need to drive shutdown from outside the process (e.g. the
// Windows Service Control Manager) should use this variant and cancel ctx
// when a stop request is received.
func RunContext(ctx context.Context, cfg *config.Config, logger *logging.Logger) error {
	// Size the per-upstream connection pools before any client is built. A cap
	// below the widest burst of concurrent queries re-handshakes the excess on
	// every burst, so this is a bandwidth setting, not a memory one.
	upstream.SetMaxIdleConns(cfg.UpstreamSettings.MaxIdleConns)

	// Create upstream resolver
	resolver, err := upstream.NewResolver(cfg, logger)
	if err != nil {
		return fmt.Errorf("create upstream resolver: %w", err)
	}
	// Upstream transports pool connections; release them on shutdown.
	defer resolver.Close()

	// Create whitelist resolver (nil when disabled)
	wlBootstrapIPs := upstream.ParseBootstrapDNSAddrs(cfg.UpstreamSettings.BootstrapDNS)
	wlIPFamily := cfg.UpstreamSettings.BootstrapIPFamily
	if wlIPFamily == "" {
		wlIPFamily = "auto"
	}
	wlResolver, err := upstream.NewWhitelistResolver(&cfg.Whitelist, cfg.UpstreamSettings.VerifyCertificates, wlBootstrapIPs, wlIPFamily, cfg.UpstreamSettings.UpstreamTTL, cfg.Cache.RenewPercent, logger)
	if err != nil {
		return fmt.Errorf("create whitelist resolver: %w", err)
	}
	// The whitelist upstream must apply the same EDNS privacy policy and
	// transaction-ID handling as the main fan-out; without this its queries
	// would carry the client's own OPT record.
	if wlResolver != nil {
		wlResolver.SetEDNS(edns.NewMiddleware(cfg))
	}

	// Create blacklist (nil when disabled)
	blacklist := newBlacklist(&cfg.Blacklist, logger)

	// Create cache
	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(
			cfg.Cache.MaxEntries,
			cfg.Cache.BlockedTTL,
			cfg.Cache.MinTTL,
			cfg.Cache.RenewPercent,
		)
	} else {
		// Disabled cache -- use a zero-size cache that never stores
		c = cache.New(0, 1, 1, 0)
	}

	handler := NewHandler(resolver, wlResolver, blacklist, c, logger, cfg)

	// Set up background cache refresh when renew_percent > 0.
	if cfg.Cache.Enabled && cfg.Cache.RenewPercent > 0 {
		timeoutDur := time.Duration(cfg.UpstreamSettings.TimeoutMS) * time.Millisecond
		c.SetRefreshFunc(makeRefreshFunc(resolver, wlResolver, c, cfg, logger, timeoutDur))
	}

	// When the whitelist hot-reloads, invalidate cache entries whose whitelist
	// membership changed so that the next query picks the correct resolution
	// path (whitelist resolver vs. blocking upstreams).
	if wlResolver != nil {
		wlResolver.OnListReload(makeWhitelistInvalidator(c, logger))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	if err := startListeners(ctx, handler, cfg, logger, errCh, &wg); err != nil {
		return err
	}

	logger.Infof("DNSieve server started. Waiting for queries...")

	select {
	case <-ctx.Done():
	case err := <-errCh:
		cancel()
		wg.Wait()
		stopListWatchers(wlResolver, blacklist)
		return err
	}

	wg.Wait()
	stopListWatchers(wlResolver, blacklist)
	logger.Infof("DNSieve server stopped.")
	return nil
}

// newBlacklist creates and loads a DomainList for the blacklist config.
// Returns nil when blacklisting is disabled.
func newBlacklist(cfg *config.BlacklistConfig, logger *logging.Logger) *domainlist.DomainList {
	if !cfg.Enabled {
		return nil
	}
	bl := domainlist.NewDomainList("blacklist", domainlist.ModeBlock, cfg.ListFiles)
	count, invalid, dedup, loadErr := bl.Load(logger.Debugf)
	upstream.LogListLoadResult(upstream.BlacklistReport, cfg.ListFiles, count, invalid, dedup, loadErr, logger)

	if cfg.ListTTL > 0 {
		bl.StartWatcher(cfg.ListTTL, logger.Infof, logger.Warnf, logger.Debugf)
		logger.Infof("Blacklist: file watcher started (check interval: %ds)", cfg.ListTTL)
	}
	return bl
}

// stopListWatchers stops background file watchers for whitelist and blacklist.
func stopListWatchers(wl *upstream.WhitelistResolver, bl *domainlist.DomainList) {
	if wl != nil {
		wl.Stop()
	}
	if bl != nil {
		bl.Stop()
	}
}

// refreshQueryInfo extracts the query name and type string for logging.
// Returns empty strings if the query has no question section.
func refreshQueryInfo(query *dns.Msg) (qname, qtype string) {
	if len(query.Question) == 0 {
		return "", ""
	}
	return normalizeQueryName(query.Question[0].Header().Name),
		dns.TypeToString[dns.RRToType(query.Question[0])]
}
