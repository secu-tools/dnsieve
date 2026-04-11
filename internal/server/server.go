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
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// Handler processes DNS queries using the cache and upstream resolver.
type Handler struct {
	resolver          *upstream.Resolver
	whitelistResolver *upstream.WhitelistResolver
	cache             *cache.Cache
	logger            *logging.Logger
	cfg               *config.Config
	edns              *edns.Middleware
}

// NewHandler creates a new DNS query handler.
// wlResolver may be nil when the whitelist is disabled.
func NewHandler(resolver *upstream.Resolver, wlResolver *upstream.WhitelistResolver, c *cache.Cache, logger *logging.Logger, cfg *config.Config) *Handler {
	return &Handler{
		resolver:          resolver,
		whitelistResolver: wlResolver,
		cache:             c,
		logger:            logger,
		cfg:               cfg,
		edns:              edns.NewMiddleware(cfg),
	}
}

// handleWhitelistedQuery checks whether qname is whitelisted and, if so,
// resolves it via the whitelist resolver and returns the response.
// Returns nil when the query is not whitelisted (normal path continues).
func (h *Handler) handleWhitelistedQuery(ctx context.Context, query *dns.Msg, qname, qtype string) *dns.Msg {
	if h.whitelistResolver == nil || !h.whitelistResolver.IsWhitelisted(qname) {
		return nil
	}
	h.logger.Debugf("Query %s %s -> whitelisted", qname, qtype)
	resp, err := h.whitelistResolver.Query(ctx, query)
	if err != nil {
		h.logger.Warnf("Whitelist resolver error for %s: %v", qname, err)
		resp = new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		return resp
	}
	resp.ID = query.ID
	resp.RecursionAvailable = true
	if h.cfg.Cache.Enabled {
		h.cache.Put(query, resp, false)
	}
	return resp
}

// handleCacheHit looks up the query in the cache and returns a cached
// response if available. Returns nil on a cache miss or when disabled.
func (h *Handler) handleCacheHit(query *dns.Msg, qname, qtype string) *dns.Msg {
	if !h.cfg.Cache.Enabled {
		return nil
	}
	entry, refreshTriggered := h.cache.Get(query)
	if entry == nil {
		return nil
	}

	ttlSec := int64(entry.ExpiresAt.Sub(entry.InsertedAt).Seconds())
	rtlSec := int64(time.Until(entry.ExpiresAt).Seconds())
	if rtlSec < 0 {
		rtlSec = 0
	}

	if entry.Blocked {
		if refreshTriggered {
			h.logger.Infof("%s is blocked (from cache, background-refresh queued, ttl=%ds rtl=%ds)", qname, ttlSec, rtlSec)
		} else {
			h.logger.Infof("%s is blocked (from cache, ttl=%ds rtl=%ds)", qname, ttlSec, rtlSec)
		}
	} else {
		if refreshTriggered {
			h.logger.Debugf("Query %s %s -> stale cache (background-refresh queued, ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
		} else {
			h.logger.Debugf("Query %s %s -> cached (ttl=%ds rtl=%ds)", qname, qtype, ttlSec, rtlSec)
		}
	}
	return cache.MakeCachedResponse(query, entry)
}

// HandleQuery processes a single DNS query and returns the response.
// This is the core logic shared by all downstream listeners.
//
// Flow:
//  1. Handle DDR (RFC 9461/9462) if applicable
//  2. Check cache -> return cached if hit
//  3. Fan out to all upstreams concurrently (with EDNS middleware)
//  4. If any upstream signals blocked -> cache blocked, return 0.0.0.0/::
//  5. If not blocked and all responded -> cache from 1st priority, return
//  6. If some failed -> don't cache, return best available
//  7. Process DNAME synthesis (RFC 6672)
//  8. Process EDNS response options
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

	qname := query.Question[0].Header().Name
	qtype := dns.TypeToString[dns.RRToType(query.Question[0])]

	h.logger.Debugf("Query %s %s from client", qname, qtype)

	// Step 0: DDR (RFC 9461/9462)
	if ddrResp := edns.HandleDDR(query, h.cfg); ddrResp != nil {
		h.logger.Debugf("Query %s %s -> DDR response", qname, qtype)
		return ddrResp
	}

	// Step 1: Whitelist check -- bypass all blocking upstreams
	if resp := h.handleWhitelistedQuery(ctx, query, qname, qtype); resp != nil {
		return resp
	}

	// Step 2: Cache lookup
	if resp := h.handleCacheHit(query, qname, qtype); resp != nil {
		return resp
	}

	// Step 3: Resolve via upstreams
	result := h.resolver.Resolve(ctx, query)

	if result.BestResponse == nil {
		h.logger.Warnf("All upstreams failed for %s %s", qname, qtype)
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeServerFailure
		resp.RecursionAvailable = true
		h.logger.Debugf("Query %s %s -> final: rcode=SERVFAIL blocked=false cached=false", qname, qtype)
		return resp
	}

	// Step 4: If blocked, return blocked response
	if result.Blocked {
		h.logger.Infof("%s is blocked by %s", qname, result.BlockedBy)

		blockedResp := dnsmsg.MakeBlockedResponse(query, h.cfg.Blocking.Mode, result.BlockedBy)

		if h.cfg.Cache.Enabled && result.Cacheable {
			h.cache.Put(query, blockedResp, true)
		}

		h.logger.Debugf("Query %s %s -> final: rcode=%s blocked=true cached=%v",
			qname, qtype, dns.RcodeToString[blockedResp.Rcode], h.cfg.Cache.Enabled && result.Cacheable)
		return blockedResp
	}

	// Step 5: Process upstream response through EDNS middleware
	h.edns.ProcessUpstreamResponse(result.BestResponse, "")

	// Step 6: DNAME synthesis (RFC 6672)
	edns.SynthesizeDNAME(query, result.BestResponse)

	// Step 7: NSID substitute (RFC 5001)
	h.edns.HandleNSIDSubstitute(query, result.BestResponse)

	// Step 8: Return best response, cache if appropriate
	h.logger.Debugf("Query %s %s -> rcode=%s cacheable=%v allResponded=%v",
		qname, qtype, dns.RcodeToString[result.BestResponse.Rcode], result.Cacheable, result.AllResponded)

	if h.cfg.Cache.Enabled && result.Cacheable {
		h.cache.Put(query, result.BestResponse, false)
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
		qname, qtype, dns.RcodeToString[result.BestResponse.Rcode], h.cfg.Cache.Enabled && result.Cacheable)
	return result.BestResponse
}

// startListeners starts all enabled downstream protocol listeners as
// background goroutines, sending any fatal errors to errCh.
// Returns an error immediately if no listeners are enabled.
func startListeners(ctx context.Context, handler *Handler, cfg *config.Config, logger *logging.Logger, errCh chan<- error, wg *sync.WaitGroup) error {
	count := 0

	if cfg.Downstream.Plain.Enabled {
		count++
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ServePlain(ctx, handler, cfg, logger); err != nil {
				errCh <- err
			}
		}()
	}

	if cfg.Downstream.DoT.Enabled {
		count++
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ServeDoT(ctx, handler, cfg, logger); err != nil {
				errCh <- err
			}
		}()
	}

	if cfg.Downstream.DoH.Enabled {
		count++
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ServeDoH(ctx, handler, cfg, logger); err != nil {
				errCh <- err
			}
		}()
	}

	if count == 0 {
		return fmt.Errorf("no downstream listeners enabled. Enable at least one of: plain, dot, doh")
	}
	return nil
}

// Run starts all configured downstream listeners and blocks until
// a shutdown signal is received.
func Run(cfg *config.Config, logger *logging.Logger) error {
	// Create upstream resolver
	resolver, err := upstream.NewResolver(cfg, logger)
	if err != nil {
		return fmt.Errorf("create upstream resolver: %w", err)
	}

	// Create whitelist resolver (nil when disabled)
	wlResolver, err := upstream.NewWhitelistResolver(&cfg.Whitelist, cfg.UpstreamSettings.VerifyCertificates)
	if err != nil {
		return fmt.Errorf("create whitelist resolver: %w", err)
	}
	if wlResolver != nil {
		logger.Infof("Whitelist enabled: %d domain(s), resolver=%s",
			len(cfg.Whitelist.Domains), cfg.Whitelist.ResolverAddress)
	}

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

	handler := NewHandler(resolver, wlResolver, c, logger, cfg)

	// Set up background cache refresh when renew_percent > 0.
	// On each trigger: fan out to ALL upstreams using the same block-consensus
	// rules. Commit to cache only when the result is cacheable. If not
	// cacheable, the old entry remains valid until it naturally expires.
	if cfg.Cache.Enabled && cfg.Cache.RenewPercent > 0 {
		timeoutDur := time.Duration(cfg.UpstreamSettings.TimeoutMS) * time.Millisecond
		c.SetRefreshFunc(func(query *dns.Msg) {
			qname, qtype := refreshQueryInfo(query)
			logger.Debugf("Cache background-refresh started: %s %s", qname, qtype)

			ctx, cancel := context.WithTimeout(context.Background(), timeoutDur)
			defer cancel()

			result := resolver.Resolve(ctx, query)

			if result.BestResponse == nil {
				logger.Debugf("Cache background-refresh failed (no response): %s %s", qname, qtype)
				return
			}
			if !result.Cacheable {
				logger.Debugf("Cache background-refresh skipped (not cacheable): %s %s", qname, qtype)
				return // old entry stays valid until expiry
			}
			if result.Blocked {
				logger.Debugf("Cache background-refresh: %s %s is now blocked, updating cache", qname, qtype)
				blockedResp := dnsmsg.MakeBlockedResponse(query, cfg.Blocking.Mode, result.BlockedBy)
				c.Put(query, blockedResp, true)
			} else {
				logger.Debugf("Cache background-refresh success: %s %s (rcode=%d)", qname, qtype, result.BestResponse.Rcode)
				c.Put(query, result.BestResponse, false)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	if err := startListeners(ctx, handler, cfg, logger, errCh, &wg); err != nil {
		return err
	}

	logger.Infof("DNSieve server started. Waiting for queries...")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Infof("Received signal %v, shutting down...", sig)
		cancel()
	case err := <-errCh:
		cancel()
		wg.Wait()
		return err
	}

	wg.Wait()
	logger.Infof("DNSieve server stopped.")
	return nil
}

// refreshQueryInfo extracts the query name and type string for logging.
// Returns empty strings if the query has no question section.
func refreshQueryInfo(query *dns.Msg) (qname, qtype string) {
	if len(query.Question) == 0 {
		return "", ""
	}
	return query.Question[0].Header().Name,
		dns.TypeToString[dns.RRToType(query.Question[0])]
}
