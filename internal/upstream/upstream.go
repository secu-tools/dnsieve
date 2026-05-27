// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package upstream implements concurrent fan-out DNS resolution across
// multiple upstream servers with block-aware result selection.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"golang.org/x/net/idna"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// Result holds the outcome of a single upstream query.
type Result struct {
	Index      int
	Client     string
	Msg        *dns.Msg
	Inspect    dnsmsg.InspectResult
	Err        error
	DurationMS int64  // wall-clock time for the upstream query in milliseconds
	Protocol   string // "doh", "dot", or "udp"
}

// OK reports whether the upstream responded without error and without
// server failure (SERVFAIL).
func (r *Result) OK() bool {
	return r.Err == nil && r.Msg != nil && !r.Inspect.ServFail
}

// Resolver fans out DNS queries to multiple upstream servers and
// applies the block-consensus logic.
type Resolver struct {
	clients       []Client
	timeout       time.Duration
	minWait       time.Duration
	slowThreshold time.Duration
	logger        *logging.Logger
	edns          *edns.Middleware
}

// Client is the interface for a single upstream protocol.
type Client interface {
	// Query sends a DNS query and returns the response.
	Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	// String returns a human-readable description.
	String() string
}

// NewResolver creates a resolver from the given config.
func NewResolver(cfg *config.Config, logger *logging.Logger) (*Resolver, error) {
	bootstrapIPs := ParseBootstrapDNSAddrs(cfg.UpstreamSettings.BootstrapDNS)
	ipFamily := cfg.UpstreamSettings.BootstrapIPFamily
	if ipFamily == "" {
		ipFamily = "auto"
	}
	resolveMode := cfg.UpstreamSettings.UpstreamTTL
	renewPercent := cfg.Cache.RenewPercent
	clients := make([]Client, 0, len(cfg.Upstream))
	for _, u := range cfg.Upstream {
		verifyCert := u.ShouldVerifyCert(cfg.UpstreamSettings.VerifyCertificates)
		c, err := newClient(u, verifyCert, bootstrapIPs, ipFamily, resolveMode, renewPercent, logger)
		if err != nil {
			return nil, fmt.Errorf("upstream %s: %w", u.Address, err)
		}
		clients = append(clients, c)
	}

	slowThreshold := time.Duration(cfg.Logging.SlowUpstreamMS) * time.Millisecond

	return &Resolver{
		clients:       clients,
		timeout:       time.Duration(cfg.UpstreamSettings.TimeoutMS) * time.Millisecond,
		minWait:       time.Duration(cfg.UpstreamSettings.MinWaitMS) * time.Millisecond,
		slowThreshold: slowThreshold,
		logger:        logger,
		edns:          edns.NewMiddleware(cfg),
	}, nil
}

// NewResolverFromClients creates a resolver directly from client instances.
// This is primarily useful for testing.
func NewResolverFromClients(clients []Client, timeout, minWait time.Duration, logger *logging.Logger) *Resolver {
	return &Resolver{
		clients:       clients,
		timeout:       timeout,
		minWait:       minWait,
		slowThreshold: 200 * time.Millisecond,
		logger:        logger,
	}
}

// SlowThreshold returns the duration above which an upstream query is
// considered slow and logged as a warning.
func (r *Resolver) SlowThreshold() time.Duration {
	return r.slowThreshold
}

// normalizeDomain strips the trailing DNS root dot and converts any
// non-ASCII (Unicode) labels to their Punycode/ACE equivalent so that
// log messages always display the standard ASCII DNS form.
// On conversion failure the name is returned with only the trailing dot stripped.
func normalizeDomain(name string) string {
	name = strings.TrimSuffix(name, ".")
	if ascii, err := idna.Lookup.ToASCII(name); err == nil {
		return ascii
	}
	return name
}

// isClientTCP returns true if the upstream client uses TCP-based transport.
func isClientTCP(c Client) bool {
	switch c.(type) {
	case *DoTClient, *DoHClient:
		return true
	default:
		return false
	}
}

// clientProtocol returns the short protocol label for a Client.
// Returns "doh" for DoHClient, "dot" for DoTClient, "udp" for PlainClient.
func clientProtocol(c Client) string {
	switch c.(type) {
	case *DoHClient:
		return "doh"
	case *DoTClient:
		return "dot"
	default:
		return "udp"
	}
}

// newClient creates the appropriate upstream client for a server config.
func newClient(srv config.UpstreamServer, verifyCert bool, bootstrapIPs []string, ipFamily string, resolveMode int, renewPercent int, logger *logging.Logger) (Client, error) {
	switch srv.Protocol {
	case "doh":
		return NewDoHClient(srv.Address, verifyCert, ipFamily, resolveMode, renewPercent, logger, bootstrapIPs...)
	case "dot":
		return NewDoTClient(srv.Address, verifyCert, ipFamily, resolveMode, renewPercent, logger, bootstrapIPs...)
	case "udp":
		return NewPlainClient(srv.Address)
	default:
		return nil, fmt.Errorf("unsupported protocol %q", srv.Protocol)
	}
}

// FanOutResult holds the aggregated result of querying all upstreams.
type FanOutResult struct {
	// BestResponse is the response to send to the client.
	BestResponse *dns.Msg
	// Blocked is true if any upstream signalled a block.
	Blocked bool
	// BlockedBy is the upstream address that signalled the block (empty if from cache).
	BlockedBy string
	// AllResponded is true if every upstream returned a valid response.
	AllResponded bool
	// Cacheable is true if the result should be cached.
	Cacheable bool
	// Results holds individual upstream results (indexed by priority).
	Results []*Result
	// WaitAll, when non-nil, blocks until all upstream goroutines have
	// completed (or the query timeout expires) and returns the full per-upstream
	// Results slice. Present when a block was detected early before all
	// upstreams responded. Call from a goroutine to avoid blocking the
	// response path.
	WaitAll func() []*Result
}

// resolveUpstream issues a single query to one upstream client, logs
// timing/errors, and writes the Result into results[idx] under mu.
// A signal is sent on blockDetected if the response is a block.
func (r *Resolver) resolveUpstream(ctx context.Context, idx int, c Client, query *dns.Msg, qname string, results []*Result, mu *sync.Mutex, blockDetected chan<- struct{}) {
	r.logger.Debugf("Upstream[%d] query %s -> %s", idx, qname, c)

	// RFC 6891: rebuild OPT record from scratch for upstream
	isTCP := isClientTCP(c)
	upstreamQuery := query
	if r.edns != nil {
		upstreamQuery = r.edns.PrepareUpstreamQuery(query, c.String(), isTCP)
	}

	start := time.Now()
	resp, err := c.Query(ctx, upstreamQuery)
	elapsed := time.Since(start)

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			r.logger.Warnf("Upstream[%d] %s timed out resolving %s", idx, c, qname)
		} else {
			r.logger.Warnf("Upstream[%d] %s error resolving %s: %v", idx, c, qname, err)
		}
	} else if r.slowThreshold > 0 && elapsed > r.slowThreshold {
		r.logger.Warnf("Slow upstream[%d] %s took %dms to resolve %s", idx, c, elapsed.Milliseconds(), qname)
	}

	// RFC 7873: update per-upstream cookie state immediately after receiving
	// the response so that the correct upstream address is recorded. This must
	// happen before result aggregation, where the address is no longer tracked.
	if err == nil && resp != nil && r.edns != nil {
		r.edns.ProcessResponseCookieOnly(resp, c.String())
	}

	var inspect dnsmsg.InspectResult
	if err == nil && resp != nil {
		inspect = dnsmsg.InspectResponse(resp)
	} else {
		inspect = dnsmsg.InspectResult{ServFail: true}
	}

	r.logger.Debugf("Upstream[%d] %s: blocked=%v servfail=%v rcode=%d err=%v",
		idx, c, inspect.Blocked, inspect.ServFail, inspect.Rcode, err)

	res := &Result{
		Index:      idx,
		Client:     c.String(),
		Msg:        resp,
		Inspect:    inspect,
		Err:        err,
		DurationMS: elapsed.Milliseconds(),
		Protocol:   clientProtocol(c),
	}

	mu.Lock()
	results[idx] = res
	isBlock := res.OK() && inspect.Blocked
	mu.Unlock()

	if isBlock {
		select {
		case blockDetected <- struct{}{}:
		default:
		}
	}
}

// Resolve queries all upstream servers concurrently and returns the
// aggregated result following the block-consensus algorithm:
//
//  1. If ANY upstream signals blocked -> return blocked, cache if all responded
//  2. If NOT blocked and ALL responded without server error -> cache from 1st
//  3. If some have server errors -> don't cache, return best available
//  4. If servers disagree on NXDOMAIN -> don't cache
//
// When a block is detected in Phase 1 (before all upstreams have responded),
// Resolve returns immediately with a FanOutResult whose WaitAll field is
// non-nil. The caller should spawn a goroutine that calls WaitAll() to obtain
// the complete per-upstream results for structured logging.
func (r *Resolver) Resolve(ctx context.Context, query *dns.Msg) *FanOutResult {
	n := len(r.clients)
	results := make([]*Result, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	blockDetected := make(chan struct{}, 1)

	// Detach from the request context so upstream goroutines and the WaitAll
	// goroutine in the caller continue running after the HTTP/plain handler
	// returns the response to the client.
	queryCtx, cancel := context.WithTimeout(context.Background(), r.timeout)

	qname := ""
	if len(query.Question) > 0 {
		qname = normalizeDomain(query.Question[0].Header().Name)
	}

	// Fan out to all upstreams
	for i, client := range r.clients {
		wg.Add(1)
		go func(idx int, c Client) {
			defer wg.Done()
			r.resolveUpstream(queryCtx, idx, c, query, qname, results, &mu, blockDetected)
		}(i, client)
	}

	// Wait for either: a block, min wait, or all settled
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	minTimer := time.NewTimer(r.minWait)
	defer minTimer.Stop()

	// Phase 1: Wait for min_wait or block detection
	earlyBlock := false
	select {
	case <-blockDetected:
		earlyBlock = true
	case <-minTimer.C:
	case <-allDone:
	case <-queryCtx.Done():
	}

	// Early block: at least one upstream signalled a block before all responded.
	// Return to the client immediately; provide WaitAll for deferred logging.
	if earlyBlock {
		select {
		case <-allDone:
			// All upstreams finished before we could return early.
			// Fall through to the normal aggregation path.
		default:
			partialResult := r.selectResult(results)
			partialResult.WaitAll = func() []*Result {
				<-allDone
				cancel()
				mu.Lock()
				out := make([]*Result, len(results))
				copy(out, results)
				mu.Unlock()
				return out
			}
			return partialResult
		}
	}

	// Phase 2: Wait for all to finish (up to timeout)
	select {
	case <-allDone:
	case <-queryCtx.Done():
	}

	// Ensure all goroutines have finished before returning.
	cancel()
	<-allDone

	return r.selectResult(results)
}

// countResults tallies OK responses and finds the first block result.
func countResults(results []*Result) (okCount int, blockedResult *Result) {
	for _, res := range results {
		if res == nil || !res.OK() {
			continue
		}
		okCount++
		if blockedResult == nil && res.Inspect.Blocked {
			blockedResult = res
		}
	}
	return
}

// pickBestResponse returns the best OK response, preferring responses that
// carry DNSSEC data (RRSIG records or AD=1) over unsigned ones. Among DNSSEC
// responses the lowest-index (highest-priority) wins. If no upstream returned
// DNSSEC data the lowest-index valid response is used.
func pickBestResponse(results []*Result) *dns.Msg {
	var fallback *dns.Msg
	for _, res := range results {
		if res == nil || !res.OK() {
			continue
		}
		if res.Inspect.HasDNSSEC {
			return res.Msg
		}
		if fallback == nil {
			fallback = res.Msg
		}
	}
	return fallback
}

// selectResult applies the block-consensus algorithm to pick the best response.
func (r *Resolver) selectResult(results []*Result) *FanOutResult {
	out := &FanOutResult{Results: results}

	okCount, blockedResult := countResults(results)
	out.AllResponded = okCount == len(results)

	if blockedResult != nil {
		out.BestResponse = blockedResult.Msg
		out.Blocked = true
		out.BlockedBy = blockedResult.Client
		out.Cacheable = out.AllResponded
		return out
	}

	out.BestResponse = pickBestResponse(results)
	if out.BestResponse == nil {
		out.BestResponse = makeServFail(results)
		return out
	}

	out.Cacheable = out.AllResponded && !r.hasNXDomainDisagreement(results)
	return out
}

// hasNXDomainDisagreement returns true if some OK results return NXDOMAIN
// and others don't (servers disagree).
func (r *Resolver) hasNXDomainDisagreement(results []*Result) bool {
	hasNX := false
	hasNonNX := false
	for _, res := range results {
		if res == nil || !res.OK() {
			continue
		}
		if res.Inspect.NXDomain {
			hasNX = true
		} else {
			hasNonNX = true
		}
	}
	return hasNX && hasNonNX
}

// makeServFail creates a SERVFAIL response when all upstreams fail.
func makeServFail(results []*Result) *dns.Msg {
	// Try to find a response to use for the header (Question/ID).
	for _, res := range results {
		if res != nil && res.Msg != nil {
			resp := new(dns.Msg)
			resp.ID = res.Msg.ID
			resp.Question = res.Msg.Question
			resp.Response = true
			resp.RecursionAvailable = res.Msg.RecursionAvailable
			resp.RecursionDesired = res.Msg.RecursionDesired
			resp.Rcode = dns.RcodeServerFailure
			return resp
		}
	}
	// No template available -- return minimal SERVFAIL
	msg := new(dns.Msg)
	msg.Response = true
	msg.Rcode = dns.RcodeServerFailure
	return msg
}
