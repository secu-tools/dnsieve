// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
// Package upstream implements concurrent fan-out DNS resolution across
// multiple upstream servers with block-aware result selection.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// Result holds the outcome of a single upstream query.
type Result struct {
	Index   int
	Client  string
	Msg     *dns.Msg
	Inspect dnsmsg.InspectResult
	Err     error
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
	clients := make([]Client, 0, len(cfg.Upstream))
	for _, u := range cfg.Upstream {
		verifyCert := u.ShouldVerifyCert(cfg.UpstreamSettings.VerifyCertificates)
		c, err := newClient(u, verifyCert, bootstrapIPs, ipFamily)
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

// isClientTCP returns true if the upstream client uses TCP-based transport.
func isClientTCP(c Client) bool {
	switch c.(type) {
	case *DoTClient, *DoHClient:
		return true
	default:
		return false
	}
}

// newClient creates the appropriate upstream client for a server config.
func newClient(srv config.UpstreamServer, verifyCert bool, bootstrapIPs []string, ipFamily string) (Client, error) {
	switch srv.Protocol {
	case "doh":
		return NewDoHClient(srv.Address, verifyCert, ipFamily, bootstrapIPs...)
	case "dot":
		return NewDoTClient(srv.Address, verifyCert, ipFamily, bootstrapIPs...)
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
		Index:   idx,
		Client:  c.String(),
		Msg:     resp,
		Inspect: inspect,
		Err:     err,
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
func (r *Resolver) Resolve(ctx context.Context, query *dns.Msg) *FanOutResult {
	n := len(r.clients)
	results := make([]*Result, n)
	var mu sync.Mutex
	var wg sync.WaitGroup
	blockDetected := make(chan struct{}, 1)

	queryCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	qname := ""
	if len(query.Question) > 0 {
		qname = query.Question[0].Header().Name
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
	select {
	case <-blockDetected:
		// Early block detected
	case <-minTimer.C:
		// Min wait elapsed
	case <-allDone:
		// All settled
	case <-queryCtx.Done():
		// Timeout
	}

	// Phase 2: If no block yet, wait for all to finish (up to timeout)
	select {
	case <-allDone:
	case <-queryCtx.Done():
	}

	// Ensure all goroutines have finished (including their logging) before
	// returning. The cancel() below causes any still-running upstream queries
	// to exit their context-aware select immediately.
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
