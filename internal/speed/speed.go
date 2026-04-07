// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package speed provides upstream DNS server speed testing and
// diagnostics for DNSieve.
package speed

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// DefaultTestDomains are popular global domains used for latency testing.
var DefaultTestDomains = []string{
	"google.com",
	"cloudflare.com",
	"facebook.com",
	"amazon.com",
	"microsoft.com",
}

// ServerResult holds the test results for a single upstream server.
type ServerResult struct {
	Address      string
	Protocol     string
	ResolveOK    bool
	Latencies    []time.Duration
	Errors       []string
	AvgLatency   time.Duration
	MinLatency   time.Duration
	MaxLatency   time.Duration
	DNSErrors    int
	ConnErrors   int
	CertErrors   int
	TotalQueries int
	SuccessCount int
}

// RunInteractiveTest runs the speed test in interactive (CLI) mode.
// Output goes to stderr so it is visible immediately.
func RunInteractiveTest(cfg *config.Config, domains []string) {
	if len(domains) == 0 {
		domains = DefaultTestDomains
	}

	fmt.Fprintln(os.Stderr, "DNSieve Upstream Speed Test")
	fmt.Fprintln(os.Stderr, "===========================")
	fmt.Fprintf(os.Stderr, "Testing %d upstream server(s) with %d domain(s)...\n\n", len(cfg.Upstream), len(domains))

	results := runTests(cfg, domains)
	printResults(results, os.Stderr)
}

// RunStartupTest runs a brief speed test at startup and logs results.
func RunStartupTest(cfg *config.Config, logger *logging.Logger) {
	domains := DefaultTestDomains[:3] // Use fewer domains at startup
	results := runTests(cfg, domains)

	for _, r := range results {
		if r.SuccessCount > 0 {
			logger.Infof("Speed test: %s (%s) avg=%v min=%v max=%v success=%d/%d",
				r.Address, r.Protocol, r.AvgLatency.Round(time.Millisecond),
				r.MinLatency.Round(time.Millisecond), r.MaxLatency.Round(time.Millisecond),
				r.SuccessCount, r.TotalQueries)
		}

		if r.AvgLatency > 500*time.Millisecond && r.SuccessCount > 0 {
			logger.Warnf("Upstream %s is slow (avg %v) -- this may impact DNS resolution speed", r.Address, r.AvgLatency.Round(time.Millisecond))
		}
		if r.ConnErrors > 0 {
			logger.Warnf("Upstream %s had %d connection error(s) during speed test", r.Address, r.ConnErrors)
		}
		if r.CertErrors > 0 {
			logger.Warnf("Upstream %s had %d certificate error(s) during speed test", r.Address, r.CertErrors)
		}
		if r.DNSErrors > 0 {
			logger.Warnf("Upstream %s had %d DNS error(s) during speed test", r.Address, r.DNSErrors)
		}
		if r.SuccessCount == 0 {
			logger.Warnf("Upstream %s failed all %d queries during speed test", r.Address, r.TotalQueries)
		}
	}
}

func runTests(cfg *config.Config, domains []string) []ServerResult {
	var results []ServerResult

	bootstrapDNS := cfg.UpstreamSettings.BootstrapDNS

	for _, u := range cfg.Upstream {
		verifyCert := u.ShouldVerifyCert(cfg.UpstreamSettings.VerifyCertificates)
		r := testServer(u, verifyCert, bootstrapDNS, domains)
		results = append(results, r)
	}

	return results
}

func testServer(srv config.UpstreamServer, verifyCert bool, bootstrapDNS string, domains []string) ServerResult {
	r := ServerResult{
		Address:  srv.Address,
		Protocol: srv.Protocol,
	}

	r.ResolveOK = checkBootstrapResolve(&r, srv, bootstrapDNS)

	bootstrapIPs := upstream.ParseBootstrapDNSAddrs(bootstrapDNS)
	client, err := createClient(srv, verifyCert, bootstrapIPs)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("client creation failed: %v", err))
		return r
	}

	for _, domain := range domains {
		queryDomain(&r, client, domain)
	}

	computeStats(&r)
	return r
}

func checkBootstrapResolve(r *ServerResult, srv config.UpstreamServer, bootstrapDNS string) bool {
	if srv.Protocol != "doh" && srv.Protocol != "dot" {
		return true
	}
	host := extractHost(srv.Address, srv.Protocol)
	if host == "" || net.ParseIP(host) != nil {
		return true
	}
	resolver := bootstrapDNS
	if resolver == "" {
		resolver = "system"
	}
	_, err := resolveHost(host, bootstrapDNS)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("bootstrap DNS resolve failed for %s (via %s): %v", host, resolver, err))
		return false
	}
	return true
}

func queryDomain(r *ServerResult, client upstream.Client, domain string) {
	r.TotalQueries++
	query := new(dns.Msg)
	dnsutil.SetQuestion(query, dnsutil.Fqdn(domain), dns.TypeA)
	query.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	start := time.Now()
	resp, err := client.Query(ctx, query)
	elapsed := time.Since(start)
	cancel()

	if err != nil {
		classifyError(r, domain, err)
		return
	}

	if resp.Rcode == dns.RcodeServerFailure {
		r.DNSErrors++
		r.Errors = append(r.Errors, fmt.Sprintf("%s: SERVFAIL", domain))
		return
	}

	r.SuccessCount++
	r.Latencies = append(r.Latencies, elapsed)
}

func classifyError(r *ServerResult, domain string, err error) {
	errStr := err.Error()
	switch {
	case isCertError(errStr):
		r.CertErrors++
		r.Errors = append(r.Errors, fmt.Sprintf("%s: certificate error: %v", domain, err))
	case isConnError(errStr):
		r.ConnErrors++
		r.Errors = append(r.Errors, fmt.Sprintf("%s: connection error: %v", domain, err))
	default:
		r.DNSErrors++
		r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", domain, err))
	}
}

func computeStats(r *ServerResult) {
	if len(r.Latencies) > 0 {
		var total time.Duration
		r.MinLatency = r.Latencies[0]
		r.MaxLatency = r.Latencies[0]
		for _, l := range r.Latencies {
			total += l
			if l < r.MinLatency {
				r.MinLatency = l
			}
			if l > r.MaxLatency {
				r.MaxLatency = l
			}
		}
		r.AvgLatency = total / time.Duration(len(r.Latencies))
	}
}

func createClient(srv config.UpstreamServer, verifyCert bool, bootstrapIPs []string) (upstream.Client, error) {
	switch srv.Protocol {
	case "doh":
		return upstream.NewDoHClient(srv.Address, verifyCert, bootstrapIPs...)
	case "dot":
		return upstream.NewDoTClient(srv.Address, verifyCert, bootstrapIPs...)
	case "udp":
		return upstream.NewPlainClient(srv.Address)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", srv.Protocol)
	}
}

func extractHost(address, protocol string) string {
	if protocol == "doh" {
		// Extract hostname from URL
		addr := address
		for _, prefix := range []string{"https://", "http://"} {
			if strings.HasPrefix(addr, prefix) {
				addr = addr[len(prefix):]
				break
			}
		}
		if idx := strings.Index(addr, "/"); idx > 0 {
			addr = addr[:idx]
		}
		if idx := strings.Index(addr, ":"); idx > 0 {
			addr = addr[:idx]
		}
		return addr
	}
	if protocol == "dot" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return address
		}
		return host
	}
	return ""
}

func resolveHost(host, bootstrapDNS string) ([]string, error) {
	if bootstrapDNS == "" {
		// Use system resolver
		return net.LookupHost(host)
	}

	// Use bootstrap DNS server
	c := new(dns.Client)

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, _, err := c.Exchange(ctx, m, "udp", bootstrapDNS)
	if err != nil {
		return nil, err
	}

	var addrs []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			addrs = append(addrs, a.Addr.String())
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A records returned")
	}
	return addrs, nil
}

func isCertError(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "certificate") ||
		strings.Contains(lower, "x509") ||
		strings.Contains(lower, "tls")
}

func isConnError(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "network is unreachable")
}

func printResults(results []ServerResult, w *os.File) {
	// Sort by average latency (fastest first), failures last
	sort.Slice(results, func(i, j int) bool {
		if results[i].SuccessCount == 0 && results[j].SuccessCount > 0 {
			return false
		}
		if results[i].SuccessCount > 0 && results[j].SuccessCount == 0 {
			return true
		}
		return results[i].AvgLatency < results[j].AvgLatency
	})

	for _, r := range results {
		printServerResult(w, &r)
	}

	printSummary(w, results)
}

func printServerResult(w *os.File, r *ServerResult) {
	fmt.Fprintf(w, "--- %s (%s) ---\n", r.Address, r.Protocol)

	if r.SuccessCount > 0 {
		fmt.Fprintf(w, "  Queries:   %d/%d successful\n", r.SuccessCount, r.TotalQueries)
		fmt.Fprintf(w, "  Avg:       %v\n", r.AvgLatency.Round(time.Millisecond))
		fmt.Fprintf(w, "  Min:       %v\n", r.MinLatency.Round(time.Millisecond))
		fmt.Fprintf(w, "  Max:       %v\n", r.MaxLatency.Round(time.Millisecond))

		if len(r.Latencies) > 1 {
			avg := float64(r.AvgLatency)
			var sumSq float64
			for _, l := range r.Latencies {
				diff := float64(l) - avg
				sumSq += diff * diff
			}
			stddev := time.Duration(math.Sqrt(sumSq / float64(len(r.Latencies))))
			fmt.Fprintf(w, "  Stddev:    %v\n", stddev.Round(time.Millisecond))
		}
	} else {
		fmt.Fprintf(w, "  FAILED: all %d queries failed\n", r.TotalQueries)
	}

	printWarnings(w, r)
	for _, e := range r.Errors {
		fmt.Fprintf(w, "  Error: %s\n", e)
	}
	fmt.Fprintln(w)
}

func printWarnings(w *os.File, r *ServerResult) {
	if r.CertErrors > 0 {
		fmt.Fprintf(w, "  WARNING: %d certificate error(s)\n", r.CertErrors)
	}
	if r.ConnErrors > 0 {
		fmt.Fprintf(w, "  WARNING: %d connection error(s)\n", r.ConnErrors)
	}
	if r.DNSErrors > 0 {
		fmt.Fprintf(w, "  WARNING: %d DNS error(s)\n", r.DNSErrors)
	}
	if r.AvgLatency > 500*time.Millisecond && r.SuccessCount > 0 {
		fmt.Fprintf(w, "  WARNING: slow server (avg > 500ms) -- may impact DNS speed\n")
	}
	if !r.ResolveOK {
		fmt.Fprintf(w, "  WARNING: bootstrap DNS resolution failed for this server\n")
	}
}

func printSummary(w *os.File, results []ServerResult) {
	fmt.Fprintln(w, "Summary:")
	for i, r := range results {
		status := serverStatus(&r)
		fmt.Fprintf(w, "  #%d %-6s %s (%s)", i+1, status, r.Address, r.Protocol)
		if r.SuccessCount > 0 {
			fmt.Fprintf(w, " avg=%v", r.AvgLatency.Round(time.Millisecond))
		}
		fmt.Fprintln(w)
	}
}

func serverStatus(r *ServerResult) string {
	switch {
	case r.SuccessCount == 0:
		return "FAIL"
	case r.AvgLatency > 500*time.Millisecond:
		return "SLOW"
	case r.CertErrors > 0 || r.ConnErrors > 0:
		return "WARN"
	default:
		return "OK"
	}
}
