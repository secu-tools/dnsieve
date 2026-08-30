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
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/dnsmsg"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// DefaultTestDomains are the domains used as a fallback when no domains are
// supplied to --speed.
var DefaultTestDomains = []string{
	// Major technology providers
	"google.com",
	"apple.com",
	"microsoft.com",
	"cloudflare.com",
	"github.com",
	// Privacy-focused services
	"duckduckgo.com",
	"proton.me",
	"signal.org",
	"brave.com",
	"startpage.com",
}

// DomainResult holds the diagnostic outcome for a single domain query.
type DomainResult struct {
	Domain      string
	Status      string        // OK, NXDOMAIN, BLOCKED, NODATA, SERVFAIL, REFUSED, CERT_ERR, CONN_ERR, ERROR, RCODEn
	Latency     time.Duration // single round-trip from query send to response receipt; zero on transport error
	DNSSEC      bool          // true if the response carries DNSSEC data (AD bit or RRSIG)
	EDECode     string        // non-empty when an EDE option is present, e.g. "15:Blocked"
	ResolvedIPs []string      // A or AAAA addresses from the answer section; nil when no IPs were returned
}

// ServerResult holds the test results for a single upstream server.
type ServerResult struct {
	Address          string
	Protocol         string
	ResolveOK        bool
	Latencies        []time.Duration
	Errors           []string
	AvgLatency       time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	DNSErrors        int
	ConnErrors       int
	CertErrors       int
	TotalQueries     int
	SuccessCount     int
	DomainResults    []DomainResult
	NXDomains        int           // genuine NXDOMAIN responses (SOA present)
	Blocked          int           // sinkholed or filtered responses
	Refused          int           // REFUSED responses
	DNSSECAware      int           // responses with DNSSEC data (AD bit or RRSIG)
	BootstrapLatency time.Duration // round-trip for bootstrap DNS hostname resolution; 0 for IP/UDP upstreams
	BootstrapIP      string        // resolved IP of the upstream hostname; empty for IP/UDP upstreams
}

// RunInteractiveTest runs the speed test in interactive (CLI) mode.
// Output goes to stderr so it is visible immediately.
func RunInteractiveTest(cfg *config.Config, domains []string) {
	usingDefaults := len(domains) == 0
	if usingDefaults {
		domains = DefaultTestDomains
	}

	fmt.Fprintln(os.Stderr, "DNSieve Upstream Speed Test")
	fmt.Fprintln(os.Stderr, "===========================")
	fmt.Fprintf(os.Stderr, "Testing %d upstream server(s) with %d domain(s)...\n", len(cfg.Upstream), len(domains))
	if usingDefaults {
		fmt.Fprintln(os.Stderr, "Domains (built-in defaults):")
	} else {
		fmt.Fprintln(os.Stderr, "Domains (user-supplied):")
	}
	for _, d := range domains {
		fmt.Fprintf(os.Stderr, "  %s\n", d)
	}
	fmt.Fprintln(os.Stderr)

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
		if r.Blocked > 0 {
			logger.Warnf("Upstream %s filtered or sinkholed %d domain(s) during speed test", r.Address, r.Blocked)
		}
		if r.SuccessCount == 0 {
			logger.Warnf("Upstream %s failed all %d queries during speed test", r.Address, r.TotalQueries)
		}
	}
}

func runTests(cfg *config.Config, domains []string) []ServerResult {
	var results []ServerResult

	bootstrapDNS := cfg.UpstreamSettings.BootstrapDNS
	ipFamily := cfg.UpstreamSettings.BootstrapIPFamily
	if ipFamily == "" {
		ipFamily = "auto"
	}

	for _, u := range cfg.Upstream {
		verifyCert := u.ShouldVerifyCert(cfg.UpstreamSettings.VerifyCertificates)
		r := testServer(u, verifyCert, bootstrapDNS, ipFamily, domains)
		results = append(results, r)
	}

	return results
}

func testServer(srv config.UpstreamServer, verifyCert bool, bootstrapDNS, ipFamily string, domains []string) ServerResult {
	r := ServerResult{
		Address:  srv.Address,
		Protocol: srv.Protocol,
	}

	r.ResolveOK = checkBootstrapResolve(&r, srv, bootstrapDNS, ipFamily)

	bootstrapIPs := upstream.ParseBootstrapDNSAddrs(bootstrapDNS)
	client, err := createClient(srv, verifyCert, bootstrapIPs, ipFamily)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("client creation failed: %v", err))
		return r
	}
	// Throwaway client: without Close it would leave pooled connections open
	// for every configured upstream.
	defer client.Close()

	for _, domain := range domains {
		queryDomain(&r, client, domain, ipFamily)
	}

	computeStats(&r)
	return r
}

func checkBootstrapResolve(r *ServerResult, srv config.UpstreamServer, bootstrapDNS, ipFamily string) bool {
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
	start := time.Now()
	ips, err := resolveHost(host, bootstrapDNS, ipFamily)
	r.BootstrapLatency = time.Since(start)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("bootstrap DNS resolve failed for %s (via %s): %v", host, resolver, err))
		return false
	}
	if len(ips) > 0 {
		r.BootstrapIP = ips[0]
	}
	return true
}

// queryDomain queries a single domain against the upstream client and records
// the result.  ipFamily controls the record type: "ipv6" uses TypeAAAA, all
// other values (including "", "auto", "ipv4") use TypeA.
//
// Latency in the resulting DomainResult is the single end-to-end round-trip
// measured from immediately before client.Query is called to immediately after
// it returns.  Context creation and query assembly are not included.
func queryDomain(r *ServerResult, client upstream.Client, domain, ipFamily string) {
	r.TotalQueries++

	qtype := dns.TypeA
	if ipFamily == "ipv6" {
		qtype = dns.TypeAAAA
	}

	query := new(dns.Msg)
	dnsutil.SetQuestion(query, dnsutil.Fqdn(domain), qtype)
	query.RecursionDesired = true
	// Signal EDNS0 support so that upstream resolvers include Extended DNS Error
	// (EDE) options in their responses (RFC 8914).  Without an OPT record,
	// resolvers such as Quad9 return SERVFAIL for filtered domains but omit the
	// EDE option, making it impossible to distinguish a genuine server failure
	// from a policy block.
	query.UDPSize = 4096

	// Latency is measured as the single round-trip from query send to response
	// receipt.  Context creation and query assembly are excluded from the timing
	// window deliberately.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	start := time.Now()
	resp, err := client.Query(ctx, query)
	elapsed := time.Since(start)
	cancel()

	if err != nil {
		classifyError(r, domain, err)
		return
	}

	dr := buildDomainResult(domain, resp, elapsed)
	r.DomainResults = append(r.DomainResults, dr)
	applyDomainResult(r, dr)
}

func classifyError(r *ServerResult, domain string, err error) {
	errStr := err.Error()
	dr := DomainResult{Domain: domain}
	switch {
	case isCertError(errStr):
		r.CertErrors++
		dr.Status = "CERT_ERR"
	case isConnError(errStr):
		r.ConnErrors++
		dr.Status = "CONN_ERR"
	default:
		r.DNSErrors++
		dr.Status = "ERROR"
	}
	r.DomainResults = append(r.DomainResults, dr)
}

// buildDomainResult classifies a DNS response into a DomainResult using the
// shared InspectResponse logic from the dnsmsg package.
func buildDomainResult(domain string, resp *dns.Msg, elapsed time.Duration) DomainResult {
	ir := dnsmsg.InspectResponse(resp)
	dr := DomainResult{
		Domain:      domain,
		Latency:     elapsed,
		DNSSEC:      ir.HasDNSSEC,
		EDECode:     extractEDECode(resp),
		ResolvedIPs: extractAnswerIPs(resp),
	}
	setDomainStatus(&dr, resp, ir)
	return dr
}

// extractAnswerIPs returns all A and AAAA addresses present in the answer
// section of msg. Returns nil when the answer section is empty.
func extractAnswerIPs(msg *dns.Msg) []string {
	var ips []string
	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			ips = append(ips, a.Addr.String())
		case *dns.AAAA:
			ips = append(ips, a.Addr.String())
		}
	}
	return ips
}

// setDomainStatus assigns Status on dr based on the inspection result.
// SERVFAIL responses with an EDE InfoCode indicating blocking are classified
// as BLOCKED rather than SERVFAIL (covers Quad9-style SERVFAIL blocks).
func setDomainStatus(dr *DomainResult, resp *dns.Msg, ir dnsmsg.InspectResult) {
	switch {
	case ir.ServFail && hasEDEBlocked(resp):
		dr.Status = "BLOCKED"
	case ir.ServFail:
		dr.Status = "SERVFAIL"
	case ir.NXDomain && ir.Blocked:
		dr.Status = "BLOCKED"
	case ir.NXDomain:
		dr.Status = "NXDOMAIN"
	case ir.Blocked && ir.Rcode == dns.RcodeRefused:
		dr.Status = "REFUSED"
	case ir.Blocked:
		dr.Status = "BLOCKED"
	case ir.Rcode != dns.RcodeSuccess:
		dr.Status = fmt.Sprintf("RCODE%d", ir.Rcode)
	case len(resp.Answer) == 0:
		dr.Status = "NODATA"
	default:
		dr.Status = "OK"
	}
}

// extractEDECode returns a formatted EDE string for the first EDE option found
// in msg.Pseudo, e.g. "15:Blocked". Returns empty string when no EDE is present.
func extractEDECode(msg *dns.Msg) string {
	for _, rr := range msg.Pseudo {
		ede, ok := rr.(*dns.EDE)
		if !ok {
			continue
		}
		if name, ok := dns.ExtendedErrorToString[ede.InfoCode]; ok {
			return fmt.Sprintf("%d:%s", ede.InfoCode, name)
		}
		return strconv.Itoa(int(ede.InfoCode))
	}
	return ""
}

// hasEDEBlocked reports whether msg carries an Extended DNS Error option
// (RFC 8914) that indicates blocking: Blocked (15), Censored (16),
// Filtered (17), or Prohibited (18).
func hasEDEBlocked(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		ede, ok := rr.(*dns.EDE)
		if !ok {
			continue
		}
		switch ede.InfoCode {
		case dns.ExtendedErrorBlocked,
			dns.ExtendedErrorCensored,
			dns.ExtendedErrorFiltered,
			dns.ExtendedErrorProhibited:
			return true
		}
	}
	return false
}

// applyDomainResult updates the aggregate counters on r from a classified response.
func applyDomainResult(r *ServerResult, dr DomainResult) {
	if dr.DNSSEC {
		r.DNSSECAware++
	}
	switch dr.Status {
	case "SERVFAIL":
		r.DNSErrors++
	case "NXDOMAIN":
		r.NXDomains++
		r.SuccessCount++
		r.Latencies = append(r.Latencies, dr.Latency)
	case "BLOCKED":
		r.Blocked++
		r.SuccessCount++
		r.Latencies = append(r.Latencies, dr.Latency)
	case "REFUSED":
		r.Refused++
		r.SuccessCount++
		r.Latencies = append(r.Latencies, dr.Latency)
	case "OK", "NODATA":
		r.SuccessCount++
		r.Latencies = append(r.Latencies, dr.Latency)
	default:
		r.DNSErrors++
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

func createClient(srv config.UpstreamServer, verifyCert bool, bootstrapIPs []string, ipFamily string) (upstream.Client, error) {
	switch srv.Protocol {
	case "doh":
		return upstream.NewDoHClient(srv.Address, verifyCert, ipFamily, upstream.ResolveDisabled, 0, nil, bootstrapIPs...)
	case "dot":
		return upstream.NewDoTClient(srv.Address, verifyCert, ipFamily, upstream.ResolveDisabled, 0, nil, bootstrapIPs...)
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

// resolveHost resolves host using bootstrapDNS (comma-separated host:port list)
// or the system resolver when bootstrapDNS is empty.  ipFamily controls which
// record type is queried: "ipv6" sends TypeAAAA, all other values use TypeA.
func resolveHost(host, bootstrapDNS, ipFamily string) ([]string, error) {
	if bootstrapDNS == "" {
		return net.LookupHost(host)
	}

	addrs := upstream.ParseBootstrapDNSAddrs(bootstrapDNS)
	if len(addrs) == 0 {
		return net.LookupHost(host)
	}

	qtype := dns.TypeA
	if ipFamily == "ipv6" {
		qtype = dns.TypeAAAA
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	dnsutil.SetQuestion(m, dnsutil.Fqdn(host), qtype)
	m.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lastErr error
	for _, addr := range addrs {
		resp, _, err := c.Exchange(ctx, m, "udp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		result := extractAnswerIPs(resp)
		if len(result) > 0 {
			return result, nil
		}
		lastErr = fmt.Errorf("no records returned from %s", addr)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no records returned")
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
}

func printServerResult(w *os.File, r *ServerResult) {
	fmt.Fprintf(w, "--- %s (%s) ---\n", r.Address, r.Protocol)

	if r.BootstrapLatency > 0 {
		fmt.Fprintf(w, "  Bootstrap: %s (%v)\n", r.BootstrapIP, r.BootstrapLatency.Round(time.Millisecond))
	}

	if r.SuccessCount > 0 {
		fmt.Fprintf(w, "  Queries:   %d/%d responded\n", r.SuccessCount, r.TotalQueries)
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

	printDomainResults(w, r.DomainResults)
	printWarnings(w, r)
	for _, e := range r.Errors {
		fmt.Fprintf(w, "  Error: %s\n", e)
	}
	fmt.Fprintln(w)
}

// domainTableIndent is the fixed 4-space indent applied to every table line.
const domainTableIndent = "    "

func printDomainResults(w *os.File, results []DomainResult) {
	if len(results) == 0 {
		return
	}
	fmt.Fprintln(w, "  Domain Details:")
	// Header row
	fmt.Fprintf(w, "%s%-40s  %-8s  %-10s  %s\n",
		domainTableIndent, "Domain", "Latency", "Status", "EDE/Info")
	// Separator
	fmt.Fprintf(w, "%s%-40s  %-8s  %-10s  %s\n",
		domainTableIndent,
		strings.Repeat("-", 40),
		strings.Repeat("-", 8),
		strings.Repeat("-", 10),
		strings.Repeat("-", 8))
	for _, dr := range results {
		printDomainRow(w, dr)
	}
}

func printDomainRow(w *os.File, dr DomainResult) {
	latStr := "--"
	if dr.Latency > 0 {
		latStr = dr.Latency.Round(time.Millisecond).String()
	}
	// Column order: domain | latency | status | EDE code
	line := fmt.Sprintf("    %-40s  %-8s  %-10s", truncateDomain(dr.Domain, 40), latStr, dr.Status)
	if dr.EDECode != "" {
		line += "  " + dr.EDECode
	} else if dr.DNSSEC {
		line += "  [DNSSEC]"
	}
	fmt.Fprintln(w, line)
	if len(dr.ResolvedIPs) > 0 {
		fmt.Fprintf(w, "      Resolved IPs: %s\n", strings.Join(dr.ResolvedIPs, ", "))
	}
	fmt.Fprintln(w)
}

// truncateDomain shortens domain to at most maxLen runes for display.
// When truncation is needed, exactly 3 dots are inserted; the TLD is kept
// in full and 5 characters from just before the TLD dot are preserved:
//
//	fuecionwoqrucoewunqcoruneuqo...adwde.com    (TLD=com)
//	fewquriounefxwoqureuwoq2d...uoqur.tokoyo    (TLD=tokoyo)
//	abc.def.fewqr.dsafe.rew...rewqf.yokohama    (TLD=yokohama)
//
// Falls back to a head-truncation with "..." when the TLD is too long
// to fit the suffix formula or the pre-TLD part is shorter than 5 chars.
func truncateDomain(domain string, maxLen int) string {
	if len(domain) <= maxLen {
		return domain
	}
	lastDot := strings.LastIndex(domain, ".")
	if lastDot < 1 {
		if maxLen > 3 {
			return domain[:maxLen-3] + "..."
		}
		return domain[:maxLen]
	}
	tld := domain[lastDot+1:]
	beforeTLD := domain[:lastDot]
	const tailLen = 5
	// Total suffix: "..." + 5 tail chars + "." + TLD
	suffixLen := 3 + tailLen + 1 + len(tld)
	prefixLen := maxLen - suffixLen
	if prefixLen < 1 || len(beforeTLD) < tailLen {
		if maxLen > 3 {
			return domain[:maxLen-3] + "..."
		}
		return domain[:maxLen]
	}
	tail := beforeTLD[len(beforeTLD)-tailLen:]
	return domain[:prefixLen] + "..." + tail + "." + tld
}

func printWarnings(w *os.File, r *ServerResult) {
	if !r.ResolveOK {
		fmt.Fprintf(w, "  WARNING: bootstrap DNS resolution failed for this server\n")
	}
	if r.AvgLatency > 500*time.Millisecond && r.SuccessCount > 0 {
		fmt.Fprintf(w, "  WARNING: slow server (avg > 500ms) -- may impact DNS speed\n")
	}
}
