// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ParseBootstrapDNSAddrs parses a comma-separated string of bootstrap DNS
// addresses into a slice of normalised host:port strings. Addresses without
// a port get ":53" appended. Empty entries are ignored.
func ParseBootstrapDNSAddrs(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	addrs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(p); err != nil {
			// No port component: add default DNS port 53.
			if strings.Contains(p, ":") {
				// Raw IPv6 address without brackets and port.
				p = "[" + p + "]:53"
			} else {
				p = p + ":53"
			}
		}
		addrs = append(addrs, p)
	}
	return addrs
}

// queryBootstrapRecord sends a single DNS query of the given type to
// bootstrapAddr and returns the first IP address and its TTL found in the
// answer, or an error. Used as the per-record-type worker by
// lookupHostViaBootstrap.
func queryBootstrapRecord(ctx context.Context, client *dns.Client, host, bootstrapAddr string, qtype uint16) (string, uint32, error) {
	m := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(host), qtype)
	m.RecursionDesired = true
	resp, _, err := client.Exchange(ctx, m, "udp", bootstrapAddr)
	if err != nil {
		return "", 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", 0, fmt.Errorf("bootstrap DNS rcode %d for %s", resp.Rcode, host)
	}
	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			return a.Addr.String(), a.Hdr.TTL, nil
		case *dns.AAAA:
			return a.Addr.String(), a.Hdr.TTL, nil
		}
	}
	return "", 0, fmt.Errorf("no A/AAAA record for %s via %s", host, bootstrapAddr)
}

// lookupHostViaBootstrap sends A and AAAA queries concurrently to the given
// bootstrapAddr (host:port, UDP) and returns the first IP and its TTL that
// responds successfully, preferring whichever record type arrives first.
// This supports both IPv4-only and IPv6-only environments (Happy Eyeballs,
// RFC 6555). ipFamily controls which record types are queried: "ipv4" sends
// only A, "ipv6" sends only AAAA, and any other value (including "auto" or
// "") races both.
func lookupHostViaBootstrap(ctx context.Context, host, bootstrapAddr, ipFamily string) (string, uint32, error) {
	type result struct {
		ip  string
		ttl uint32
		err error
	}

	queryCtx, queryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer queryCancel()

	ch := make(chan result, 2)

	transport := &dns.Transport{
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		Dialer:       &net.Dialer{Timeout: 3 * time.Second},
	}
	client := &dns.Client{Transport: transport}

	sendQuery := func(qtype uint16) {
		ip, ttl, err := queryBootstrapRecord(queryCtx, client, host, bootstrapAddr, qtype)
		select {
		case ch <- result{ip: ip, ttl: ttl, err: err}:
		default:
		}
	}

	var expected int
	if ipFamily == "ipv4" {
		expected = 1
		go sendQuery(dns.TypeA)
	} else if ipFamily == "ipv6" {
		expected = 1
		go sendQuery(dns.TypeAAAA)
	} else {
		expected = 2
		go sendQuery(dns.TypeA)
		go sendQuery(dns.TypeAAAA)
	}

	var lastErr error
	for i := 0; i < expected; i++ {
		select {
		case r := <-ch:
			if r.err == nil {
				queryCancel()
				return r.ip, r.ttl, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return "", 0, fmt.Errorf("bootstrap cancelled")
		}
	}
	if lastErr != nil {
		return "", 0, fmt.Errorf("via %s: %w", bootstrapAddr, lastErr)
	}
	return "", 0, fmt.Errorf("via %s: no A/AAAA record", bootstrapAddr)
}

// resolveViaBootstrap queries all bootstrapAddrs in parallel and returns the
// IP and TTL from the first successful response. It cancels remaining
// in-flight queries once a result is obtained.
// ipFamily is forwarded to each individual lookup; see lookupHostViaBootstrap.
func resolveViaBootstrap(ctx context.Context, host string, bootstrapAddrs []string, ipFamily string) (string, uint32, error) {
	if len(bootstrapAddrs) == 0 {
		return "", 0, fmt.Errorf("no bootstrap DNS addresses")
	}

	type result struct {
		ip  string
		ttl uint32
		err error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(bootstrapAddrs))
	for _, addr := range bootstrapAddrs {
		addr := addr
		go func() {
			ip, ttl, err := lookupHostViaBootstrap(ctx, host, addr, ipFamily)
			select {
			case ch <- result{ip, ttl, err}:
			case <-ctx.Done():
			}
		}()
	}

	var lastErr error
	for i := 0; i < len(bootstrapAddrs); i++ {
		select {
		case r := <-ch:
			if r.err == nil {
				cancel()
				return r.ip, r.ttl, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return "", 0, fmt.Errorf("bootstrap cancelled")
		}
	}
	if lastErr != nil {
		return "", 0, fmt.Errorf("bootstrap DNS failed for %s: %w", host, lastErr)
	}
	return "", 0, fmt.Errorf("bootstrap DNS failed for %s: no response", host)
}

// makeBootstrapDialer returns a DialContext function that resolves hostnames
// via the given bootstrap DNS addresses before dialling. If the address is
// already a numeric IP, the default dialer is used directly.
// ipFamily is forwarded to resolveViaBootstrap; see lookupHostViaBootstrap.
func makeBootstrapDialer(bootstrapAddrs []string, ipFamily string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		// If the host is already a numeric IP, skip bootstrap DNS lookup.
		if net.ParseIP(host) != nil {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		ip, _, err := resolveViaBootstrap(ctx, host, bootstrapAddrs, ipFamily)
		if err != nil {
			// Bootstrap DNS unreachable; fall back to system resolver so the
			// upstream can still be reached via OS-configured DNS.
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}

// makeDialerFromResolver returns a DialContext function backed by a
// hostResolver. The resolver handles TTL- or interval-based re-resolution;
// the dialer simply dials whatever address the resolver currently holds.
func makeDialerFromResolver(hr *hostResolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, hr.Addr())
	}
}
