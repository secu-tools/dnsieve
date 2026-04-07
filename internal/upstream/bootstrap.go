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

// lookupHostViaBootstrap sends a single A-record query for host to the
// given bootstrapAddr (host:port, UDP) and returns the first A record IP.
func lookupHostViaBootstrap(ctx context.Context, host, bootstrapAddr string) (string, error) {
	m := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	transport := &dns.Transport{
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		Dialer:       &net.Dialer{Timeout: 3 * time.Second},
	}
	client := &dns.Client{Transport: transport}
	resp, _, err := client.Exchange(queryCtx, m, "udp", bootstrapAddr)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("bootstrap DNS rcode %d for %s", resp.Rcode, host)
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.Addr.String(), nil
		}
	}
	return "", fmt.Errorf("no A record for %s via %s", host, bootstrapAddr)
}

// resolveViaBootstrap queries all bootstrapAddrs in parallel and returns the
// IP from the first successful response. It cancels the remaining in-flight
// queries once a result is obtained.
func resolveViaBootstrap(ctx context.Context, host string, bootstrapAddrs []string) (string, error) {
	if len(bootstrapAddrs) == 0 {
		return "", fmt.Errorf("no bootstrap DNS addresses")
	}

	type result struct {
		ip  string
		err error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(bootstrapAddrs))
	for _, addr := range bootstrapAddrs {
		addr := addr
		go func() {
			ip, err := lookupHostViaBootstrap(ctx, host, addr)
			select {
			case ch <- result{ip, err}:
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
				return r.ip, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return "", fmt.Errorf("bootstrap DNS cancelled for %s", host)
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("all bootstrap DNS servers failed for %s: %w", host, lastErr)
	}
	return "", fmt.Errorf("bootstrap DNS resolution failed for %s", host)
}

// makeBootstrapDialer returns a DialContext function that resolves hostnames
// via the given bootstrap DNS addresses before dialling. If the address is
// already a numeric IP, the default dialer is used directly.
func makeBootstrapDialer(bootstrapAddrs []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		// If the host is already a numeric IP, skip bootstrap DNS lookup.
		if net.ParseIP(host) != nil {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		ip, err := resolveViaBootstrap(ctx, host, bootstrapAddrs)
		if err != nil {
			return nil, fmt.Errorf("bootstrap dial %s: %w", host, err)
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
}
