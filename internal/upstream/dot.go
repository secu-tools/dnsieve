// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/logging"
)

// DoTClient implements DNS-over-TLS (RFC 7858 / RFC 8310).
type DoTClient struct {
	address   string
	tlsConfig *tls.Config
	// resolver is non-nil when TTL- or interval-based re-resolution is
	// configured. Addr() is called before each new connection to obtain the
	// current resolved IP, which may have been refreshed in the background.
	resolver *hostResolver
}

// NewDoTClient creates a DoT client for the given server address (host:port).
// bootstrapIPs is an optional list of host:port addresses used to resolve
// the DoT server hostname instead of the system resolver.
// ipFamily controls bootstrap address-family selection: "ipv4", "ipv6", or
// "auto" (default) to race both as per RFC 6555.
// resolveMode controls re-resolution after startup: resolveDisabled (-1)
// disables it (one-time resolution, default), resolveByTTL (0) re-resolves
// based on the DNS record TTL, and any positive value re-resolves every that
// many seconds. See resolve.go for details.
// renewPercent is the percentage of the TTL/interval remaining that triggers
// a background re-resolution (from cache.renew_percent); 0 disables it.
// logger receives debug messages when the upstream IP is re-resolved (nil = silent).
func NewDoTClient(address string, verifyCert bool, ipFamily string, resolveMode int, renewPercent int, logger *logging.Logger, bootstrapIPs ...string) (*DoTClient, error) {
	if address == "" {
		return nil, fmt.Errorf("empty DoT address")
	}

	// Extract hostname for TLS ServerName
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// Bare address without port: check if it is a raw IPv6 address.
		if strings.Contains(address, ":") {
			// Raw IPv6 (e.g. "2620:fe::fe") - wrap in brackets and add default port.
			host = address
			address = "[" + address + "]:853"
			port = "853"
		} else {
			host = address
			address = address + ":853"
			port = "853"
		}
	}

	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !verifyCert, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	client := &DoTClient{address: address, tlsConfig: tlsCfg}

	if len(bootstrapIPs) > 0 && net.ParseIP(host) == nil {
		if resolveMode == resolveDisabled {
			// One-time resolution at construction (current behaviour).
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if ip, _, err := resolveViaBootstrap(ctx, host, bootstrapIPs, ipFamily); err == nil {
				client.address = net.JoinHostPort(ip, port)
			}
			// On resolution failure keep the original address; OS resolver
			// will be tried when dialling.
		} else {
			// Re-resolution enabled: create a hostResolver.
			hr, _ := newHostResolver(host, port, bootstrapIPs, ipFamily, resolveMode, renewPercent, logger)
			if hr != nil {
				client.address = hr.Addr()
				client.resolver = hr
			}
		}
	}

	return client, nil
}

// Query sends a DNS query via DoT and returns the response.
// Per RFC 7858: DNS messages are sent over TLS on a TCP connection
// using the standard DNS TCP wire format (2-byte length prefix).
//
// When a hostResolver is configured the current resolved address is obtained
// before each connection attempt. A background refresh may have updated the
// address since the previous call; if the address has expired a synchronous
// re-resolution is performed first.
func (c *DoTClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Obtain the dial address: use the resolver if re-resolution is enabled.
	addr := c.address
	if c.resolver != nil {
		addr = c.resolver.Addr()
	}

	transport := &dns.Transport{
		TLSConfig: c.tlsConfig,
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		transport.ReadTimeout = remaining
		transport.WriteTimeout = remaining
		transport.Dialer = &net.Dialer{Timeout: remaining}
	} else {
		transport.ReadTimeout = 10 * time.Second
		transport.WriteTimeout = 10 * time.Second
	}
	dnsClient := &dns.Client{Transport: transport}

	// The library's Transport.dial passes the network string directly to
	// tls.Dialer.DialContext when TLSConfig is set.  tls.Dialer wraps a plain
	// TCP dialer and applies TLS on top, so the network must be "tcp".
	// "tcp-tls" is not a recognised Go network type and causes "unknown network
	// tcp-tls" at dial time.
	resp, _, err := dnsClient.Exchange(ctx, msg, "tcp", addr)
	if err != nil {
		return nil, shortNetError(err)
	}

	return resp, nil
}

// shortNetError simplifies a *net.OpError by stripping the source and
// destination addresses from the error string. The upstream address is
// already present in the log prefix via Client.String(), so repeating it
// (along with internal local addresses) in the error message is redundant.
// Other error types are returned unchanged.
func shortNetError(err error) error {
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return fmt.Errorf("%s %s: %w", netErr.Op, netErr.Net, netErr.Err)
	}
	return err
}

// String returns a description of this client.
func (c *DoTClient) String() string {
	return fmt.Sprintf("DoT(%s)", c.address)
}
