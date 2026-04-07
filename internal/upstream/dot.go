// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
)

// DoTClient implements DNS-over-TLS (RFC 7858 / RFC 8310).
type DoTClient struct {
	address   string
	tlsConfig *tls.Config
}

// NewDoTClient creates a DoT client for the given server address (host:port).
// bootstrapIPs is an optional list of host:port addresses used to resolve
// the DoT server hostname instead of the system resolver.
func NewDoTClient(address string, verifyCert bool, bootstrapIPs ...string) (*DoTClient, error) {
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

	// Pre-resolve the hostname via bootstrap DNS at creation time.
	// The resolved IP replaces the hostname in the dial address while the
	// original hostname is kept as the TLS ServerName for SNI.
	if len(bootstrapIPs) > 0 && net.ParseIP(host) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if ip, err := resolveViaBootstrap(ctx, host, bootstrapIPs); err == nil {
			address = net.JoinHostPort(ip, port)
		}
		// On resolution failure, fall through and use the original address
		// (system resolver will be tried when dialling).
	}

	return &DoTClient{
		address: address,
		tlsConfig: &tls.Config{
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
		},
	}, nil
}

// Query sends a DNS query via DoT and returns the response.
// Per RFC 7858: DNS messages are sent over TLS on a TCP connection
// using the standard DNS TCP wire format (2-byte length prefix).
func (c *DoTClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
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
	resp, _, err := dnsClient.Exchange(ctx, msg, "tcp", c.address)
	if err != nil {
		return nil, fmt.Errorf("DoT query to %s: %w", c.address, err)
	}

	return resp, nil
}

// String returns a description of this client.
func (c *DoTClient) String() string {
	return fmt.Sprintf("DoT(%s)", c.address)
}
