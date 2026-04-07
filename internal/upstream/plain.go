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
)

// PlainClient implements plain DNS over UDP with TCP fallback.
type PlainClient struct {
	address string
}

// NewPlainClient creates a plain DNS client for the given server address
// (host:port).
func NewPlainClient(address string) (*PlainClient, error) {
	if address == "" {
		return nil, fmt.Errorf("empty DNS address")
	}
	// Normalise: if the address has no port component, append the default.
	if _, _, err := net.SplitHostPort(address); err != nil {
		if strings.Contains(address, ":") {
			// Raw IPv6 address without port (e.g. "2001:db8::1").
			address = "[" + address + "]:53"
		} else {
			address = address + ":53"
		}
	}
	return &PlainClient{address: address}, nil
}

// Query sends a DNS query via UDP and falls back to TCP if the response
// is truncated.
func (c *PlainClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	transport := &dns.Transport{}
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
	client := &dns.Client{Transport: transport}

	resp, _, err := client.Exchange(ctx, msg, "udp", c.address)
	if err != nil {
		return nil, fmt.Errorf("UDP query to %s: %w", c.address, err)
	}

	// TCP fallback on truncation
	if resp.Truncated {
		resp, _, err = client.Exchange(ctx, msg, "tcp", c.address)
		if err != nil {
			return nil, fmt.Errorf("TCP fallback to %s: %w", c.address, err)
		}
	}

	return resp, nil
}

// String returns a description of this client.
func (c *PlainClient) String() string {
	return fmt.Sprintf("UDP(%s)", c.address)
}
