// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"strconv"
)

// ClientMeta carries per-request client information through the context.
// It is attached by each downstream listener (plain, DoT, DoH) before
// invoking HandleQuery so that structured log events can include full
// client details regardless of which transport delivered the query.
type ClientMeta struct {
	// IP is the client's source IP address (IPv4 or IPv6, no port).
	IP string
	// Port is the client's source port number.
	Port int
	// Protocol is the downstream transport: "plain", "dot", or "doh".
	Protocol string
}

// clientMetaKey is the unexported context key for ClientMeta values.
// Using a private type prevents key collisions with other packages.
type clientMetaKey struct{}

// WithClientMeta returns a copy of ctx with meta attached.
// Downstream listeners call this before forwarding to HandleQuery.
func WithClientMeta(ctx context.Context, meta *ClientMeta) context.Context {
	return context.WithValue(ctx, clientMetaKey{}, meta)
}

// ClientMetaFrom extracts a ClientMeta from ctx.
// Returns nil when no metadata was attached (e.g. internal/background queries).
func ClientMetaFrom(ctx context.Context) *ClientMeta {
	meta, _ := ctx.Value(clientMetaKey{}).(*ClientMeta)
	return meta
}

// parseRemoteAddr splits a "host:port" address string into its components.
// Returns an empty IP and zero port on parse failure.
func parseRemoteAddr(addr net.Addr) (ip string, port int) {
	if addr == nil {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}

// parseRemoteAddrString splits a "host:port" string (as in http.Request.RemoteAddr)
// into its components. Returns an empty IP and zero port on parse failure.
func parseRemoteAddrString(addr string) (ip string, port int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}
