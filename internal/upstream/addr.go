// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package upstream: addr.go normalizes upstream server addresses.
package upstream

import (
	"net"
	"strings"
)

// Default ports for the upstream transports, used when an address carries no
// port component.
const (
	defaultPlainPort = "53"
	defaultDoTPort   = "853"
)

// addrWithDefaultPort normalizes a server address to "host:port" form, adding
// defaultPort when the address has none. A raw IPv6 literal without brackets
// (e.g. "2001:db8::1") is bracketed so the result parses as host:port.
//
// It returns the full "host:port" address plus the host and port separately,
// so callers that need the bare hostname (for TLS SNI) do not re-split it.
func addrWithDefaultPort(address, defaultPort string) (full, host, port string) {
	if h, p, err := net.SplitHostPort(address); err == nil {
		return address, h, p
	}
	if strings.Contains(address, ":") {
		// Raw IPv6 address without brackets and port.
		return "[" + address + "]:" + defaultPort, address, defaultPort
	}
	return address + ":" + defaultPort, address, defaultPort
}
