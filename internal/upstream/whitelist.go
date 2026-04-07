// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/config"
)

// WhitelistResolver resolves whitelisted domains through a dedicated
// non-blocking upstream, bypassing all block-filtering upstreams.
type WhitelistResolver struct {
	client Client
	cfg    *config.WhitelistConfig
}

// NewWhitelistResolverFromClient creates a WhitelistResolver from an existing
// Client. This is primarily useful for testing.
func NewWhitelistResolverFromClient(c Client, cfg *config.WhitelistConfig) *WhitelistResolver {
	return &WhitelistResolver{client: c, cfg: cfg}
}

// NewWhitelistResolver creates a WhitelistResolver from config.
// When cfg.Enabled is false this returns nil without error; callers
// should check for nil before using the resolver.
func NewWhitelistResolver(cfg *config.WhitelistConfig, verifyCert bool) (*WhitelistResolver, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	addr := cfg.ResolverAddress
	if addr == "" {
		addr = "https://1.1.1.1/dns-query"
	}
	proto := cfg.ResolverProtocol
	if proto == "" {
		proto = "doh"
	}

	srv := config.UpstreamServer{
		Address:  addr,
		Protocol: proto,
	}
	c, err := newClient(srv, verifyCert, nil)
	if err != nil {
		return nil, err
	}

	return &WhitelistResolver{client: c, cfg: cfg}, nil
}

// IsWhitelisted reports whether the given FQDN matches any entry in the
// whitelist. Domain matching syntax:
//   - "example.com" matches only example.com exactly
//   - "*.example.com" matches all subdomains of example.com
//   - "*.cn" matches all .cn domains
//   - "*" matches everything
func (w *WhitelistResolver) IsWhitelisted(qname string) bool {
	if w == nil || !w.cfg.Enabled {
		return false
	}

	qname = dnsutil.Fqdn(strings.ToLower(qname))

	for _, entry := range w.cfg.Domains {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}

		// Global wildcard: matches everything
		if entry == "*" {
			return true
		}

		// Wildcard pattern: *.example.com
		if strings.HasPrefix(entry, "*.") {
			suffix := entry[1:] // ".example.com"
			suffix = dnsutil.Fqdn(suffix)
			// Match the suffix (e.g., qname "sub.example.com." ends with ".example.com.")
			if strings.HasSuffix(qname, suffix) {
				return true
			}
			// Also match the base domain itself (e.g., *.example.com matches example.com)
			base := dnsutil.Fqdn(entry[2:])
			if qname == base {
				return true
			}
			continue
		}

		// Exact match
		candidate := dnsutil.Fqdn(entry)
		if qname == candidate {
			return true
		}
	}
	return false
}

// Query resolves a DNS message through the whitelist resolver's upstream.
// This bypasses all blocking upstreams.
func (w *WhitelistResolver) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	return w.client.Query(ctx, msg)
}
