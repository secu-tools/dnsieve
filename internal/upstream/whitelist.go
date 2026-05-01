// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/net/idna"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// toACEDomain converts a domain label sequence that may contain Unicode
// characters to its ASCII Compatible Encoding (ACE/Punycode) representation
// as defined in RFC 5891 (IDNA 2008). For example, the German city domain
// encoded with an umlaut character becomes its xn-- Punycode equivalent.
// Domains that are already in ASCII form (including those with existing xn--
// encoded labels) are returned unchanged. The trailing FQDN dot, if present,
// is temporarily stripped before conversion and not re-added; callers should
// apply dnsutil.Fqdn after this function when a fully-qualified form is
// needed. If conversion fails the input is returned as-is so that ASCII-only
// configured entries continue to match correctly.
func toACEDomain(domain string) string {
	domainNoTrailingDot := strings.TrimSuffix(domain, ".")
	ace, err := idna.Lookup.ToASCII(domainNoTrailingDot)
	if err != nil {
		return domainNoTrailingDot
	}
	return ace
}

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
// bootstrapIPs, ipFamily, and resolveMode are forwarded to the underlying
// client so that re-resolution behaves identically to main upstreams.
// renewPercent and logger are forwarded to the hostResolver for background
// refresh logging (pass 0, nil to use defaults / silence logging).
func NewWhitelistResolver(cfg *config.WhitelistConfig, verifyCert bool, bootstrapIPs []string, ipFamily string, resolveMode int, renewPercent int, logger *logging.Logger) (*WhitelistResolver, error) {
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
	c, err := newClient(srv, verifyCert, bootstrapIPs, ipFamily, resolveMode, renewPercent, logger)
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

		// Wildcard pattern: *.example.com or *.idn-domain (IDN labels supported)
		if strings.HasPrefix(entry, "*.") {
			// Convert the base domain to ACE form for IDN support, then reconstruct
			// the suffix and base FQDN used for matching.
			aceBase := toACEDomain(entry[2:])     // "m\u00fcnchen.de" -> "xn--mnchen-3ya.de"
			suffix := "." + dnsutil.Fqdn(aceBase) // ".xn--mnchen-3ya.de."
			base := dnsutil.Fqdn(aceBase)         // "xn--mnchen-3ya.de."
			// Match any subdomain suffix (e.g., "sub.xn--mnchen-3ya.de.")
			if strings.HasSuffix(qname, suffix) {
				return true
			}
			// Also match the base domain itself (e.g., *.example.com matches example.com)
			if qname == base {
				return true
			}
			continue
		}

		// Exact match - convert to ACE form first to support IDN (Unicode) entries
		candidate := dnsutil.Fqdn(toACEDomain(entry))
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
