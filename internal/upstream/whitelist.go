// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/domainlist"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// WhitelistResolver resolves whitelisted domains through a dedicated
// non-blocking upstream, bypassing all block-filtering upstreams.
type WhitelistResolver struct {
	client Client
	cfg    *config.WhitelistConfig
	list   *domainlist.DomainList
}

// NewWhitelistResolverFromClient creates a WhitelistResolver from an existing
// Client and DomainList. This is primarily useful for testing.
func NewWhitelistResolverFromClient(c Client, cfg *config.WhitelistConfig, list *domainlist.DomainList) *WhitelistResolver {
	return &WhitelistResolver{client: c, cfg: cfg, list: list}
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

	// Load domain list from files
	list := domainlist.NewDomainList("whitelist", cfg.ListFiles)
	var dbg domainlist.LogFunc
	if logger != nil {
		dbg = func(f string, a ...interface{}) { logger.Debugf(f, a...) }
	}
	count, invalid, dedup, loadErr := list.Load(dbg)
	if logger != nil {
		logListLoadResult("Whitelist", cfg.ListFiles, count, invalid, dedup, loadErr, logger)
	}

	// Start background watcher if list_ttl > 0
	if cfg.ListTTL > 0 && logger != nil {
		list.StartWatcher(cfg.ListTTL,
			func(f string, a ...interface{}) { logger.Infof(f, a...) },
			func(f string, a ...interface{}) { logger.Warnf(f, a...) },
			func(f string, a ...interface{}) { logger.Debugf(f, a...) },
		)
		logger.Infof("Whitelist: file watcher started (check interval: %ds)", cfg.ListTTL)
	}

	return &WhitelistResolver{client: c, cfg: cfg, list: list}, nil
}

// IsWhitelisted reports whether the given FQDN matches any entry in the
// whitelist domain list.
func (w *WhitelistResolver) IsWhitelisted(qname string) bool {
	if w == nil || !w.cfg.Enabled || w.list == nil {
		return false
	}
	return w.list.Contains(qname)
}

// Query resolves a DNS message through the whitelist resolver's upstream.
// This bypasses all blocking upstreams.
func (w *WhitelistResolver) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	return w.client.Query(ctx, msg)
}

// Stop shuts down the whitelist resolver's background watcher.
func (w *WhitelistResolver) Stop() {
	if w != nil && w.list != nil {
		w.list.Stop()
	}
}

// logListLoadResult logs the outcome of an initial domain list load.
// prefix is "Whitelist" or "Blacklist".
func logListLoadResult(prefix string, listFiles []string, count, invalid, dedup int, loadErr error, logger *logging.Logger) {
	if loadErr != nil {
		logger.Warnf("%s: failed to load list files: %v", prefix, loadErr)
		return
	}
	if count > 0 {
		msg := fmt.Sprintf("%s: loaded %d domains", prefix, count)
		if dedup > 0 {
			msg += fmt.Sprintf(" (%d dedup)", dedup)
		}
		if invalid > 0 {
			msg += fmt.Sprintf(", %d invalid", invalid)
		}
		msg += " from list files"
		if invalid > 0 {
			logger.Warnf("%s", msg)
		} else {
			logger.Infof("%s", msg)
		}
		if count > domainlist.LargeListThreshold {
			logger.Warnf("%s: %d domains exceeds recommended threshold (%d)", prefix, count, domainlist.LargeListThreshold)
		}
		return
	}
	if len(listFiles) == 0 {
		logger.Warnf("%s: enabled but no list_files configured; list has no effect", prefix)
		return
	}
	if invalid > 0 {
		logger.Warnf("%s: enabled but no valid domains loaded from configured list_files (%d invalid lines)", prefix, invalid)
	} else {
		logger.Warnf("%s: enabled but no domains loaded from configured list_files", prefix)
	}
}
