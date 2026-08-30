// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package upstream

import (
	"context"
	"fmt"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/domainlist"
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// WhitelistResolver resolves whitelisted domains through a dedicated
// non-blocking upstream, bypassing all block-filtering upstreams.
type WhitelistResolver struct {
	client Client
	cfg    *config.WhitelistConfig
	list   *domainlist.DomainList
	// edns rebuilds the OPT record on forwarded queries. Nil leaves the
	// client's own OPT in place, which is only appropriate in tests.
	edns *edns.Middleware
}

// SetEDNS attaches the EDNS middleware used to rebuild the OPT record on
// queries forwarded to the whitelist upstream. Without it the client's own
// OPT section, including any ECS, cookie and NSID options, would be sent
// verbatim to the upstream, bypassing the configured privacy policy.
func (w *WhitelistResolver) SetEDNS(m *edns.Middleware) {
	if w != nil {
		w.edns = m
	}
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
	list := domainlist.NewDomainList("whitelist", domainlist.ModeAllow, cfg.ListFiles)
	var dbg domainlist.LogFunc
	if logger != nil {
		dbg = logger.Debugf
	}
	count, invalid, dedup, loadErr := list.Load(dbg)
	if logger != nil {
		LogListLoadResult(WhitelistReport, cfg.ListFiles, count, invalid, dedup, loadErr, logger)
	}

	// Start background watcher if list_ttl > 0
	if cfg.ListTTL > 0 && logger != nil {
		list.StartWatcher(cfg.ListTTL, logger.Infof, logger.Warnf, logger.Debugf)
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
	// Rebuild the OPT record exactly as the main fan-out does, so the
	// privacy policy (ECS, cookies, NSID, padding) and RFC 5452 transaction
	// ID apply here too rather than forwarding the client's query verbatim.
	out := msg
	if w.edns != nil {
		out = w.edns.PrepareUpstreamQuery(msg, w.client.String(), isClientTCP(w.client))
	}
	resp, err := w.client.Query(ctx, out)
	if err != nil {
		return nil, err
	}
	if w.edns != nil {
		w.edns.ProcessUpstreamResponse(resp, w.client.String())
	}
	return resp, nil
}

// Stop shuts down the background watcher and releases the upstream client.
func (w *WhitelistResolver) Stop() {
	if w == nil {
		return
	}
	if w.list != nil {
		w.list.Stop()
	}
	// This resolver owns a second upstream client, separate from Resolver's.
	if w.client != nil {
		w.client.Close()
	}
}

// OnListReload registers cb to be called after each successful hot-reload of
// the whitelist domain list with the newly loaded DomainSet. The callback is
// invoked in the watcher goroutine; schedule expensive work in its own goroutine.
// Safe to call before or after the watcher is started.
func (w *WhitelistResolver) OnListReload(cb func(newSet *domainlist.DomainSet)) {
	if w != nil && w.list != nil {
		w.list.OnReload(cb)
	}
}

// ListLoadReport describes the wording differences between the whitelist and
// blacklist variants of the load report, so both can share one implementation
// without changing either one's log output.
type ListLoadReport struct {
	// Prefix labels every line ("Whitelist" or "Blacklist").
	Prefix string
	// NoFilesMsg is the message used when the list is enabled but no
	// list_files are configured. It is formatted with Prefix.
	NoFilesMsg string
	// ThresholdSuffix is appended to the large-list warning (may be empty).
	ThresholdSuffix string
}

// WhitelistReport is the wording used for whitelist list loads.
var WhitelistReport = ListLoadReport{
	Prefix:     "Whitelist",
	NoFilesMsg: "%s: enabled but no list_files configured; list has no effect",
}

// BlacklistReport is the wording used for blacklist list loads.
var BlacklistReport = ListLoadReport{
	Prefix:          "Blacklist",
	NoFilesMsg:      "%s: enabled but no list_files configured; blacklist has no effect",
	ThresholdSuffix: "; large blocklists are not officially supported",
}

// LogListLoadResult logs the outcome of an initial domain list load.
// rep supplies the label and the two messages that differ between the
// whitelist and blacklist variants.
func LogListLoadResult(rep ListLoadReport, listFiles []string, count, invalid, dedup int, loadErr error, logger *logging.Logger) {
	prefix := rep.Prefix
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
			logger.Warnf("%s: %d domains exceeds recommended threshold (%d)%s", prefix, count, domainlist.LargeListThreshold, rep.ThresholdSuffix)
		}
		return
	}
	if len(listFiles) == 0 {
		logger.Warnf(rep.NoFilesMsg, prefix)
		return
	}
	if invalid > 0 {
		logger.Warnf("%s: enabled but no valid domains loaded from configured list_files (%d invalid lines)", prefix, invalid)
	} else {
		logger.Warnf("%s: enabled but no domains loaded from configured list_files", prefix)
	}
}
