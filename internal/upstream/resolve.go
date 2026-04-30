// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package upstream: resolve.go implements TTL- and interval-aware
// re-resolution of upstream hostnames.
package upstream

import (
	"context"
	"net"
	"sync"
	"time"
)

// ResolveDisabled is the exported sentinel value for resolveMode that disables
// re-resolution. Use this constant when calling NewDoHClient or NewDoTClient
// from outside the upstream package and re-resolution is not needed.
const ResolveDisabled = resolveDisabled

// resolveDisabled is the sentinel value for resolveMode that disables
// re-resolution. The hostname is resolved once at startup and never again.
// Matches the behaviour of AdGuard Home, dnscrypt-proxy, and CoreDNS.
const resolveDisabled = -1

// resolveByTTL is the sentinel value for resolveMode that enables TTL-based
// re-resolution. The resolved IP is reused for the lifetime of the DNS record
// TTL returned by the bootstrap server. A background refresh is started when
// 10% of the TTL remains.
const resolveByTTL = 0

// minResolveInterval is the minimum floor applied to all TTL and interval
// values to prevent hammering the bootstrap DNS server on very short TTLs.
const minResolveInterval = 30 * time.Second

// renewThresholdFrac determines when the background refresh is triggered.
// A background refresh starts when the remaining TTL/interval falls below
// 1/renewThresholdFrac of the total, i.e. at 10% remaining for a value of 10.
const renewThresholdFrac = 10

// hostResolver caches the resolved IP for a single upstream hostname and
// refreshes it according to the configured mode:
//
//   - resolveDisabled (-1): never re-resolve; use the initial IP forever.
//   - resolveByTTL (0): respect the DNS record TTL from the bootstrap
//     response; re-resolve after TTL expiry, with background refresh.
//   - N > 0: re-resolve at most once every N seconds, with background
//     refresh at 90% elapsed (10% remaining).
//
// Re-resolution only occurs during the connection-establishing phase
// (when Addr is called). Existing connections are never closed.
// All methods are safe for concurrent use.
type hostResolver struct {
	// immutable after construction
	host         string
	port         string
	bootstrapIPs []string
	ipFamily     string
	mode         int

	mu          sync.Mutex
	currentAddr string        // current "ip:port" or "host:port" fallback
	expiresAt   time.Time     // when the cached address is considered stale
	totalDur    time.Duration // full interval for renewal-threshold maths
	refreshing  bool          // a refresh (sync or background) is in progress
}

// newHostResolver creates a hostResolver for the given host and port.
// It performs an initial synchronous resolution via bootstrap DNS using the
// same bootstrapIPs and ipFamily settings that were used at startup.
//
// Returns nil (without error) when:
//   - mode is resolveDisabled (-1),
//   - host is already a numeric IP address,
//   - bootstrapIPs is empty (OS resolver handles per-dial resolution).
//
// When the initial bootstrap resolution fails the resolver falls back to
// storing host:port so that the OS resolver is tried at dial time, and
// schedules an early retry after minResolveInterval.
func newHostResolver(host, port string, bootstrapIPs []string, ipFamily string, mode int) (*hostResolver, error) {
	if mode == resolveDisabled {
		return nil, nil
	}
	if net.ParseIP(host) != nil {
		// Numeric IP: no hostname to track.
		return nil, nil
	}
	if len(bootstrapIPs) == 0 {
		// No bootstrap DNS configured: OS resolver handles re-resolution
		// naturally on each new dial attempt.
		return nil, nil
	}

	hr := &hostResolver{
		host:         host,
		port:         port,
		bootstrapIPs: bootstrapIPs,
		ipFamily:     ipFamily,
		mode:         mode,
		// Store host:port as the fallback before first resolution attempt.
		currentAddr: net.JoinHostPort(host, port),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, ttl, err := resolveViaBootstrap(ctx, host, bootstrapIPs, ipFamily)
	if err != nil {
		// Initial resolution failed. Keep the hostname as a fallback address
		// and set a short expiry so we retry soon.
		hr.setExpiry(0, mode)
		return hr, nil
	}

	hr.currentAddr = net.JoinHostPort(ip, port)
	hr.setExpiry(ttl, mode)
	return hr, nil
}

// setExpiry calculates and stores expiresAt and totalDur from a DNS TTL and
// the configured mode. Must be called with hr.mu held or before the resolver
// is shared across goroutines.
func (h *hostResolver) setExpiry(ttl uint32, mode int) {
	var dur time.Duration
	if mode == resolveByTTL {
		dur = time.Duration(ttl) * time.Second
		if dur < minResolveInterval {
			dur = minResolveInterval
		}
	} else {
		// Fixed interval: mode value is the number of seconds.
		dur = time.Duration(mode) * time.Second
	}
	h.totalDur = dur
	h.expiresAt = time.Now().Add(dur)
}

// Addr returns the current resolved "ip:port" for use when establishing a new
// connection.
//
// Behaviour:
//   - If the cached address has not expired, it is returned immediately.
//     When only 1/renewThresholdFrac (10%) of the TTL/interval remains a background
//     refresh is started so the new address is usually ready before expiry.
//   - If the cached address has expired and no refresh is running, a
//     synchronous re-resolution is performed (blocks up to 5 s). A refreshing
//     flag prevents concurrent callers from issuing duplicate DNS queries.
//   - If the cached address has expired but a refresh is already in progress,
//     the (stale) cached address is returned immediately; the caller can still
//     connect, and the refresh will update the address when it completes.
func (h *hostResolver) Addr() string {
	h.mu.Lock()

	now := time.Now()
	expired := !now.Before(h.expiresAt)

	if expired && !h.refreshing {
		// Mark in-progress before releasing the lock so concurrent callers
		// fall through to the "stale but refreshing" path below.
		h.refreshing = true
		h.mu.Unlock()
		return h.doRefresh()
	}

	if !expired && !h.refreshing && h.totalDur > 0 {
		remaining := h.expiresAt.Sub(now)
		if remaining < h.totalDur/renewThresholdFrac {
			h.refreshing = true
			go h.doRefresh()
		}
	}

	addr := h.currentAddr
	h.mu.Unlock()
	return addr
}

// doRefresh performs a DNS re-resolution, updates the stored address and
// expiry, then clears the refreshing flag. It is safe to call from both a
// synchronous (Addr) and asynchronous (background goroutine) context.
// It always uses its own 5-second context so it is not affected by the
// calling query's deadline.
func (h *hostResolver) doRefresh() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, ttl, err := resolveViaBootstrap(ctx, h.host, h.bootstrapIPs, h.ipFamily)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.refreshing = false
	if err != nil {
		// Extend expiry by minResolveInterval to avoid a retry storm on
		// persistent bootstrap failures.
		h.expiresAt = time.Now().Add(minResolveInterval)
		h.totalDur = minResolveInterval
		return h.currentAddr
	}
	h.currentAddr = net.JoinHostPort(ip, h.port)
	h.setExpiry(ttl, h.mode)
	return h.currentAddr
}
