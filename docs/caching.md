# Cache Design and Behavior

The DNSieve response cache: structure, TTL handling, eviction, background
refresh, and the whitelist caching design.

For configuration options (`max_entries`, `min_ttl`, `blocked_ttl`,
`renew_percent`) see [configuration.md](configuration.md#cache). For where
the cache sits in the query pipeline see
[configuration.md -- Query Processing Order](configuration.md#query-processing-order).

## Overview

DNSieve keeps a single in-memory cache shared by all query paths, keyed by
the DNS question (name + type + DO bit). Each entry stores the wire-format
response plus metadata (expiry, Blocked / Whitelisted / DNSSEC flags).

- **Single cache**: whitelist, blocked, and general responses share one map,
  one TTL/eviction policy.
- **Wire-format storage**: serving a cached entry unpacks a fresh copy, so
  callers can never mutate the cache.
- **Proactive refresh**: a background goroutine re-queries upstreams before
  an entry expires.
- **Memory-bounded**: at `max_entries`, the entry closest to expiry is
  evicted (TTL-priority, not LRU).

### Memory sizing

Each entry uses roughly 500-1500 bytes depending on response size:

| max_entries | Approximate memory | Suitable for                    |
|-------------|--------------------|---------------------------------|
| 10,000      | 5-15 MB            | ~20 users, 30 devices (default) |
| 50,000      | 25-75 MB           | ~100 users, 200 devices         |
| 100,000     | 50-150 MB          | ~500 users, 1000 devices        |

> [!NOTE]
> `renew_percent` also controls when upstream hostnames are re-resolved for
> `upstream_ttl` modes 0 and N>0. See
> [configuration.md](configuration.md#upstream-re-resolution-upstream_ttl).

## Cache Key Format

```
<lowercased-fqdn>/<qtype>/<qclass>[/DO]
```

Example: `example.com./A/IN`, or `example.com./A/IN/DO` for a DO=1 query.

- **Case-insensitive**: names are lowercased (RFC 4343).
- **Type-segregated**: A and AAAA for the same name are separate entries.
- **DO-bit segregated**: DO=0 and DO=1 queries use different keys (RFC 3225),
  so DNSSEC and non-DNSSEC clients never see each other's responses.
- **Unknown types/classes**: encoded numerically as `TYPEn`/`CLASSn`.

## Entry Structure

| Field        | Type       | Description                                       |
|--------------|------------|---------------------------------------------------|
| `Data`       | `[]byte`   | Wire-format packed DNS message                    |
| `Blocked`    | `bool`     | Entry represents a blocked response               |
| `Whitelisted`| `bool`     | Entry was resolved via the whitelist resolver     |
| `DNSSEC`     | `bool`     | Originating query had DO=1                        |
| `ExpiresAt`  | `time.Time`| Expiry time                                       |
| `InsertedAt` | `time.Time`| Insertion time                                    |

## TTL Handling

- **Normal responses**: `cached_ttl = max(min(all Answer/Authority TTLs), min_ttl)`.
  Responses without such records (e.g. NODATA) use `min_ttl`.
- **Blocked responses**: always cached for `blocked_ttl`, regardless of the
  upstream TTL. (Local blacklist hits bypass the cache entirely; see below.)
- **On serve**: record TTLs are capped at the seconds remaining until expiry,
  with a 1-second minimum so clients never receive 0-TTL records.

> [!TIP]
> `min_ttl` (default 60) stops very short CDN TTLs from causing bursts of
> upstream queries. Setting it too high serves stale data longer than the
> upstream intended.

## Eviction Policy

When the cache is full and a new entry arrives:

1. A linear scan removes the first expired entry found, if any.
2. Otherwise the entry with the smallest `ExpiresAt` is removed.

This is TTL-priority eviction, not LRU: entries about to expire anyway are
sacrificed before long-lived records.

## Background Refresh

When `renew_percent > 0` and a served entry has less than that percentage of
its TTL remaining, DNSieve re-queries upstreams in the background while the
cached answer is returned immediately. Example: `renew_percent = 10` with a
300-second TTL triggers a refresh when under 30 seconds remain.

- **Deduplicated**: at most one refresh goroutine per cache key.
- **Path-aware**: whitelisted domains are refreshed via the whitelist
  resolver (entry stays `Whitelisted=true`); all others go through the
  normal fan-out with block-consensus.
- **Safe**: the result is committed only when cacheable (all upstreams
  responded, no NXDOMAIN disagreement). On failure or SERVFAIL the old
  entry keeps serving until it expires.

## Whitelist Caching Design

Whitelist-resolved responses live in the same cache, distinguished by the
`Whitelisted=true` flag -- no duplicate storage, one eviction policy, one
invalidation pass.

On the whitelist path the cache is checked first. A hit is served only when
`entry.Whitelisted == true`; any other entry (e.g. a stale blocked entry not
yet invalidated after a reload) is ignored and the whitelist resolver is
queried, overwriting the stale entry. If a stored entry fails to unpack, a
warning is logged and the resolver is queried fresh.

## Cache Invalidation on Whitelist Hot-Reload

After each successful whitelist reload, a background goroutine removes every
entry whose stored `Whitelisted` flag disagrees with the domain's current
whitelist membership:

| Cached state      | Now in whitelist | Action     |
|-------------------|------------------|------------|
| Whitelisted=true  | yes              | Keep       |
| Whitelisted=true  | no               | **Remove** |
| Whitelisted=false | no               | Keep       |
| Whitelisted=false | yes              | **Remove** |

The membership check uses full wildcard matching (`*.example.com` covers the
apex and all subdomains at any depth), so adding or removing a wildcard
correctly invalidates deep-subdomain entries. DO-bit variants and all query
types for a domain are covered by the same pass.

Invalidation is selective (only changed domains), runs off the hot path, and
holds the write lock only for an in-memory scan -- a few milliseconds even on
large caches. Races around the reload window are benign: a query landing
between the list swap and the invalidation either re-queries the whitelist
resolver (and overwrites the entry) or briefly serves the still-correct old
response.

> [!NOTE]
> If a domain is in both the whitelist and the blacklist, the whitelist wins:
> it is checked earlier in the pipeline.

## Blacklist and Cache

Locally-blacklisted domains bypass the cache in both directions: no read (a
stale non-blocked entry can never override the blacklist) and no write
(blacklist edits take effect on the next query without any cache flush).
The per-query cost is one O(1) hash lookup.

If you want blocked domains cached, use upstream-level blocking instead --
upstream block responses ARE cached with `blocked_ttl`.

## Thread Safety

A single `sync.RWMutex` protects the entry map: read lock for `Get`, write
lock for `Put`, `Flush`, and `InvalidateIf`. In-flight background refreshes
are tracked in a separate lock-free `sync.Map`. Concurrent `Put` calls for
the same key are safe -- last writer wins with a complete entry.

## Edge Cases

- **Wildcard scope**: `*.abc.example.com` covers `abc.example.com` and its
  subdomains only -- never `example.com` or siblings. A broader wildcard
  already in the list makes adding a narrower one a no-op.
- **Wildcard depth**: matching walks up the labels of the queried name (at
  most 127), so unlimited subdomain depth is safe.
- **Empty whitelist**: with no entries loaded, all `Whitelisted=true` entries
  are invalidated on reload.
- **`max_entries = 0`** (or cache disabled): the constructor falls back to a
  10,000-entry cache, but no reads or writes happen when
  `cache.enabled = false`.
- **`renew_percent = 0`**: no background refresh; entries expire and the next
  query goes upstream.

> [!WARNING]
> A bare `*` does NOT match all domains in either list -- it only matches a
> query literally named `*`. Use explicit `*.domain.tld` wildcards, or a
> non-blocking upstream if you want to disable blocking.

## Diagnostic Logging

Set `log_level_stdout = "debug"` (or `log_level_file`) to see per-query cache
activity: hits with `ttl=`/`rtl=` (original/remaining seconds), misses,
background-refresh start/success/failure, and stale-entry warnings.
Whitelist reload invalidation logs the removed-entry count at info level
when non-zero.

In JSON mode a `dns_query` event is also emitted when a background refresh
completes; it carries the upstream results and caching decision but no
`response` field (the client was already answered from cache). See
[logging.md](logging.md#background-refresh-upstream-query).
