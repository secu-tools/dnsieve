# Cache Design and Behavior Reference

This document describes the DNSieve response cache in detail: its internal
structure, TTL handling, eviction, background refresh, the whitelist caching
design, and all known edge cases.

For configuration options (`max_entries`, `min_ttl`, `blocked_ttl`,
`renew_percent`) see [configuration.md](configuration.md#cache).

For the query processing order (where the cache sits in the pipeline) see
[protocol.md](protocol.md#cache-behavior).

---

## Table of Contents

1. [Overview](#overview)
2. [Cache Key Format](#cache-key-format)
3. [Entry Structure](#entry-structure)
4. [TTL Handling](#ttl-handling)
5. [Eviction Policy](#eviction-policy)
6. [Background Refresh](#background-refresh)
7. [Whitelist Caching Design](#whitelist-caching-design)
8. [Cache Invalidation on Whitelist Hot-Reload](#cache-invalidation-on-whitelist-hot-reload)
9. [Blacklist and Cache](#blacklist-and-cache)
10. [Thread Safety](#thread-safety)
11. [Edge Cases](#edge-cases)
12. [Diagnostic Logging](#diagnostic-logging)

---

## Overview

DNSieve maintains a single in-memory DNS response cache shared by all query
paths. The cache is keyed by the DNS question (name + type + DO bit) and stores
the wire-format DNS response together with metadata (TTL expiry, Blocked flag,
Whitelisted flag, DNSSEC flag).

Design goals:

- **Single cache**: whitelist, blocked, and general responses all live in the
  same map. One TTL/eviction logic, no duplicate storage.
- **Wire-format storage**: responses are packed to binary before storage.
  Serving a cached entry unpacks a fresh copy so callers get independent
  message objects and the cache is never mutated by callers.
- **Proactive refresh**: a background goroutine re-queries upstreams before
  an entry expires, reducing latency spikes at TTL boundaries.
- **Memory-bounded**: when the entry count reaches `max_entries`, the entry
  closest to expiry is evicted (TTL-priority eviction, not LRU).

### Memory sizing

Each cached entry uses approximately 500-1500 bytes depending on DNS response
size (wire-format storage). Estimates:

| max_entries | Approximate memory | Suitable for                         |
|-------------|-------------------|--------------------------------------|
| 10,000      | 5-15 MB           | ~20 users, 30 devices (default)      |
| 50,000      | 25-75 MB          | ~100 users, 200 devices              |
| 100,000     | 50-150 MB         | ~500 users, 1000 devices             |

The `renew_percent` setting also controls when the upstream hostname
resolver triggers a background re-resolution for `upstream_ttl` modes 0
and N>0. See [configuration.md -- Upstream Re-resolution](configuration.md#upstream-re-resolution-upstream_ttl).

---

## Cache Key Format

```
<lowercased-fqdn>/<qtype>/<qclass>[/DO]
```

Examples:

| DNS question                  | Cache key                          |
|-------------------------------|------------------------------------|
| `example.com. A IN`           | `example.com./A/IN`                |
| `EXAMPLE.COM. A IN`           | `example.com./A/IN` (lowercased)   |
| `example.com. AAAA IN`        | `example.com./AAAA/IN`             |
| `example.com. A IN` (DO=1)    | `example.com./A/IN/DO`             |
| `example.com. TYPE65 IN`      | `example.com./TYPE65/IN`           |
| `example.com. A CLASS5`       | `example.com./A/CLASS5`            |

Key properties:

- **Case-insensitive**: domain names are lowercased before keying (DNS names
  are case-insensitive per RFC 4343).
- **Type-segregated**: A and AAAA for the same name are stored separately.
- **DO-bit segregated**: `DO=0` and `DO=1` queries are stored under different
  keys (RFC 3225). A DO=0 client will never read a DO=1 cached response and
  vice versa.
- **Unknown types/classes**: encoded as `TYPEn`/`CLASSn` using the numeric
  value, so unknown RR types still get individual cache entries.

The domain portion of the key is extracted by `keyDomain()` for use in
invalidation predicates (see [Cache Invalidation](#cache-invalidation-on-whitelist-hot-reload)).

---

## Entry Structure

Each cache entry stores:

| Field        | Type       | Description                                          |
|--------------|------------|------------------------------------------------------|
| `Data`       | `[]byte`   | Wire-format packed DNS message (deep copy)           |
| `Blocked`    | `bool`     | True if this entry represents a blocked response     |
| `Whitelisted`| `bool`     | True if this entry was resolved via whitelist resolver|
| `DNSSEC`     | `bool`     | True if the originating query had DO=1               |
| `ExpiresAt`  | `time.Time`| Absolute wall-clock time when entry expires          |
| `InsertedAt` | `time.Time`| Absolute wall-clock time when entry was stored       |

The `Whitelisted` and `Blocked` flags are mutually exclusive in practice:
a response is either a whitelist resolution or a blocked response, never both.
Storing both flags allows the invalidation predicate to reason about the
exact cached state without re-parsing the DNS response.

---

## TTL Handling

### Normal responses

The cached TTL is the **minimum TTL across all Answer and Authority records**
in the response, floored by `min_ttl`:

```
cached_ttl = max(min(all_record_ttls), min_ttl)
```

If the response has no Answer or Authority records (e.g. NODATA), `min_ttl`
is used as the fallback.

### Blocked responses

Blocked entries (from upstream detection or local blacklist via upstream
path) use `blocked_ttl` regardless of what the upstream returned. Local
blacklist queries bypass the cache entirely (see
[Blacklist and Cache](#blacklist-and-cache)).

### TTL adjustment on serve

When a cached entry is served to a client, all resource record TTLs in the
response are adjusted to reflect the **remaining time** rather than the
original upstream TTL. Each RR's TTL is capped at the remaining seconds:

```
served_ttl = min(original_rr_ttl, seconds_until_expiry)
```

If an entry has 0 seconds remaining (just about to expire), served TTLs
are set to 1 second minimum to avoid sending 0-TTL records that clients
treat as uncacheable.

### min_ttl

`min_ttl` is the floor for upstream TTLs. It prevents very short TTLs (some
CDN records use 30s or less) from causing a burst of upstream queries. The
default is 60 seconds.

Setting `min_ttl` too high causes the cache to serve stale data for longer
than the upstream intended. Setting it too low allows high-churn domains to
exhaust the cache capacity and generate excessive upstream traffic.

---

## Eviction Policy

When `len(entries) >= max_entries` and a new entry is about to be inserted,
one existing entry is evicted. The eviction strategy is:

1. **Expired entries first**: a single linear scan finds the first expired
   entry and removes it. This is O(n) in the worst case but terminates as
   soon as one expired entry is found.
2. **Closest-to-expiry**: if no expired entries are found, the entry with
   the smallest `ExpiresAt` is removed.

This is TTL-priority eviction, not LRU. It avoids premature eviction of
long-lived authoritative records (e.g. a 24-hour TTL) in favour of entries
that are about to expire anyway.

The practical consequence: under heavy load with `max_entries` reached, the
entries that would have expired next are removed, which roughly matches the
ideal behaviour of expiring the least-valuable entries first.

---

## Background Refresh

When `renew_percent > 0`, DNSieve triggers a background upstream query while
serving a near-expiry entry from cache. This keeps the cache continuously
populated and avoids the latency spike that occurs when an entry expires and
the next query must wait for a full upstream round-trip.

### Trigger condition

A background refresh is triggered when an entry is served AND:

```
remaining_ttl < (original_ttl * renew_percent / 100)
```

Example with `renew_percent = 10` and an entry with a 300-second TTL:
the refresh triggers when fewer than 30 seconds remain.

### Deduplication

Only one background refresh goroutine is in flight per cache key at a time.
A `sync.Map` (`refreshing`) tracks in-flight keys. If a second request for
the same key arrives while a refresh is already running, no new goroutine
is started.

### Refresh paths

The refresh callback (`SetRefreshFunc`) dispatches based on the domain's
current whitelist membership at the time of the refresh:

- **Whitelisted domain**: refreshed via the whitelist resolver. The new entry
  is stored with `Whitelisted=true`. This ensures that a domain which was
  being actively whitelisted continues to be resolved cleanly after refresh.
- **Normal domain**: refreshed via the main upstream fan-out with full
  block-consensus. The new entry is stored as `Blocked=true` (with
  `blocked_ttl`) or `Blocked=false` depending on the consensus result.

### Refresh result storage

A refresh result is committed to cache only when the result is **cacheable**
(all upstreams responded and there is no NXDOMAIN disagreement). If the
result is not cacheable, the old entry remains valid until it expires.
This prevents a partial upstream response from evicting a good cached entry.

### SERVFAIL handling

If the upstream refresh returns SERVFAIL or no response, the error is
logged at debug level and the old entry continues to be served until expiry.

---

## Whitelist Caching Design

### Single shared cache

Whitelist-resolved responses are stored in the **same cache** as all other
responses. There is no separate whitelist cache. The `Whitelisted=true` flag
in the entry distinguishes whitelist-resolved entries from general or blocked
entries for the same domain.

Benefits of this design:
- No duplicate memory usage.
- One TTL/eviction policy for all entries.
- `max_entries`, `min_ttl`, `blocked_ttl`, and `renew_percent` all apply
  uniformly.
- Simpler invalidation: a single `InvalidateIf` pass over all entries.

### Cache-first lookup on whitelist path

When a query is identified as whitelisted (step 2 of the query processing
order), the cache is checked **before** the whitelist resolver is queried:

1. `cache.Get` is called.
2. If `entry != nil && entry.Whitelisted == true`: a cached response exists
   from a prior whitelist resolution. The response is returned immediately.
   No network round-trip occurs.
3. If `entry == nil` or `entry.Whitelisted == false`: proceed to the
   whitelist resolver (see below).

**Why check Whitelisted==true?** A non-whitelist entry (e.g. a stale blocked
entry that has not yet been invalidated after a whitelist reload) must not be
served on the whitelist path. The whitelist path always re-queries the
whitelist resolver in this case so the domain resolves correctly.

### Whitelisted=false entry in cache for a whitelisted domain

This is a transient race condition that occurs between the moment a domain is
added to the whitelist and the moment the whitelist reload runs and invalidates
the old entry. The handler handles it gracefully: when it finds an entry with
`Whitelisted=false` for a domain it knows to be whitelisted, it ignores the
cached entry and queries the whitelist resolver. The new resolver response
overwrites the stale entry in cache.

### Corrupted cache entry fallback

`MakeCachedResponse` unpacks the stored wire bytes to build the response
message. In the (rare) event that the stored bytes are corrupted or cannot
be unpacked (e.g. due to a memory corruption), `MakeCachedResponse` returns
nil. The handler detects this, logs a warning, and falls through to the
whitelist resolver for a fresh query. The re-queried response is stored,
replacing the corrupted entry. This prevents a corrupted whitelist entry
from causing a whitelisted domain to be incorrectly blocked by the normal
pipeline.

---

## Cache Invalidation on Whitelist Hot-Reload

### When it runs

Every `list_ttl` seconds, the whitelist domain list is hot-reloaded (if any
file changed). After a successful reload, a background goroutine runs
`InvalidateIf` to remove cache entries whose whitelist membership has changed.

### The predicate

```go
func(name string, entry *cache.Entry) bool {
    isNowWhitelisted := newSet.Contains(name)
    return entry.Whitelisted != isNowWhitelisted
}
```

An entry is removed when its stored `Whitelisted` flag disagrees with whether
the domain is now in the whitelist. This covers four cases:

| Cached state      | Current whitelist | Action     | Reason                                       |
|-------------------|-------------------|------------|----------------------------------------------|
| Whitelisted=true  | domain present    | Keep       | No change                                    |
| Whitelisted=true  | domain absent     | **Remove** | Domain left whitelist; must re-evaluate      |
| Whitelisted=false | domain absent     | Keep       | No change                                    |
| Whitelisted=false | domain present    | **Remove** | Domain joined whitelist; re-route to WL path |

### Wildcard matching in the predicate

`newSet.Contains(name)` performs full wildcard matching via `DomainSet`:

- The cache key stores the FQDN with a trailing dot (e.g. `example.com.`).
  `Contains` normalizes by stripping the trailing dot before matching.
- Wildcard entries (`*.example.com`) cover the apex AND all subdomains at
  any depth. `matchWildcard` walks up the label hierarchy:
  `e1.a2.b3.example.com` -> `a2.b3.example.com` -> `b3.example.com` ->
  `example.com` -- if `*.example.com` is in the set, the last step matches.
- A cached entry for `e1.a2.b3.v4.sub.example.com` (Whitelisted=true) is
  correctly invalidated when `*.example.com` is removed from the whitelist.
- Conversely, a cached entry for `e1.a2.b3.v4.sub.example.com`
  (Whitelisted=false) is correctly invalidated when `*.example.com` is added.

### DO-bit segregated entries

A single domain can have up to two entries per query type: one for `DO=0`
and one for `DO=1` (different cache keys per RFC 3225). Both entries share
the same domain name, so both are matched by `keyDomain()` and both are
invalidated by the same predicate invocation. No special handling is required.

### Multiple query types

A domain with separate entries for A, AAAA, MX, TXT, etc. (all whitelisted)
will have all entries invalidated in a single `InvalidateIf` pass because
each key's domain portion is the same and the predicate fires for each key.

### Goroutine and lock behavior

`InvalidateIf` acquires the cache write lock for the full scan. On large
caches (100k entries), this can take a few milliseconds. The goroutine is
launched from the reload callback to avoid blocking the file-watcher goroutine.
During the write lock, query goroutines that need to read or write the cache
will block briefly. This is acceptable because:

1. Invalidation runs in the background, not in the hot query path.
2. The lock is held only as long as the scan takes (no I/O, no network calls).
3. Blocking is brief: the scan is a simple in-memory map iteration.

### Partial invalidation

Invalidation is **selective**, not a full flush. Only entries whose whitelist
membership changed are removed. Entries for domains unrelated to the reload
are unaffected. Example: if 5 domains are removed from the whitelist and the
cache has 50,000 entries, at most 5 * (number of qtypes) entries are removed.

---

## Blacklist and Cache

The local blacklist (step 3 of the query processing order) bypasses the cache
entirely in **both directions**:

- **No cache read**: blacklisted domains are blocked immediately without
  checking the cache. This prevents a stale non-blocked entry from bypassing
  the blacklist.
- **No cache write**: the blocked response is not stored in cache. This
  allows hot-reloading the blacklist to take effect immediately for the next
  query without requiring a cache flush or invalidation pass.

The consequence: every query for a locally-blacklisted domain hits this check.
Since the blacklist uses a hash map lookup, this is O(1) and the overhead is
negligible compared to a network round-trip.

If you need blacklisted domains to be cached (to reduce the overhead of
the hash map lookup), consider using upstream-level blocking instead: upstream
blocked responses ARE cached using `blocked_ttl`.

---

## Thread Safety

The cache is protected by a single `sync.RWMutex`:

- **Read lock** (`RLock`): held during `Get` (lookup only).
- **Write lock** (`Lock`): held during `Put` (insert/evict) and
  `InvalidateIf` (scan and delete).

`Flush` acquires the write lock to replace the entries map.

Background refresh goroutines call `Put` (write lock) after completing their
upstream query. Multiple refresh goroutines for different keys can run
concurrently; they will serialize on the write lock only for the brief
duration of the map update.

The `refreshing` sync.Map is used separately from the main mutex to track
in-flight refresh keys. It is lock-free (compare-and-swap semantics).

---

## Edge Cases

### Query for domain just added to whitelist (race)

The sequence: domain added to whitelist -> reload scheduled -> client query
arrives before the reload runs -> cache has a non-whitelist entry (or no entry).

Outcome: the handler sees the domain as whitelisted, finds `entry.Whitelisted=false`
(or nil), and queries the whitelist resolver. The new entry is stored with
`Whitelisted=true`. The next reload will find no mismatch (the entry already
has the correct flag) and no invalidation occurs.

### Query for domain just removed from whitelist (race)

The sequence: domain removed from whitelist, reload scheduled, client query
arrives before the reload runs, cache has a `Whitelisted=true` entry.

Two sub-cases depending on whether the atomic pointer has been swapped yet:

- **Pointer not yet swapped** (reload in progress): `IsWhitelisted` reads
  the old set and returns true. The `Whitelisted=true` cache entry is served
  normally via the whitelist path. The entry will be invalidated shortly by
  the background goroutine after the swap completes.
- **Pointer already swapped** (reload done, invalidation goroutine not yet
  run): `IsWhitelisted` returns false. `handleWhitelistedQuery` returns nil.
  The query falls through to `handleCacheHit` at step 4, which finds the
  `Whitelisted=true` entry and serves it (no flag check at the general cache
  step). The entry will be removed by the background invalidation goroutine.

In both sub-cases the domain resolves successfully. The brief window where a
stale `Whitelisted=true` cache entry is served through the general path is
harmless: the entry still contains the correct (unblocked) response.

### Domain in both whitelist and blacklist

The whitelist takes precedence (step 2 before step 3). A domain in both lists
always resolves via the whitelist resolver and is never blocked by the
local blacklist.

If the domain is removed from the whitelist and the cache entry is invalidated,
the next query falls through to the blacklist (step 3) and is blocked.

### Scoped wildcard does not affect parent or sibling domains

A wildcard `*.abc.example.com` covers `abc.example.com` and all its
subdomains, but does NOT match `www.example.com` or `example.com`. The
`matchWildcard` walk for `www.example.com` goes:

```
"www.example.com" -> "example.com" -> (no more labels)
```

Neither step finds `"abc.example.com"` in the wildcard map, so the match
returns false. `www.example.com` and `example.com` are therefore unaffected
when `*.abc.example.com` is added or removed from the whitelist.

Practical scenarios:

| Change to whitelist          | Affected cached entries         | Unaffected entries                  |
|------------------------------|---------------------------------|-------------------------------------|
| Add `*.abc.example.com`      | `sub.abc.example.com` (now WL)  | `www.example.com`, `example.com`    |
| Remove `*.abc.example.com`   | `sub.abc.example.com` (was WL)  | `www.example.com`, `example.com`    |
| Remove `*.example.com` only  | `www.example.com`, `example.com`, `sub.abc.example.com` (all lose WL coverage) | none |
| Add `*.abc.example.com` when `*.example.com` already in WL | nothing changes -- all entries already covered by `*.example.com` | everything |

The last row is important: if `*.example.com` is in the whitelist, then
`sub.abc.example.com` is already matched by `*.example.com`. Adding a
narrower `*.abc.example.com` makes no difference to the invalidation
predicate because `DomainSet.Contains` returns true for `sub.abc.example.com`
either way.

### Very large domain hierarchy

A wildcard `*.example.com` in the whitelist covers an unlimited depth of
subdomains. The `matchWildcard` walk is bounded by the number of labels in
the queried domain, which is at most 127 labels (DNS name length limit).
No stack overflow or infinite loop is possible.

### Empty whitelist (all domains removed)

`DomainSet.Contains` returns false for any domain when the set is empty
(`count == 0`). The invalidation predicate removes all `Whitelisted=true`
entries. A nil `DomainSet` is also handled (early return false). This
covers the edge case where the whitelist file is deleted or emptied.

### Global wildcard in whitelist (`*`)

If the whitelist contains `*` (global wildcard), every domain is whitelisted.
`DomainSet.Contains` checks the exact map first and finds `*`... actually
the global wildcard `*` is stored as `exact["*"]`. The match logic:

1. `exact["e.example.com"]` -- not found
2. `matchWildcard("e.example.com")` -- walks up: `e.example.com` -> `example.com`
   -> `com` -> not found

The global wildcard `*` is stored in the exact map, not the wildcard map, and
the current `matchWildcard` does not check for `"*"` as a catch-all. The
`Contains` function checks `exact["*"]` only if the normalized query exactly
equals `"*"`, which no real domain will.

**Consequence**: a global wildcard `*` in the whitelist via `exact["*"]`
does NOT match all domains -- it only matches a query literally named `"*"`.

This is a known design decision: the global wildcard is intended for use in
the blocklist to disable blocking entirely, not in the whitelist. Users
should not add bare `*` to the whitelist and expect all domains to be
whitelisted. Use explicit wildcards for each TLD or use an upstream-level
non-blocking resolver instead.

### max_entries = 0

`New(0, ...)` is interpreted as the default (10000 entries) per the
constructor guard `if maxEntries <= 0 { maxEntries = 10000 }`. There is no
way to create a zero-capacity cache through the constructor. Callers that
want a no-op cache (e.g. when cache is disabled in config) pass `New(0, ...)`
and receive a 10000-entry cache.

Internally, when cache is disabled (`cfg.Cache.Enabled = false`), DNSieve
creates `cache.New(0, 1, 1, 0)` -- a cache with default capacity but 0
renew_percent (no background refresh). The cache is created but none of the
`Put`/`Get` calls in the handler are guarded by the capacity; they are
guarded by `cfg.Cache.Enabled`. So no entries are written when disabled.

### renew_percent = 0

Background refresh is disabled. Entries are served until they expire.
On expiry, `cache.Get` deletes the expired entry and returns nil, causing
the next query to go to upstreams directly. No background goroutines are
started.

### All upstreams fail during background refresh

The refresh callback calls `resolver.Resolve`. If all upstreams fail
(`BestResponse == nil`), the refresh is abandoned with a debug log. The old
cache entry remains valid until its own expiry. The next time the entry is
served (if it has not yet expired), a new refresh may be triggered if the
remaining TTL is still below the `renew_percent` threshold.

### Concurrent Put for same key (two goroutines racing)

Two goroutines may call `Put` for the same key concurrently (e.g. a
background refresh and a direct upstream query for the same domain). Both
acquire the write lock sequentially. The last writer wins, which is the
desired behavior: the most recent upstream response is stored. No data is
lost or corrupted because each `Put` writes a complete, independent entry.

---

## Diagnostic Logging

All cache-related log messages use the following patterns. Set
`log_level = "debug"` to see the full set.

### Whitelist cache hit (debug)

```
Query example.com. A -> whitelisted (cached, ttl=300s rtl=247s)
```

`ttl=` is the original entry lifetime; `rtl=` is seconds remaining.

### Whitelist cache hit with background refresh queued (debug)

```
Query example.com. A -> whitelisted (cached, background-refresh queued, ttl=300s rtl=28s)
```

Indicates the entry is near expiry and a refresh was triggered.

### Whitelist cache miss -- querying resolver (debug)

```
Query example.com. A -> whitelisted (querying resolver)
```

### Non-whitelist entry found, querying resolver anyway (debug)

```
Query example.com. A -> whitelisted (non-whitelist cache entry present, querying resolver)
```

A stale non-whitelisted entry (e.g. a blocked entry from before the domain
was added to the whitelist) was found but ignored.

### Whitelist resolver result cached (debug)

```
Query example.com. A -> final: rcode=NOERROR blocked=false cached=true (whitelist resolver)
```

### Whitelist resolver result, cache disabled (debug)

```
Query example.com. A -> final: rcode=NOERROR blocked=false cached=false (whitelist resolver)
```

### Corrupted whitelist cache entry (warn)

```
Whitelist cache entry for example.com. A could not be unpacked, re-querying whitelist resolver
```

Indicates a stored wire-format entry failed to unpack. The entry is replaced
after the re-query. This should not occur under normal operation.

### Whitelist resolver error (warn)

```
Whitelist resolver error for example.com. A: dial tcp: connection refused
```

### General cache hit (debug)

```
Query example.com. A -> cached (ttl=300s rtl=247s)
```

### General cache hit with refresh queued (debug)

```
Query example.com. A -> stale cache (background-refresh queued, ttl=300s rtl=28s)
```

### Blocked entry from cache (info)

```
example.com. is blocked (from cache, ttl=86400s rtl=80000s)
```

Logged at info level so operators can see blocked-domain cache hits.

### Background refresh logs (debug) and JSON events

```
Cache background-refresh started: example.com. A
Cache background-refresh (whitelist) success: example.com. A (rcode=NOERROR)
Cache background-refresh (whitelist) failed: example.com. A: <error>
Cache background-refresh success: example.com. A (rcode=NOERROR)
Cache background-refresh failed (no response): example.com. A
Cache background-refresh skipped (not cacheable): example.com. A
Cache background-refresh: example.com. A is now blocked, updating cache
```

In JSON mode (`log_level_stdout = "json"` or `log_level_file = "json"`), a
`dns_query` event is also emitted after a background refresh completes
successfully. This event contains the upstream results and the caching
decision but **no `response` field** -- the client already received their
answer from the cache; the background refresh only updates the cache for
future requests.

See [docs/logging.md](logging.md#background-refresh-upstream-query) for an
example JSON event.

### Whitelist reload invalidation (info, only when entries removed)

```
whitelist reload: invalidated 5 cache entries whose whitelist membership changed
```

Only logged when at least one entry was removed. If no entries changed,
no log is emitted.
