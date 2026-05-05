# Configuration

DNSieve uses a TOML configuration file. On first run, if no config file
exists, DNSieve prompts you to generate a default one.

## Config File Location

| Platform       | Default Path                              |
|----------------|------------------------------------------|
| Linux / macOS  | `/etc/dnsieve/config.toml`               |
| Windows        | `<exe_dir>\config\config.toml`           |

Override with `--cfgfile /path/to/config.toml`.

## Generating a Default Config

```bash
dnsieve
# If no config exists, you will be prompted:
#   Config file not found: /etc/dnsieve/config.toml
#   Would you like to generate a default config file? [Y/n]
```

## Upstream DNS Servers

DNSieve queries all configured upstream servers concurrently. If **any**
upstream signals a domain is blocked, the blocked response is returned.

Using more than 3 upstream servers may slow down DNS resolution and
increase startup time. For best results, pick 2-3 fast providers with
complementary filtering.

**Recommendation: use DNSSEC-supporting upstreams.** DNSieve always sets
DO=1 on every upstream query. If an upstream supports DNSSEC it returns
signed records (RRSIG) or sets the Authenticated Data (AD) bit. DNSieve
then prefers that response over unsigned responses from other upstreams,
even if those upstreams have a higher priority index. If none of your
configured upstreams support DNSSEC, DNSieve falls back to the
highest-priority valid response.

```toml
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"
```

Supported protocols:
- `"doh"` -- DNS-over-HTTPS (RFC 8484). Address is a full URL. Encrypted.
- `"dot"` -- DNS-over-TLS (RFC 7858). Address is `host:port` (default 853). Encrypted.
- `"udp"` -- Plain DNS over UDP with TCP fallback. Address is `host:port`. **Unencrypted** -- queries can be intercepted.

### Per-Upstream Certificate Verification

Each upstream can override the global `verify_certificates` setting:

```toml
[[upstream]]
address = "https://internal-dns.corp.example.com/dns-query"
protocol = "doh"
verify_certificates = false  # Only for trusted internal servers
```

### Additional Providers

```toml
# Control D (malware blocking)
[[upstream]]
address = "https://freedns.controld.com/p2"
protocol = "doh"

# DoT example
[[upstream]]
address = "dns.quad9.net:853"
protocol = "dot"

# Plain DNS (unencrypted -- not recommended)
[[upstream]]
address = "9.9.9.9:53"
protocol = "udp"
```

## Upstream Settings

```toml
[upstream_settings]
timeout_ms = 2000            # Per-upstream query timeout
min_wait_ms = 200            # Minimum wait for block consensus
verify_certificates = true   # Global TLS cert verification
# bootstrap_dns = "9.9.9.9:53"  # Bootstrap DNS for DoH/DoT hostname resolution
```

### timeout_ms vs min_wait_ms

These two settings work together to implement the block-consensus algorithm:

- **`timeout_ms`** is the hard deadline for each upstream query. If an upstream
  does not respond within this time, the query to that upstream is cancelled.

- **`min_wait_ms`** is the minimum time DNSieve waits before it is allowed to
  return an early result. Even if one upstream responds very quickly, DNSieve
  will wait at least `min_wait_ms` so that slower upstreams have a chance to
  signal a block.

**Why `min_wait_ms` matters:** Suppose upstream A (fast, non-blocking) responds
in 10ms and upstream B (slow, blocking) responds in 150ms. Without
`min_wait_ms`, DNSieve would accept upstream A's response immediately and the
blocked domain would be served. With `min_wait_ms = 200`, DNSieve waits the
full 200ms, receives upstream B's block signal, and returns the blocked
response correctly.

Set `min_wait_ms` high enough that all your blocking upstreams can respond, but
no higher than necessary (latency cost). A value of 150-300ms works well for
publicly hosted blocking resolvers.

### Bootstrap DNS

When using DoH or DoT upstreams, DNSieve needs to resolve the upstream
server's hostname. By default this uses system DNS, but you can set a
dedicated bootstrap server to avoid circular dependencies:

```toml
[upstream_settings]
bootstrap_dns = "9.9.9.9:53"
```

### Bootstrap IP Family

The bootstrap lookup races an A query and a AAAA query concurrently
(RFC 6555 Happy Eyeballs) and uses the first response. On hosts where one
address family is unreachable this can cause connection failures if the
wrong address type wins the race. `bootstrap_ip_family` locks the lookup to
one family:

| Value | Behaviour |
|-------|-----------|
| `"auto"` | Race A and AAAA; fastest response wins. **Default.** |
| `"ipv4"` | Query only A records. Use on IPv4-only hosts. |
| `"ipv6"` | Query only AAAA records. Use on IPv6-only hosts. |

```toml
[upstream_settings]
bootstrap_ip_family = "ipv4"   # IPv4-only host
```

This setting affects only the bootstrap hostname resolution step (resolving
`dns.quad9.net` to an IP before connecting). The encrypted DNS traffic itself
flows over whichever address was resolved -- there is no separate restriction
on the upstream connection. Leave as `"auto"` on dual-stack hosts.

### Upstream Re-resolution (`upstream_ttl`)

By default DNSieve resolves each upstream hostname **once at startup** and
reuses that IP for the lifetime of the process. This is fine for providers
whose IPs rarely or never change.

For environments where upstream IPs may change (custom internal resolvers,
split-horizon DNS, etc.) `upstream_ttl` controls when and how the
hostname is re-resolved.

| Value | Behaviour |
|-------|-----------|
| `-1` | **Disabled (default).** Resolve once at startup. Matches most DNS proxies. |
| `0` | **TTL-based.** Reuse the IP for the full TTL of the DNS record. After expiry, re-resolve when the next new connection is established. A background refresh is started when `renew_percent` of the TTL remains so the new address is usually ready before the old one expires. A 30-second floor prevents excessive bootstrap queries on very short TTLs. |
| `1-2147483647` | **Fixed interval (seconds).** Reuse the IP for this many seconds. Re-resolve at the next new connection after the interval expires. A background refresh starts when `renew_percent` of the interval remains. |

The background refresh threshold is set by `cache.renew_percent` (default 10%).
Set `renew_percent = 0` to disable background re-resolution for `upstream_ttl` as well.
A debug log message is emitted each time the upstream IP is re-resolved.

In all modes:
- Re-resolution uses the same `bootstrap_dns` and `bootstrap_ip_family`
  settings as the initial startup resolution. The config file is never
  re-read.
- **Existing connections are never closed forcibly.** The new IP is picked
  up when a new TCP/TLS connection is established (DoT creates a new
  connection per query; DoH reuses a pooled HTTP/2 connection).
- If the bootstrap DNS is unreachable during a refresh, the current
  (possibly stale) address continues to be used. A retry is scheduled
  after 30 seconds.
- Plain-DNS (`"udp"`) upstreams configured with a numeric IP are
  unaffected by this setting.

```toml
[upstream_settings]
upstream_ttl = -1   # default: disabled (one-time startup resolution)
# upstream_ttl = 0  # TTL-based re-resolution
# upstream_ttl = 300  # re-resolve every 5 minutes
```

## TLS Certificate (Shared)

A single TLS certificate is shared by both DoT and DoH downstream listeners.
TLS 1.2+ is enforced with strong AEAD cipher suites only (AES-GCM,
ChaCha20-Poly1305). Weak algorithms (RC4, 3DES, MD5-based) are not supported.

```toml
[tls]
cert_file = "/etc/dnsieve/cert.pem"
key_file = "/etc/dnsieve/key.pem"

# Alternatively, embed base64-encoded PEM content:
# cert_base64 = "LS0tLS1CRUdJTi..."
# key_base64 = "LS0tLS1CRUdJTi..."
```

File paths take precedence over base64 content.

Required when DoT or DoH (without `use_plaintext_http`) is enabled.

## Downstream Listeners

Each listener accepts a `listen_addresses` array so you can bind to multiple
interfaces or IP families at once. All addresses share the same port.
DNSieve fails to start if any configured address cannot be bound.

```toml
[downstream.plain]
enabled = true
listen_addresses = ["0.0.0.0", "::"]   # Default: bind both IPv4 and IPv6
port = 5353  # Change to 53 for standard DNS (requires root/admin)

[downstream.dot]
enabled = false
listen_addresses = ["0.0.0.0", "::"]
port = 8853  # Change to 853 for standard DoT (requires root/admin)

[downstream.doh]
enabled = false
listen_addresses = ["0.0.0.0", "::"]
port = 4433  # Change to 443 for standard DoH (requires root/admin)
use_plaintext_http = false  # Set true for reverse proxy (no TLS cert needed)
```

### IPv4 and IPv6 Listening

Each listener's `listen_addresses` is an array of IP addresses to bind.
Common values:

| Value       | Behaviour                                      |
|-------------|------------------------------------------------|
| `"0.0.0.0"` | All IPv4 interfaces                            |
| `"::"`      | All IPv6 interfaces only                       |
| `"127.0.0.1"` | IPv4 loopback only                           |
| `"::1"`     | IPv6 loopback only                             |

The default configuration binds to both `0.0.0.0` and `::` so that clients
using either address family can reach DNSieve:

```toml
listen_addresses = ["0.0.0.0", "::"]
```

DNSieve uses explicit IPv4 (`tcp4`/`udp4`) and IPv6 (`tcp6`/`udp6`) socket
types for each address. This prevents the OS-level dual-stack conflict that
occurs on Linux and Windows when a generic IPv6 socket implicitly claims all
IPv4 addresses as well, which would cause a "bind: address already in use"
error when `0.0.0.0` and `::` are both configured.

You can mix any combination of IPv4 and IPv6 addresses:

```toml
# Common combinations
listen_addresses = ["0.0.0.0", "::"]                          # all interfaces, both families
listen_addresses = ["127.0.0.1", "::1"]                       # loopback only, both families
listen_addresses = ["192.168.1.10", "fd12:3456:789a:1::5"]    # specific interfaces

# Single family
listen_addresses = ["0.0.0.0"]                                # IPv4 only
listen_addresses = ["::"]                                     # IPv6 only
```

At least one address must be present in `listen_addresses` for each enabled
listener; an empty array is a startup error.

### DoH Without TLS (Reverse Proxy)

If you run DNSieve behind a reverse proxy like nginx that handles TLS
termination, set `use_plaintext_http = true`. No TLS certificate is needed
in this mode. A warning is logged at startup as a reminder.

## Cache

DNSieve respects the TTL values from upstream DNS responses. The cache
uses LRU (Least Recently Used) eviction when full.

```toml
[cache]
enabled = true
max_entries = 10000  # LRU eviction when full
blocked_ttl = 86400  # 24 hours for blocked domains
min_ttl = 60         # Floor for upstream TTLs
renew_percent = 10   # Trigger background refresh at 10% TTL remaining (0 = off)
```

### How TTL Works

- **Upstream TTL**: The TTL from the upstream DNS response is used directly.
  This means the cache respects what the authoritative server intended.
- **min_ttl**: If the upstream TTL is shorter than `min_ttl`, the minimum
  is used instead. Very short TTLs (under 60 seconds) cause frequent
  re-queries and slow down resolution. Recommended: 60-300 seconds.
- **blocked_ttl**: Blocked domains use this fixed TTL since block status
  rarely changes. Default: 86400 (24 hours).

### Background Cache Refresh

When a cached entry's remaining TTL falls below `renew_percent` of its
original TTL and a client requests that domain, DNSieve returns the cached
result immediately and re-queries all upstream servers in the background:

- **All upstream rules apply**: block-consensus, `allResponded`, NXDOMAIN
  disagreement checks all run as normal.
- **Blocked and non-blocked entries** are both eligible for background
  refresh. This means that if a domain's block status changes upstream
  (a previously blocked domain becomes unblocked, or vice versa), the
  cache reflects the updated state before the entry expires naturally.
- **Not cacheable**: if upstreams disagree (e.g. only some responded, or
  NXDOMAIN disagreement), the old cached entry stays valid until it expires
  naturally. On the next client request for that domain, DNSieve retries the
  background refresh.
- **`renew_percent = 0`**: disables background refresh entirely. Entries
  expire and the next query is a fresh (slower) upstream resolve.
- When a background refresh is queued, debug logs show the original TTL
  (`ttl=`) and the remaining time to live (`rtl=`):
  `Query example.com. A -> stale cache (background-refresh queued, ttl=300s rtl=42s)`
  or `example.com. is blocked (from cache, background-refresh queued, ttl=86400s rtl=1200s)`.
  These values are useful for diagnosing when entries are refreshing too
  early or too late relative to your `renew_percent` setting.

```toml
[cache]
renew_percent = 10   # default: refresh when 10% of TTL remains
# renew_percent = 25  # more aggressive: refresh when 25% of TTL remains
```

Valid range: 0 to 99. A value of 0 disables background refresh.

This setting also controls when the upstream hostname resolver triggers a
background re-resolution for `upstream_ttl` modes 0 and N>0 (see
[Upstream Re-resolution](#upstream-re-resolution-upstream_ttl) above).

### Sizing max_entries

Each cached entry uses approximately 500-1500 bytes depending on DNS
response size. Memory estimates:

| max_entries | Memory  | Suitable For                           |
|-------------|---------|----------------------------------------|
| 10,000      | 5-15 MB | ~20 users, 30 devices (default)        |
| 50,000      | 25-75 MB| ~100 users, 200 devices                |
| 100,000     | 50-150 MB| ~500 users, 1000 devices              |

For a business with 100 employees plus ~1900 servers, consider
50,000-100,000 entries depending on available memory.

## Blocking Mode

When an upstream DNS server signals that a domain is blocked (malware,
phishing, tracking, etc.), DNSieve constructs its own response to the
client. The `blocking.mode` setting controls the format of that response.

```toml
[blocking]
mode = "null"   # "null", "nxdomain", "nodata", or "refused"
```

All modes include an Extended DNS Error (EDE) option with info code 15
("Blocked") per RFC 8914. The EDE extra text identifies which upstream
service detected the block, for example: `Blocked (dns.quad9.net)`.

### Modes

| Mode        | Rcode    | Answer                          | Recommended |
|-------------|----------|---------------------------------|-------------|
| `"null"`    | NOERROR  | 0.0.0.0 (A) or :: (AAAA)       | Yes         |
| `"nxdomain"`| NXDOMAIN | Empty                           |             |
| `"nodata"`  | NOERROR  | Empty                           |             |
| `"refused"` | REFUSED  | Empty                           |             |

#### null (default, recommended)

Returns NOERROR with a synthesized answer: `0.0.0.0` for A queries,
`::` for AAAA queries. Other query types (MX, TXT, CNAME, SRV, etc.)
receive NODATA (NOERROR with an empty answer section).

This is the safest mode and the default recommended by both Pi-hole and
Technitium. Connections to blocked domains fail immediately with
"connection refused" because 0.0.0.0 (RFC 1122 Section 3.2.1.3) and ::
(RFC 4291 Section 2.5.2) are non-routable addresses. Clients do not
experience timeouts or retry storms.

The synthesized answer uses a 10-second TTL.

```toml
[blocking]
mode = "null"
```

#### nxdomain

Returns NXDOMAIN (Name Error) with an empty answer section. Signals
that the domain does not exist. Some clients retry NXDOMAIN responses
more aggressively than null responses, which may increase DNS traffic.

```toml
[blocking]
mode = "nxdomain"
```

#### nodata

Returns NOERROR with an empty answer section. Signals that the domain
exists but has no records of the requested type. Some clients accept
NODATA more gracefully than NXDOMAIN.

```toml
[blocking]
mode = "nodata"
```

#### refused

Returns REFUSED with an empty answer section. Signals that the server
refuses to answer the query. **Use with caution**: some clients fall back
to another DNS resolver when they receive REFUSED, which bypasses the
proxy entirely.

```toml
[blocking]
mode = "refused"
```

### Choosing a Mode

For most deployments, `"null"` is the best choice:

- Web browsers and applications see an immediate "connection refused"
  error instead of a slow timeout.
- No retry storms: clients accept the response without re-querying.
- Compatible with DNSSEC validation (NOERROR is not treated as BOGUS).
- Both Pi-hole and Technitium independently recommend this approach as
  their default.

Use `"nxdomain"` or `"nodata"` if you have specific client software that
handles those rcodes better for your use case. Avoid `"refused"` unless
you understand the DNS fallback risk.

## Logging

```toml
[logging]
log_level = "info"           # debug, info, warn, error
log_max_size_mb = 10         # Max file size before rotation
log_max_backups = 5          # Rotated files to keep
log_max_age_days = 30        # Max age of rotated files
log_flood_limit_ps = 100     # Lines per second (flood protection)
slow_upstream_ms = 200       # Warn when upstream exceeds this (0 = disabled)
```

### slow_upstream_ms

When an upstream takes longer than `slow_upstream_ms` milliseconds to respond,
a warning is logged. Default: 200. Set to `0` to disable.

Setting `log_level = "debug"` enables detailed logging of:
- Each client DNS query received (`Query example.com. A from client`)
- Cache hit/miss status with TTL and remaining TTL:
  `Query example.com. A -> cached (ttl=300s rtl=247s)`
- Background refresh triggers with TTL/RTL values
- Per-upstream query and response details (rcode, blocked/servfail status)
- Block detection decisions
- Final result for each query:
  `Query example.com. A -> final: rcode=NOERROR blocked=false cached=true`
  `malware.example.com. A -> final: rcode=NOERROR blocked=true cached=true`
  `fail.example.com. A -> final: rcode=SERVFAIL blocked=false cached=false`

The `ttl=` value is the original cache entry lifetime; `rtl=` (remaining
time to live) is how many seconds remain before expiry at the time the
entry was served. Comparing these two values shows how much of the TTL
has been consumed.

## Whitelist

The whitelist allows specific domains to bypass all blocking upstreams and be
resolved through a dedicated non-blocking resolver (Cloudflare 1.1.1.1 by
default). Whitelisted domains are never blocked, even if every blocking
upstream signals them as malicious.

The whitelist is **disabled by default**.

```toml
[whitelist]
enabled = false
list_files = ["/etc/dnsieve/whitelist.txt", "/etc/dnsieve/lists/wl-*.txt"]
list_ttl = 300
resolver_address = "https://1.1.1.1/dns-query"
resolver_protocol = "doh"
```

### List Files

Domain lists are loaded from external files specified via `list_files`.
Each entry is a file path or **glob pattern**. A glob is a filename
pattern where `*` matches any sequence of characters, so
`/etc/dnsieve/lists/whitelist-*.txt` matches `whitelist-work.txt`,
`whitelist-home.txt`, and so on:

```toml
list_files = [
  "/etc/dnsieve/whitelist.txt",          # single file
  "/etc/dnsieve/lists/whitelist-*.txt",  # glob: matches whitelist-work.txt, whitelist-home.txt, etc.
]
```

**Windows path example:** On Windows, paths in `list_files` require either
forward slashes or escaped backslashes:

```toml
list_files = [
  "C:/dnsieve/lists/blocklist.txt",
  "C:\\dnsieve\\lists\\blocklist.txt",  # double backslash in TOML string
]
```

**File format:** DNSieve accepts four formats in the same file. Empty lines
and lines starting with `#` or `!` are treated as comments. Lines starting
with `[` (Adblock format headers such as `[Adblock Plus]`) and Adblock
exception rules starting with `@@` are silently skipped. Trailing dots are
stripped. Entries are case-insensitive.

| Format | Example line | Behaviour |
|--------|-------------|----------|
| **Plain domain** | `example.com` | Exact match only -- subdomains are NOT matched |
| **Wildcard domain** | `*.example.com` | Matches `example.com` AND all subdomains |
| **Hosts-file** | `0.0.0.0 example.com` | Exact match; IP address prefix (`0.0.0.0`, `127.0.0.1`, `::1`, `::`) is ignored |
| **Adblock/uBlock double-pipe** | `\|\|example.com^` | Matches `example.com` AND all subdomains (same as `*.example.com`) |

Adblock exception rules (`@@\|\|...`) and format headers (`[Adblock Plus]`)
are silently skipped and are not counted as invalid lines. Adblock rules
with a URL path (`\|\|domain.com/path^`) are counted as invalid because DNS
filtering cannot target sub-paths.

```text
# My list (all four formats are supported in the same file)
example.com
*.internal.local
0.0.0.0 ads.tracker.net
||google-analytics.com^
```

### Hot Reload

When `list_ttl` is set to a positive value (in seconds), DNSieve
periodically checks all list files for changes and reloads them
atomically without downtime:

```toml
list_ttl = 300  # check every 5 minutes; 0 = no auto-reload
```

Reload is atomic: DNS queries always see either the old or the new
complete set -- never a partial load.

#### How hot reload works

Every `list_ttl` seconds a background goroutine wakes up and:

1. **Checks for changes** by calling `os.Stat` on each file and comparing
   modification time and size against the last-known values. It also
   re-expands glob patterns to detect added or removed files. If nothing
   changed, no reload occurs (a debug log entry is written).

2. **Builds the new set** entirely in private memory -- the running server
   is not touched yet. All files are read into new Go maps. No compilation
   occurs; this is pure runtime file I/O.

3. **Swaps atomically** via a single `atomic.Pointer.Store()`. DNS query
   goroutines read the pointer with `atomic.Load()`, which is non-blocking.
   They see the old set or the new set -- never a mix of both.

4. **Releases the old set** for garbage collection. No explicit cleanup is
   needed.

#### Behaviour in edge cases

| Situation | What happens |
|-----------|-------------|
| No file changes detected | Skip reload; debug log only |
| A file is **modified** | Reload triggered |
| A new file **appears** matching a glob | Reload triggered |
| A file is **deleted** | Reload triggered; the deleted file is excluded and the remaining files are loaded normally - no error, no interruption |
| An **unrecognised line** in a file | Line is skipped; if any lines were skipped a warning is logged with the count after each load or reload; with `log_level = "debug"` each invalid line is logged individually |
| A file **fails to read** (permissions, I/O error) | Reload aborted; previous list kept; warning logged |
| Reload takes a long time | DNS queries are **never blocked** -- they read the old set from the atomic pointer until the swap completes |
| New list is very large and causes OOM | The Go runtime panics and the process crashes; there is no guard against this -- keep list sizes reasonable (see the 100,000-domain warning threshold) |

### Domain Matching

Domains support two matching modes based on the entry format:

```text
# Exact match only -- subdomains NOT matched
example.com

# Wildcard match -- matches apex and all subdomains
*.example.com
||example.com^             # Adblock/uBlock double-pipe: equivalent wildcard

# TLD wildcard
*.fr
# matches: all .fr domains

# Global wildcard (disables blocking entirely -- use with caution)
*
```

**Hierarchical deduplication** is applied automatically after loading all
files. A broader wildcard supersedes any narrower entry at any depth:

```text
# All of these reduce to just *.example.com:
*.example.com
example.com              # covered: *.example.com matches apex
test.example.com         # covered: subdomain of example.com
*.sub.example.com        # covered: narrower wildcard
deep.sub.example.com     # covered: deep subdomain
```

This deduplication happens regardless of the order entries appear in the
file or across multiple files. The final domain count and dedup count are
logged at startup and on each reload.

### Internationalized Domain Names (IDN)

Whitelist entries support internationalized domain names. You may write
entries either in ACE/Punycode form (the `xn--` encoded representation used
in DNS wire messages) or in their native Unicode form as UTF-8 text in the
list file. DNSieve normalises Unicode entries to ACE form internally
(RFC 5891 / IDNA 2008) before comparing them to incoming query names, so
both representations match identically.

```text
# These two entries are equivalent:
xn--bcher-kva.example.com
bücher.example.com
```

ACE-encoded domain names (labels starting with `xn--`) are ordinary ASCII
labels in the DNS wire protocol and require no special treatment by the
proxy. DNSieve passes them to upstream resolvers unchanged, just like any
other ASCII-labelled domain name.

### Custom whitelist resolver

You can use any non-blocking DNS resolver for whitelist lookups:

```toml
[whitelist]
enabled = true
resolver_address = "https://cloudflare-dns.com/dns-query"
resolver_protocol = "doh"

# Or plain DNS:
# resolver_address = "1.1.1.1:53"
# resolver_protocol = "udp"
```

## Blacklist

The blacklist blocks specific domains locally without querying upstream
servers. Blocked domains return the same response as upstream-detected blocks
(configured via `[blocking]`). Blacklist has higher priority than the cache
and upstream resolvers.

The blacklist is **disabled by default**.

> **Note:** Large-scale DNS blocking is not the primary purpose of DNSieve.
> The blacklist is provided for cases where you need to block specific
> domains not covered by upstream filtering.

```toml
[blacklist]
enabled = false
list_files = ["/etc/dnsieve/blacklist.txt"]
list_ttl = 300
```

The `list_files` and `list_ttl` options work identically to the whitelist
(see above). The file format, domain matching, glob patterns, hot reload,
and IDN support are all the same.

### Query Processing Order

When both whitelist and blacklist are enabled, queries are processed in
this order:

1. **DDR** (Discovery of Designated Resolvers) -- handled first
2. **Blacklist** -- if matched, return blocked response immediately
3. **Whitelist** -- if matched, resolve through whitelist resolver
4. **Cache** -- return cached response if available
5. **Upstream** -- query all configured upstream servers


## Privacy (EDNS0 Options)

DNSieve processes EDNS0 options to protect client privacy when forwarding
queries to upstream servers. The proxy rebuilds the OPT record from scratch
(RFC 6891) rather than forwarding the client's OPT record verbatim.

```toml
[privacy.ecs]
mode = "strip"              # "strip", "forward", or "substitute"
# subnet = "203.0.113.0/24" # Required when mode = "substitute"

[privacy.cookies]
mode = "reoriginate"        # "strip" or "reoriginate"

[privacy.nsid]
mode = "strip"              # "strip", "forward", or "substitute"
# value = "dnsieve-01"      # Required when mode = "substitute"
```

### EDNS Client Subnet (RFC 7871)

| Mode          | Behaviour                                                 |
|---------------|-----------------------------------------------------------|
| `"strip"`     | Remove ECS from all forwarded queries (default, best for privacy) |
| `"forward"`   | Forward client ECS verbatim to upstreams                  |
| `"substitute"`| Replace client ECS with the configured `subnet`           |

### DNS Cookies (RFC 7873)

| Mode            | Behaviour                                               |
|-----------------|---------------------------------------------------------|
| `"strip"`       | Remove all cookies from forwarded queries and responses   |
| `"reoriginate"` | Maintain per-upstream cookie state; generate proxy's own client cookies (default) |

### Name Server Identifier (RFC 5001)

| Mode          | Behaviour                                                 |
|---------------|-----------------------------------------------------------|
| `"strip"`     | Remove NSID from forwarded queries (default)              |
| `"forward"`   | Forward NSID requests to upstreams verbatim               |
| `"substitute"`| Return proxy's own NSID `value` to clients                |

## TCP Keepalive (RFC 7828)

Controls TCP keepalive EDNS0 timeouts for persistent connections.

```toml
[tcp_keepalive]
client_timeout_sec = 120    # Keepalive timeout advertised to clients (seconds)
upstream_timeout_sec = 120  # Keepalive timeout sent to upstreams (seconds)
```

The timeout is included in responses to TCP clients via the EDNS TCP
Keepalive option. Clients that support RFC 7828 can reuse the TCP
connection for the indicated period.

## Discovery of Designated Resolvers (RFC 9461/9462)

DDR allows clients to discover that DNSieve supports encrypted DNS
protocols by querying `_dns.resolver.arpa.` for SVCB records.

```toml
[ddr]
enabled = false             # Enable DDR SVCB responses
```

When enabled, queries for `_dns.resolver.arpa. SVCB` are answered locally
with SVCB records advertising the proxy's enabled encrypted listeners
(DoT and/or DoH).

## CLI Flags

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| `--cfgfile`      | Custom config file path                          |
| `--logdir`       | Custom log directory path                        |
| `--version`      | Show version and exit                            |
| `--install`      | Install as system service (prompts for label)    |
| `--uninstall`    | Uninstall system service (lists and prompts)     |
| `--speed`        | Test upstream server speed (optional: domains)   |

Both single-dash (`-cfgfile`) and double-dash (`--cfgfile`) are accepted.

## Validation

On startup, DNSieve validates the config and reports warnings and errors.

**Errors (prevent startup):**

Upstreams:
- No `[[upstream]]` entries configured
- `upstream[N].address` is empty
- `upstream[N].protocol` not one of `doh`, `dot`, `udp`
- `upstream_settings.bootstrap_ip_family` not one of `auto`, `ipv4`, `ipv6`
- `upstream_settings.upstream_ttl` < −1 (must be −1, 0, or a positive integer)
- `upstream_settings.upstream_ttl` > 2,147,483,647

Listeners:
- No downstream listeners enabled (plain, dot, and doh are all `enabled = false`)
- `downstream.plain.listen_addresses` empty when plain listener is enabled
- `downstream.dot.listen_addresses` empty when DoT is enabled
- `downstream.doh.listen_addresses` empty when DoH is enabled
- `downstream.*.port` > 65535

TLS:
- DoT enabled but no TLS certificate configured (`cert_file`/`key_file` or `cert_base64`/`key_base64`)
- DoH (HTTPS mode) enabled but no TLS certificate configured

Cache:
- `cache.renew_percent` < 0 or > 99
- `cache.max_entries`, `cache.blocked_ttl`, or `cache.min_ttl` < 0

Logging:
- `logging.log_level` not one of `debug`, `info`, `warn`, `error`
- `logging.log_max_size_mb` < 0

Blocking:
- `blocking.mode` not one of `null`, `nxdomain`, `nodata`, `refused`

Privacy:
- `privacy.ecs.mode` not one of `strip`, `forward`, `substitute`
- `privacy.ecs.mode = "substitute"` but `privacy.ecs.subnet` is not set
- `privacy.cookies.mode` not one of `strip`, `reoriginate`
- `privacy.nsid.mode` not one of `strip`, `forward`, `substitute`
- `tcp_keepalive.client_timeout_sec` or `tcp_keepalive.upstream_timeout_sec` < 0

Whitelist:
- `whitelist.resolver_protocol` not one of `doh`, `dot`, `udp`

---

**Warnings (startup proceeds, logged to stderr):**

Upstreams:
- Any upstream has `verify_certificates = false`
- Global `upstream_settings.verify_certificates = false`
- `upstream_settings.timeout_ms` < 100 ms
- `upstream_settings.min_wait_ms` ≥ `timeout_ms` (block consensus may not function correctly)
- More than 3 upstream servers configured
- Any upstream uses `protocol = "udp"` (plain DNS, unencrypted)

Listeners:
- DoH listener running in plain HTTP mode (`use_plaintext_http = true`)

Blocking:
- `blocking.mode = "refused"` (some clients may fall back to another resolver)

Logging:
- `logging.slow_upstream_ms` is negative (treated as 0, disabled)

Privacy:
- `privacy.ecs.mode = "forward"` (sends client IP subnet to upstreams, reduces privacy)
- `privacy.nsid.mode = "substitute"` but no `value` configured (returns empty NSID)

Whitelist / Blacklist:
- Whitelist or blacklist enabled but `list_files` is not configured
- `whitelist.list_ttl` or `blacklist.list_ttl` is negative (treated as 0, auto-reload disabled)

---

**Runtime warnings (logged after startup, during domain list loading):**

These occur after config validation passes, as the server loads list files into memory:
- A glob pattern in `list_files` matches no files -- warning logged, that entry is skipped
- A list file fails to open or read -- warning logged, that file is skipped
- All `list_files` loaded but no valid domain entries found -- warning logged
- A line that is not a comment, not blank, not an Adblock format header (`[Adblock Plus]`), not an exception rule (`@@||`), and not a valid plain/hosts/Adblock domain entry is counted as invalid. A warning is logged with the total invalid count after each load or reload. With `log_level = "debug"`, each invalid line is logged individually with its line number and content.
- Total loaded domain count exceeds 100,000 -- warning logged (large lists are not officially supported)

**Deduplication** is applied automatically during loading:
- `*.foo.com` covers `foo.com` (apex) and all subdomains, so any exact entry for `foo.com`, or for any subdomain like `sub.foo.com`, is removed as redundant.
- A narrower wildcard like `*.sub.foo.com` is removed when a broader wildcard like `*.foo.com` is present.
- Deduplication runs hierarchically and is order-independent: it does not matter whether the broader wildcard appears before or after narrower entries in the file, or whether entries come from different files.
- The loaded domain count and any dedup/invalid counts are reported in the startup log:
  `Blacklist: loaded 42 domains (3 dedup), 1 invalid from list files`

---

**Notes - not validated at startup:**

- `whitelist.resolver_address` is not checked at startup. An invalid or unreachable address does not prevent startup. Queries for whitelisted domains will return SERVFAIL; the error is logged per query.
