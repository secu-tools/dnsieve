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
# renew_percent = 0   # disable background refresh
```

Valid range: 0 (disabled) to 99.

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
domains = ["example.com", "*.internal.local"]
resolver_address = "https://1.1.1.1/dns-query"
resolver_protocol = "doh"
```

### Domain Matching

Domains support two matching modes based on the entry format:

```toml
# Exact match only
domains = ["example.com"]
# matches: example.com
# does NOT match: sub.example.com

# Wildcard match (prefix with *)
domains = ["*.example.com"]
# matches: sub.example.com, deep.sub.example.com, example.com

# TLD wildcard
domains = ["*.cn"]
# matches: all .cn domains

# Global wildcard (disables blocking entirely -- use with caution)
domains = ["*"]
```

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

On startup, DNSieve validates the config and reports warnings and errors:

**Errors (prevent startup):**
- Missing upstream servers
- No listeners enabled
- Empty `listen_addresses` for any enabled listener
- DoT/DoH without TLS certificate
- Unsupported upstream protocol
- Empty upstream address
- `cache renew_percent` out of range (must be 0-99)
- `cache max_entries`, `blocked_ttl`, or `min_ttl` negative
- `logging log_level` not one of debug/info/warn/error
- `logging log_max_size_mb` negative
- Downstream listener port > 65535

**Warnings (logged at startup, operation continues):**
- Disabled certificate verification
- Very low timeouts (< 100ms)
- `min_wait_ms` >= `timeout_ms` (block consensus may not work)
- More than 3 upstream servers
- Plain DNS upstream (unencrypted)
- DoH running over plain HTTP without TLS
- Whitelist with `*` global wildcard
- Negative `slow_upstream_ms` (treated as 0/disabled)
