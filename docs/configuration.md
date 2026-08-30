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

> [!TIP]
> Pick 2-3 fast providers with complementary filtering. More than 3
> upstreams slows down resolution and startup. Prefer DNSSEC-supporting
> upstreams: DNSieve prefers a DNSSEC-validated response (RRSIG or AD=1)
> over unsigned ones when selecting which answer to return.

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
bootstrap_dns = "9.9.9.9:53,149.112.112.112:53"  # Bootstrap DNS for DoH/DoT hostname resolution
max_idle_conns = 128         # Idle connections kept per upstream (DoT/DoH)
```

### Connection pooling (`max_idle_conns`)

DNSieve reuses TLS connections to DoT and DoH upstreams instead of handshaking
per lookup. One in-flight query holds one connection, so this cap must cover
the widest burst of simultaneous lookups; connections above it are closed after
a single query and re-handshaked on the next burst, which costs upstream
bandwidth.

| Deployment | Value |
|---|---|
| A handful of devices | `32` |
| Household or small office, up to ~100 clients | `128` (default) |
| Hundreds of clients | `256`+ |

It is a ceiling, not a reservation: idle connections are dropped after 30
seconds, so the pool drains to nothing when traffic stops. Raise the process
file-descriptor limit alongside values of 256 or more.

Mainly affects DoT. DoH upstreams that speak HTTP/2 multiplex every concurrent
query onto one connection, so the cap only applies there on an HTTP/1.1
fallback. Plain UDP upstreams do not pool.

### timeout_ms vs min_wait_ms

- **`timeout_ms`** is the hard deadline for each upstream query.
- **`min_wait_ms`** is the minimum time DNSieve waits before accepting an
  early result, so a fast non-blocking upstream cannot win before a slower
  blocking upstream has a chance to signal a block.

> [!IMPORTANT]
> Set `min_wait_ms` high enough for your slowest blocking upstream to
> respond, but no higher (it is a latency floor on cache misses). 150-300 ms
> works well for public blocking resolvers.

### Bootstrap DNS

When using DoH or DoT upstreams, DNSieve needs to resolve the upstream
server's hostname. `bootstrap_dns` takes a comma-separated list of IP:port
addresses queried in parallel; the fastest response wins. The default config
uses both Quad9 anycast IPs. Set it to an empty string to use the system
resolver instead.

```toml
[upstream_settings]
bootstrap_dns = "9.9.9.9:53,149.112.112.112:53"
```

### Bootstrap IP Family

The bootstrap lookup races an A query and a AAAA query concurrently
(RFC 6555 Happy Eyeballs) and uses the first response. On hosts where one
address family is unreachable this can cause connection failures if the
wrong address type wins the race. `bootstrap_ip_family` locks the lookup to
one family:

| Value | Behaviour |
|-------|-----------|
| `"auto"` | Race A and AAAA; fastest response wins. Default when the key is omitted. |
| `"ipv4"` | Query only A records. Set in the generated default config. |
| `"ipv6"` | Query only AAAA records. Use on IPv6-only hosts. |

```toml
[upstream_settings]
bootstrap_ip_family = "ipv4"   # IPv4-only host
```

> [!NOTE]
> This setting affects only the bootstrap hostname lookup. The generated
> default config sets `"ipv4"` (works everywhere); on dual-stack hosts you
> can switch to `"auto"`.

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
| `0` | **TTL-based.** Reuse the IP for the full TTL of the DNS record (30-second floor), then re-resolve on the next new connection. |
| `1-2147483647` | **Fixed interval (seconds).** Reuse the IP for this many seconds, then re-resolve on the next new connection. |

In modes 0 and N>0 a background refresh starts when `cache.renew_percent`
(default 10%) of the TTL/interval remains, so the new address is usually
ready before the old one expires. `renew_percent = 0` disables this.

In all modes:
- Re-resolution reuses `bootstrap_dns` and `bootstrap_ip_family`.
- Existing connections are never closed forcibly; the new IP applies to new
  connections only.
- If the bootstrap DNS is unreachable, the current address stays in use and
  a retry is scheduled after 30 seconds.
- Upstreams configured with a numeric IP are unaffected.

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

`listen_addresses` accepts any mix of IPv4 and IPv6 addresses; the default
`["0.0.0.0", "::"]` binds all interfaces in both families. An empty array on
an enabled listener is a startup error.

```toml
listen_addresses = ["0.0.0.0", "::"]                          # all interfaces, both families
listen_addresses = ["127.0.0.1", "::1"]                       # loopback only
listen_addresses = ["192.168.1.10", "fd12:3456:789a:1::5"]    # specific interfaces
listen_addresses = ["0.0.0.0"]                                # IPv4 only
```

DNSieve binds each address with an explicit single-family socket type, so
configuring both `0.0.0.0` and `::` does not cause the dual-stack
"address already in use" conflict seen on Linux and Windows.

### DoH Without TLS (Reverse Proxy)

If you run DNSieve behind a reverse proxy like nginx that handles TLS
termination, set `use_plaintext_http = true`. No TLS certificate is needed
in this mode. A warning is logged at startup as a reminder.

## Cache

```toml
[cache]
enabled = true
max_entries = 10000  # evict closest-to-expiry entry when full
blocked_ttl = 86400  # TTL for blocked-domain entries (seconds)
min_ttl = 60         # floor for upstream TTLs (seconds)
renew_percent = 10   # background refresh when this % of TTL remains (0 = off)
```

| Option | Description |
|--------|-------------|
| `enabled` | Enable or disable the in-memory response cache. Default: `true`. |
| `max_entries` | Maximum number of cached entries. When full, the entry closest to expiry is removed first (TTL-priority, not LRU). |
| `blocked_ttl` | How long to cache blocked responses. Default: 86400 (24 hours). |
| `min_ttl` | Floor for upstream TTLs. Upstream TTLs shorter than this are raised to `min_ttl`. Prevents short-lived records from flooding the cache. Default: 60. |
| `renew_percent` | Threshold (0-99) at which a near-expiry entry triggers a background upstream re-query while the cached response is served immediately. `0` disables background refresh. Default: 10. |

For detailed behavior -- TTL adjustment on serve, eviction algorithm, background
refresh paths (including how whitelisted entries are refreshed), memory sizing,
and all edge cases -- see [docs/caching.md](caching.md).

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

| Mode        | Rcode    | Answer                    | Notes                                              |
|-------------|----------|---------------------------|----------------------------------------------------|
| `"null"`    | NOERROR  | 0.0.0.0 (A) or :: (AAAA)  | **Default, recommended.** Immediate "connection refused"; other query types get NODATA. 10-second answer TTL. |
| `"nxdomain"`| NXDOMAIN | Empty                     | Some clients retry NXDOMAIN more aggressively.     |
| `"nodata"`  | NOERROR  | Empty                     | Domain exists, no records of the requested type.   |
| `"refused"` | REFUSED  | Empty                     | See warning below.                                 |

`"null"` is the default recommended by both Pi-hole and Technitium: clients
fail fast with no timeouts or retry storms. Use `"nxdomain"` or `"nodata"`
only if specific client software handles them better.

> [!WARNING]
> With `"refused"`, some clients fall back to another DNS resolver,
> bypassing the proxy entirely.

For the exact wire format of each mode see
[protocol.md -- Blocked Response Format](protocol.md#blocked-response-format).

## Logging

```toml
[logging]
log_level_stdout = "info"    # json, debug, info, warn, error, off
log_level_file   = "info"    # same values -- controls the rotating log file
log_max_size_mb  = 10        # Max file size before rotation
log_max_backups  = 5         # Rotated files to keep
log_max_age_days = 30        # Max age of rotated files
slow_upstream_ms = 200       # Warn when upstream exceeds this (0 = disabled)
```

See [docs/logging.md](logging.md) for full documentation on text and JSON log
formats, output modes, the complete JSON schema, and configuration examples.

### slow_upstream_ms

When an upstream takes longer than `slow_upstream_ms` milliseconds to respond,
a warning is logged in all output modes. In JSON mode the `upstream[].slow`
field is also set to `true` in the `dns_query` event. Default: 200. Set to
`0` to disable.

Setting `log_level_stdout` (or `log_level_file`) to `json` emits a structured
`dns_query` event for every DNS query including cache hit/miss status with TTL
and remaining TTL, per-upstream response details, and final query results.
`dns_query` events are only emitted in JSON mode; text modes do not include
per-query lines.


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

Domain lists are loaded from the files in `list_files`. Each entry is a
file path or glob pattern (`*` matches any characters):

```toml
list_files = [
  "/etc/dnsieve/whitelist.txt",          # single file
  "/etc/dnsieve/lists/whitelist-*.txt",  # glob
]
```

> [!NOTE]
> On Windows, use forward slashes (`"C:/dnsieve/lists/blocklist.txt"`) or
> doubled backslashes (`"C:\\dnsieve\\..."`) in TOML strings.

**File format:** DNSieve accepts the following formats in a list file. Empty
lines and lines starting with `#` or `!` are treated as comments and are
silently skipped. Lines starting with `[` (Adblock format headers such as
`[Adblock Plus]`) are also silently skipped.

The following formats are accepted in **both** blocklists and allowlists:

| Format | Example line | Behaviour |
|--------|-------------|----------|
| **Plain domain** | `example.com` | Exact match only -- subdomains are NOT matched |
| **Wildcard domain** | `*.example.com` | Matches `example.com` AND all subdomains |
| **Hosts-file** | `0.0.0.0 example.com` | Exact match; IP address prefix (`0.0.0.0`, `127.0.0.1`, `::1`, `::`) is ignored |

In addition, **AdGuard-style rules** use mode-specific prefixes:

| Rule | Valid in blocklist | Valid in allowlist | Behaviour when valid |
|------|-------------------|--------------------|----------------------|
| `\|\|example.com^` | **Yes** | Silently skipped | Matches `example.com` AND all subdomains |
| `@@\|\|example.com^` | Silently skipped | **Yes** | Matches `example.com` AND all subdomains |

Lines that are silently skipped are **not counted as invalid**. This means
you can point both `whitelist.list_files` and `blacklist.list_files` at the
same file without spurious warnings: the blocklist loads only the `||domain^`
rules and the allowlist loads only the `@@||domain^` rules.
See [Sharing a File Between Whitelist and Blacklist](#sharing-a-file-between-whitelist-and-blacklist)
for important restrictions.

Everything after `^` in an AdGuard rule is a rule modifier (e.g. `$important`,
`$third-party`). Rule modifiers are not applicable at the DNS level and are
silently ignored -- the domain is still loaded normally.

AdGuard rules with a URL path (`\|\|domain.com/path^`) are counted as invalid
because DNS filtering cannot target sub-paths.

```text
# Blocklist file: only block rules and universal formats.
# @@|| lines are silently skipped; they are not counted as invalid.
||google-analytics.com^
||tracker.example.com^
@@||safe.example.com^        # silently skipped in blocklist mode
example.com
*.internal.local
0.0.0.0 ads.tracker.net
```

```text
# Allowlist file: only exception rules and universal formats.
# || lines are silently skipped; they are not counted as invalid.
||google-analytics.com^       # silently skipped in allowlist mode
@@||safe.example.com^
@@||cdn.example.net^$important
exact-allow.example.org
*.whitelist.local
```

### Hot Reload

When `list_ttl` is a positive number of seconds, DNSieve periodically checks
all list files (mtime/size, plus re-expanding globs) and reloads them on
change:

```toml
list_ttl = 300  # check every 5 minutes; 0 = no auto-reload
```

The new set is built in private memory and swapped in atomically -- queries
always see either the old or the new complete set, never a partial load, and
are never blocked by a reload.

| Situation | What happens |
|-----------|-------------|
| No changes detected | Skip reload; debug log only |
| File modified, added (via glob), or deleted | Reload triggered; deleted files are simply excluded |
| Unrecognised line in a file | Line skipped; warning with the count after each load; debug level logs each line |
| File fails to read (permissions, I/O) | Reload aborted; previous list kept; warning logged |

> [!CAUTION]
> There is no guard against a list too large for available memory. Keep
> lists reasonable -- a warning is logged above 100,000 domains and large
> lists are not officially supported.

### Domain Matching

Domains support two matching modes based on the entry format:

```text
# Exact match only -- subdomains NOT matched
example.com

# Wildcard match -- matches apex and all subdomains
*.example.com
||example.com^              # blocklist only: AdGuard block rule (same as *.example.com)
@@||example.com^            # allowlist only: AdGuard exception rule (same as *.example.com)
```

> [!NOTE]
> A wildcard base must contain at least one dot: TLD-wide entries like
> `*.fr` are silently dropped, and a bare `*` matches only a query
> literally named `*` -- neither can be used to match everything.

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

List entries may be written in ACE/Punycode form (`xn--...`) or in native
Unicode as UTF-8 text. Unicode entries are normalised to ACE form internally
(RFC 5891 / IDNA 2008), so both representations match identically:

```text
# These two entries are equivalent:
xn--bcher-kva.example.com
bücher.example.com
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

## Blacklist

The blacklist blocks specific domains locally without querying upstream
servers. Blocked domains return the same response as upstream-detected blocks
(configured via `[blocking]`). Blacklist has higher priority than the cache
and upstream resolvers, but lower priority than the whitelist.

The blacklist is **disabled by default**.

> [!NOTE]
> Large-scale DNS blocking is not the primary purpose of DNSieve. The
> blacklist is provided for cases where you need to block specific domains
> not covered by upstream filtering.

```toml
[blacklist]
enabled = false
list_files = ["/etc/dnsieve/blacklist.txt"]
list_ttl = 300
```

The `list_files` and `list_ttl` options work identically to the whitelist
(see above): same file format, domain matching, glob patterns, hot reload,
and IDN support.

### Query Processing Order

When both whitelist and blacklist are enabled, queries are processed in
this order:

1. **DDR** (Discovery of Designated Resolvers) -- handled first
2. **Whitelist check** -- if the domain is whitelisted:
   a. **Whitelist cache check** -- return the cached result immediately if
      a prior whitelist resolution is still valid (entry tagged Whitelisted).
   b. **Whitelist resolver** -- query the dedicated non-blocking upstream,
      store the result in the shared cache (tagged Whitelisted=true), return.
3. **Blacklist check** -- if matched, return a blocked response immediately.
   No cache lookup and no cache write occur for locally-blacklisted domains.
4. **General cache** -- return a cached response if available.
5. **Upstream** -- query all configured upstream servers; cache the result.

For a detailed explanation of how whitelist results are cached, how the
shared-cache design works, and how cache entries are selectively invalidated
on whitelist hot-reload (including wildcard matching semantics), see
[docs/caching.md](caching.md).

## Sharing a File Between Whitelist and Blacklist

Because `||domain^` lines are silently skipped by the allowlist and
`@@||domain^` lines by the blocklist, the same file can appear in both
`whitelist.list_files` and `blacklist.list_files` without warnings:

```text
# Shared file: AdGuard-style rules only.
||ads.example.com^       # loaded by blocklist, skipped by allowlist
@@||cdn.trusted.com^     # loaded by allowlist, skipped by blocklist
```

> [!WARNING]
> A shared file must contain **only** `||domain^` and `@@||domain^` lines.
> Plain domains, wildcards, and hosts-file lines are loaded by **both**
> lists, and since the whitelist is checked first, such entries become
> unconditionally whitelisted -- they will never be blocked. Keep
> plain/wildcard/hosts entries in dedicated blocklist or allowlist files.

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

[privacy.padding]
upstream_padding = true     # Add RFC 8467 block-length padding to encrypted upstream queries
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

### Padding (RFC 7830 / RFC 8467)

| Setting                      | Behaviour                                                                             |
|------------------------------|---------------------------------------------------------------------------------------|
| `upstream_padding = false`   | No padding added to upstream queries                                                  |
| `upstream_padding = true`    | Pad upstream queries to 128-byte blocks with random jitter (RFC 8467 s4.1) (default) |

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
| `--speed`        | Test upstream speed and diagnose resolver behaviour (optional: comma-separated domains) |

Both single-dash (`-cfgfile`) and double-dash (`--cfgfile`) are accepted.

## Validation

On startup, DNSieve validates the config and reports warnings and errors.

**Errors (prevent startup):**

Upstreams:
- No `[[upstream]]` entries configured
- `upstream[N].address` is empty
- `upstream[N].protocol` not one of `doh`, `dot`, `udp`
- `upstream_settings.bootstrap_ip_family` not one of `auto`, `ipv4`, `ipv6`
- `upstream_settings.upstream_ttl` < -1 (must be -1, 0, or a positive integer)
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
- `logging.log_level_stdout` / `logging.log_level_file` not one of `json`, `debug`, `info`, `warn`, `error`, `off`
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
- `upstream_settings.min_wait_ms` >= `timeout_ms` (block consensus may not function correctly)
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

- A glob pattern in `list_files` matches no files, or a file fails to open -- warning logged, entry/file skipped
- All `list_files` loaded but no valid domain entries found -- warning logged
- Lines that are not a comment, blank, Adblock header, or valid domain entry are counted as invalid; a warning with the total count follows each load. Debug level logs each invalid line. Mode-crossing rules (`||` in an allowlist, `@@||` in a blocklist) are silently skipped and not counted.
- Entries violating DNS length limits (label > 63 chars or name > 253 chars, RFC 1035 s2.3.4) are rejected as invalid.
- Total loaded domain count exceeds 100,000 -- warning logged (large lists are not officially supported)

**Deduplication** is applied automatically and order-independently during
loading: a broader wildcard removes any exact entry or narrower wildcard it
covers, at any depth and across files. The result is reported at startup:
`Blacklist: loaded 42 domains (3 dedup), 1 invalid from list files`

> [!NOTE]
> `whitelist.resolver_address` is not checked at startup. An unreachable
> address does not prevent startup; whitelisted queries return SERVFAIL and
> the error is logged per query.
