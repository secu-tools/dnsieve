# Frequently Asked Questions

**Q: How is DNSieve different from Pi-hole or AdGuard Home?**

Pi-hole and AdGuard Home maintain local block lists that must be downloaded, stored, and periodically refreshed. DNSieve relies primarily on upstream resolvers (such as Quad9 or Cloudflare for Families) that perform threat-intelligence filtering on their end, so there is no list management overhead by default. For cases where upstream filtering does not cover specific domains, DNSieve also supports an optional local blacklist -- it is disabled by default and entirely opt-in. The trade-off is that DNSieve's blocking scope is primarily as broad (or narrow) as your chosen upstream providers, extended only by what you explicitly add to the local blacklist.

**Q: Can I use DNSieve together with Pi-hole?**

Yes. The recommended topology is Pi-hole in front:

```
Clients -> Pi-hole (port 53) -> DNSieve -> [Quad9, Cloudflare, ...]
```

In Pi-hole's *Settings -> DNS*, set a Custom upstream DNS server pointing at
DNSieve (e.g. `127.0.0.1#5353` on the same host). You get Pi-hole's ad-list
blocking plus DNSieve's multi-provider filtering.

Alternatively, run DNSieve in front with Pi-hole as one upstream
(`Clients -> DNSieve -> [Pi-hole, Quad9, ...]`) so Pi-hole's list decisions
participate in the block-consensus.

> [!WARNING]
> In that second topology, Pi-hole's own upstream must NOT point back to
> DNSieve, or queries loop indefinitely. Give Pi-hole one separate
> non-blocking resolver (e.g. `8.8.8.8`).

---

**Q: Does DNSieve do DNSSEC validation?**

No. DNSieve is a forwarding proxy and does not validate DNSSEC signatures. However:

- DO=1 is always set on every upstream query so DNSSEC-capable upstreams return
  signed records even when the client did not request DNSSEC.
- When multiple upstreams respond, DNSieve prefers a DNSSEC response (RRSIG or
  AD=1) over an unsigned one.
- Cache entries are segregated by the DO bit so DNSSEC-aware and non-DNSSEC
  clients both receive correct responses.

See [docs/protocol.md -- DO Bit](protocol.md#do-bit-rfc-3225) for full details.

**Q: Is DNSieve a recursive resolver?**

No. DNSieve is a forwarding proxy. It does not walk the DNS tree itself -- it
forwards every query to the configured upstream resolvers and returns their answers.

**Q: Why is the default port 5353 instead of 53?**

Port 53 requires elevated privileges (root/Administrator) on most operating
systems. DNSieve defaults to 5353 so it can run without special permissions during
development and testing. To use the standard port, change `port = 5353` to
`port = 53` in your config and ensure DNSieve has the required privileges (see
[docs/files.md](files.md)).

**Q: How does block-consensus work?**

On a cache miss, DNSieve fans out every query to all configured upstreams
concurrently. If any upstream signals the domain is blocked, DNSieve returns
a blocked response -- the strictest upstream always wins. See
[docs/protocol.md -- Consensus Algorithm](protocol.md#consensus-algorithm) for
the full algorithm.

**Q: What does a "blocked" response look like to clients?**

The response format depends on `blocking.mode` in config. The default `"null"`
mode returns NOERROR with 0.0.0.0 (A queries) or :: (AAAA queries) and an EDE
option with InfoCode 15 (Blocked) per RFC 8914. Connections fail immediately with
"connection refused". See [docs/protocol.md -- Blocked Response Format](protocol.md#blocked-response-format)
and [docs/configuration.md -- Blocking Mode](configuration.md#blocking-mode).

**Q: What is `min_wait_ms` and why does it exist?**

Without a minimum wait, a fast non-blocking upstream could respond before a slower
blocking upstream has a chance to reply, and the blocked domain would be served.
`min_wait_ms` (default: 200 ms) forces DNSieve to wait at least that long before
accepting an early result, giving all blocking upstreams enough time to respond.
Set it high enough that your slowest blocking upstream can respond, but no higher
than necessary to keep latency low.

**Q: How many upstream servers should I configure?**

Two or three is the recommended sweet spot. More upstreams give complementary
coverage but increase startup time (each is speed-tested at launch) and add a
small amount of base latency to every query. DNSieve emits a warning if you
configure more than three.

**Q: Does DNSieve support serving DoH or DoT to clients?**

Yes. Enable the `[downstream.dot]` and/or `[downstream.doh]` listeners in your
config and provide a TLS certificate under `[tls]`. DoH can also run in plaintext
HTTP mode (`use_plaintext_http = true`) behind a reverse proxy. See
[docs/configuration.md -- Downstream Listeners](configuration.md#downstream-listeners).

**Q: Can I whitelist a domain so it is never blocked?**

Yes, using the `[whitelist]` config section. Enable it, point `list_files` at
one or more plain-text files containing domains (one per line), and set a
non-blocking resolver for whitelist lookups. Whitelisted domains completely
bypass the blocking upstreams.

```toml
[whitelist]
enabled = true
list_files = ["/etc/dnsieve/whitelist.txt"]
resolver_address = "https://1.1.1.1/dns-query"
resolver_protocol = "doh"
```

**Q: Can I blacklist (locally block) domains without relying on upstream filtering?**

Yes, using the `[blacklist]` config section. Blacklisted domains are blocked
locally before any cache or upstream lookup, returning the same blocked
response as upstream-detected blocks (configured via `[blocking]`).

```toml
[blacklist]
enabled = true
list_files = ["/etc/dnsieve/blacklist.txt"]
```

**Q: Does the whitelist/blacklist support wildcards?**

Yes -- entries in list files use the same format:
- `example.com` -- exact match only
- `*.example.com` -- all subdomains (and `example.com` itself)

The wildcard base must contain at least one dot: TLD-wide entries like
`*.fr` and the bare `*` do not match everything (see
[configuration.md -- Domain Matching](configuration.md#domain-matching)).

**Q: How does the cache background refresh work?**

When a cached entry's remaining TTL falls below `renew_percent` (default 10%)
and a client requests that domain, DNSieve returns the cached result immediately
and re-queries upstreams in the background. This keeps frequently used entries
fresh without adding latency. See [docs/caching.md -- Background Refresh](caching.md#background-refresh) for full details.

**Q: Do I need to restart DNSieve to change the config?**

Yes. The configuration is loaded once at startup. Edit the config file and restart
the process (or service) for changes to take effect.

**Q: Can I run multiple DNSieve instances on the same machine?**

Yes. Use `--cfgfile` to point each instance at a different config file with
different listener ports, and use a unique label during `--install` so each
instance gets a distinct service name.

**Q: Does DNSieve support IPv6?**

Yes. The default `listen_addresses = ["0.0.0.0", "::"]` binds to both IPv4 and
IPv6 interfaces simultaneously. DNSieve also forwards AAAA queries and blocks
AAAA answers according to the configured `blocking.mode` (default: `"null"`,
which returns `::` for blocked AAAA queries).

**Q: How do I test that blocking is working?**

Use a domain known to be blocked by your upstream providers. For example,
Quad9 blocks `malware.testcategory.com`:

```bash
dig @127.0.0.1 -p 5353 malware.testcategory.com A
```

In the default `"null"` mode, look for `status: NOERROR`, a `0.0.0.0` answer
record, and an `EDE: 15 (Blocked)` line in the OPT pseudo-section.

**Q: How do I check which upstreams are fastest for my location?**

Run the built-in speed test:

```bash
./dnsieve --speed
# Or test with specific domains:
./dnsieve --speed example.com,example.net,example.org
```

When no domains are supplied, DNSieve queries 10 built-in domains.
The full list is printed at the start of the test. Results include
average, min, and max latency per upstream and a per-domain breakdown
in table form.

**Q: Does DNSieve log which domains are blocked?**

Yes, in two ways:

- **Text mode**: set `log_level_stdout = "debug"` (or `log_level_file`) to
  see every query, cache hit/miss, per-upstream result, and the final
  decision -- including blocked domains. Default `info` text mode does not
  log per-query lines.
- **JSON mode** (`log_level_stdout = "json"`): a structured `dns_query`
  event is emitted for every query, with `decision.blocked` and the block
  source. See [docs/logging.md](logging.md).
