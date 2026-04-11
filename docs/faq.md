# Frequently Asked Questions

**Q: How is DNSieve different from Pi-hole or AdGuard Home?**

Pi-hole and AdGuard Home maintain local block lists that must be downloaded, stored, and periodically refreshed. DNSieve carries no lists of its own -- it delegates to upstream resolvers (such as Quad9 or Cloudflare for Families) that perform threat-intelligence filtering on their end. This means there is no list management overhead. The trade-off is that DNSieve's blocking scope is exactly as broad (or narrow) as your chosen upstream providers.

**Q: Can I use DNSieve together with Pi-hole?**

Yes, and there are two useful topologies depending on what you want to achieve.

**Topology A -- Pi-hole in front (recommended for most setups):**

```
Clients -> Pi-hole (port 53) -> DNSieve -> [Quad9, Cloudflare, ...]
```

Pi-hole handles its local block lists and serves your network on port 53. You set
DNSieve as Pi-hole's upstream resolver. This gives you Pi-hole's ad-list blocking
*and* DNSieve's multi-provider threat-intelligence filtering in a single stack.

To configure this, go to Pi-hole's *Settings -> DNS* and set a Custom upstream DNS
server pointing at DNSieve's address and port (e.g. `127.0.0.1#5353` if both run
on the same host).

**Topology B -- DNSieve in front, Pi-hole as one upstream:**

```
Clients -> DNSieve -> [Pi-hole, Quad9, Cloudflare, ...]
```

DNSieve fans all queries out to Pi-hole *and* to threat-intel providers
concurrently. If any of them signals a block, DNSieve returns a blocked response
(block-consensus). This lets Pi-hole's list-based decisions participate in the
consensus alongside Quad9/Cloudflare.

There is one important requirement: Pi-hole must use a **separate** upstream DNS
(e.g. `8.8.8.8` or `9.9.9.9` directly) that does **not** point back to DNSieve.
If Pi-hole's upstream is DNSieve, queries loop indefinitely.

Keep Pi-hole's upstream server count low in this topology -- DNSieve already
fans out to multiple providers, so Pi-hole only needs one reliable non-blocking
resolver for its own lookups.

**Which topology should I choose?**

Topology A

---

**Q: Does DNSieve do DNSSEC validation?**

No. DNSieve does not validate DNSSEC signatures itself. However, it does the
following to improve DNSSEC behaviour:

- It always sets DO=1 on every upstream query so that DNSSEC-capable upstreams
  return signed records (RRSIG) and the Authenticated Data (AD) bit, even when
  the client did not request DNSSEC.
- When multiple upstreams respond, DNSieve prefers a response that carries DNSSEC
  data (RRSIG records or AD=1) over an unsigned response, regardless of the
  upstream's configured priority index. Among DNSSEC responses, the
  highest-priority index wins.
- If none of the configured upstreams support DNSSEC, DNSieve falls back to the
  normal highest-priority selection.

For best results, configure DNSSEC-validating upstreams. They perform the full
chain-of-trust validation and set AD=1, which DNSieve recognises and forwards to
clients that requested DNSSEC. Cache entries are segregated by the DO bit so
DNSSEC-aware and non-DNSSEC clients both receive correct responses.

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
concurrently. If **any** upstream signals that the domain is blocked (by returning
0.0.0.0, NXDOMAIN with no authority, REFUSED, or similar provider conventions),
DNSieve caches and returns a blocked response to the client -- regardless of what
the other upstreams replied. This ensures that the strictest upstream always wins.

**Q: What does a "blocked" response look like to clients?**

The response format depends on the configured `blocking.mode` setting. The
default mode is `"null"`, which returns NOERROR with 0.0.0.0 (for A queries)
or :: (for AAAA queries) and an Extended DNS Error (EDE) option with InfoCode
15 (Blocked) per RFC 8914. Connections to 0.0.0.0/:: fail immediately with
"connection refused" -- no timeout, no retry. This is the same approach used
by Pi-hole (NULL blocking mode) and Technitium (AnyAddress mode).

Other available modes: `"nxdomain"` (NXDOMAIN + empty answer), `"nodata"`
(NOERROR + empty answer), and `"refused"` (REFUSED + empty answer). All modes
include EDE code 15 with the name of the upstream that detected the block.
See [configuration.md](configuration.md#blocking-mode) for details.

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
HTTP mode (`use_plaintext_http = true`) behind a reverse proxy like nginx that
handles TLS termination.

**Q: Can I whitelist a domain so it is never blocked?**

Yes, using the `[whitelist]` config section. Enable it, list the domains (exact
matches or wildcard patterns such as `*.example.com`), and set a non-blocking
resolver for whitelist lookups. Whitelisted domains completely bypass the blocking
upstreams.

**Q: Does the whitelist support wildcards?**

Yes:
- `"example.com"` -- exact match only
- `"*.example.com"` -- all subdomains (and `example.com` itself)
- `"*.cn"` -- every `.cn` domain
- `"*"` -- everything (effectively disables blocking)

**Q: How does the cache background refresh work?**

When a cached entry's remaining TTL falls below `renew_percent` (default: 10 %)
and a client requests that domain, DNSieve returns the cached result immediately
and re-queries all upstreams in the background. This keeps frequently used entries
fresh without adding latency to the client. If the background re-query shows a
change in block status, the cache is updated before the entry expires naturally.

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

Use a domain known to be blocked by your upstream providers. For example, Quad9
blocks `malware.testcategory.com`. Query it through DNSieve:

```bash
# Plain DNS
nslookup malware.testcategory.com 127.0.0.1

# Dig (port 5353)
dig @127.0.0.1 -p 5353 malware.testcategory.com A
```

A blocked response depends on the configured `blocking.mode`. In the default
`"null"` mode, the response has status NOERROR with a 0.0.0.0 answer and
EDE code 15 (Blocked) in the OPT record. You can verify this with:

```bash
dig @127.0.0.1 -p 5353 malware.testcategory.com A +norecurse
```

Look for `status: NOERROR`, a `0.0.0.0` answer record, and an
`EDE: 15 (Blocked)` line in the OPT pseudo-section.

**Q: How do I check which upstreams are fastest for my location?**

Run the built-in speed test:

```bash
./dnsieve --speed
# Or test with specific domains:
./dnsieve --speed google.com,github.com,example.org
```

Results show average, min, and max latency per upstream so you can pick the
fastest providers for your network.

**Q: Does DNSieve log which domains are blocked?**

Yes. At the default `info` log level, blocked domains are logged:
```
example.com. is blocked (ttl=86400s)
```
Set `log_level = "debug"` to see every query, cache hit/miss, per-upstream result,
and the final decision for each request.
