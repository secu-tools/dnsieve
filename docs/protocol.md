# Protocol Details

## Overview

DNSieve operates as a DNS proxy, accepting queries from downstream clients
and forwarding them to upstream DNS servers. It supports three protocols on
both sides:

- **Plain DNS** -- UDP/TCP on port 53
- **DNS-over-TLS (DoT)** -- RFC 7858 / RFC 8310, port 853
- **DNS-over-HTTPS (DoH)** -- RFC 8484, port 443

## Upstream Protocols

### DNS-over-HTTPS (DoH)

- Implementation follows RFC 8484
- Uses HTTP/2 POST with `Content-Type: application/dns-message`
- DNS query ID is set to 0 in wire format per section 4.1
- Responses are unpacked from `application/dns-message` body
- TLS 1.2 minimum
- Per-upstream certificate verification (configurable)
- One automatic retry on unexpected EOF: HTTP keep-alive connections can be
  closed by the server between requests; since `net/http` does not retry POST
  automatically, the client retries once if the error is EOF and the context
  is still valid

### DNS-over-TLS (DoT)

- Implementation follows RFC 7858 / RFC 8310
- Standard DNS TCP wire format (2-byte length prefix) over TLS
- Default port: 853
- TLS `ServerName` extracted from address for SNI
- TLS 1.2 minimum

### Plain DNS (UDP/TCP)

- Standard UDP queries with automatic TCP fallback on truncation
- Default port: 5353 (change to 53 in config for standard DNS; requires elevated privileges)

## Downstream Protocols

### Plain DNS Server

Listens on UDP and TCP simultaneously on the configured address/port.
Standard DNS wire format. No encryption.

### DoT Server

Serves DNS-over-TLS. Requires a TLS certificate (shared `[tls]` config).
Uses TLS 1.2 minimum.

### DoH Server

Serves DNS-over-HTTPS on the `/dns-query` path. Supports:
- **POST** -- `Content-Type: application/dns-message`, body is raw DNS wire.
  The media type is parsed per RFC 2045: MIME parameters (e.g. `charset=utf-8`)
  and case differences (e.g. `Application/DNS-Message`) are accepted.
- **GET** -- `?dns=<base64url>` parameter with base64url-encoded DNS query
- **JSON API** -- `?name=<domain>&type=<type>` with `Accept: application/dns-json` (Google JSON DNS API compatible)
- **OPTIONS** -- CORS preflight responses

Can run in plaintext HTTP mode (`use_plaintext_http = true`) for
reverse proxy setups.

HTTP/2 is supported natively via Go's TLS HTTP server.

Cache-Control header behaviour per RFC 8484 s5.1:
- Successful responses: `Cache-Control: public, max-age=<min-TTL>`
- SERVFAIL or REFUSED responses: `Cache-Control: no-store`
- All HTTP error responses (4xx, 5xx): `Cache-Control: no-store`

## EDNS0 Processing

DNSieve rebuilds the OPT record from scratch when forwarding queries to
upstream servers (RFC 6891). The client's OPT record is never forwarded
verbatim.

### Buffer Size (RFC 9715)
- UDP queries: advertise 1232-byte payload size
- TCP queries: advertise 65535-byte payload size
- Responses exceeding 1232 bytes over UDP are truncated (TC=1)

### DO Bit (RFC 3225)
- DO=1 is always set on every upstream query, regardless of whether the client
  requested DNSSEC. This ensures that upstreams which support DNSSEC return signed
  records (RRSIG) and the Authenticated Data (AD) bit, which DNSieve uses for
  DNSSEC-preference selection (see below).
- The DO bit in the response to the client reflects the client's original request.
- Cache entries are segregated by DO bit (DO=1 and DO=0 have separate entries).

### ECS (RFC 7871)
- Configurable: strip (default), forward, or substitute with a fixed subnet

### Cookies (RFC 7873)

Configurable: `"strip"` or `"reoriginate"` per-upstream (default: `"reoriginate"`).

#### strip mode

All COOKIE EDNS0 options are removed from queries forwarded to upstreams and
from responses sent back to clients. No cookie state is maintained.

#### reoriginate mode

The proxy acts as the DNS cookie originator. The client's own cookies are always
discarded; the proxy generates and maintains its own cookies on behalf of clients.

**Cookie state storage**

Cookie state is held in an in-memory map inside the EDNS middleware. Two maps
are maintained per `Resolver` instance:

- `clients` -- maps upstream address (e.g. `"1.1.1.1:853"`) to the proxy's own
  8-byte (16 hex-char) client cookie for that upstream. Generated once per
  upstream using `crypto/rand` on first use; stable for the lifetime of the
  process. Never written to disk.
- `servers` -- maps upstream address to the most recently received server cookie
  (hex-encoded). Populated from upstream responses; cleared on process restart.

Both maps are protected by a `sync.RWMutex`.

**Query path**

When `PrepareUpstreamQuery` builds the OPT record for an upstream:

1. The proxy's stable client cookie for that upstream is looked up (or generated).
2. If a server cookie has been stored for that upstream from a previous response,
   it is appended after the client cookie.
3. A `COOKIE` EDNS0 option is added: `<client-cookie(16 hex)>[<server-cookie>]`.
4. The incoming client's COOKIE option is not forwarded.

**Response path**

When `ProcessResponseCookieOnly` is called immediately after each upstream
responds (correct upstream address is available at that point):

1. If the response contains a `COOKIE` option with a valid server cookie --
   total length 32-80 hex chars (16 client + 16-64 server, i.e. 8-32 bytes per
   RFC 7873 s4.1) -- the server-cookie portion is stored for that upstream.
2. Server cookies outside the valid length range are silently dropped.

When `ProcessUpstreamResponse` is called on the selected best response:

1. All `COOKIE` options are stripped before the response is forwarded to clients.
   Clients never see the proxy's upstream cookie state.

**RFC 7873 compliance notes**

| Requirement | Status |
|---|---|
| Client cookie exactly 8 bytes (RFC 7873 s4.1) | Implemented |
| Client cookie stable per upstream | Implemented |
| Server cookie 8-32 bytes validated on receipt | Implemented |
| Client cookie included in every upstream query | Implemented |
| Server cookie included when one is known | Implemented |
| Cookies stripped from responses to clients | Implemented |
| BADCOOKIE (RCODE 23) retry with fresh cookie | Not implemented (see below) |

**Known limitation: BADCOOKIE handling**

RFC 7873 Section 5.4 requires that if an upstream returns RCODE 23 (BADCOOKIE),
the client must not use the answer and must retry the query. The proxy detects
RCODE 23 from upstreams and classifies it as a server error, excluding the
response from the consensus result. A one-shot protocol-level retry with a
refreshed cookie is not performed. In practice this is rare: it only occurs when
a server rotates its secret and the stored server cookie becomes stale. The next
query after the BADCOOKIE response will carry only the client cookie (no stale
server cookie), and normal operation resumes.

### NSID (RFC 5001)
- Configurable: strip (default), forward, or substitute with proxy's own ID

### TCP Keepalive (RFC 7828)
- Proxy advertises keepalive timeout to TCP clients
- Configurable client and upstream timeout values

### Extended DNS Errors (RFC 8914)
- EDE options from upstream responses are forwarded to clients

### DNAME (RFC 6672)
- If an upstream response contains a DNAME but no synthesized CNAME,
  the proxy synthesizes one per RFC 6672

### DDR (RFC 9461/9462)
- When enabled, queries for `_dns.resolver.arpa. SVCB` are answered locally
  advertising the proxy's encrypted endpoints
- DoT SVCB records include `alpn=dot` and `port=<port>` service parameters
- DoH SVCB records include `alpn=h2`, `port=<port>`, and `dohpath=/dns-query{?dns}`
  service parameters (RFC 9461 s4)

## Block Detection

DNSieve detects blocked domains by inspecting upstream responses:

1. **0.0.0.0 / :: in Answer** -- Common blocking response (Cloudflare,
   AdGuard, Control D, etc.)
2. **NXDOMAIN without Authority (SOA)** -- Quad9-style blocking. A genuine
   NXDOMAIN includes a SOA record in the Authority section; a blocked
   NXDOMAIN has no Authority section (NSCOUNT=0).
3. **REFUSED (rcode 5)** -- Some providers return REFUSED for blocked domains.
4. **SERVFAIL** -- Treated as a server error, not a block signal. Excluded
   from consensus.

### Consensus Algorithm

1. If **any** upstream signals blocked -> cache blocked, return blocked response
2. If not blocked, among the valid responses prefer a DNSSEC response (one that
   carries RRSIG records in the Answer or Authority section, or has AD=1) over a
   plain unsigned response. The lowest-index DNSSEC response wins; if no upstream
   returned DNSSEC data, the lowest-index valid response is used.
3. If not blocked and **all** responded without error -> cache the selected response
4. If some upstreams had errors -> don't cache, return best available
5. If upstreams disagree on NXDOMAIN -> don't cache (prevents false positives)

## Blocked Response Format

The response format depends on the configured `blocking.mode`
(see [configuration.md](configuration.md#blocking-mode)):

| Mode        | Rcode    | Answer                          | Authority                        |
|-------------|----------|---------------------------------|----------------------------------|
| `null`      | NOERROR  | 0.0.0.0 (A), :: (AAAA), empty (other types) | None            |
| `nxdomain`  | NXDOMAIN | Empty                           | Synthesized SOA (RFC 2308 s3)    |
| `nodata`    | NOERROR  | Empty                           | Synthesized SOA (RFC 2308 s2.2)  |
| `refused`   | REFUSED  | Empty                           | None                             |

All modes include:
- An **Extended DNS Error** (EDE) option with `InfoCode = 15` (Blocked)
  per RFC 8914, only when the client sent a query with an OPT record
  (RFC 6891: EDNS0 extension mechanism is required to carry EDE). Supporting
  clients such as Pi-hole FTL >= 5.18 classify this as "Blocked (upstream)"
  rather than an error.
- EDE extra text identifying the upstream that detected the block,
  for example: `Blocked (dns.quad9.net)`.

Non-EDNS clients (queries without an OPT record) receive no OPT record in
the response, and therefore no EDE. This is correct per RFC 6891 s7.

The default mode is `null` (NOERROR with 0.0.0.0/::), which is the
recommended default by both Pi-hole and Technitium. Connections to
blocked domains fail immediately with "connection refused" because
0.0.0.0 and :: are non-routable addresses. Clients do not experience
timeouts or retry storms.

In `null` mode, the synthesized answer record uses a 10-second TTL.
Query types other than A and AAAA receive NODATA (NOERROR with empty
answer), since there is no meaningful null address to return for
record types like MX, TXT, CNAME, or SRV.

## Cache Behavior

- TTL-priority eviction when capacity is reached (entry closest to expiry is removed first)
- TTL honored from upstream responses (floored by `min_ttl`)
- Blocked responses cached with `blocked_ttl`
- Entries not cached when upstreams disagree or have errors
- Cache key: question name + question type + DO bit (RFC 3225 segregation)
- DNSSEC responses (DO=1) are cached separately from non-DNSSEC responses
