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
- Default port: 53 (appended automatically when the upstream address has no port)

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

Configurable via `privacy.cookies.mode`: `"strip"` or `"reoriginate"`
(default: `"reoriginate"`). Cookie state is kept per upstream.

#### strip mode

All COOKIE EDNS0 options are removed from queries forwarded to upstreams and
from responses sent back to clients. No cookie state is maintained.

#### reoriginate mode

The proxy acts as the DNS cookie originator on behalf of clients:

- The client's own cookies are always discarded and never forwarded.
- The proxy generates a stable 8-byte client cookie per upstream
  (`crypto/rand`, in-memory only, regenerated on restart) and includes it in
  every upstream query, together with the most recently received server
  cookie for that upstream (validated to 8-32 bytes per RFC 7873 s4.1).
- All COOKIE options are stripped from responses before they reach clients.

> [!NOTE]
> BADCOOKIE (RCODE 23) responses are treated as a server error and excluded
> from consensus; the proxy does not retry with a fresh cookie. This only
> matters when an upstream rotates its cookie secret -- the next query drops
> the stale server cookie and normal operation resumes.

### NSID (RFC 5001)
- Configurable: strip (default), forward, or substitute with proxy's own ID

### Padding (RFC 7830 / RFC 8467)

The proxy handles EDNS(0) Padding in two directions:

**Client padding (inbound)**

The proxy always accepts the PADDING option from clients, regardless of any
configuration. Client padding is stripped from queries forwarded to upstream
servers (the proxy rebuilds the OPT record from scratch). When the client
included a PADDING option and the transport is TCP-based (plain TCP, DoT, or
DoH), the proxy adds padding to the response (RFC 8467 s4.2). Padding is never
added to UDP responses (RFC 7830 s3.1).

| Condition                              | Server response padding          |
|----------------------------------------|----------------------------------|
| Client sent PADDING over TCP/DoT/DoH   | Added (468-byte blocks, random)  |
| Client sent PADDING over UDP           | Not added (RFC 7830 s3.1)        |
| Client did not send PADDING            | Not added                        |

**Upstream padding (outbound)**

Controlled by `privacy.padding.upstream_padding` (default: `true`). When
enabled, the proxy pads queries forwarded to encrypted upstreams (DoT, DoH)
to a multiple of 128 bytes (RFC 8467 s4.1). Plain UDP upstreams are never
padded (RFC 7830 s3.1).

**Randomisation (RFC 8467 s3)**

Both upstream queries and client responses add a random jitter of 0 to
(block-1) bytes before block alignment, so the same DNS message produces a
different wire size on each request, defeating cross-query size correlation.
Padding bytes are all zeros (RFC 7830 recommendation).

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

All modes include an **Extended DNS Error** (EDE) option with
`InfoCode = 15` (Blocked, RFC 8914) whose extra text identifies the upstream
that detected the block, e.g. `Blocked (dns.quad9.net)`. The EDE is only
present when the client sent an OPT record (EDNS0 is required to carry EDE,
RFC 6891 s7).

In the default `null` mode the synthesized answer uses a 10-second TTL, and
query types other than A/AAAA receive NODATA since there is no meaningful
null address for types like MX or TXT.