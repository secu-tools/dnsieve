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
- **POST** -- `Content-Type: application/dns-message`, body is raw DNS wire
- **GET** -- `?dns=<base64url>` parameter with base64url-encoded DNS query
- **JSON API** -- `?name=<domain>&type=<type>` with `Accept: application/dns-json` (Google JSON DNS API compatible)
- **OPTIONS** -- CORS preflight responses

Can run in plaintext HTTP mode (`use_plaintext_http = true`) for
reverse proxy setups.

HTTP/2 is supported natively via Go's TLS HTTP server.

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
- Configurable: strip or reoriginate per-upstream (default: reoriginate)

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

1. If **any** upstream signals blocked -> cache blocked, return REFUSED + EDE Blocked
2. If not blocked, among the valid responses prefer a DNSSEC response (one that
   carries RRSIG records in the Answer or Authority section, or has AD=1) over a
   plain unsigned response. The lowest-index DNSSEC response wins; if no upstream
   returned DNSSEC data, the lowest-index valid response is used.
3. If not blocked and **all** responded without error -> cache the selected response
4. If some upstreams had errors -> don't cache, return best available
5. If upstreams disagree on NXDOMAIN -> don't cache (prevents false positives)

## Blocked Response Format

Blocked responses return:
- `RCODE` = `REFUSED` (rcode 5) -- bypasses DNSSEC validation in dnsmasq (Pi-hole).
  dnsmasq's `process_reply()` short-circuits on any rcode that is not NOERROR or
  NXDOMAIN, so REFUSED is never subjected to BOGUS detection. Pi-hole FTL's own
  `answer_disallowed()` uses the same pattern (REFUSED + EDE Blocked).
- `Answer` section is **empty** -- no spoofed IP is returned
- `Pseudo` section contains an **Extended DNS Error** (EDE) option with
  `InfoCode = 15` (Blocked) per RFC 8914 -- supporting clients such as
  Pi-hole FTL >= 5.18 classify this as "Blocked (upstream)" rather than an error

## Cache Behavior

- LRU eviction when capacity is reached
- TTL honored from upstream responses (floored by `min_ttl`)
- Blocked responses cached with `blocked_ttl`
- Entries not cached when upstreams disagree or have errors
- Cache key: question name + question type + DO bit (RFC 3225 segregation)
- DNSSEC responses (DO=1) are cached separately from non-DNSSEC responses
