# Testing

## Quick Reference

Use the build scripts to run tests. They manage temp directories and cleanup
automatically. These work on Linux, macOS, and Windows.

| Flag | What runs |
|------|-----------|
| `./build.sh -test` | Unit tests + integration tests + fuzz seed corpus |
| `./build.sh -testsmoke` | Smoke tests only (builds binary, requires network) |
| `./build.sh -teste2e` | End-to-end tests only (requires network) |
| `./build.sh -testall` | Smoke + unit + integration + fuzz seeds + e2e (full suite) |
| `./build.sh -coverage` | Unit tests with coverage report |

On Windows use `.\build.ps1` with the same flags. On Windows or Linux,
`build.cmd` also accepts these flags.

---

## Smoke Tests

Smoke tests build the DNSieve binary from source and run it as a real OS
process. They verify binary startup, config file generation, graceful
shutdown, and live query handling over plain DNS, DoH, and DoT.

Unlike e2e tests (which start the server in-process), smoke tests exercise
the compiled binary end-to-end and are the appropriate check before shipping
a release.

Requirements: a working internet connection (queries are forwarded to real
upstreams) and a toolchain capable of building the binary.

```bash
./build.sh -testsmoke
```

The smoke suite is split across focused files:

| File | Contents |
|------|----------|
| `smoke_startup_test.go` | Binary exists, --version flag, config generation, startup/shutdown, missing config exits non-zero |
| `smoke_dns_test.go` | Plain DNS UDP A/AAAA, NXDOMAIN, cache hit latency, multiple query types |
| `smoke_protocols_test.go` | DoH POST, DoH content type, DoT basic query, all-protocols combined |
| `smoke_helpers_test.go` | Shared helpers: port finder, wait, UDP query, config writer |
| `smoke_main_test.go` | TestMain: builds binary once into a temp dir (cleaned up on exit) |

---

## Unit Tests

```bash
./build.sh -test
```

This also runs integration tests and fuzz seed corpus. To run unit tests
alone with the go tool:

```bash
go test ./...
```

## Coverage

```bash
./build.sh -coverage
```

The coverage report is written to `coverage.html`. To run manually:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

---

## Integration Tests

Integration tests start a real in-process DNSieve server on loopback ports
and send queries over the wire. No binary build is required. They require
network access.

```bash
./build.sh -test
```

Or directly:

```bash
go test -tags integration -v -count=1 -timeout 120s ./tests/integration/
```

The integration suite is split across focused files:

| File | Contents |
|------|----------|
| `integration_basic_test.go` | BasicQuery, IPv4 answer, AAAA, IPv6 answer, NXDOMAIN |
| `integration_block_test.go` | Blocked domain IPv4/IPv6, blocked responses never leak real IPs |
| `integration_cache_test.go` | Cache hit returns same answer within TTL |
| `integration_helpers_test.go` | Shared helpers: free port, start server, wait, query |

---

## E2E Tests

End-to-end tests spin up a real DNSieve server on loopback ports, send DNS
queries over the wire, and verify protocol behaviour end-to-end. They require a
working internet connection (the proxy resolves queries via the configured DoH
upstreams).

```bash
./build.sh -teste2e
```

Or directly:

```bash
go test -tags e2e -v -count=1 ./tests/e2e/
```

The e2e suite is split across focused files:

| File | Contents |
|------|----------|
| `e2e_protocol_test.go` | Plain DNS (UDP/TCP), DoH, DoT, all-protocols tests |
| `e2e_cache_block_test.go` | Cache behaviour, MinTTL, background refresh, block detection |
| `e2e_edns_test.go` | ECS, DNS Cookies, NSID, TCP keepalive |
| `e2e_rfc_test.go` | DDR (RFC 9461), RFC 9715, DNSSEC OK bit (RFC 3225), ANY (RFC 8482), DNAME (RFC 6672) |
| `e2e_complex_test.go` | Whitelist bypass, multi-EDNS, concurrency, performance |
| `e2e_rfc_security_additional_test.go` | CNAME chains, unknown qtypes, EDNS truncation, cookie robustness, security injection tests |

---

## Provider Tests

Provider tests verify that specific DNS providers correctly block known
malicious domains.

```bash
go test -tags providers -v -count=1 ./tests/providers/
```

## RFC Compliance Tests

RFC compliance tests verify adherence to DNS protocol standards. Tests are
split per-RFC for clarity. They query live public resolvers and require
network access.

```bash
go test -tags rfc -v -count=1 ./tests/rfc/
```

Test files:
- `rfc1034_2181_foundation_test.go` -- RFC 1034/2181 CNAME chain and RR-set TTL uniformity
- `rfc1035_basic_dns_test.go` -- Standard DNS (UDP, TCP, question echo, RA bit, NXDOMAIN)
- `rfc3225_do_bit_dnssec_test.go` -- DNSSEC OK (DO) bit handling
- `rfc3597_unknown_rr_test.go` -- Handling of unknown DNS RR types
- `rfc4343_case_insensitivity_test.go` -- DNS case insensitivity
- `rfc4592_wildcards_test.go` -- Wildcard query style handling
- `rfc5001_nsid_test.go` -- Name Server Identifier (NSID)
- `rfc5966_tcp_requirements_test.go` -- TCP requirements (UDP truncation fallback)
- `rfc6672_dname_synthesis_test.go` -- DNAME redirection and synthesis
- `rfc6891_edns0_test.go` -- EDNS0 OPT record, version 0, buffer size
- `rfc7828_tcp_keepalive_test.go` -- TCP keepalive
- `rfc7858_dot_test.go` -- DNS-over-TLS (DoT)
- `rfc7871_ecs_test.go` -- EDNS Client Subnet (ECS)
- `rfc7873_dns_cookies_test.go` -- DNS Cookies
- `rfc8482_any_query_test.go` -- Minimal responses to ANY queries
- `rfc8484_doh_test.go` -- DNS-over-HTTPS (DoH) POST, GET, ID=0, content type
- `rfc8914_ede_test.go` -- Extended DNS Errors (EDE)
- `rfc9460_svcb_https_test.go` -- SVCB/HTTPS record transport
- `rfc9461_ddr_test.go` -- Discovery of Designated Resolvers (DDR)
- `rfc9715_udp_buffer_size_test.go` -- UDP fragmentation avoidance

## Fuzz Testing

Fuzz tests exercise config parsing, DNS message handling, and wire format
parsing with random inputs. Run each test for a desired duration with `-fuzztime`.

```bash
# Config parsing
go test -fuzz FuzzConfigParse -fuzztime=60s ./internal/config/

# DNS wire format and block inspection
go test -fuzz FuzzInspectWireResponse -fuzztime=60s ./internal/dnsmsg/

# Cache TTL and renewal logic
go test -fuzz FuzzCacheRenewPercent -fuzztime=60s ./internal/cache/
go test -fuzz FuzzCacheKeys -fuzztime=60s ./internal/cache/
go test -fuzz FuzzCacheConcurrentRefresh -fuzztime=60s ./internal/cache/

# DNS query handler
go test -fuzz FuzzHandleQuery -fuzztime=60s ./internal/server/
go test -fuzz FuzzHandleQueryDomainNames -fuzztime=60s ./internal/server/
go test -fuzz FuzzHandleQueryWithCacheRefresh -fuzztime=60s ./internal/server/
go test -fuzz FuzzHandleQueryIPv6 -fuzztime=60s ./internal/server/

# DoH security and payload fuzzing
go test -fuzz FuzzReadDOHWireQueryPOSTLimit -fuzztime=60s ./internal/server/
go test -fuzz FuzzBuildQueryFromJSONParamsNoPanic -fuzztime=60s ./internal/server/
go test -fuzz FuzzDoHPayloadParsing -fuzztime=60s ./internal/server/

# EDNS0 middleware
go test -fuzz FuzzPrepareUpstreamQuery -fuzztime=60s ./internal/edns/
go test -fuzz FuzzProcessUpstreamResponse -fuzztime=60s ./internal/edns/
go test -fuzz FuzzSynthesizeDNAME -fuzztime=60s ./internal/edns/

# Upstream resolver and whitelist
go test -fuzz FuzzResolveWithMockResponses -fuzztime=60s ./internal/upstream/
go test -fuzz FuzzWhitelistIsWhitelisted -fuzztime=60s ./internal/upstream/
```

The CI pipeline runs each fuzz target for 30 seconds automatically.

## IPv4 / IPv6 Tests

The unit tests cover both IPv4 and IPv6 query handling. Listener binding
to IPv6 addresses is tested when the host supports IPv6 (tests are skipped
automatically if IPv6 is unavailable):

```bash
go test -run TestServePlain_IPv6_UDPQuery -v ./internal/server/
```

IPv6-specific unit tests include:
- `TestHandleQuery_IPv6_AAAA_Normal` -- legitimate AAAA address not treated as blocked
- `TestHandleQuery_IPv6_AAAA_Blocked_Unspecified` -- `::` treated as block signal
- `TestHandleQuery_MixedIPv4IPv6` -- A and AAAA cache entries are independent
- `TestResolve_IPv6_AAAA_Normal` -- resolver correctly classifies real IPv6 addresses
- `TestResolve_IPv6_AAAA_Blocked` -- resolver detects `::` as block signal
- `TestResolve_IPv4_Blocked_ZeroAddr` -- resolver detects `0.0.0.0` as block signal
- `TestNewPlainClient_BareIPv6` -- bare IPv6 address normalised to `[addr]:53`
- `TestNewDoTClient_BareIPv6` -- bare IPv6 address normalised to `[addr]:853`


---

## CI Network Reliability: bootstrap_ip_family

GitHub-hosted runners do not have outbound IPv6 connectivity. The default
bootstrap behaviour -- racing both an A and a AAAA lookup -- can therefore
return an IPv6 address that is unreachable, causing every upstream DoH/DoT
connection attempt to fail with "network is unreachable" and the proxy to
return SERVFAIL.

The `bootstrap_ip_family` config option locks the bootstrap resolver to one
address family:

| Value | Behaviour |
|-------|-----------|
| `"auto"` | Race A and AAAA; fastest answer wins (default) |
| `"ipv4"` | Send only A queries; IPv4 address always returned |
| `"ipv6"` | Send only AAAA queries; IPv6 address always returned |

Example TOML:

```toml
[upstream_settings]
bootstrap_ip_family = "ipv4"
```

### How tests handle this

**E2E tests** that depend on live upstream responses use
`startServerReachable` instead of `startServer`. This helper tries three
strategies in order -- `"auto"`, `"ipv4"`, `"ipv6"` -- sending a health-check
query (`example.com A`) after each start. Trying `"auto"` first verifies that
the default code path works on the current runner. The first strategy that
returns a non-SERVFAIL response is used for the remainder of that test. If all
three strategies fail the test fails immediately (t.Fatal): a genuine network
outage or proxy bug is always visible, never silently skipped.

**Integration tests** use the same "auto" then "ipv4" then "ipv6" probe loop
inside `startTestServer`. A free port is acquired for each attempt; if the
upstream probe passes the server stays on that port for the duration of the
test.

**Smoke tests** detect IPv6 connectivity once in `TestMain` by attempting a
TCP connection to `[2620:fe::fe]:53` (Quad9 IPv6). When unreachable, all
generated TOML configs include `bootstrap_ip_family = "ipv4"` automatically.

This approach is deterministic: there is no test skipping. A genuine upstream
connectivity failure always produces a test failure.

