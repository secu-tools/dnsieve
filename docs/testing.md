# Testing

## Quick Reference

Use the build scripts to run tests; they manage temp directories and cleanup
automatically and work on Linux, macOS, and Windows (`.\build.ps1` with the
same flags; `build.cmd` also works on Windows and Linux).

| Flag | What runs |
|------|-----------|
| `./build.sh -test` | Unit tests + integration tests + fuzz seed corpus |
| `./build.sh -testsmoke` | Smoke tests only (builds binary, requires network) |
| `./build.sh -teste2e` | End-to-end tests only (requires network) |
| `./build.sh -testall` | Smoke + unit + integration + fuzz seeds + e2e (full suite) |
| `./build.sh -coverage` | Unit tests with coverage report (`coverage.html`) |

> [!NOTE]
> Smoke, integration, e2e, RFC, and provider tests forward queries to real
> upstream resolvers and require a working internet connection.

## Test Suites

- **Unit tests** (`go test ./...`) -- per-package tests, no network needed
  for most.
- **Smoke tests** (`tests/smoke/`) -- build the real binary and run it as an
  OS process: startup, config generation, shutdown, service install, and
  live queries over plain DNS, DoH, and DoT. The right check before shipping
  a release.
- **Integration tests** (`tests/integration/`) -- start an in-process server
  on loopback ports and query it over the wire. Run directly with:
  ```bash
  go test -tags integration -v -count=1 -timeout 120s ./tests/integration/
  ```
- **E2E tests** (`tests/e2e/`) -- in-process server exercised end-to-end:
  protocols, cache/block behaviour, EDNS options, RFC behaviours, whitelist,
  concurrency.
  ```bash
  go test -tags e2e -v -count=1 ./tests/e2e/
  ```
- **Provider tests** (`tests/providers/`) -- verify that specific DNS
  providers block known malicious domains.
  ```bash
  go test -tags providers -v -count=1 ./tests/providers/
  ```
- **RFC compliance tests** (`tests/rfc/`) -- one file per RFC (see the
  `rfc*_test.go` filenames for the covered standards).
  ```bash
  go test -tags rfc -v -count=1 ./tests/rfc/
  ```

## Fuzz Testing

Fuzz targets exist in `internal/config` (config parsing), `internal/dnsmsg`
(wire format and block inspection), `internal/cache` (TTL/renewal/keys),
`internal/server` (query handler, DoH payloads), `internal/edns` (EDNS0
middleware, DNAME), and `internal/upstream` (resolver, whitelist). Run any
target with:

```bash
go test -fuzz <FuzzTargetName> -fuzztime=60s ./internal/<package>/
```

List the targets in a package with `grep -r "func Fuzz" internal/<package>/`.
The CI pipeline runs each fuzz target for 30 seconds automatically.

## CI Network Reliability: bootstrap_ip_family

GitHub-hosted runners have no outbound IPv6. The default bootstrap behaviour
(racing A and AAAA lookups) can pick an unreachable IPv6 address, making
every upstream connection fail with SERVFAIL. The `bootstrap_ip_family`
config option locks the bootstrap lookup to one family (see
[configuration.md](configuration.md#bootstrap-ip-family)).

Tests that depend on live upstreams probe strategies in order -- `"auto"`,
`"ipv4"`, `"ipv6"` -- with a health-check query after each server start, and
keep the first strategy that returns a non-SERVFAIL response. Smoke tests
detect IPv6 connectivity once in `TestMain` and add
`bootstrap_ip_family = "ipv4"` to generated configs when unreachable.

There is no test skipping: if all strategies fail, the test fails, so a
genuine outage or proxy bug is always visible.
