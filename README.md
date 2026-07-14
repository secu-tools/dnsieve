# DNSieve

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/secu-tools/dnsieve/actions/workflows/ci.yml/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/ci.yml)
[![Build](https://github.com/secu-tools/dnsieve/actions/workflows/build.yml/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/build.yml)
[![CodeQL](https://github.com/secu-tools/dnsieve/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/github-code-scanning/codeql)
[![Dependency Graph](https://github.com/secu-tools/dnsieve/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/dependabot/update-graph)

## Introduction

DNS filtering proxy that queries multiple upstream DNS servers concurrently
and enforces block-consensus: if **any** upstream signals a domain is
blocked, the blocked response is returned to the client.

Instead of maintaining local block lists, DNSieve fans each query out to
upstream resolvers that already perform threat-intelligence filtering --
such as Quad9, Cloudflare for Families, or Control D -- and enforces the
strictest outcome. There are no lists to download or refresh, and combining
providers gives complementary coverage. An optional local blacklist
(disabled by default) covers domains your upstreams miss.

> [!TIP]
> Fanning out to all upstreams adds a little latency versus a single
> resolver. Use 2-3 fast upstream servers for best results.

## App Privacy

The app communicates only with the IPs and domains you configure. If bootstrap servers are unavailable or not configured, it falls back to your computer's default DNS servers to resolve upstream domains. No telemetry, no callbacks -- feel free to read the code to verify.

## How It Works

1. Client sends a DNS query to DNSieve (plain DNS, DoT, or DoH)
2. DDR check: queries for `_dns.resolver.arpa. SVCB` are answered locally
3. Whitelist check: if matched, resolve via the whitelist resolver immediately
4. Blacklist check: if matched, return a blocked response immediately
5. DNSieve checks the cache -- if hit, returns immediately
6. On cache miss, DNSieve fans out the query to all configured upstream
   servers concurrently
7. Results are collected:
   - If **any** upstream signals **blocked**, cache the block and return
     a blocked response with EDE Blocked (RFC 8914 code 15) to the client.
     Default mode: NOERROR + 0.0.0.0/:: (configurable: null, nxdomain,
     nodata, refused)
   - If **not blocked** and **all** upstreams responded, cache and return
     the best response (DNSSEC-validated preferred, then highest priority)
   - If some upstreams had errors, do **not** cache but still return the
     best available result
8. Nearly-expired cache entries are refreshed in the background to keep
   responses fast for frequently queried domains

## Features

- **Concurrent fan-out** with block-consensus across multiple upstreams
- **DNS-over-HTTPS** (RFC 8484), **DNS-over-TLS** (RFC 7858), and **plain DNS**
  for both upstream and downstream
- **In-memory caching** with upstream TTL respect, background refresh for
  nearly-expired entries, and configurable minimum TTL
- **Domain whitelist and blacklist** with file-based lists, glob patterns, and wildcard support (`*.example.com`); hot-reload without restarts
- **Bootstrap DNS** for resolving DoH/DoT hostnames without system DNS
- **Speed testing** via `--speed` flag
- **Service management** via `--install` / `--uninstall` for Windows,
  Linux (systemd/OpenWRT), and macOS (launchd)
- **TLS hardening** with strong cipher suites (TLS 1.2+ with AEAD only)
- **Cross-platform** builds for Linux, Windows, macOS, and OpenWRT
  (amd64/arm64), with IPv4 and IPv6 support

## Quick Start

```bash
# Install via go install
go install github.com/secu-tools/dnsieve@latest

# Or build from source
go build -o dnsieve ./

# Run (generates config on first launch)
./dnsieve

# With custom paths
./dnsieve --cfgfile /etc/dnsieve/config.toml --logdir /var/log/dnsieve/
```

## Docker

The easiest way to deploy DNSieve is with Docker Compose:

```bash
mkdir -p config log
docker compose -f docker/docker-compose.yml up -d
# A default config.toml is generated in ./config/ on first run
```

The included `docker/docker-compose.yml` pulls the pre-built image from GHCR and
runs DNSieve with security hardening (dropped capabilities, read-only
filesystem, non-root user).

See [docs/docker.md](docs/docker.md) for advanced Docker configuration.

## Configuration

On first run, DNSieve prompts to generate a default config file at the
platform-appropriate location:

| Platform       | Path                              |
|----------------|----------------------------------|
| Linux / macOS  | `/etc/dnsieve/config.toml`       |
| Windows        | `<exe_dir>\config\config.toml`   |

Override with `--cfgfile /path/to/config.toml`.

See [docs/configuration.md](docs/configuration.md) for the full reference.

## Service Management

```bash
# Install as system service (prompts for optional label)
sudo ./dnsieve --install

# With custom paths
sudo ./dnsieve --install --cfgfile /etc/dnsieve/office.toml

# Uninstall (lists services, prompts which to remove)
sudo ./dnsieve --uninstall
```

Supported platforms: Windows (sc.exe), Linux (systemd/OpenWRT procd),
macOS (launchd).

## Building

```bash
# Linux/macOS
./build.sh

# Windows
.\build.ps1

# Or use Make
make build
```

See [docs/compilation.md](docs/compilation.md) for full build instructions
including cross-compilation, packaging (.deb/.rpm), and version embedding.

## Speed Testing

```bash
# Test all configured upstreams
./dnsieve --speed

# Test with specific domains
./dnsieve --speed google.com,github.com,example.org
```

## Testing

See [docs/testing.md](docs/testing.md) for test instructions including
unit tests, e2e tests, integration tests, RFC compliance tests, and fuzz testing.

## FAQ

See [docs/faq.md](docs/faq.md) for the full FAQ, including topics such as how
block-consensus works, using DNSieve with Pi-hole, whitelist configuration,
DoH/DoT setup, caching behaviour, and provider recommendations.

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for solutions to common
problems including port conflicts, permission errors, blocked or unblocked
domains, Docker networking, TLS certificates, service installation, and config
validation errors.

## Documentation

- [docs/caching.md](docs/caching.md) -- Caching design details
- [docs/compilation.md](docs/compilation.md) -- Build instructions
- [docs/configuration.md](docs/configuration.md) -- Configuration reference
- [docs/docker.md](docs/docker.md) -- Docker deployment guide
- [docs/faq.md](docs/faq.md) -- Frequently asked questions
- [docs/files.md](docs/files.md) -- Project structure and file locations
- [docs/protocol.md](docs/protocol.md) -- DNS protocol details
- [docs/testing.md](docs/testing.md) -- Test instructions
- [docs/troubleshooting.md](docs/troubleshooting.md) -- Troubleshooting guide

## License

MIT License -- see [LICENSE](LICENSE).

Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)

GitHub Repository: https://github.com/secu-tools/dnsieve

