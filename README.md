# DNSieve

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/secu-tools/dnsieve/actions/workflows/ci.yml/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/ci.yml)
[![Build](https://github.com/secu-tools/dnsieve/actions/workflows/build.yml/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/build.yml)
[![CodeQL](https://github.com/secu-tools/dnsieve/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/github-code-scanning/codeql)
[![Dependency Graph](https://github.com/secu-tools/dnsieve/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/secu-tools/dnsieve/actions/workflows/dependabot/update-graph)
[![Go Report Card](https://goreportcard.com/badge/github.com/secu-tools/dnsieve)](https://goreportcard.com/report/github.com/secu-tools/dnsieve)

DNS filtering proxy that queries multiple upstream DNS servers concurrently
and enforces block-consensus: if **any** upstream signals a domain is
blocked, the blocked response is returned to the client.

> **Development Status**
>
> DNSieve is still under active development. Not all features have been fully tested and edge cases may exist. This project was built for personal use -- use it at your own discretion.
>
> If you encounter any issues, please open a report in the [Issues](../../issues) section. Include a screenshot and steps to reproduce when possible -- it helps a lot. I may or may not have time to address every report, but all feedback is appreciated.

## Introduction

DNSieve carries no local block lists of its own. Instead of downloading and
maintaining lists of known-bad domains (as Pi-hole or AdGuard Home do),
DNSieve acts as an intelligent proxy that fans out each DNS query to multiple
upstream resolvers -- such as Quad9, Cloudflare for Families, or Control D --
that already perform threat-intelligence filtering on their end. DNSieve then
enforces the strictest outcome: if any upstream signals a domain is blocked,
DNSieve returns a blocked response to the client. This means there are no
lists to download, store, deduplicate, or refresh -- protection is always as
current as the upstream providers. Combining multiple providers gives
complementary coverage across malware, phishing, and newly registered domains
without managing separate subscriptions. The trade-off is that querying all
upstreams concurrently introduces a small amount of latency compared to a
single-server setup; for best results, use fast upstream servers and keep the
count to 2-3.

## How It Works

1. Client sends a DNS query to DNSieve (plain DNS, DoT, or DoH)
2. DNSieve checks the cache -- if hit, returns immediately
3. On cache miss, DNSieve fans out the query to all configured upstream
   servers concurrently
4. Results are collected:
   - If **any** upstream signals **blocked**, cache the block and return
     REFUSED + EDE Blocked (RFC 8914 code 15) to the client
   - If **not blocked** and **all** upstreams responded, cache from the
     highest-priority upstream and return
   - If some upstreams had errors, do **not** cache but still return the
     best available result
5. Nearly-expired cache entries are refreshed in the background to keep
   responses fast for frequently queried domains

## Features

- **Concurrent fan-out** with block-consensus across multiple upstreams
- **DNS-over-HTTPS** (RFC 8484), **DNS-over-TLS** (RFC 7858), and **plain DNS**
  for both upstream and downstream
- **LRU caching** with upstream TTL respect, background refresh for
  nearly-expired entries, and configurable minimum TTL
- **Domain whitelist** with wildcard support (`*.example.com`)
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
# Place your config.toml in ./config/ (or run dnsieve once to generate one)
docker compose -f docker/docker-compose.yml up -d
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

## Documentation

- [docs/compilation.md](docs/compilation.md) -- Build instructions
- [docs/configuration.md](docs/configuration.md) -- Configuration reference
- [docs/docker.md](docs/docker.md) -- Docker deployment guide
- [docs/faq.md](docs/faq.md) -- Frequently asked questions
- [docs/files.md](docs/files.md) -- Project structure and file locations
- [docs/protocol.md](docs/protocol.md) -- DNS protocol details
- [docs/testing.md](docs/testing.md) -- Test instructions
- [docs/troubleshooting.md](docs/troubleshooting.md) -- Troubleshooting guide

## FAQ

See [docs/faq.md](docs/faq.md) for the full FAQ, including topics such as how
block-consensus works, using DNSieve with Pi-hole, whitelist configuration,
DoH/DoT setup, caching behaviour, and provider recommendations.

---

## Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md) for solutions to common
problems including port conflicts, permission errors, blocked or unblocked
domains, Docker networking, TLS certificates, service installation, and config
validation errors.

## License

MIT License -- see [LICENSE](LICENSE).

Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)

GitHub Repository: https://github.com/secu-tools/dnsieve

