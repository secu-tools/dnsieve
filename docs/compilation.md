# Compilation

## Prerequisites

- [Go](https://go.dev/dl/) -- see `go.mod` for the minimum required version
- Git (for version embedding)

## Quick Build

```bash
# Build for the current platform
go build -o dnsieve ./
```

## Build Scripts

All three scripts accept the same flags. Run the one for your OS:

| Platform | Command |
|---|---|
| Linux / macOS | `./build.sh [flags]` |
| Windows (PowerShell) | `.\build.ps1 [flags]` |
| Windows (CMD) | `build.cmd [flags]` (forwards to `build.ps1`) |

| Flag | Effect |
|---|---|
| `-windows` / `-linux` / `-darwin` | Select platform(s); combine freely |
| `-amd64` / `-arm64` | Select architecture(s); combine freely |
| `-all` | Build every platform/arch combination |
| `-upx` | Enable UPX binary compression (requires `upx` in `PATH`) |
| `-deb` / `-rpm` | Package linux builds as .deb/.rpm (combine with `-linux`) |
| `-test` | Run unit + integration tests + fuzz seed corpus |
| `-testall` | Run the full suite: smoke, unit, integration, fuzz, e2e |
| `-testsmoke` | Run smoke tests (builds a binary; needs network) |
| `-teste2e` | Run end-to-end tests (needs network) |
| `-coverage` | Run tests with a coverage report |
| `-clean` | Remove build artifacts |

Example: `./build.sh -linux -arm64 -deb` builds linux/arm64 and packages it as `.deb`.

> [!NOTE]
> With no flags, all three scripts build windows/amd64 + linux/amd64. Darwin
> is always opt-in (`-darwin` or `-all`). All builds use `CGO_ENABLED=0`
> (pure Go).

**Makefile** (Linux/macOS convenience wrapper; not flag-based):

```bash
make build          # Native build
make cross          # All platforms (delegates to build.sh)
make test           # Run unit tests
make coverage       # Tests with coverage report
```

## Version Embedding

Build scripts inject version info via ldflags:

```
-X github.com/secu-tools/dnsieve/internal/app.version=1.0.0
-X github.com/secu-tools/dnsieve/internal/app.commit=abc1234
-X github.com/secu-tools/dnsieve/internal/app.buildNumber=42
```

Version sources are in `version/version_base.txt` and `version/build_number.txt`.
The build number auto-increments with each build.

## go install

```bash
go install github.com/secu-tools/dnsieve@latest
```

When installed via `go install`, the version is resolved from Go's
`debug.BuildInfo` at runtime.

## Output Naming

Build artifacts follow the convention:

```
dnsieve_<VERSION>-<OS>-<ARCH>[.exe]
```

For example: `dnsieve_1.0.0.1001-linux-amd64`

## CGO

All builds use `CGO_ENABLED=0` for fully static binaries with no external
dependencies.
