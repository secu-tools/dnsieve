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

Cross-platform build scripts are included with support for multi-arch builds,
packaging, testing, and coverage.

### PowerShell (Windows)

```powershell
.\build.ps1                   # Windows + Linux amd64
.\build.ps1 -all              # All platforms and architectures
.\build.ps1 -linux -deb       # Linux + .deb packages
.\build.ps1 -linux -rpm       # Linux + .rpm packages
.\build.ps1 -upx              # Enable UPX compression (requires upx installed)
.\build.ps1 -test             # Run tests
.\build.ps1 -coverage         # Run tests with coverage
.\build.ps1 -clean            # Clean build artifacts
```

### Shell (Linux/macOS)

```bash
./build.sh                    # Linux + macOS amd64
./build.sh -all               # All platforms and architectures
./build.sh -linux -deb        # Linux + .deb packages
./build.sh -upx               # Enable UPX compression (requires upx installed)
./build.sh -test              # Run tests
./build.sh -coverage          # Run tests with coverage
./build.sh -clean             # Clean build artifacts
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
