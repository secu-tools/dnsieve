# Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# DNSieve build script for Windows PowerShell
# Usage:
#   .\build.ps1                   # Build windows/amd64 + linux/amd64
#   .\build.ps1 -windows          # Build windows/amd64 + windows/arm64
#   .\build.ps1 -linux            # Build linux/amd64 + linux/arm64
#   .\build.ps1 -darwin           # Build darwin/amd64 + darwin/arm64
#   .\build.ps1 -amd64            # Build all platforms for amd64 only
#   .\build.ps1 -arm64            # Build all platforms for arm64 only
#   .\build.ps1 -linux -amd64     # Build linux/amd64 only
#   .\build.ps1 -linux -arm64     # Build linux/arm64 only
#   .\build.ps1 -windows -amd64   # Build windows/amd64 only
#   .\build.ps1 -windows -arm64   # Build windows/arm64 only
#   .\build.ps1 -all              # Build all platform/arch combinations
#   .\build.ps1 -test             # Run unit + integration tests and short fuzz seeds
#   .\build.ps1 -testall          # Run smoke -> unit+integration -> fuzz -> e2e (full suite)
#   .\build.ps1 -coverage         # Run tests with coverage
#   .\build.ps1 -clean            # Clean build artifacts
#   .\build.ps1 -linux -deb       # Build linux + create .deb packages
#   .\build.ps1 -linux -rpm       # Build linux + create .rpm packages
#   .\build.ps1 -linux -deb -rpm  # Build linux + both .deb and .rpm
#   .\build.ps1 -upx              # Enable UPX compression (requires upx installed)
#   .\build.ps1 -teste2e          # Run end-to-end tests (requires network)
#   .\build.ps1 -testsmoke        # Run smoke tests (builds binary + network required)
#
# All builds use CGO_ENABLED=0 (pure Go).
#
# Filename convention:
#   dnsieve_<VERSION>-<OS>-<ARCH>[.exe]
param(
    [switch]$windows,
    [switch]$linux,
    [switch]$darwin,
    [switch]$amd64,
    [switch]$arm64,
    [switch]$all,
    [switch]$test,
    [switch]$testall,
    [switch]$coverage,
    [switch]$clean,
    [switch]$deb,
    [switch]$rpm,
    [switch]$upx,
    [switch]$teste2e,
    [switch]$testsmoke
)

$Binary = "dnsieve"
$Commit = try { git rev-parse --short HEAD 2>$null } catch { "dev" }
if (-not $Commit) { $Commit = "dev" }

# Read base version from version/version_base.txt
$VersionBaseFile = Join-Path $PSScriptRoot "version\version_base.txt"
if (Test-Path $VersionBaseFile) {
    $Version = (Get-Content $VersionBaseFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
}
if (-not $Version) { $Version = "1.0.0" }
if ($env:VERSION) { $Version = $env:VERSION }

# Auto-increment build number
$BuildNumberFile = Join-Path $PSScriptRoot "version\build_number.txt"
$SkipBuildNumberBump = $false
if ($env:BUILD_NUMBER) {
    $BuildNumber = [int]$env:BUILD_NUMBER
    $SkipBuildNumberBump = $true
} else {
    $BuildNumber = 0
    if (Test-Path $BuildNumberFile) {
        $raw = (Get-Content $BuildNumberFile -Raw -ErrorAction SilentlyContinue).Trim() -replace '[^0-9]', ''
        if ($raw) { $BuildNumber = [int]$raw }
    }
}
if (-not $SkipBuildNumberBump) {
    Set-Content $BuildNumberFile ($BuildNumber + 1)
}

$FullVersion = "$Version.$BuildNumber"
$Module = "github.com/secu-tools/dnsieve/internal/app"
$LDFlags = "-X ${Module}.version=$Version -X ${Module}.commit=$Commit -X ${Module}.buildNumber=$BuildNumber"
$BuildDir = "build"

Write-Host "DNSieve Build Script" -ForegroundColor Cyan
Write-Host "========================"
Write-Host "Version: $FullVersion"
Write-Host "Commit:  $Commit"

# -- Detect toolchain ------------------------------------------------

# nfpm (needed for -deb / -rpm packaging)
$NfpmAvailable = $false
$NfpmPath = Get-Command nfpm -ErrorAction SilentlyContinue
if ($NfpmPath) {
    $NfpmAvailable = $true
    Write-Host "nfpm:    found ($($NfpmPath.Source))" -ForegroundColor Green
} else {
    if ($deb.IsPresent -or $rpm.IsPresent) {
        Write-Host "nfpm:    not found -- auto-installing..." -ForegroundColor Yellow
        & go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest 2>&1 | Out-Null
        $NfpmPath = Get-Command nfpm -ErrorAction SilentlyContinue
        if ($NfpmPath) {
            $NfpmAvailable = $true
            Write-Host "nfpm:    installed ($($NfpmPath.Source))" -ForegroundColor Green
        } else {
            Write-Host "nfpm:    auto-install failed" -ForegroundColor Red
            Write-Host "         Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" -ForegroundColor Yellow
            exit 1
        }
    }
}

# UPX (only active when -upx flag is passed)
$UPXAvailable = $false
if ($upx.IsPresent) {
    $UPXPath = Get-Command upx -ErrorAction SilentlyContinue
    if ($UPXPath) {
        $UPXAvailable = $true
        Write-Host "UPX:     found ($($UPXPath.Source))" -ForegroundColor Green
    } else {
        Write-Host "UPX:     not found -- -upx requires upx to be installed" -ForegroundColor Yellow
    }
}

Write-Host ""

# Helper: create $TEMP/dnsieve as the test temp root, redirect TEMP/TMP into it,
# and return a saved state for cleanup.
function Enter-TestTmp {
    $origTemp = $env:TEMP
    $origTmp  = $env:TMP
    $dnsTmp   = Join-Path $origTemp "dnsieve"
    New-Item -ItemType Directory -Path $dnsTmp -Force | Out-Null
    $env:TEMP = $dnsTmp
    $env:TMP  = $dnsTmp
    return @{ OrigTemp = $origTemp; OrigTmp = $origTmp; DnsTmp = $dnsTmp }
}

# Helper: restore TEMP/TMP and remove the dnsieve test temp tree.
function Exit-TestTmp($saved) {
    $env:TEMP = $saved.OrigTemp
    $env:TMP  = $saved.OrigTmp
    Remove-Item $saved.DnsTmp -Recurse -Force -ErrorAction SilentlyContinue
}

# Handle test/coverage/clean first
if ($test) {
    Write-Host "Running unit + integration tests + fuzz seed corpus..." -ForegroundColor Green
    Write-Host ""
    $saved = Enter-TestTmp
    try {
        Write-Host "[1/3] Unit tests..." -ForegroundColor Cyan
        go test -v -count=1 ./...
        if ($LASTEXITCODE -ne 0) { throw "Unit tests failed" }

        Write-Host ""
        Write-Host "[2/3] Integration tests..." -ForegroundColor Cyan
        go test -v -tags integration -count=1 -timeout 120s ./tests/integration/
        if ($LASTEXITCODE -ne 0) { throw "Integration tests failed" }

        Write-Host ""
        Write-Host "[3/3] Fuzz seed corpus..." -ForegroundColor Cyan
        go test -v -count=1 -run '^Fuzz' ./internal/...
        if ($LASTEXITCODE -ne 0) { throw "Fuzz seed tests failed" }
    } catch {
        Write-Host "$_" -ForegroundColor Red
        Exit-TestTmp $saved
        exit 1
    }
    Exit-TestTmp $saved
    Write-Host ""
    Write-Host "All tests passed." -ForegroundColor Green
    exit 0
}

if ($testall) {
    Write-Host "Running full test suite: smoke -> unit -> integration -> fuzz -> e2e..." -ForegroundColor Green
    Write-Host ""
    $saved = Enter-TestTmp
    try {
        Write-Host "[1/5] Smoke tests..." -ForegroundColor Cyan
        go test -v -buildvcs=false -tags smoke -count=1 -timeout 300s ./tests/smoke/
        if ($LASTEXITCODE -ne 0) { throw "Smoke tests failed" }

        Write-Host ""
        Write-Host "[2/5] Unit tests..." -ForegroundColor Cyan
        go test -v -count=1 ./...
        if ($LASTEXITCODE -ne 0) { throw "Unit tests failed" }

        Write-Host ""
        Write-Host "[3/5] Integration tests..." -ForegroundColor Cyan
        go test -v -tags integration -count=1 -timeout 120s ./tests/integration/
        if ($LASTEXITCODE -ne 0) { throw "Integration tests failed" }

        Write-Host ""
        Write-Host "[4/5] Fuzz seed corpus..." -ForegroundColor Cyan
        go test -v -count=1 -run '^Fuzz' ./internal/...
        if ($LASTEXITCODE -ne 0) { throw "Fuzz seed tests failed" }

        Write-Host ""
        Write-Host "[5/5] E2E tests..." -ForegroundColor Cyan
        go test -v -tags e2e -count=1 -timeout 300s ./tests/e2e/
        if ($LASTEXITCODE -ne 0) { throw "E2E tests failed" }
    } catch {
        Write-Host "$_" -ForegroundColor Red
        Exit-TestTmp $saved
        exit 1
    }
    Exit-TestTmp $saved
    Write-Host ""
    Write-Host "Full test suite passed." -ForegroundColor Green
    exit 0
}

if ($coverage) {
    Write-Host "Running tests with coverage..." -ForegroundColor Green
    $saved = Enter-TestTmp
    try {
        go test -v ./... -coverprofile=coverage.out
        if ($LASTEXITCODE -ne 0) { throw "Coverage tests failed" }
    } catch {
        Write-Host "$_" -ForegroundColor Red
        Exit-TestTmp $saved
        exit 1
    }
    Exit-TestTmp $saved
    go tool cover -html=coverage.out -o coverage.html
    Write-Host "Coverage report: coverage.html" -ForegroundColor Green
    exit 0
}

if ($clean) {
    Write-Host "Cleaning..." -ForegroundColor Yellow
    Get-ChildItem -Path . -Filter "$Binary*" -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Remove-Item $BuildDir -Recurse -ErrorAction SilentlyContinue
    Remove-Item coverage.out -ErrorAction SilentlyContinue
    Remove-Item coverage.html -ErrorAction SilentlyContinue
    Write-Host "Clean complete."
    exit 0
}

if ($testsmoke) {
    Write-Host "Running smoke tests..." -ForegroundColor Green
    $saved = Enter-TestTmp
    try {
        go test -v -buildvcs=false -tags smoke -count=1 -timeout 300s ./tests/smoke/
        if ($LASTEXITCODE -ne 0) { throw "Smoke tests failed" }
    } catch {
        Write-Host "$_" -ForegroundColor Red
        Exit-TestTmp $saved
        exit 1
    }
    Exit-TestTmp $saved
    Write-Host "Smoke tests passed." -ForegroundColor Green
    exit 0
}

if ($teste2e) {
    Write-Host "Running e2e tests..." -ForegroundColor Green
    $saved = Enter-TestTmp
    try {
        go test -v -tags e2e -count=1 -timeout 300s ./tests/e2e/
        if ($LASTEXITCODE -ne 0) { throw "E2E tests failed" }
    } catch {
        Write-Host "$_" -ForegroundColor Red
        Exit-TestTmp $saved
        exit 1
    }
    Exit-TestTmp $saved
    Write-Host "E2E tests passed." -ForegroundColor Green
    exit 0
}

# Wipe build directory
if (Test-Path $BuildDir) {
    Remove-Item $BuildDir -Recurse -Force
}

# Determine platforms to build
$platforms = @()
$osExplicit  = $windows.IsPresent -or $linux.IsPresent -or $darwin.IsPresent
$archExplicit = $amd64.IsPresent -or $arm64.IsPresent

if ($all) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("amd64", "arm64")
} elseif ($osExplicit -and $archExplicit) {
    $selectedOS = @()
    if ($windows.IsPresent) { $selectedOS += "windows" }
    if ($linux.IsPresent)   { $selectedOS += "linux" }
    if ($darwin.IsPresent)  { $selectedOS += "darwin" }
    $selectedArch = @()
    if ($amd64.IsPresent) { $selectedArch += "amd64" }
    if ($arm64.IsPresent) { $selectedArch += "arm64" }
} elseif ($osExplicit) {
    $selectedOS = @()
    if ($windows.IsPresent) { $selectedOS += "windows" }
    if ($linux.IsPresent)   { $selectedOS += "linux" }
    if ($darwin.IsPresent)  { $selectedOS += "darwin" }
    $selectedArch = @("amd64", "arm64")
} elseif ($amd64.IsPresent -and -not $arm64.IsPresent) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("amd64")
} elseif ($arm64.IsPresent -and -not $amd64.IsPresent) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("arm64")
} elseif ($amd64.IsPresent -and $arm64.IsPresent) {
    $selectedOS = @("windows", "linux", "darwin")
    $selectedArch = @("amd64", "arm64")
} else {
    # Default: windows+linux, amd64 only
    $selectedOS = @("windows", "linux")
    $selectedArch = @("amd64")
}

$extMap = @{ "windows" = ".exe"; "linux" = ""; "darwin" = "" }
$dirMap = @{ "windows" = "windows"; "linux" = "linux"; "darwin" = "darwin" }

foreach ($os in $selectedOS) {
    foreach ($arch in $selectedArch) {
        $platforms += @{ GOOS = $os; GOARCH = $arch; Ext = $extMap[$os]; Dir = $dirMap[$os] }
    }
}

Write-Host "Building $($platforms.Count) target(s)..." -ForegroundColor Green

# -- Build function ---------------------------------------------------
function Build-Target($p) {
    $outDir = "$BuildDir/$($p.Dir)"
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $output = "$outDir/${Binary}_${FullVersion}-$($p.GOOS)-$($p.GOARCH)$($p.Ext)"
    $env:GOOS = $p.GOOS
    $env:GOARCH = $p.GOARCH
    $env:CGO_ENABLED = "0"

    Write-Host "  Building $output..."

    $buildArgs = @("build", "-ldflags", "$LDFlags -s -w", "-trimpath", "-o", $output, "./")

    & go @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    FAILED: $output" -ForegroundColor Red
        Remove-Item $output -ErrorAction SilentlyContinue
        return $false
    }

    $origSize = (Get-Item $output).Length
    if ($UPXAvailable) {
        upx --best --lzma -q $output 2>$null
        if ($LASTEXITCODE -eq 0) {
            $newSize = (Get-Item $output).Length
            $ratio = [math]::Round(($newSize / $origSize) * 100, 1)
            Write-Host "    -> $([math]::Round($newSize/1MB, 2)) MB (UPX: $ratio%)" -ForegroundColor Cyan
        } else {
            Write-Host "    -> $([math]::Round($origSize/1MB, 2)) MB (UPX skipped)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "    -> $([math]::Round($origSize/1MB, 2)) MB" -ForegroundColor White
    }
    return $true
}

# -- nfpm packaging function -------------------------------------------
function Package-Nfpm([string]$binaryPath, [string]$goarch, [string]$format) {
    $archMap = @{
        "amd64" = if ($format -eq "deb") { "amd64" } else { "x86_64" }
        "arm64" = if ($format -eq "deb") { "arm64" } else { "aarch64" }
    }
    $pkgArch = $archMap[$goarch]
    if (-not $pkgArch) { $pkgArch = $goarch }

    $outDir = Split-Path $binaryPath
    $binName = (Get-Item $binaryPath).Name
    $pkgFile = "$outDir/${binName}.${format}"

    $nfpmYaml = @"
name: dnsieve
arch: $pkgArch
version: $FullVersion
maintainer: Jack L. (Cpt-JackL) <https://jack-l.com>
description: DNSieve - DNS Filtering Proxy with DoH, DoT, and plain DNS support
homepage: https://github.com/secu-tools/dnsieve
license: MIT
contents:
  - src: $($binaryPath.Replace('\', '/'))
    dst: /usr/bin/dnsieve
    file_info:
      mode: 0755
"@

    $tmpYaml = Join-Path $env:TEMP "nfpm_$(Get-Random).yaml"
    Set-Content -Path $tmpYaml -Value $nfpmYaml -Encoding UTF8

    Write-Host "  Packaging $pkgFile..." -ForegroundColor Magenta
    & nfpm pkg --config $tmpYaml --packager $format --target $pkgFile
    $exitCode = $LASTEXITCODE
    Remove-Item $tmpYaml -ErrorAction SilentlyContinue

    if ($exitCode -ne 0) {
        Write-Host "    FAILED: $pkgFile" -ForegroundColor Red
        return
    }
    $size = (Get-Item $pkgFile).Length
    Write-Host "    -> $([math]::Round($size/1KB, 1)) KB" -ForegroundColor Magenta
}

# -- Main build loop --------------------------------------------------
foreach ($p in $platforms) {
    Build-Target $p | Out-Null
}

# -- Package Linux binaries with nfpm if -deb or -rpm requested --------
if ($NfpmAvailable -and ($deb.IsPresent -or $rpm.IsPresent)) {
    Write-Host ""
    Write-Host "Packaging Linux binaries..." -ForegroundColor Magenta

    $linuxBinaries = Get-ChildItem "$BuildDir/linux" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^dnsieve_.*-linux-(amd64|arm64)$' }

    foreach ($bin in $linuxBinaries) {
        if ($bin.Name -match '-linux-(amd64|arm64)$') {
            $arch = $Matches[1]
            if ($deb.IsPresent) {
                Package-Nfpm $bin.FullName $arch "deb"
            }
            if ($rpm.IsPresent) {
                Package-Nfpm $bin.FullName $arch "rpm"
            }
        }
    }
}

# Reset environment
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build complete. Output in $BuildDir/" -ForegroundColor Green
Get-ChildItem $BuildDir -Recurse -File | ForEach-Object {
    Write-Host "  $($_.FullName.Replace((Get-Location).Path + '\', ''))"
}
