@echo off
REM Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
REM SPDX-License-Identifier: MIT
REM DNSieve build script for Windows CMD
REM This is a convenience wrapper that launches build.ps1 with PowerShell.
REM All arguments are forwarded.
REM
REM Examples:
REM   build.cmd                    Build windows/amd64 + linux/amd64
REM   build.cmd -all               Build all platform/arch combos
REM   build.cmd -test              Run unit + integration tests and fuzz seeds
REM   build.cmd -testall           Run smoke -> unit+integration -> fuzz -> e2e
REM   build.cmd -testsmoke         Run smoke tests (builds binary + network required)
REM   build.cmd -teste2e           Run end-to-end tests (requires network)
REM   build.cmd -clean             Clean build artifacts
REM   build.cmd -windows -arm64    Build Windows amd64 + arm64
REM
REM Binaries: dnsieve_<VER>-<OS>-<ARCH>[.exe]

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
