@echo off
REM Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
REM SPDX-License-Identifier: MIT
REM DNSieve build script for Windows CMD.
REM Forwards all arguments to build.ps1 - see "Build Scripts" in
REM docs/compilation.md for usage and flags.
REM
REM Binaries: dnsieve_<VER>-<OS>-<ARCH>[.exe]

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
