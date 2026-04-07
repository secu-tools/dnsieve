#!/usr/bin/env bash
# Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# DNSieve build script for Linux/macOS
# Usage:
#   ./build.sh                    # Build linux/amd64 + windows/amd64
#   ./build.sh -windows           # Build windows/amd64 + windows/arm64
#   ./build.sh -linux             # Build linux/amd64 + linux/arm64
#   ./build.sh -darwin            # Build darwin/amd64 + darwin/arm64
#   ./build.sh -amd64             # Build all platforms for amd64 only
#   ./build.sh -arm64             # Build all platforms for arm64 only
#   ./build.sh -linux -amd64      # Build linux/amd64 only
#   ./build.sh -linux -arm64      # Build linux/arm64 only
#   ./build.sh -windows -amd64    # Build windows/amd64 only
#   ./build.sh -windows -arm64    # Build windows/arm64 only
#   ./build.sh -all               # Build all platform/arch combinations
#   ./build.sh -test              # Run unit + integration tests and short fuzz seeds
#   ./build.sh -testall           # Run smoke -> unit+integration -> fuzz -> e2e (full suite)
#   ./build.sh -coverage          # Run tests with coverage
#   ./build.sh -clean             # Clean build artifacts
#   ./build.sh -linux -deb        # Build linux + create .deb packages
#   ./build.sh -linux -rpm        # Build linux + create .rpm packages
#   ./build.sh -linux -deb -rpm   # Build linux + both .deb and .rpm
#   ./build.sh -upx               # Enable UPX compression (requires upx installed)
#   ./build.sh -teste2e           # Run end-to-end tests (requires network)
#   ./build.sh -testsmoke         # Run smoke tests (builds binary + network required)
#
# All builds use CGO_ENABLED=0 (pure Go).
#
# Filename convention:
#   dnsieve_<VERSION>-<OS>-<ARCH>[.exe]
set -e

BINARY="dnsieve"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Read base version from version/version_base.txt (env VERSION overrides)
VERSION_BASE_FILE="$(dirname "$0")/version/version_base.txt"
if [ -z "${VERSION}" ] && [ -f "${VERSION_BASE_FILE}" ]; then
  VERSION=$(head -1 "${VERSION_BASE_FILE}" 2>/dev/null | tr -cd '0-9.')
fi
VERSION="${VERSION:-1.0.0}"

# Auto-increment build number (or use BUILD_NUMBER env var to pin an exact value)
BUILD_NUMBER_FILE="$(dirname "$0")/version/build_number.txt"
SKIP_BUILD_NUMBER_BUMP=false
if [ -n "${BUILD_NUMBER}" ]; then
  SKIP_BUILD_NUMBER_BUMP=true
else
  BUILD_NUMBER=0
  if [ -f "${BUILD_NUMBER_FILE}" ]; then
    BUILD_NUMBER=$(head -1 "${BUILD_NUMBER_FILE}" 2>/dev/null | tr -cd '0-9')
    [ -z "${BUILD_NUMBER}" ] && BUILD_NUMBER=0
  fi
fi
if ! $SKIP_BUILD_NUMBER_BUMP; then
  printf '%s\n' "$((BUILD_NUMBER + 1))" > "${BUILD_NUMBER_FILE}"
fi

FULL_VERSION="${VERSION}.${BUILD_NUMBER}"
MODULE="github.com/secu-tools/dnsieve/internal/app"
LDFLAGS="-X ${MODULE}.version=${VERSION} -X ${MODULE}.commit=${COMMIT} -X ${MODULE}.buildNumber=${BUILD_NUMBER} -s -w"
BUILD_DIR="build"

echo "DNSieve Build Script"
echo "========================"
echo "Version: ${FULL_VERSION}"
echo "Commit:  ${COMMIT}"
echo ""

# Parse arguments
BUILD_WINDOWS=false
BUILD_LINUX=false
BUILD_DARWIN=false
INCLUDE_AMD64=false
INCLUDE_ARM64=false
RUN_TEST=false
RUN_TESTALL=false
RUN_COVERAGE=false
RUN_CLEAN=false
BUILD_DEB=false
BUILD_RPM=false
BUILD_UPX=false
RUN_E2E=false
RUN_SMOKE=false
HAS_PLATFORM=false
HAS_ARCH=false

for arg in "$@"; do
  case "$arg" in
    -windows)      BUILD_WINDOWS=true; HAS_PLATFORM=true ;;
    -linux)        BUILD_LINUX=true; HAS_PLATFORM=true ;;
    -darwin)       BUILD_DARWIN=true; HAS_PLATFORM=true ;;
    -amd64)        INCLUDE_AMD64=true; HAS_ARCH=true ;;
    -arm64)        INCLUDE_ARM64=true; HAS_ARCH=true ;;
    -all)          BUILD_WINDOWS=true; BUILD_LINUX=true; BUILD_DARWIN=true; INCLUDE_AMD64=true; INCLUDE_ARM64=true; HAS_PLATFORM=true; HAS_ARCH=true ;;
    -test)         RUN_TEST=true ;;
    -testall)      RUN_TESTALL=true ;;
    -coverage)     RUN_COVERAGE=true ;;
    -clean)        RUN_CLEAN=true ;;
    -deb)          BUILD_DEB=true ;;
    -rpm)          BUILD_RPM=true ;;
    -upx)          BUILD_UPX=true ;;
    -teste2e)      RUN_E2E=true ;;
    -testsmoke)    RUN_SMOKE=true ;;
    *)             echo "Unknown argument: $arg"; echo "Usage: $0 [-windows] [-linux] [-darwin] [-amd64] [-arm64] [-all] [-test] [-testall] [-coverage] [-clean] [-deb] [-rpm] [-upx] [-teste2e] [-testsmoke]"; exit 1 ;;
  esac
done

if $RUN_TEST; then
  echo "Running unit + integration tests + fuzz seed corpus..."
  echo ""

  DNS_TMP="${TMPDIR:-/tmp}/dnsieve"
  mkdir -p "${DNS_TMP}"
  ORIG_TMPDIR="${TMPDIR:-}"
  export TMPDIR="${DNS_TMP}"
  export TMP="${DNS_TMP}"
  export TEMP="${DNS_TMP}"

  cleanup_test_tmp() {
    export TMPDIR="${ORIG_TMPDIR}"
    unset TMP TEMP
    rm -rf "${DNS_TMP}"
  }
  trap cleanup_test_tmp EXIT

  echo "[1/3] Unit tests..."
  go test -v -count=1 ./... || { echo "Unit tests failed"; exit 1; }

  echo ""
  echo "[2/3] Integration tests..."
  go test -v -tags integration -count=1 -timeout 120s ./tests/integration/ || { echo "Integration tests failed"; exit 1; }

  echo ""
  echo "[3/3] Fuzz seed corpus..."
  go test -v -count=1 -run '^Fuzz' ./internal/... || { echo "Fuzz seed tests failed"; exit 1; }

  cleanup_test_tmp
  trap - EXIT
  echo ""
  echo "All tests passed."
  exit 0
fi

if $RUN_TESTALL; then
  echo "Running full test suite: smoke -> unit -> integration -> fuzz -> e2e..."
  echo ""

  DNS_TMP="${TMPDIR:-/tmp}/dnsieve"
  mkdir -p "${DNS_TMP}"
  ORIG_TMPDIR="${TMPDIR:-}"
  export TMPDIR="${DNS_TMP}"
  export TMP="${DNS_TMP}"
  export TEMP="${DNS_TMP}"

  cleanup_test_tmp() {
    export TMPDIR="${ORIG_TMPDIR}"
    unset TMP TEMP
    rm -rf "${DNS_TMP}"
  }
  trap cleanup_test_tmp EXIT

  echo "[1/5] Smoke tests..."
  go test -v -buildvcs=false -tags smoke -count=1 -timeout 300s ./tests/smoke/ || { echo "Smoke tests failed"; exit 1; }

  echo ""
  echo "[2/5] Unit tests..."
  go test -v -count=1 ./... || { echo "Unit tests failed"; exit 1; }

  echo ""
  echo "[3/5] Integration tests..."
  go test -v -tags integration -count=1 -timeout 120s ./tests/integration/ || { echo "Integration tests failed"; exit 1; }

  echo ""
  echo "[4/5] Fuzz seed corpus..."
  go test -v -count=1 -run '^Fuzz' ./internal/... || { echo "Fuzz seed tests failed"; exit 1; }

  echo ""
  echo "[5/5] E2E tests..."
  go test -v -tags e2e -count=1 -timeout 300s ./tests/e2e/ || { echo "E2E tests failed"; exit 1; }

  cleanup_test_tmp
  trap - EXIT
  echo ""
  echo "Full test suite passed."
  exit 0
fi

if $RUN_COVERAGE; then
  echo "Running tests with coverage..."

  DNS_TMP="${TMPDIR:-/tmp}/dnsieve"
  mkdir -p "${DNS_TMP}"
  ORIG_TMPDIR="${TMPDIR:-}"
  export TMPDIR="${DNS_TMP}"
  export TMP="${DNS_TMP}"
  export TEMP="${DNS_TMP}"

  cleanup_cov_tmp() {
    export TMPDIR="${ORIG_TMPDIR}"
    unset TMP TEMP
    rm -rf "${DNS_TMP}"
  }
  trap cleanup_cov_tmp EXIT

  go test -v ./... -coverprofile=coverage.out || { cleanup_cov_tmp; trap - EXIT; echo "Coverage tests failed"; exit 1; }
  cleanup_cov_tmp
  trap - EXIT
  go tool cover -html=coverage.out -o coverage.html
  echo "Coverage report: coverage.html"
  exit 0
fi

if $RUN_CLEAN; then
  echo "Cleaning..."
  rm -f ${BINARY} ${BINARY}.exe ${BINARY}_*
  rm -rf "${BUILD_DIR}"
  rm -f coverage.out coverage.html
  echo "Clean complete."
  exit 0
fi

if $RUN_SMOKE; then
  echo "Running smoke tests..."

  DNS_TMP="${TMPDIR:-/tmp}/dnsieve"
  mkdir -p "${DNS_TMP}"
  ORIG_TMPDIR="${TMPDIR:-}"
  export TMPDIR="${DNS_TMP}"
  export TMP="${DNS_TMP}"
  export TEMP="${DNS_TMP}"

  cleanup_smoke_tmp() {
    export TMPDIR="${ORIG_TMPDIR}"
    unset TMP TEMP
    rm -rf "${DNS_TMP}"
  }
  trap cleanup_smoke_tmp EXIT

  go test -v -buildvcs=false -tags smoke -count=1 -timeout 300s ./tests/smoke/ || { cleanup_smoke_tmp; trap - EXIT; echo "Smoke tests failed"; exit 1; }
  cleanup_smoke_tmp
  trap - EXIT
  echo "Smoke tests passed."
  exit 0
fi

if $RUN_E2E; then
  echo "Running e2e tests..."

  DNS_TMP="${TMPDIR:-/tmp}/dnsieve"
  mkdir -p "${DNS_TMP}"
  ORIG_TMPDIR="${TMPDIR:-}"
  export TMPDIR="${DNS_TMP}"
  export TMP="${DNS_TMP}"
  export TEMP="${DNS_TMP}"

  cleanup_e2e_tmp() {
    export TMPDIR="${ORIG_TMPDIR}"
    unset TMP TEMP
    rm -rf "${DNS_TMP}"
  }
  trap cleanup_e2e_tmp EXIT

  go test -v -tags e2e -count=1 -timeout 300s ./tests/e2e/ || { cleanup_e2e_tmp; trap - EXIT; echo "E2E tests failed"; exit 1; }
  cleanup_e2e_tmp
  trap - EXIT
  echo "E2E tests passed."
  exit 0
fi

# Default: build linux + windows amd64
if ! $HAS_PLATFORM; then
  BUILD_LINUX=true
  BUILD_WINDOWS=true
fi

if $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
  INCLUDE_ARM64=true
elif $HAS_ARCH && ! $HAS_PLATFORM; then
  BUILD_WINDOWS=true
  BUILD_LINUX=true
  BUILD_DARWIN=true
elif ! $HAS_PLATFORM && ! $HAS_ARCH; then
  INCLUDE_AMD64=true
fi

# Wipe build directory
rm -rf "${BUILD_DIR}"

# Collect platform/arch targets
declare -a TARGETS

if $BUILD_WINDOWS; then
  $INCLUDE_AMD64 && TARGETS+=("windows/amd64/.exe/windows")
  $INCLUDE_ARM64 && TARGETS+=("windows/arm64/.exe/windows")
fi

if $BUILD_LINUX; then
  $INCLUDE_AMD64 && TARGETS+=("linux/amd64//linux")
  $INCLUDE_ARM64 && TARGETS+=("linux/arm64//linux")
fi

if $BUILD_DARWIN; then
  $INCLUDE_AMD64 && TARGETS+=("darwin/amd64//darwin")
  $INCLUDE_ARM64 && TARGETS+=("darwin/arm64//darwin")
fi

echo "Building ${#TARGETS[@]} target(s)..."

# Check for UPX (binary compression) -- only active when -upx flag is passed
UPX_AVAILABLE=false
if $BUILD_UPX; then
  if command -v upx &>/dev/null; then
    UPX_AVAILABLE=true
    echo "UPX: found ($(command -v upx))"
  else
    echo "UPX: not found -- -upx requires upx to be installed"
  fi
fi

# Check for nfpm (needed for -deb / -rpm packaging)
NFPM_AVAILABLE=false
if command -v nfpm &>/dev/null; then
  NFPM_AVAILABLE=true
  echo "nfpm: found ($(command -v nfpm))"
else
  if $BUILD_DEB || $BUILD_RPM; then
    echo "nfpm: not found -- auto-installing..."
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest 2>/dev/null
    if command -v nfpm &>/dev/null; then
      NFPM_AVAILABLE=true
      echo "nfpm: installed ($(command -v nfpm))"
    else
      echo "ERROR: nfpm auto-install failed"
      echo "  Install manually: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
      exit 1
    fi
  fi
fi
echo ""

# Build helper: build_one <goos> <goarch> <ext> <subdir>
build_one() {
  local goos="$1" goarch="$2" ext="$3" subdir="$4"

  local outdir="${BUILD_DIR}/${subdir}"
  mkdir -p "${outdir}"
  local output="${outdir}/${BINARY}_${FULL_VERSION}-${goos}-${goarch}${ext}"

  echo "  Building ${output}..."

  if (
    export GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED="0"
    go build -ldflags "${LDFLAGS}" -trimpath -o "${output}" ./
  ); then
    # UPX compress if available
    if $UPX_AVAILABLE && [ -f "${output}" ]; then
      local orig_size
      orig_size=$(stat -f%z "${output}" 2>/dev/null || stat -c%s "${output}" 2>/dev/null || echo 0)
      if upx --best --lzma -q "${output}" 2>/dev/null; then
        local new_size
        new_size=$(stat -f%z "${output}" 2>/dev/null || stat -c%s "${output}" 2>/dev/null || echo 0)
        echo "    -> UPX compressed: ${new_size} bytes (was ${orig_size})"
      else
        echo "    -> UPX skipped for ${output}"
      fi
    fi
    return 0
  else
    echo "    FAILED: ${output}"
    rm -f "${output}"
    return 1
  fi
}

for target in "${TARGETS[@]}"; do
  IFS='/' read -r goos goarch ext subdir <<< "$target"
  build_one "$goos" "$goarch" "$ext" "$subdir"
done

# -- Package Linux binaries with nfpm if -deb or -rpm requested --------
package_nfpm() {
  local binary_path="$1" goarch="$2" format="$3"

  # Map Go arch to package arch
  local pkg_arch
  if [ "$format" = "deb" ]; then
    case "$goarch" in
      amd64) pkg_arch="amd64" ;;
      arm64) pkg_arch="arm64" ;;
      *)     pkg_arch="$goarch" ;;
    esac
  else
    case "$goarch" in
      amd64) pkg_arch="x86_64" ;;
      arm64) pkg_arch="aarch64" ;;
      *)     pkg_arch="$goarch" ;;
    esac
  fi

  local out_dir
  out_dir=$(dirname "$binary_path")
  local base_name
  base_name=$(basename "$binary_path")
  local pkg_file="${out_dir}/${base_name}.${format}"

  # Generate nfpm config
  local tmp_yaml
  tmp_yaml=$(mktemp /tmp/nfpm_XXXXXX.yaml)
  cat > "$tmp_yaml" <<NFPMEOF
name: dnsieve
arch: ${pkg_arch}
version: ${FULL_VERSION}
maintainer: "Jack L. (Cpt-JackL) <https://jack-l.com>"
description: "DNSieve - DNS Filtering Proxy with DoH, DoT, and plain DNS support"
homepage: "https://github.com/secu-tools/dnsieve"
license: MIT
contents:
  - src: ${binary_path}
    dst: /usr/bin/dnsieve
    file_info:
      mode: 0755
NFPMEOF

  echo "  Packaging ${pkg_file}..."
  if nfpm pkg --config "$tmp_yaml" --packager "$format" --target "$pkg_file"; then
    local size
    size=$(stat -f%z "$pkg_file" 2>/dev/null || stat -c%s "$pkg_file" 2>/dev/null || echo 0)
    echo "    -> ${size} bytes"
  else
    echo "    FAILED: ${pkg_file}"
  fi
  rm -f "$tmp_yaml"
}

if $NFPM_AVAILABLE && ($BUILD_DEB || $BUILD_RPM); then
  echo ""
  echo "Packaging Linux binaries..."

  for bin in "${BUILD_DIR}"/linux/dnsieve_*; do
    [ -f "$bin" ] || continue
    case "$bin" in *.deb|*.rpm) continue ;; esac

    arch=""
    case "$bin" in
      *-linux-amd64*) arch="amd64" ;;
      *-linux-arm64*) arch="arm64" ;;
    esac
    [ -z "$arch" ] && continue

    if $BUILD_DEB; then
      package_nfpm "$bin" "$arch" "deb"
    fi
    if $BUILD_RPM; then
      package_nfpm "$bin" "$arch" "rpm"
    fi
  done
fi

echo ""
echo "Build complete. Output in ${BUILD_DIR}/"
find "${BUILD_DIR}" -type f | sort
