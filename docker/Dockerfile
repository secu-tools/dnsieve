# Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
# Multi-stage build for DNSieve DNS Filtering Proxy

# --- Build stage ---
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Declare platform ARGs after source copy so the go mod download and COPY
# layers are not cache-busted when switching target platform.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT=
ARG VERSION=1.0.0
ARG BUILD_NUMBER=0

RUN set -e; \
    if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
        export GOARM="${TARGETVARIANT#v}"; \
    fi; \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
    -ldflags "-s -w \
      -X github.com/secu-tools/dnsieve/internal/app.version=${VERSION} \
      -X github.com/secu-tools/dnsieve/internal/app.commit=$(git rev-parse --short HEAD 2>/dev/null || echo docker) \
      -X github.com/secu-tools/dnsieve/internal/app.buildNumber=${BUILD_NUMBER} \
      -X github.com/secu-tools/dnsieve/internal/app.buildMode=docker" \
    -trimpath \
    -o /dnsieve ./

# --- Runtime stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 1000 dnsieve && \
    adduser -S -u 1000 -G dnsieve dnsieve

WORKDIR /app

COPY --from=builder /dnsieve /app/dnsieve
COPY docker/docker-entrypoint.sh /docker-entrypoint.sh

RUN mkdir -p /app/config /app/log && \
    chown -R dnsieve:dnsieve /app && \
    chmod +x /app/dnsieve /docker-entrypoint.sh

EXPOSE 5353/udp 5353/tcp 8853/tcp 4433/tcp

VOLUME ["/app/config", "/app/log"]

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["--cfgfile", "/app/config/config.toml", "--logdir", "/app/log"]
