#!/bin/sh
# Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
#
# Entrypoint script for DNSieve Docker images.
# The container runs directly as the unprivileged dnsieve user (uid 1000),
# set via the 'user:' key in docker-compose.yml. No privilege dropping needed.
set -e

exec /app/dnsieve "$@"
