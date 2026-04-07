# Docker Deployment

## Quick Start

```bash
mkdir -p config log
docker compose -f docker/docker-compose.yml up -d
```

On first run DNSieve auto-generates a default configuration file at
`./config/config.toml`. Stop the container, edit the file to customise
upstreams, ports, and other settings, then restart:

```bash
docker compose -f docker/docker-compose.yml stop
# edit ./config/config.toml
docker compose -f docker/docker-compose.yml up -d
```

> **Note:** Create the `config` and `log` directories before the first run.
> On Linux the container user (UID 1000) must be able to write to them.
> If your host user is UID 1000 (the default on most Linux desktops),
> `mkdir -p config log` is all that is needed. On macOS or with a different
> UID, run `sudo chown -R 1000:1000 config log` after creating the directories.

## Default Ports

| Protocol | Default port | Standard port | Config key              |
|----------|-------------|---------------|-------------------------|
| DNS      | 5353        | 53            | `[downstream.plain]`    |
| DoT      | 8853        | 853           | `[downstream.dot]`      |
| DoH      | 4433        | 443           | `[downstream.doh]`      |

Default ports are non-privileged (above 1024) so the container requires no
elevated capabilities. To use standard ports (53, 853, 443), update
`config.toml` and uncomment `cap_add: NET_BIND_SERVICE` in `docker/docker-compose.yml`.

## Security

The container runs as a non-root user (`dnsieve`, UID 1000) with a read-only
root filesystem and all Linux capabilities dropped:

| Control                          | Effect                                                           |
|----------------------------------|------------------------------------------------------------------|
| Non-root user (UID 1000)         | Process has no root access inside the container.                 |
| `cap_drop: ALL`                  | No Linux capabilities (including NET_BIND_SERVICE by default).   |
| `read_only: true`                | Container filesystem is read-only; only volumes and tmpfs can be written. |
| `security_opt: no-new-privileges`| Prevents privilege escalation via setuid executables.            |

## Docker Compose

The included `docker/docker-compose.yml` runs DNSieve with:
- Port 5353 (UDP + TCP) for plain DNS
- Config at `./config/` (auto-generated on first run)
- Logs at `./log/`
- Non-root user, read-only filesystem, all capabilities dropped

To enable DoT or DoH, uncomment the port mappings in `docker/docker-compose.yml` and
configure TLS certificates in `config/config.toml`.

To bind to privileged ports (53, 853, 443), also uncomment `cap_add: NET_BIND_SERVICE`.

## GHCR (GitHub Container Registry)

### Linux images

```
ghcr.io/secu-tools/dnsieve:latest
ghcr.io/secu-tools/dnsieve:<version>
```

Multi-arch: `linux/amd64`, `linux/arm64`, `linux/arm/v7`,
`linux/386`, `linux/ppc64le`, `linux/s390x`, `linux/riscv64`.

### Windows images

```
ghcr.io/secu-tools/dnsieve:latest-windows-ltsc2022
ghcr.io/secu-tools/dnsieve:<version>-windows-ltsc2022
```

Windows images are built for `windows/amd64` (Windows Server 2022 LTSC).
For `windows/arm64`, build locally using `docker/Dockerfile.windows`:

```powershell
docker build --platform windows/arm64 --build-arg TARGETARCH=arm64 `
  -f docker/Dockerfile.windows -t dnsieve-windows-arm64 .
```

## Running Directly

```bash
mkdir -p config log
docker run -d \
  --name dnsieve \
  -p 5353:5353/udp -p 5353:5353/tcp \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/log:/app/log \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp \
  --security-opt no-new-privileges \
  --restart on-failure \
  ghcr.io/secu-tools/dnsieve:latest
```

## Building the Image Locally

```bash
docker build -f docker/Dockerfile -t dnsieve .

# With version info
docker build -f docker/Dockerfile --build-arg VERSION=1.0.0 --build-arg BUILD_NUMBER=42 -t dnsieve .
```

## Image Details

- **Base:** `alpine:3.20`
- **User:** `dnsieve` (UID 1000, non-root)
- **Working directory:** `/app`
- **Ports:** 5353/udp, 5353/tcp, 8853/tcp, 4433/tcp
- **Volumes:** `/app/config` (config), `/app/log` (logs)

## Auto-generated Config

If no `config.toml` is present when the container starts, DNSieve
auto-generates a default one at `/app/config/config.toml` and starts with
that configuration. The container user must have write access to `/app/config`
(see the note in Quick Start about pre-creating the `config` and `log`
directories with correct ownership).

Stop the container, edit `./config/config.toml`, and restart to apply custom
settings.

## Restart Policy

The compose file uses `restart: on-failure`. This means:
- The container restarts automatically if DNSieve exits with a non-zero code
  (e.g., a crash or config error on startup).
- A clean shutdown via `docker stop` or `docker compose stop` (exit 0) does
  not trigger a restart.

## Environment Variables

| Variable | Description                             |
|----------|-----------------------------------------|
| `TZ`     | Timezone for log timestamps (default: UTC) |

## Health Check

The compose file includes a health check that queries `google.com` via the
DNS server:

```yaml
healthcheck:
  test: ["CMD", "nslookup", "google.com", "127.0.0.1"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

