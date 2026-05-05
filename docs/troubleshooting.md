# Troubleshooting

### DNSieve fails to start: "config file not found"

DNSieve looks for `config.toml` at `/etc/dnsieve/config.toml` (Linux/macOS) or
`<exe_dir>\config\config.toml` (Windows). If it is missing, DNSieve prompts to
generate a default file. Accept the prompt, review the generated file, and restart:

```bash
./dnsieve
# Config file not found: /etc/dnsieve/config.toml
# Would you like to generate a default config file? [Y/n] Y
```

Use `--cfgfile /path/to/config.toml` to specify a custom path.

---

### "bind: address already in use"

Another process is already listening on the configured port.

**Find the conflicting process:**
```bash
# Linux
ss -tulnp | grep :5353
# macOS
lsof -i :5353
# Windows
netstat -ano | findstr :5353
```

On Linux with dual-stack (`listen_addresses = ["0.0.0.0", "::"]`), this error can
appear if another program binds a generic IPv6 socket that implicitly claims all
IPv4 addresses. DNSieve uses explicit `tcp4`/`udp4` and `tcp6`/`udp6` socket
types to avoid this, but other programs on the same port may still conflict.
Change DNSieve's `port` to an unused one, or stop the conflicting service.

**Common culprits on port 53:**
- `systemd-resolved` (Linux) -- disable or reconfigure stub resolver
- `dnsmasq` -- stop or move it to another port
- `named` / `bind9` -- stop if not needed

To free port 53 on Ubuntu/Debian with `systemd-resolved`:
```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
# Then point /etc/resolv.conf at DNSieve
```

---

### Linux systemd service fails to start when using a home-directory path

If you installed the service with `--cfgfile` or `--logdir` pointing to a path
under `/home/`, `/root/`, or `/run/user/`, the unit file must have
`ProtectHome=no`. DNSieve sets this automatically during `--install` when it
detects a home-directory path. If you moved the files after installation, edit
the unit file manually:

```bash
sudo systemctl edit --full dnsieve
# Change:  ProtectHome=yes
# To:      ProtectHome=no
sudo systemctl daemon-reload
sudo systemctl restart dnsieve
```

To avoid this entirely, store config and logs in standard system directories:
- Config: `/etc/dnsieve/config.toml`
- Logs:   `/var/log/dnsieve/`

---

### Permission denied binding to port 53

Ports below 1024 require elevated privileges.

**Linux -- grant capability without running as root:**
```bash
sudo setcap cap_net_bind_service=+ep /usr/local/bin/dnsieve
```

**Linux -- systemd service:** The generated unit file already includes
`AmbientCapabilities=CAP_NET_BIND_SERVICE`; ensure the binary has the capability
set as above.

**Docker:** The compose file already adds `NET_BIND_SERVICE`. For port 53
mappings update `docker/docker-compose.yml`:
```yaml
ports:
  - "53:5353/udp"
  - "53:5353/tcp"
```

**Windows:** Run as Administrator or install as a service (services run with
elevated privileges automatically).

---

### Domains are not being blocked

1. **Confirm the upstream blocks the domain.** Test each upstream directly without
   DNSieve:
   ```bash
   dig @9.9.9.9 malware.testcategory.com A
   ```
   If the upstream itself does not block the domain, DNSieve cannot block it either.

2. **Check `min_wait_ms`.** If `min_wait_ms` is set lower than the time it takes
   your blocking upstream to respond, the non-blocking upstream's answer may be
   accepted first. Increase `min_wait_ms` to at least 200-300 ms:
   ```toml
   [upstream_settings]
   min_wait_ms = 300
   ```

3. **Check the cache.** If you recently queried the domain before DNSieve was
   configured correctly, a non-blocked response may be cached. The cache respects
   the upstream TTL (minimum `min_ttl`, default 60 s). Wait for the entry to
   expire, or restart DNSieve to clear the in-memory cache.

4. **Check the whitelist.** If the domain or a parent domain matches a
   `[whitelist]` entry, it bypasses all blocking upstreams. Check your whitelist
   config.

5. **Enable debug logging** to see per-upstream results:
   ```toml
   [logging]
   log_level = "debug"
   ```
   Look for `Upstream[n] ... blocked=true/false` in the logs.

---

### Legitimate domains are being blocked (false positives)

Block decisions come from your upstream providers and, optionally, from the
local blacklist -- DNSieve does not perform its own threat-intelligence analysis.
False positives caused by upstream providers are a limitation of their threat
intelligence.

**Options:**
1. **Whitelist the domain** so it bypasses all blocking upstreams:
   ```toml
   [whitelist]
   enabled = true
   domains = ["falsepositive.example.com"]
   resolver_address = "https://1.1.1.1/dns-query"
   resolver_protocol = "doh"
   ```
2. **Report the false positive** to the upstream provider. Most providers (Quad9,
   Cloudflare) have false-positive reporting forms.
3. **Remove the upstream** that is responsible for the false positive if it
   generates too many.

---

### DNS resolution is slow / high latency

1. **Run the speed test** to identify slow upstreams:
   ```bash
   ./dnsieve --speed
   ```
   Replace any upstream with average latency above ~300 ms with a geographically
   closer provider.

2. **Reduce the number of upstreams.** Each query is fanned out to all upstreams
   concurrently. Using more than three providers increases connection overhead.
   The overall response time is bounded by the slowest upstream that needs to
   respond.

3. **Lower `timeout_ms`** if an upstream frequently times out -- a timed-out
   upstream adds the full timeout duration to every query on a cache miss:
   ```toml
   [upstream_settings]
   timeout_ms = 1500
   ```

4. **Verify caching is enabled.** Repeated queries for the same domain should be
   served from cache with sub-millisecond latency. Confirm `cache.enabled = true`
   in config and check the debug logs for `-> cached` entries.

5. **Increase `min_ttl`** to reduce upstream re-queries for domains with very
   short TTLs:
   ```toml
   [cache]
   min_ttl = 300
   ```

---

### Docker: container starts but DNS queries fail

1. **Check the health check:**
   ```bash
   docker inspect dnsieve | grep -A 10 Health
   ```

2. **Confirm port mapping.** The default compose maps `5353:5353`. If your clients
   use port 53, update the mapping:
   ```yaml
   ports:
     - "53:5353/udp"
     - "53:5353/tcp"
   ```

3. **Check if config is mounted.** The config volume must exist and contain a
   valid `config.toml`:
   ```bash
   docker exec dnsieve cat /etc/dnsieve/config.toml
   ```
   If the file is missing, the container will exit immediately. Create the
   `./config/` directory and place your `config.toml` in it before running
   `docker compose -f docker/docker-compose.yml up -d`.

4. **View container logs:**
   ```bash
   docker logs dnsieve
   docker logs dnsieve --follow
   ```

5. **Read-only filesystem errors.** The compose file mounts the container root as
   read-only. If DNSieve tries to write files outside `/etc/dnsieve` or
   `/var/log/dnsieve`, it will fail. Ensure `--logdir` is not set to a path
   outside the mounted volume, and that no process writes to unexpected paths in
   the container.

6. **TZ environment variable.** If log timestamps are in the wrong timezone, set
   the `TZ` variable in `docker/docker-compose.yml`:
   ```yaml
   environment:
     - TZ=America/New_York
   ```

---

### Docker: IPv6 DNS queries not reaching the container

Docker's default network mode does not enable IPv6 routing. To expose IPv6 port
mappings, add explicit mappings in `docker/docker-compose.yml`:

```yaml
ports:
  - "5353:5353/udp"
  - "5353:5353/tcp"
  - "[::]:5353:5353/udp"
  - "[::]:5353:5353/tcp"
```

You may also need to enable IPv6 in the Docker daemon
(`/etc/docker/daemon.json`):
```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80"
}
```

---

### TLS certificate errors (DoT / DoH)

**"tls: failed to find any PEM data"** -- The cert or key file path is wrong, or
the files are empty. Double-check `cert_file` and `key_file` in `[tls]`.

**"certificate signed by unknown authority"** -- You are using a self-signed
certificate and a client is rejecting it. Either install the CA certificate on the
client, or use a certificate from a public CA (e.g., Let's Encrypt).

**Upstream TLS verification failure** -- If an upstream's certificate cannot be
verified (expired, self-signed, or wrong hostname), DNSieve logs a warning and
treats the upstream as failed for that query. Disable verification only for
trusted internal servers:
```toml
[[upstream]]
address = "https://internal-dns.corp.example.com/dns-query"
protocol = "doh"
verify_certificates = false
```
Never disable certificate verification for public upstream servers.

**Generating a self-signed certificate for testing:**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=dnsieve"
```

---

### System service fails to start (Linux / systemd)

```bash
# Check status
systemctl status dnsieve

# View recent logs
journalctl -u dnsieve -n 50 --no-pager

# Common issues:
# - Config file missing or invalid
# - Port already in use
# - Binary not found at the recorded path
```

If you moved the binary after installing the service, uninstall and reinstall:
```bash
sudo ./dnsieve --uninstall
sudo ./dnsieve --install
```

For permission errors on port 53, ensure the binary has the `cap_net_bind_service`
capability (the unit file sets `AmbientCapabilities=CAP_NET_BIND_SERVICE`, but the
capability must also be set on the binary itself with `setcap`).

---

### System service fails to start (Windows)

```powershell
# Check Windows Event Log
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 20

# Check service status
sc.exe query dnsieve

# Start manually to see error output
sc.exe start dnsieve
```

The service binary path is recorded at install time. If you move the executable,
uninstall and reinstall the service. The service runs as Local System -- ensure
the config file path is accessible to that account.

---

### All upstreams return SERVFAIL

1. **Check internet / outbound connectivity.** DoH upstreams require port 443;
   DoT requires port 853. Ensure your firewall allows outbound connections on
   these ports.

2. **Check bootstrap DNS.** When using DoH or DoT upstreams, DNSieve must resolve
   the upstream hostname. If your system DNS is broken or circular, set a
   bootstrap DNS server:
   ```toml
   [upstream_settings]
   bootstrap_dns = "9.9.9.9:53"
   ```
   The bootstrap server uses plain UDP on port 53 -- ensure it is reachable.

3. **Verify TLS certificate verification.** If `verify_certificates = true`
   (default) and the upstream's certificate cannot be validated (e.g., clock skew
   causing an "expired" certificate), all encrypted upstreams fail. Check that the
   system clock is accurate:
   ```bash
   timedatectl status       # Linux
   w32tm /query /status     # Windows
   ```

4. **Increase `timeout_ms`** if upstreams are slow to respond on your network:
   ```toml
   [upstream_settings]
   timeout_ms = 5000
   ```

---

### Log file not created or wrong location

DNSieve writes logs to `/var/log/dnsieve/` (Linux/macOS) or `<exe_dir>\log\`
(Windows). If the default directory is not writable, it falls back to the
executable's directory and logs a warning at startup.

Override the log directory at runtime or in the service:
```bash
./dnsieve --logdir /custom/log/path
```

Or check the startup warning in stderr output:
```
WARN | Using fallback log directory (default was not writable). Use --logdir to specify a custom location.
```

In **Docker**, logs are written inside the container at `/var/log/dnsieve/`. The
compose file mounts this to `./log/` on the host. Ensure the `./log/` directory
is writable by the container's `dnsieve` user (UID varies -- run
`docker exec dnsieve id` to check, then `chown` accordingly if needed).

---

### Cache is not reducing latency

1. Make sure `cache.enabled = true` in the config (it is enabled by default).
2. Enable debug logging and look for `-> cached` vs. `-> cache miss` in the logs.
   If you see cache misses for the same domain repeatedly, the TTL may be very
   short. Increase `min_ttl`:
   ```toml
   [cache]
   min_ttl = 120
   ```
3. DNSieve caches per query type (A and AAAA are separate entries). A cache hit
   for `A` does not satisfy an `AAAA` query.
4. The cache is in-memory only and is lost when DNSieve restarts. This is by
   design.

---

### Config validation errors on startup

DNSieve validates the config before starting and prints each error to stderr with
`ERROR |` prefix. Common errors and fixes:

| Error message | Fix |
|---|---|
| `no upstream DNS servers configured` | Add at least one `[[upstream]]` block |
| `no downstream listeners enabled` | Set `enabled = true` for plain, dot, or doh |
| `unsupported protocol "..."` | Use `"doh"`, `"dot"`, or `"udp"` |
| `listen_addresses must contain at least one address` | Add an address to the empty `listen_addresses` array |
| `tls cert_file and key_file are required` | Set both `cert_file` and `key_file` under `[tls]` |
| `cache renew_percent=... is invalid` | Set a value between 0 and 99 |
| `upstream min_wait_ms >= timeout_ms` | Ensure `min_wait_ms` is less than `timeout_ms` |

Run `./dnsieve --version` to confirm the binary is correctly built and the version
string matches what you expect.
