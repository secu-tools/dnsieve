# Files and Directories

## File Locations

### Config Files

| Platform       | Path                            |
|----------------|---------------------------------|
| Linux / macOS  | /etc/dnsieve/config.toml        |
| Windows        | <exe_dir>\config\config.toml    |

### Log Files

| Platform       | Path                            |
|----------------|---------------------------------|
| Linux / macOS  | /var/log/dnsieve/dnsieve.log    |
| Windows        | <exe_dir>\log\dnsieve.log       |

If the default log directory is not writable, DNSieve falls back to
the executable's directory. Override with --logdir.

### Service Files (when installed)

| Platform   | File                                             |
|------------|--------------------------------------------------|
| Windows    | Windows Service (via sc.exe)                     |
| Linux      | /etc/systemd/system/dnsieve.service              |
| OpenWRT    | /etc/init.d/dnsieve                              |
| macOS      | /Library/LaunchDaemons/com.dnsieve.*.plist       |

Multi-instance services use the label suffix: dnsieve_<label>.

## Linux Systemd Service Hardening

The generated systemd unit file applies several security directives:

| Directive              | Value              | Effect                                                        |
|------------------------|--------------------|---------------------------------------------------------------|
| ProtectSystem          | strict / no        | Strict when all paths are in standard system directories; no when any path is under /tmp (development or CI install, see note below) |
| ReadWritePaths         | cfgDir, logDir     | Permits writes to the config and log directories only         |
| NoNewPrivileges        | yes                | Prevents privilege escalation via setuid/setgid binaries      |
| PrivateTmp             | true / false       | Isolated /tmp namespace; disabled when any path is under /tmp |
| ProtectHome            | yes / no           | See below                                                     |
| AmbientCapabilities    | CAP_NET_BIND_SERVICE | Allows binding to port 53 without running as root           |

### ProtectSystem

`ProtectSystem=strict` remounts the filesystem read-only for the service
except for `ReadWritePaths` (the config and log directories). DNSieve uses
it for production installs. When the binary, config, or log path is under
`/tmp` (development or CI installs), DNSieve sets `ProtectSystem=no`
instead, because strict mode would remount `/tmp` read-only and prevent the
service from starting; the other hardening directives still apply.

### ProtectHome

`ProtectHome=yes` (the default) makes `/home`, `/root`, and `/run/user`
inaccessible to the service, even for paths listed in `ReadWritePaths`.
When a custom `--cfgfile` or `--logdir` points under one of those prefixes,
DNSieve automatically sets `ProtectHome=no` in the generated unit file.

> [!TIP]
> Keep config and logs in the standard system directories (`/etc/dnsieve`,
> `/var/log/dnsieve`) so the stronger `ProtectHome=yes` setting can be used.
