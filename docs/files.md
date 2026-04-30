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

`ProtectSystem=strict` remounts the entire filesystem hierarchy read-only
inside the service mount namespace (with the exception of paths listed in
`ReadWritePaths`). This gives the service no write access anywhere outside
its designated config and log directories.

DNSieve uses `ProtectSystem=strict` for production installs (binary in a
system path such as `/usr/local/bin`, config in `/etc/dnsieve`, logs in
`/var/log/dnsieve`). In this configuration the service cannot tamper with
the rest of the filesystem even if compromised.

When any relevant path (binary, config directory, or log directory) is
located under `/tmp` -- which is typical of development builds and CI
installations -- DNSieve sets `ProtectSystem=no` instead. With
`ProtectSystem=strict` in effect, `/tmp` is also remounted read-only inside
the namespace, which prevents the service from starting correctly when the
binary or configuration lives there. Setting `ProtectSystem=no` disables all
filesystem remounting for those installs while the remaining hardening
directives (`NoNewPrivileges`, `AmbientCapabilities`) still apply.

### ProtectHome

`ProtectHome=yes` makes `/home`, `/root`, and `/run/user` appear empty and
inaccessible to the service at the mount-namespace level. This is stronger
than `ReadWritePaths`: even paths listed in `ReadWritePaths` that fall under
these prefixes remain inaccessible.

DNSieve sets `ProtectHome=yes` by default, which is appropriate when the
binary, config file, and log directory all reside in system paths such as
`/usr/local/bin`, `/etc/dnsieve`, and `/var/log/dnsieve`.

If you supply a custom `--cfgfile` or `--logdir` pointing to a path under
`/home/`, `/root/`, or `/run/user/`, DNSieve automatically sets
`ProtectHome=no` in the generated unit file so the service can access those
paths at startup.

For system-level deployments, keeping config and logs in standard system
directories (`/etc/dnsieve`, `/var/log/dnsieve`) is recommended so the
stronger `ProtectHome=yes` setting can be used.
