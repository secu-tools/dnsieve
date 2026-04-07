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

## Default Port

DNSieve defaults to port **5353** for plain DNS to avoid requiring elevated
privileges during development and testing. To use the standard DNS port:

1. Change `port = 5353` to `port = 53` in your config file.
2. On Linux: grant the binary the `CAP_NET_BIND_SERVICE` capability, or run as root.
3. On macOS: run as root or use a port forwarder.
4. On Windows: run as Administrator.
