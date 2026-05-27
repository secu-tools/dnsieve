# Logging

DNSieve supports two output formats (text and JSON) and can write to stdout and/or a rotating file independently.

---

## Configuration

See [docs/configuration.md](configuration.md) for the full `[logging]` section reference including all TOML keys, default values, and validation rules.

Quick reference: output mode values for `log_level_stdout` / `log_level_file`:

| Value   | Format | Min level | Notes                                         |
|---------|--------|-----------|-----------------------------------------------|
| `json`  | JSON   | INFO      | Newline-delimited JSON; one object per line   |
| `debug` | Text   | DEBUG     |                                               |
| `info`  | Text   | INFO      | **Default**                                   |
| `warn`  | Text   | WARN      |                                               |
| `error` | Text   | ERROR     |                                               |
| `off`   | -      | -         | Disables this output entirely                 |

The two outputs are independent -- e.g. text INFO to stdout and JSON to a file:

```toml
log_level_stdout = "info"
log_level_file   = "json"
```

---

## Text format

```
LEVEL | YYYY/MM/DD HH:MM:SS [module] message
```

Examples:

```
INFO  | 2025/07/01 14:30:00 [server] Plain DNS (UDP) listening on 127.0.0.1:5353
WARN  | 2025/07/01 14:30:12 [server] Slow upstream[0] https://dns.quad9.net/dns-query took 1807ms to resolve example.com.
```

> **Note:** Per-query details (blocked domains, resolved IPs, cache hits) are only
> emitted as structured `dns_query` events in JSON mode. Text mode does not include
> per-query lines in order to avoid excessive output volume.

---

## JSON format

When `log_level_stdout` or `log_level_file` is set to `json`, each log line is
a self-contained JSON object followed by a newline (`\n`).

> **Note:** `dns_query` events are JSON-only - they are never written to text
> outputs. This keeps text-mode logs focused on operational messages (startup,
> warnings, errors) while the full per-query detail is available in JSON.
> The slow-upstream warning appears in both text and JSON outputs.

### Top-level fields (all events)

| Field       | Type   | Description                                      |
|-------------|--------|--------------------------------------------------|
| `timestamp` | string | RFC 3339 Nano timestamp (UTC)                    |
| `level`     | string | `DEBUG`, `INFO`, `WARN`, `ERROR`                 |
| `type`      | string | `general` or `dns_query`                         |
| `module`    | string | Internal component (`server`, `upstream`, ...)     |
| `message`   | string | Human-readable summary                           |
| `dns`       | object | Present only for `dns_query` events (see below)  |

### `dns` object (`dns_query` events only)

The `dns` object groups all per-query fields. It contains five sub-objects:
`client`, `upstream`, `decision`, `cache`, and `response`.

`response` is always populated for `dns_query` events and records what the
client actually received, regardless of whether the answer came from an
upstream server, the local cache, or a block decision. The other sub-objects
provide context for *how* that answer was produced.

#### `dns.client`

| Field              | Type    | Description                                           |
|--------------------|---------|-------------------------------------------------------|
| `ip`               | string  | Client IP address                                     |
| `port`             | number  | Client source port                                    |
| `protocol`         | string  | `plain`, `doh`, `dot`                                 |
| `domain`           | string  | Queried domain name in Unicode (UTF-8)                |
| `domain_ace`       | string  | ACE/Punycode form - present **only** when it differs from `domain` |
| `qtype`            | string  | DNS query type (`A`, `AAAA`, `MX`, ...)                 |
| `qclass`           | string  | DNS query class (`IN`)                                |
| `do_bit`           | boolean | EDNS DNSSEC OK bit set by client                      |
| `edns`             | object  | EDNS0 details (see below)                             |

#### `dns.client.edns`

| Field               | Type    | Description                         |
|---------------------|---------|-------------------------------------|
| `present`           | boolean | Client sent an OPT record           |
| `udp_size`          | number  | Advertised EDNS UDP payload size     |
| `padding_requested` | boolean | Client requested EDNS padding       |

#### `dns.upstream` (array)

One element per upstream server that was queried.

| Field           | Type    | Description                                          |
|-----------------|---------|------------------------------------------------------|
| `index`         | number  | Zero-based upstream index                            |
| `address`       | string  | Upstream address (URL for DoH/DoT, IP:port for plain)|
| `protocol`      | string  | `plain`, `doh`, `dot`                                |
| `duration_ms`   | number  | Query round-trip time in milliseconds                |
| `slow`          | boolean | `true` when `duration_ms` exceeds `slow_upstream_ms` |
| `rcode`         | string  | DNS response code (`NOERROR`, `NXDOMAIN`, ...)       |
| `blocked`       | boolean | Upstream returned a blocked/sink-hole response       |
| `servfail`      | boolean | Upstream returned SERVFAIL or timed out              |
| `dnssec`        | boolean | Response carries DNSSEC data (RRSIG records or AD=1) |
| `resolved_ips`  | array   | Resolved IP addresses in the answer section          |
| `answer_count`  | number  | Number of records in the answer section              |
| `ede_code`      | number  | Extended DNS Error info code (RFC 8914) -- omitted when absent. Common codes: 0=Other, 2=SERVFAIL error, 15=Blocked, 22=No Reachable Authority |
| `ede_text`      | string  | Optional human-readable extra text accompanying the EDE code (omitted when empty) |
| `nsid`          | string  | Name Server Identifier (RFC 5001) -- UTF-8 when decodable, otherwise lowercase hex. Omitted when absent |
| `error`         | string  | Error message when the upstream query failed         |

#### `dns.decision`

| Field           | Type    | Description                                           |
|-----------------|---------|-------------------------------------------------------|
| `blocked`       | boolean | Query was blocked                                     |
| `blocked_by`    | string  | Upstream or list that caused the block                |
| `block_source`  | string  | `upstream`, `local-blacklist`                         |
| `cacheable`     | boolean | Response was eligible for caching                     |
| `all_responded` | boolean | All configured upstreams returned a response          |
| `rcode`         | string  | Final DNS response code returned to the client        |

#### `dns.cache`

| Field                          | Type    | Description                                      |
|--------------------------------|---------|--------------------------------------------------|
| `hit`                          | boolean | Response served from cache                       |
| `ttl_sec`                      | number  | Original TTL of the cached entry (seconds)       |
| `ttl_remaining_sec`            | number  | Remaining TTL at the time of this query          |
| `ttl_remaining_pct`            | number  | `ttl_remaining_sec / ttl_sec * 100`              |
| `blocked`                      | boolean | Cached entry is a blocked response               |
| `whitelisted`                  | boolean | Cached entry was whitelisted                     |
| `background_refresh_triggered` | boolean | A background re-query was queued (stale-while-revalidate) |
| `dnssec`                       | boolean | Cached entry includes DNSSEC records             |

#### `dns.response`

The authoritative record of what was returned to the client. Present for all
`dns_query` events regardless of how the answer was produced.

| Field             | Type    | Description                                                         |
|-------------------|---------|---------------------------------------------------------------------|
| `rcode`           | string  | DNS response code sent to the client (`NOERROR`, `NXDOMAIN`, ...)  |
| `answer_count`    | number  | Number of records in the answer section (omitted when 0)            |
| `ips`             | array   | IP addresses from A/AAAA records in the answer -- present only for address queries with at least one resolved address |
| `truncated`       | boolean | `true` when the TC bit was set -- client should retry over TCP (omitted when false) |
| `ad`              | boolean | Authentic Data bit -- DNSSEC validation succeeded (RFC 4035); omitted when false |
| `rrsig`           | boolean | Response contains at least one RRSIG record in Answer or Authority; omitted when false |
| `ede_code`        | number  | Extended DNS Error info code (RFC 8914) in the response to the client -- omitted when absent |
| `ede_text`        | string  | Optional extra text accompanying the EDE code (omitted when empty)  |
| `authority_count` | number  | Number of records in the Authority section (omitted when 0) -- non-zero for NXDOMAIN responses that include a SOA record |

**Why `response` alongside `upstream[].resolved_ips`?**

`upstream[].resolved_ips` shows what each individual upstream returned in a
fan-out. `dns.response.ips` shows what the client received. These differ when:
- The answer came from cache (no `upstream` array at all)
- Multiple upstreams were queried and only the best response was forwarded
- A block decision replaced the upstream answer with a sinkhole or NXDOMAIN

---

## JSON examples

> Each event is written as a single line in actual log output (NDJSON).
> The `dns_query` examples below are formatted across multiple lines for
> readability.

### Startup banner and general messages

When `log_level_stdout = "json"`, the startup banner is emitted as individual
JSON events instead of plain text, keeping stdout as valid JSON from the first
line. A JSON parser or log aggregator will receive well-formed JSON throughout.

```
{"timestamp":"2025-07-01T14:30:00.000000001Z","level":"INFO","type":"general","module":"server","message":"DNSieve - DNS Filtering Proxy - 1.2.0.1012 (afeb8f3)"}
{"timestamp":"2025-07-01T14:30:00.000000002Z","level":"INFO","type":"general","module":"server","message":"Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)"}
{"timestamp":"2025-07-01T14:30:00.000000003Z","level":"INFO","type":"general","module":"server","message":"https://github.com/secu-tools/dnsieve"}
{"timestamp":"2025-07-01T14:30:00.000000004Z","level":"INFO","type":"general","module":"server","message":"Plain DNS (UDP) listening on 127.0.0.1:5353"}
```

In text mode, the banner is printed to stderr before any log output.

### Successful DNS query (resolved via upstream)

```json
{
  "timestamp": "2025-07-01T14:30:12.123456789Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "example.com. A -> rcode=NOERROR",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54321,
      "protocol": "plain",
      "domain": "example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": true,
        "udp_size": 4096,
        "padding_requested": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "protocol": "doh",
        "duration_ms": 45,
        "slow": false,
        "rcode": "NOERROR",
        "blocked": false,
        "servfail": false,
        "dnssec": false,
        "resolved_ips": ["1.2.3.4"],
        "answer_count": 1
      }
    ],
    "decision": {
      "blocked": false,
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 1,
      "ips": ["1.2.3.4"]
    }
  }
}
```

### Cache hit

```json
{
  "timestamp": "2025-07-01T14:30:13.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "example.com. A -> cache hit",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54322,
      "protocol": "plain",
      "domain": "example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": true,
        "udp_size": 4096,
        "padding_requested": false
      }
    },
    "cache": {
      "hit": true,
      "ttl_sec": 300,
      "ttl_remaining_sec": 247,
      "ttl_remaining_pct": 82.33,
      "blocked": false,
      "whitelisted": false,
      "background_refresh_triggered": false,
      "dnssec": false
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 1,
      "ips": ["1.2.3.4"]
    }
  }
}
```

### Blocked domain (upstream block)

EDE code 15 (Blocked, RFC 8914) is included in both the upstream result and
the response sent to the client.

```json
{
  "timestamp": "2025-07-01T14:30:14.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "evil.example.com. A -> blocked",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54323,
      "protocol": "plain",
      "domain": "evil.example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "protocol": "doh",
        "duration_ms": 38,
        "rcode": "NOERROR",
        "blocked": true,
        "dnssec": false,
        "answer_count": 1,
        "ede_code": 15,
        "ede_text": "Blocked"
      }
    ],
    "decision": {
      "blocked": true,
      "blocked_by": "https://dns.quad9.net/dns-query",
      "block_source": "upstream",
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR",
      "ede_code": 15,
      "ede_text": "Blocked (dns.quad9.net)"
    }
  }
}
```

### Blocked domain (local blacklist)

```json
{
  "timestamp": "2025-07-01T14:30:15.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "tracker.example.com. A -> local blacklist",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54324,
      "protocol": "plain",
      "domain": "tracker.example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": false
      }
    },
    "decision": {
      "blocked": true,
      "blocked_by": "local-blacklist",
      "block_source": "local-blacklist",
      "cacheable": false,
      "all_responded": false,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR"
    }
  }
}
```

### Slow upstream warning

```json
{
  "timestamp": "2025-07-01T14:30:16.000000001Z",
  "level": "WARN",
  "type": "dns_query",
  "module": "server",
  "message": "example.com. A -> slow upstream",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54325,
      "protocol": "plain",
      "domain": "example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "protocol": "doh",
        "duration_ms": 1807,
        "slow": true,
        "rcode": "NOERROR",
        "blocked": false,
        "servfail": false,
        "dnssec": false,
        "resolved_ips": ["1.2.3.4"],
        "answer_count": 1
      }
    ],
    "decision": {
      "blocked": false,
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 1,
      "ips": ["1.2.3.4"]
    }
  }
}
```

### Upstream error (SERVFAIL)

```json
{
  "timestamp": "2025-07-01T14:30:17.000000001Z",
  "level": "WARN",
  "type": "dns_query",
  "module": "server",
  "message": "fail.example.com. A -> SERVFAIL",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54326,
      "protocol": "plain",
      "domain": "fail.example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "protocol": "doh",
        "duration_ms": 5001,
        "slow": true,
        "rcode": "SERVFAIL",
        "blocked": false,
        "servfail": true,
        "dnssec": false,
        "error": "context deadline exceeded"
      }
    ],
    "decision": {
      "blocked": false,
      "cacheable": false,
      "all_responded": false,
      "rcode": "SERVFAIL"
    },
    "response": {
      "rcode": "SERVFAIL"
    }
  }
}
```

### DNSSEC-validated response

When the upstream returns a DNSSEC-validated response, `ad` is set in
`dns.response`. `rrsig` is set when RRSIG records are present in the
answer or authority section. The client must have set the DO bit to receive
RRSIG records. NSID is included when the upstream returns a Name Server
Identifier option (RFC 5001).

```json
{
  "timestamp": "2025-07-01T14:30:19.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "secure.example.com. A -> rcode=NOERROR",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54328,
      "protocol": "plain",
      "domain": "secure.example.com.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": true,
      "edns": {
        "present": true,
        "udp_size": 4096
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "protocol": "doh",
        "duration_ms": 52,
        "rcode": "NOERROR",
        "dnssec": true,
        "resolved_ips": ["93.184.216.34"],
        "answer_count": 2,
        "nsid": "ns1.quad9.net"
      }
    ],
    "decision": {
      "blocked": false,
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 2,
      "ips": ["93.184.216.34"],
      "ad": true,
      "rrsig": true
    }
  }
}
```

### Internationalized domain name (IDN)

When the queried domain contains non-ASCII characters, `domain` contains the
Unicode form and `domain_ace` contains the Punycode form. For ASCII-only
domains `domain_ace` is omitted.

```json
{
  "timestamp": "2025-07-01T14:30:18.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "xn--fiq228c.example. A -> rcode=NOERROR",
  "dns": {
    "client": {
      "ip": "192.168.1.10",
      "port": 54327,
      "protocol": "plain",
      "domain": "Chinese-chars.example.",
      "domain_ace": "xn--fiq228c.example.",
      "qtype": "A",
      "qclass": "IN",
      "do_bit": false,
      "edns": {
        "present": false
      }
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 1,
      "ips": ["1.2.3.4"]
    }
  }
}
```

---

## Use with log aggregators

Because each line is a self-contained JSON object you can feed the log
directly into any log aggregator that understands newline-delimited JSON
(NDJSON).

**Grafana Loki** (`promtail` pipeline example):

```yaml
pipeline_stages:
  - json:
      expressions:
        level: level
        type: type
  - labels:
      level:
      type:
```

**Elasticsearch / Filebeat** (`filebeat.yml` input):

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/dnsieve/*.log
    json.keys_under_root: true
    json.add_error_key: true
```

**Splunk** (HEC JSON source type): set the source type to `_json` and Splunk
will automatically index all top-level fields including the nested `dns` object.

