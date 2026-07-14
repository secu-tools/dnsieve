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

> **Presence:** `always` = present in every event of this type; `optional` = omitted when false, zero, empty, or not applicable. For boolean fields, absent means `false`.

| Field       | Type   | Presence | Description                                      |
|-------------|--------|----------|--------------------------------------------------|
| `timestamp` | string | always   | RFC 3339 Nano timestamp (UTC)                    |
| `level`     | string | always   | `DEBUG`, `INFO`, `WARN`, `ERROR`                 |
| `type`      | string | always   | `general` or `dns_query`                         |
| `module`    | string | always   | Internal component (`server`, `upstream`, ...)   |
| `message`   | string | always   | Human-readable summary                           |
| `dns`       | object | optional | Per-query structured fields; only for `dns_query` events (see below) |

### `dns` object (`dns_query` events only)

The `dns` object groups all per-query fields. It contains five sub-objects:
`request`, `upstream`, `decision`, `cache`, and `response`.

`response` is populated for all `dns_query` events **except background refresh
events** (see below), and records what the client actually received, regardless
of whether the answer came from an upstream server, the local cache, or a block
decision. The other sub-objects provide context for *how* that answer was
produced.

#### `dns.request`

| Field              | Type    | Presence | Description                                           |
|--------------------|---------|----------|-------------------------------------------------------|
| `ip`               | string  | optional | Client IP address. Absent for background refresh queries. |
| `port`             | number  | optional | Client source port. Absent for background refresh queries. |
| `protocol`         | string  | optional | `plain`, `doh`, `dot`. Absent for background refresh queries. |
| `domain`           | string  | always   | Queried domain name in Punycode/ACE form as it appears in the DNS wire format (e.g. `xn--bcher-kva.example` for an internationalized label). The trailing dot is stripped. |
| `qtype`            | string  | always   | DNS query type (`A`, `AAAA`, `MX`, ...)               |
| `qclass`           | string  | always   | DNS query class (`IN`)                                |
| `do_bit`           | boolean | optional | EDNS DNSSEC OK bit set by client                      |
| `edns`             | object  | always   | EDNS0 details (see below)                             |

#### `dns.request.edns`

| Field               | Type    | Presence | Description                         |
|---------------------|---------|----------|-------------------------------------|
| `present`           | boolean | always   | Client sent an OPT record           |
| `udp_size`          | number  | optional | Advertised EDNS UDP payload size    |
| `padding_requested` | boolean | optional | Client requested EDNS padding       |

#### `dns.upstream` (array)

One element per upstream server that was queried.

| Field           | Type    | Presence | Description                                          |
|-----------------|---------|----------|------------------------------------------------------|
| `index`         | number  | always   | Zero-based upstream index                            |
| `address`       | string  | always   | Upstream server address without port. For DoH, the full URL (explicit port removed if present). For DoT and plain DNS, the hostname or IP. |
| `port`          | number  | optional | Upstream server port number. Common values: 53 (plain DNS), 853 (DoT), 443 (DoH). |
| `protocol`      | string  | optional | `plain`, `doh`, `dot`                                |
| `duration_ms`   | number  | always   | Query round-trip time in milliseconds                |
| `slow`          | boolean | optional | `true` when `duration_ms` exceeds `slow_upstream_ms` |
| `rcode`         | string  | optional | DNS response code (`NOERROR`, `NXDOMAIN`, ...). Absent when the upstream returned an error. |
| `blocked`       | boolean | optional | Upstream returned a blocked/sink-hole response       |
| `servfail`      | boolean | optional | Upstream returned SERVFAIL or timed out              |
| `dnssec`        | boolean | optional | Response carries DNSSEC data (RRSIG records or AD=1) |
| `resolved_ips`  | array   | optional | Resolved IP addresses in the answer section          |
| `answer_count`  | number  | optional | Number of records in the answer section              |
| `ede_code`      | number  | optional | Extended DNS Error info code (RFC 8914). Common codes: 0=Other, 2=SERVFAIL error, 15=Blocked, 22=No Reachable Authority |
| `ede_text`      | string  | optional | Human-readable extra text accompanying the EDE code  |
| `nsid`          | string  | optional | Name Server Identifier (RFC 5001) -- UTF-8 when decodable, otherwise lowercase hex |
| `error`         | string  | optional | Error message when the upstream query failed         |

#### `dns.decision`

| Field           | Type    | Presence | Description                                           |
|-----------------|---------|----------|-------------------------------------------------------|
| `blocked`       | boolean | always   | Query was blocked                                     |
| `block_source`  | string  | optional | `upstream`, `blacklist`, or `whitelist`. Only when `blocked` is `true`. |
| `cacheable`     | boolean | always   | Response was eligible for caching                     |
| `all_responded` | boolean | optional | All configured upstreams returned a response          |
| `rcode`         | string  | always   | Final DNS response code returned to the client        |

#### `dns.cache`

| Field                          | Type    | Presence | Description                                      |
|--------------------------------|---------|----------|--------------------------------------------------|
| `ttl_sec`                      | number  | always   | Original TTL of the cached entry (seconds)       |
| `ttl_remaining_sec`            | number  | always   | Remaining TTL at the time of this query          |
| `ttl_remaining_pct`            | number  | always   | `ttl_remaining_sec / ttl_sec * 100`, rounded to 2 decimal places |
| `blocked`                      | boolean | optional | Cached entry is a blocked response               |
| `whitelisted`                  | boolean | optional | Cached entry was whitelisted                     |
| `background_refresh_triggered` | boolean | optional | A background re-query was queued (stale-while-revalidate) |
| `dnssec`                       | boolean | optional | Cached entry includes DNSSEC records             |

#### `dns.response`

The authoritative record of what was returned to the client. Present for all
`dns_query` events except background refresh queries, regardless of whether the
answer came from upstream, cache, or a local block decision.

| Field             | Type    | Presence | Description                                                         |
|-------------------|---------|----------|---------------------------------------------------------------------|
| `rcode`           | string  | always   | DNS response code sent to the client (`NOERROR`, `NXDOMAIN`, ...)  |
| `answer_count`    | number  | optional | Number of records in the answer section                             |
| `ips`             | array   | optional | IP addresses from A/AAAA records in the answer -- present only for address queries with at least one resolved address |
| `truncated`       | boolean | optional | `true` when the TC bit was set -- client should retry over TCP      |
| `ad`              | boolean | optional | Authentic Data bit -- DNSSEC validation succeeded (RFC 4035)        |
| `rrsig`           | boolean | optional | Response contains at least one RRSIG record in Answer or Authority  |
| `ede_code`        | number  | optional | Extended DNS Error info code (RFC 8914) in the response to the client |
| `ede_text`        | string  | optional | Extra text accompanying the EDE code                                |
| `authority_count` | number  | optional | Number of records in the Authority section. Non-zero for NXDOMAIN responses that include a SOA record |

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
    "request": {
      "ip": "192.168.1.10",
      "port": 54321,
      "protocol": "plain",
      "domain": "example.com",
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
        "port": 443,
        "protocol": "doh",
        "duration_ms": 45,
        "rcode": "NOERROR",
        "blocked": false,
        "dnssec": false,
        "resolved_ips": ["9.9.9.9"],
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
      "ips": ["9.9.9.9"]
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
    "request": {
      "ip": "192.168.1.10",
      "port": 54322,
      "protocol": "plain",
      "domain": "example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": true,
        "udp_size": 4096
      }
    },
    "cache": {
      "ttl_sec": 300,
      "ttl_remaining_sec": 247,
      "ttl_remaining_pct": 82.33
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 1,
      "ips": ["9.9.9.9"]
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
  "message": "evil.example.com. A -> blocked by dns.quad9.net:53",
  "dns": {
    "request": {
      "ip": "192.168.1.10",
      "port": 54323,
      "protocol": "plain",
      "domain": "evil.example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "port": 443,
        "protocol": "doh",
        "duration_ms": 38,
        "rcode": "NOERROR",
        "blocked": true,
        "answer_count": 1,
        "ede_code": 15,
        "ede_text": "Blocked (dns.quad9.net)"
      }
    ],
    "decision": {
      "blocked": true,
      "block_source": "upstream",
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR",
      "ede_code": 15,
      "ede_text": "Blocked (https://dns.quad9.net/dns-query)"
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
  "message": "tracker.example.com. A -> blocked by blacklist",
  "dns": {
    "request": {
      "ip": "192.168.1.10",
      "port": 54324,
      "protocol": "plain",
      "domain": "tracker.example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": false
      }
    },
    "decision": {
      "blocked": true,
      "block_source": "blacklist",
      "cacheable": false,
      "rcode": "NOERROR"
    },
    "response": {
      "rcode": "NOERROR",
      "answer_count": 1,
      "ips": ["0.0.0.0"],
      "ede_code": 15,
      "ede_text": "Blocked (local-blacklist)"
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
    "request": {
      "ip": "192.168.1.10",
      "port": 54325,
      "protocol": "plain",
      "domain": "example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "port": 443,
        "protocol": "doh",
        "duration_ms": 1807,
        "slow": true,
        "rcode": "NOERROR",
        "resolved_ips": ["9.9.9.9"],
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
      "ips": ["9.9.9.9"]
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
    "request": {
      "ip": "192.168.1.10",
      "port": 54326,
      "protocol": "plain",
      "domain": "fail.example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "port": 443,
        "protocol": "doh",
        "duration_ms": 5001,
        "slow": true,
        "servfail": true,
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
    "request": {
      "ip": "192.168.1.10",
      "port": 54328,
      "protocol": "plain",
      "domain": "secure.example.com",
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
        "port": 443,
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

DNSieve always logs the Punycode/ACE form of the domain name as it appears
in the DNS wire format. There is no separate `domain_ace` field.

```json
{
  "timestamp": "2025-07-01T14:30:18.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "xn--fiq228c.example. A -> rcode=NOERROR",
  "dns": {
    "request": {
      "ip": "192.168.1.10",
      "port": 54327,
      "protocol": "plain",
      "domain": "xn--fiq228c.example",
      "qtype": "A",
      "qclass": "IN",
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

### Background refresh upstream query

When `renew_percent > 0`, a near-expiry cache entry is served to the client
and a background goroutine re-queries upstreams to refresh the cache. When
the refresh completes, a `dns_query` event is emitted with the upstream
results and the caching decision.

The `response` field is **absent** -- the client already received their answer
from the cache. The background query only updates the cache for future
requests. The `message` field includes `background-refresh` to distinguish
these events from normal client-driven queries.

The `request` sub-object contains only the domain name and query type; it has
no `ip`, `port`, or `protocol` because there is no associated network
connection.

Example -- successful refresh:

```json
{
  "timestamp": "2025-07-01T14:30:23.500000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "example.com. A -> background-refresh rcode=NOERROR",
  "dns": {
    "request": {
      "domain": "example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "port": 443,
        "protocol": "doh",
        "duration_ms": 31,
        "rcode": "NOERROR",
        "resolved_ips": ["9.9.9.9"],
        "answer_count": 1
      }
    ],
    "decision": {
      "blocked": false,
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
    }
  }
}
```

Example -- domain now blocked after refresh:

```json
{
  "timestamp": "2025-07-01T14:30:24.000000001Z",
  "level": "INFO",
  "type": "dns_query",
  "module": "server",
  "message": "evil.example.com. A -> background-refresh blocked by https://dns.quad9.net/dns-query",
  "dns": {
    "request": {
      "domain": "evil.example.com",
      "qtype": "A",
      "qclass": "IN",
      "edns": {
        "present": false
      }
    },
    "upstream": [
      {
        "index": 0,
        "address": "https://dns.quad9.net/dns-query",
        "port": 443,
        "protocol": "doh",
        "duration_ms": 29,
        "rcode": "NOERROR",
        "blocked": true,
        "ede_code": 15,
        "ede_text": "Blocked (dns.quad9.net)"
      }
    ],
    "decision": {
      "blocked": true,
      "block_source": "upstream",
      "cacheable": true,
      "all_responded": true,
      "rcode": "NOERROR"
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

