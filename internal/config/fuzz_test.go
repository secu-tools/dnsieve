// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

// FuzzConfigParse fuzz-tests TOML config parsing, defaults application,
// and validation to ensure no panics on arbitrary input.
func FuzzConfigParse(f *testing.F) {
	// Seed with valid default config
	f.Add(DefaultConfigContent())

	// Seed with minimal valid config
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
`)

	// Seed with empty
	f.Add("")

	// Seed with invalid TOML
	f.Add("[[[[garbage")

	// Seed with renew_percent values
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
[cache]
enabled = true
renew_percent = 50
`)
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
[cache]
renew_percent = 0
`)
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
[cache]
renew_percent = 100
`)

	// Seed with invalid log level
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
[logging]
log_level = "verbose"
`)

	// Seed with all sections
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
verify_certificates = false

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 100
verify_certificates = true
bootstrap_dns = "9.9.9.9:53"

[tls]
cert_file = "/etc/ssl/cert.pem"
key_file = "/etc/ssl/key.pem"

[downstream.plain]
enabled = true
port = 53

[downstream.dot]
enabled = true
port = 853

[downstream.doh]
enabled = true
port = 443

[cache]
enabled = true
max_entries = 5000
renew_percent = 10

[logging]
log_level = "debug"
slow_upstream_ms = 100
`)

	// Seed with extreme values to exercise validation
	f.Add(`
[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"
[cache]
renew_percent = -1
max_entries = -100
blocked_ttl = -1
min_ttl = -1
[logging]
slow_upstream_ms = -50
log_max_size_mb = -1
[downstream.plain]
enabled = true
port = 99999
`)

	f.Fuzz(func(t *testing.T, data string) {
		if t.Context().Err() != nil {
			return
		}
		cfg := DefaultConfig()
		err := toml.Unmarshal([]byte(data), cfg)
		if err != nil {
			// Invalid TOML is fine, just don't panic
			return
		}

		// Apply defaults and validate -- should never panic
		applyDefaults(cfg)
		_, _ = cfg.Validate()
	})
}
