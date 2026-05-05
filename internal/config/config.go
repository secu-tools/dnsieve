// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

// Package config provides TOML configuration loading with platform-aware
// defaults for DNSieve.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

// UpstreamServer defines a single upstream DNS server.
type UpstreamServer struct {
	Address            string `toml:"address"`
	Protocol           string `toml:"protocol"` // "doh", "dot", "udp"
	VerifyCertificates *bool  `toml:"verify_certificates,omitempty"`
}

// ShouldVerifyCert returns whether this upstream should verify TLS certs.
// If not explicitly set, falls back to the global setting.
func (u *UpstreamServer) ShouldVerifyCert(globalDefault bool) bool {
	if u.VerifyCertificates != nil {
		return *u.VerifyCertificates
	}
	return globalDefault
}

// UpstreamSettings holds settings for upstream resolution.
type UpstreamSettings struct {
	TimeoutMS          int    `toml:"timeout_ms"`
	MinWaitMS          int    `toml:"min_wait_ms"`
	VerifyCertificates bool   `toml:"verify_certificates"`
	BootstrapDNS       string `toml:"bootstrap_dns"`
	// BootstrapIPFamily controls which address family the bootstrap DNS
	// resolver queries when resolving upstream hostnames.
	// "auto" races A and AAAA and uses whichever responds first (RFC 6555).
	// "ipv4" queries only A records; use on IPv4-only hosts.
	// "ipv6" queries only AAAA records; use on IPv6-only hosts.
	BootstrapIPFamily string `toml:"bootstrap_ip_family"`
	// UpstreamTTL controls periodic re-resolution of upstream
	// hostnames after the initial startup resolution.
	//
	//  -1 (default): disabled. The hostname is resolved once at startup
	//               and never again. This matches the behaviour of most
	//               DNS proxy software.
	//   0:           TTL-based. The resolved IP is reused for the full
	//               lifetime of the DNS record TTL. When a new connection
	//               must be established after the TTL has expired the
	//               hostname is re-resolved via bootstrap DNS. A background
	//               refresh is triggered proactively when cache.renew_percent
	//               of the TTL remains so the new address is usually ready
	//               before the old one expires. A minimum floor of 30 s
	//               applies to avoid hammering the bootstrap server.
	//   1-2147483647: fixed interval in seconds. The resolved IP is
	//               refreshed at most once per interval. The refresh
	//               only happens when a new connection is being established
	//               (no existing connections are closed). A background
	//               refresh is started when cache.renew_percent of the
	//               interval remains so the address is ready before expiry.
	//
	// The background refresh threshold is controlled by cache.renew_percent
	// (default 10). Re-resolution uses the same bootstrap_dns and
	// bootstrap_ip_family settings as the initial startup resolution.
	UpstreamTTL int `toml:"upstream_ttl"`
}

// TLSConfig holds shared TLS certificate settings used by both DoT and DoH
// downstream listeners when they require TLS.
type TLSConfig struct {
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	CertBase64 string `toml:"cert_base64"`
	KeyBase64  string `toml:"key_base64"`
}

// HasCert reports whether any TLS certificate source is configured.
func (t *TLSConfig) HasCert() bool {
	return (t.CertFile != "" && t.KeyFile != "") || (t.CertBase64 != "" && t.KeyBase64 != "")
}

// DownstreamPlain configures the plain DNS (UDP/TCP) listener.
type DownstreamPlain struct {
	Enabled         bool     `toml:"enabled"`
	ListenAddresses []string `toml:"listen_addresses"`
	Port            int      `toml:"port"`
}

// DownstreamDoT configures the DNS-over-TLS listener.
type DownstreamDoT struct {
	Enabled         bool     `toml:"enabled"`
	ListenAddresses []string `toml:"listen_addresses"`
	Port            int      `toml:"port"`
}

// DownstreamDoH configures the DNS-over-HTTPS listener.
type DownstreamDoH struct {
	Enabled          bool     `toml:"enabled"`
	ListenAddresses  []string `toml:"listen_addresses"`
	Port             int      `toml:"port"`
	UsePlaintextHTTP bool     `toml:"use_plaintext_http"`
}

// Downstream groups all client-facing listener configurations.
type Downstream struct {
	Plain DownstreamPlain `toml:"plain"`
	DoT   DownstreamDoT   `toml:"dot"`
	DoH   DownstreamDoH   `toml:"doh"`
}

// CacheConfig holds cache settings.
type CacheConfig struct {
	Enabled    bool `toml:"enabled"`
	MaxEntries int  `toml:"max_entries"`
	BlockedTTL int  `toml:"blocked_ttl"`
	MinTTL     int  `toml:"min_ttl"`
	// RenewPercent is the percentage of a cached entry's remaining TTL below
	// which a background refresh is triggered on the next client request.
	// It also controls when the upstream hostname resolver triggers a
	// background re-resolution (see upstream_settings.upstream_ttl).
	// 0 disables background refresh. Valid range: 0-99. Default: 10.
	RenewPercent int `toml:"renew_percent"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	LogLevel        string `toml:"log_level"`
	LogMaxSizeMB    int    `toml:"log_max_size_mb"`
	LogMaxBackups   int    `toml:"log_max_backups"`
	LogMaxAgeDays   int    `toml:"log_max_age_days"`
	LogFloodLimitPS int    `toml:"log_flood_limit_ps"`
	SlowUpstreamMS  int    `toml:"slow_upstream_ms"`
}

// WhitelistConfig holds settings for the domain whitelist, which bypasses
// all blocking upstreams and resolves using a dedicated non-blocking resolver.
// Domains are loaded from external list files specified by glob patterns.
//
// List file format (one domain per line):
//   - "example.com"      exact match only (subdomains NOT matched)
//   - "*.example.com"    matches example.com AND all subdomains
//   - Lines starting with # or ! are comments
//   - Hosts-file format auto-detected: "0.0.0.0 domain" or "127.0.0.1 domain"
type WhitelistConfig struct {
	Enabled          bool     `toml:"enabled"`
	ListFiles        []string `toml:"list_files"`
	ListTTL          int      `toml:"list_ttl"`
	ResolverAddress  string   `toml:"resolver_address"`
	ResolverProtocol string   `toml:"resolver_protocol"`
}

// BlacklistConfig holds settings for the domain blacklist, which blocks
// domains locally without querying upstream servers. Blocked domains return
// the same response as upstream-detected blocks (configured via [blocking]).
//
// List file format is identical to whitelist (see WhitelistConfig).
//
// Note: blacklisting is not the primary purpose of this program. It is
// provided for cases where you need to block specific domains that are not
// covered by upstream filtering. Large blocklists are not officially
// supported; consider a dedicated tool like Pi-hole for comprehensive
// DNS-level ad blocking.
type BlacklistConfig struct {
	Enabled   bool     `toml:"enabled"`
	ListFiles []string `toml:"list_files"`
	ListTTL   int      `toml:"list_ttl"`
}

// PrivacyConfig holds privacy-related settings for EDNS0 option handling.
type PrivacyConfig struct {
	ECS     ECSConfig     `toml:"ecs"`
	Cookies CookiesConfig `toml:"cookies"`
	NSID    NSIDConfig    `toml:"nsid"`
}

// ECSConfig controls EDNS Client Subnet (RFC 7871) handling.
// Mode options:
//   - "strip"      : Remove ECS from all forwarded queries (best for privacy).
//   - "forward"    : Forward client ECS verbatim to upstreams.
//   - "substitute" : Replace client ECS with the configured subnet.
type ECSConfig struct {
	Mode   string `toml:"mode"`
	Subnet string `toml:"subnet"`
}

// CookiesConfig controls DNS Cookie (RFC 7873) handling.
// Mode options:
//   - "strip"       : Remove all cookies from forwarded queries and responses.
//   - "reoriginate" : Maintain per-upstream cookie state. Generate proxy's own
//     client cookie for each upstream. Strip client cookies
//     from downstream.
type CookiesConfig struct {
	Mode string `toml:"mode"`
}

// NSIDConfig controls Name Server Identifier (RFC 5001) handling.
// Mode options:
//   - "strip"      : Remove NSID from forwarded queries.
//   - "forward"    : Forward NSID requests to upstreams verbatim.
//   - "substitute" : Intercept NSID and return the proxy's own identifier.
type NSIDConfig struct {
	Mode  string `toml:"mode"`
	Value string `toml:"value"`
}

// TCPKeepaliveConfig controls TCP keepalive EDNS0 (RFC 7828) timeouts.
type TCPKeepaliveConfig struct {
	ClientTimeoutSec   int `toml:"client_timeout_sec"`
	UpstreamTimeoutSec int `toml:"upstream_timeout_sec"`
}

// BlockingConfig controls how DNSieve responds to clients when an upstream
// DNS server signals that a domain is blocked.
type BlockingConfig struct {
	// Mode selects the DNS response style for blocked domains.
	//
	// Supported modes (following Pi-hole and Technitium conventions):
	//   "null"     - (Default, recommended) NOERROR with 0.0.0.0 for A queries
	//                and :: for AAAA queries. Other query types receive NODATA
	//                (NOERROR with empty answer). Clients see an immediate
	//                connection failure with no timeout. Both Pi-hole and
	//                Technitium recommend this approach.
	//   "nxdomain" - NXDOMAIN with empty answer section. Signals that the
	//                domain does not exist. Some clients retry more aggressively
	//                than with "null" mode.
	//   "nodata"   - NOERROR with empty answer section. Signals that the domain
	//                exists but has no records for the requested type. Better
	//                client acceptance than NXDOMAIN in some environments.
	//   "refused"  - REFUSED with empty answer section. Signals that the server
	//                refuses to answer the query. Caution: some clients may fall
	//                back to another DNS resolver, bypassing the proxy entirely.
	//
	// All modes include Extended DNS Error (EDE) code 15 "Blocked" (RFC 8914)
	// with extra text identifying which upstream service detected the block.
	// Example EDE text: "Blocked (dns.quad9.net)"
	Mode string `toml:"mode"`
}

// DDRConfig controls Discovery of Designated Resolvers (RFC 9461/9462).
type DDRConfig struct {
	Enabled bool `toml:"enabled"`
}

// Config is the top-level DNSieve configuration.
type Config struct {
	Upstream         []UpstreamServer   `toml:"upstream"`
	UpstreamSettings UpstreamSettings   `toml:"upstream_settings"`
	TLS              TLSConfig          `toml:"tls"`
	Downstream       Downstream         `toml:"downstream"`
	Cache            CacheConfig        `toml:"cache"`
	Blocking         BlockingConfig     `toml:"blocking"`
	Logging          LoggingConfig      `toml:"logging"`
	Whitelist        WhitelistConfig    `toml:"whitelist"`
	Blacklist        BlacklistConfig    `toml:"blacklist"`
	Privacy          PrivacyConfig      `toml:"privacy"`
	TCPKeepalive     TCPKeepaliveConfig `toml:"tcp_keepalive"`
	DDR              DDRConfig          `toml:"ddr"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Upstream: []UpstreamServer{
			{Address: "https://dns.quad9.net/dns-query", Protocol: "doh"},
			{Address: "https://security.cloudflare-dns.com/dns-query", Protocol: "doh"},
		},
		UpstreamSettings: UpstreamSettings{
			TimeoutMS:          2000,
			MinWaitMS:          200,
			VerifyCertificates: true,
			BootstrapDNS:       "9.9.9.9:53,149.112.112.112:53",
			BootstrapIPFamily:  "auto",
			UpstreamTTL:        -1,
		},
		Downstream: Downstream{
			Plain: DownstreamPlain{
				Enabled:         true,
				ListenAddresses: []string{"0.0.0.0", "::"},
				Port:            5353,
			},
			DoT: DownstreamDoT{
				Enabled:         false,
				ListenAddresses: []string{"0.0.0.0", "::"},
				Port:            8853,
			},
			DoH: DownstreamDoH{
				Enabled:         false,
				ListenAddresses: []string{"0.0.0.0", "::"},
				Port:            4433,
			},
		},
		Cache: CacheConfig{
			Enabled:      true,
			MaxEntries:   10000,
			BlockedTTL:   86400,
			MinTTL:       60,
			RenewPercent: 10,
		},
		Blocking: BlockingConfig{
			Mode: "null",
		},
		Logging: LoggingConfig{
			LogLevel:        "info",
			LogMaxSizeMB:    10,
			LogMaxBackups:   5,
			LogMaxAgeDays:   30,
			LogFloodLimitPS: 100,
			SlowUpstreamMS:  200,
		},
		Whitelist: WhitelistConfig{
			Enabled:          false,
			ResolverAddress:  "https://1.1.1.1/dns-query",
			ResolverProtocol: "doh",
		},
		Blacklist: BlacklistConfig{
			Enabled: false,
		},
		Privacy: PrivacyConfig{
			ECS: ECSConfig{
				Mode: "strip",
			},
			Cookies: CookiesConfig{
				Mode: "reoriginate",
			},
			NSID: NSIDConfig{
				Mode: "strip",
			},
		},
		TCPKeepalive: TCPKeepaliveConfig{
			ClientTimeoutSec:   120,
			UpstreamTimeoutSec: 120,
		},
		DDR: DDRConfig{
			Enabled: false,
		},
	}
}

// customCfgFile is set via --cfgfile to override the platform default.
var customCfgFile string

// SetConfigFile overrides the default config file path.
func SetConfigFile(path string) {
	customCfgFile = path
}

// ConfigDir returns the platform-appropriate config directory.
// Linux/macOS: /etc/dnsieve/
// Windows:     <exe_dir>/config/
func ConfigDir() string {
	if customCfgFile != "" {
		return filepath.Dir(customCfgFile)
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		return "/etc/dnsieve"
	}
	exe, err := os.Executable()
	if err != nil {
		return "config"
	}
	return filepath.Join(filepath.Dir(exe), "config")
}

// ConfigFilePath returns the platform-appropriate config file path.
// If SetConfigFile was called, returns that override.
// Linux/macOS: /etc/dnsieve/config.toml
// Windows:     <exe_dir>/config/config.toml
func ConfigFilePath() string {
	if customCfgFile != "" {
		return customCfgFile
	}
	return filepath.Join(ConfigDir(), "config.toml")
}

// Load reads the config file at the given path (or the platform default)
// and returns the parsed Config. Missing fields use defaults.
func Load(cfgFile string) (*Config, string, error) {
	if cfgFile != "" {
		SetConfigFile(cfgFile)
	}

	cfg := DefaultConfig()
	path := ConfigFilePath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, path, fmt.Errorf("config file not found: %s", path)
		}
		return nil, path, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, path, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyDefaults(cfg)
	return cfg, path, nil
}

// GenerateDefaultConfig writes the default configuration file to the
// platform-appropriate location. It creates the directory if needed.
// Returns the path where the file was written.
func GenerateDefaultConfig(cfgFile string) (string, error) {
	if cfgFile != "" {
		SetConfigFile(cfgFile)
	}
	path := ConfigFilePath()
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create config directory %s: %w", dir, err)
	}

	if err := os.WriteFile(path, []byte(DefaultConfigContent()), 0644); err != nil {
		return "", fmt.Errorf("write config file %s: %w", path, err)
	}
	return path, nil
}

// ConfigFileExists reports whether the config file exists at the given
// or default path.
func ConfigFileExists(cfgFile string) bool {
	if cfgFile != "" {
		_, err := os.Stat(cfgFile)
		return err == nil
	}
	_, err := os.Stat(ConfigFilePath())
	return err == nil
}

// PromptGenerateConfig asks the user (on stdin) whether to generate a
// default config file at the given path. Returns true if generated.
func PromptGenerateConfig(cfgFile string) bool {
	path := ConfigFilePath()
	if cfgFile != "" {
		path = cfgFile
	}

	fmt.Fprintf(os.Stderr, "Config file not found: %s\n", path)
	fmt.Fprint(os.Stderr, "Would you like to generate a default config file? [Y/n] ")

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer == "" || answer == "y" || answer == "yes" {
			generated, err := GenerateDefaultConfig(cfgFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR | Failed to generate config: %v\n", err)
				return false
			}
			fmt.Fprintf(os.Stderr, "\nDefault config file generated: %s\n", generated)
			fmt.Fprintln(os.Stderr, "Please review and adjust the configuration, then run DNSieve again.")
			return true
		}
	}
	return false
}

// Validate checks config values for common mistakes and returns a list
// of warnings (non-fatal) and errors (fatal). Errors prevent startup.
func (c *Config) Validate() (warnings []string, errors []string) {
	if len(c.Upstream) == 0 {
		errors = append(errors, "no upstream DNS servers configured; add at least one [[upstream]] entry")
	}

	if !c.Downstream.Plain.Enabled && !c.Downstream.DoT.Enabled && !c.Downstream.DoH.Enabled {
		errors = append(errors, "no downstream listeners enabled; enable at least one of: plain, dot, doh")
	}

	w, e := c.validateUpstreams()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateTLS()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateCache()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateLogging()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateDownstreamPorts()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateWhitelist()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateBlacklist()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validateBlocking()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	w, e = c.validatePrivacy()
	warnings = append(warnings, w...)
	errors = append(errors, e...)

	return warnings, errors
}

func (c *Config) validateUpstreams() (warnings []string, errors []string) {
	hasPlainDNS := false
	for i, u := range c.Upstream {
		if u.Address == "" {
			errors = append(errors, fmt.Sprintf("upstream[%d]: address is empty", i))
		}
		if u.VerifyCertificates != nil && !*u.VerifyCertificates {
			warnings = append(warnings, fmt.Sprintf("upstream[%d] %s: TLS certificate verification is disabled, this is insecure", i, u.Address))
		}
		if u.Protocol != "doh" && u.Protocol != "dot" && u.Protocol != "udp" {
			errors = append(errors, fmt.Sprintf("upstream[%d] %s: unsupported protocol %q (use doh, dot, or udp)", i, u.Address, u.Protocol))
		}
		if u.Protocol == "udp" {
			hasPlainDNS = true
		}
	}

	if hasPlainDNS {
		warnings = append(warnings, "Plain DNS (udp) upstream is unencrypted, queries can be intercepted")
	}

	if !c.UpstreamSettings.VerifyCertificates {
		warnings = append(warnings, "Global upstream verify_certificates is disabled, all DoH/DoT upstreams will skip certificate validation")
	}

	if c.UpstreamSettings.TimeoutMS < 100 {
		warnings = append(warnings, fmt.Sprintf("Upstream timeout_ms=%d is very low, consider at least 500ms", c.UpstreamSettings.TimeoutMS))
	}

	if c.UpstreamSettings.MinWaitMS >= c.UpstreamSettings.TimeoutMS && c.UpstreamSettings.MinWaitMS > 0 {
		warnings = append(warnings, fmt.Sprintf("Upstream min_wait_ms=%d >= timeout_ms=%d, block consensus may not work correctly", c.UpstreamSettings.MinWaitMS, c.UpstreamSettings.TimeoutMS))
	}

	if len(c.Upstream) > 3 {
		warnings = append(warnings, fmt.Sprintf("%d upstream servers configured, more than 3 may slow down startup and DNS resolution", len(c.Upstream)))
	}

	switch c.UpstreamSettings.BootstrapIPFamily {
	case "", "auto", "ipv4", "ipv6":
		// valid
	default:
		errors = append(errors, fmt.Sprintf(
			"upstream_settings.bootstrap_ip_family: invalid value %q (must be \"auto\", \"ipv4\", or \"ipv6\")",
			c.UpstreamSettings.BootstrapIPFamily,
		))
	}

	const maxUpstreamTTL = 1<<31 - 1 // math.MaxInt32, prevents Duration overflow
	ri := c.UpstreamSettings.UpstreamTTL
	if ri < -1 {
		errors = append(errors, "upstream_settings.upstream_ttl must be -1 (disabled), 0 (TTL-based), or 1-2147483647 (seconds interval)")
	} else if ri > maxUpstreamTTL {
		errors = append(errors, fmt.Sprintf(
			"upstream_settings.upstream_ttl=%d exceeds maximum %d (approximately 68 years)",
			ri, maxUpstreamTTL,
		))
	}

	return warnings, errors
}

// validateCache checks cache configuration for invalid values.
func (c *Config) validateCache() (warnings []string, errors []string) {
	if c.Cache.RenewPercent < 0 || c.Cache.RenewPercent > 99 {
		errors = append(errors, fmt.Sprintf("cache renew_percent=%d is invalid, must be 0 (disabled) to 99", c.Cache.RenewPercent))
	}
	if c.Cache.MaxEntries < 0 {
		errors = append(errors, fmt.Sprintf("cache max_entries=%d is invalid, must be >= 0", c.Cache.MaxEntries))
	}
	if c.Cache.BlockedTTL < 0 {
		errors = append(errors, fmt.Sprintf("cache blocked_ttl=%d is invalid, must be >= 0", c.Cache.BlockedTTL))
	}
	if c.Cache.MinTTL < 0 {
		errors = append(errors, fmt.Sprintf("cache min_ttl=%d is invalid, must be >= 0", c.Cache.MinTTL))
	}
	return warnings, errors
}

// validateLogging checks logging configuration for invalid values.
func (c *Config) validateLogging() (warnings []string, errors []string) {
	switch c.Logging.LogLevel {
	case "debug", "info", "warn", "error", "":
		// valid; empty is corrected by applyDefaults
	default:
		errors = append(errors, fmt.Sprintf("logging log_level=%q is invalid, must be debug, info, warn, or error", c.Logging.LogLevel))
	}
	if c.Logging.SlowUpstreamMS < 0 {
		warnings = append(warnings, fmt.Sprintf("logging slow_upstream_ms=%d is negative, treated as disabled (0)", c.Logging.SlowUpstreamMS))
	}
	if c.Logging.LogMaxSizeMB < 0 {
		errors = append(errors, fmt.Sprintf("logging log_max_size_mb=%d is invalid, must be >= 0", c.Logging.LogMaxSizeMB))
	}
	return warnings, errors
}

// validateDownstreamPorts checks that listener port numbers and addresses are valid.
func (c *Config) validateDownstreamPorts() (warnings []string, errors []string) {
	const maxPort = 65535
	if c.Downstream.Plain.Enabled {
		if c.Downstream.Plain.Port > maxPort {
			errors = append(errors, fmt.Sprintf("downstream plain port=%d is out of range, must be 1-65535", c.Downstream.Plain.Port))
		}
		if len(c.Downstream.Plain.ListenAddresses) == 0 {
			errors = append(errors, "downstream plain: listen_addresses must contain at least one address")
		}
	}
	if c.Downstream.DoT.Enabled {
		if c.Downstream.DoT.Port > maxPort {
			errors = append(errors, fmt.Sprintf("downstream dot port=%d is out of range, must be 1-65535", c.Downstream.DoT.Port))
		}
		if len(c.Downstream.DoT.ListenAddresses) == 0 {
			errors = append(errors, "downstream dot: listen_addresses must contain at least one address")
		}
	}
	if c.Downstream.DoH.Enabled {
		if c.Downstream.DoH.Port > maxPort {
			errors = append(errors, fmt.Sprintf("downstream doh port=%d is out of range, must be 1-65535", c.Downstream.DoH.Port))
		}
		if len(c.Downstream.DoH.ListenAddresses) == 0 {
			errors = append(errors, "downstream doh: listen_addresses must contain at least one address")
		}
	}
	return warnings, errors
}

func (c *Config) validateTLS() (warnings []string, errors []string) {
	if c.Downstream.DoT.Enabled && !c.TLS.HasCert() {
		errors = append(errors, "Downstream DoT is enabled but no TLS certificate is configured, set [tls] cert_file/key_file or cert_base64/key_base64")
	}

	if c.Downstream.DoH.Enabled && !c.Downstream.DoH.UsePlaintextHTTP && !c.TLS.HasCert() {
		errors = append(errors, "Downstream DoH (HTTPS) is enabled but no TLS certificate is configured, set [tls] section or enable use_plaintext_http for reverse proxy setups")
	}

	if c.Downstream.DoH.Enabled && c.Downstream.DoH.UsePlaintextHTTP {
		warnings = append(warnings, "Downstream DoH is running over plain HTTP without TLS, ensure a reverse proxy handles TLS termination")
	}

	return warnings, errors
}

// validateWhitelist checks whitelist configuration for potential issues.
func (c *Config) validateWhitelist() (warnings []string, errors []string) {
	if !c.Whitelist.Enabled {
		return nil, nil
	}
	if len(c.Whitelist.ListFiles) == 0 {
		warnings = append(warnings, "Whitelist is enabled but list_files is not configured; whitelist will have no effect until list files are specified")
	}
	if c.Whitelist.ListTTL < 0 {
		warnings = append(warnings, fmt.Sprintf("whitelist.list_ttl=%d is negative, treated as disabled (0)", c.Whitelist.ListTTL))
	}
	switch c.Whitelist.ResolverProtocol {
	case "", "doh", "dot", "udp":
		// valid (empty defaults to doh)
	default:
		errors = append(errors, fmt.Sprintf("whitelist.resolver_protocol=%q is invalid, must be doh, dot, or udp", c.Whitelist.ResolverProtocol))
	}
	return warnings, errors
}

// validateBlacklist checks blacklist configuration for potential issues.
func (c *Config) validateBlacklist() (warnings []string, errors []string) {
	if !c.Blacklist.Enabled {
		return nil, nil
	}
	if len(c.Blacklist.ListFiles) == 0 {
		warnings = append(warnings, "Blacklist is enabled but list_files is not configured; blacklist will have no effect until list files are specified")
	}
	if c.Blacklist.ListTTL < 0 {
		warnings = append(warnings, fmt.Sprintf("blacklist.list_ttl=%d is negative, treated as disabled (0)", c.Blacklist.ListTTL))
	}
	return warnings, errors
}

// validateBlocking checks blocking configuration for invalid values.
func (c *Config) validateBlocking() (warnings []string, errors []string) {
	switch c.Blocking.Mode {
	case "null", "nxdomain", "nodata", "refused":
		// valid modes
	case "":
		// empty is corrected by applyDefaults
	default:
		errors = append(errors, fmt.Sprintf("blocking.mode=%q is invalid, must be null, nxdomain, nodata, or refused", c.Blocking.Mode))
	}
	if c.Blocking.Mode == "refused" {
		warnings = append(warnings, "blocking.mode=\"refused\" may cause clients to fall back to another DNS resolver, bypassing the proxy")
	}
	return warnings, errors
}

// validatePrivacy checks privacy and EDNS0 option configuration.
func (c *Config) validatePrivacy() (warnings []string, errors []string) {
	switch c.Privacy.ECS.Mode {
	case "strip", "forward", "substitute":
	default:
		errors = append(errors, fmt.Sprintf("privacy.ecs.mode=%q is invalid, must be strip, forward, or substitute", c.Privacy.ECS.Mode))
	}
	if c.Privacy.ECS.Mode == "substitute" && c.Privacy.ECS.Subnet == "" {
		errors = append(errors, "privacy.ecs.mode is \"substitute\" but no subnet is configured")
	}
	if c.Privacy.ECS.Mode == "forward" {
		warnings = append(warnings, "privacy.ecs.mode=\"forward\" sends client subnet information to upstream servers, which may reduce privacy")
	}

	switch c.Privacy.Cookies.Mode {
	case "strip", "reoriginate":
	default:
		errors = append(errors, fmt.Sprintf("privacy.cookies.mode=%q is invalid, must be strip or reoriginate", c.Privacy.Cookies.Mode))
	}

	switch c.Privacy.NSID.Mode {
	case "strip", "forward", "substitute":
	default:
		errors = append(errors, fmt.Sprintf("privacy.nsid.mode=%q is invalid, must be strip, forward, or substitute", c.Privacy.NSID.Mode))
	}
	if c.Privacy.NSID.Mode == "substitute" && c.Privacy.NSID.Value == "" {
		warnings = append(warnings, "privacy.nsid.mode is \"substitute\" but no value is configured, will return empty NSID")
	}

	if c.TCPKeepalive.ClientTimeoutSec < 0 {
		errors = append(errors, fmt.Sprintf("tcp_keepalive.client_timeout_sec=%d is invalid, must be >= 0", c.TCPKeepalive.ClientTimeoutSec))
	}
	if c.TCPKeepalive.UpstreamTimeoutSec < 0 {
		errors = append(errors, fmt.Sprintf("tcp_keepalive.upstream_timeout_sec=%d is invalid, must be >= 0", c.TCPKeepalive.UpstreamTimeoutSec))
	}

	return warnings, errors
}

// applyDefaults fills in zero-valued fields with sensible defaults.
func applyDefaults(cfg *Config) {
	applyUpstreamDefaults(cfg)
	applyCacheDefaults(cfg)
	applyBlockingDefaults(cfg)
	applyLoggingDefaults(cfg)
	applyDownstreamDefaults(cfg)
	applyWhitelistDefaults(cfg)
	applyPrivacyDefaults(cfg)
	applyTCPKeepaliveDefaults(cfg)
}

func applyUpstreamDefaults(cfg *Config) {
	if cfg.UpstreamSettings.TimeoutMS <= 0 {
		cfg.UpstreamSettings.TimeoutMS = 2000
	}
	if cfg.UpstreamSettings.MinWaitMS <= 0 {
		cfg.UpstreamSettings.MinWaitMS = 200
	}
}

func applyCacheDefaults(cfg *Config) {
	if cfg.Cache.MaxEntries <= 0 {
		cfg.Cache.MaxEntries = 10000
	}
	if cfg.Cache.BlockedTTL <= 0 {
		cfg.Cache.BlockedTTL = 86400
	}
	if cfg.Cache.MinTTL <= 0 {
		cfg.Cache.MinTTL = 60
	}
}

func applyBlockingDefaults(cfg *Config) {
	if cfg.Blocking.Mode == "" {
		cfg.Blocking.Mode = "null"
	}
}

func applyLoggingDefaults(cfg *Config) {
	if cfg.Logging.LogMaxSizeMB <= 0 {
		cfg.Logging.LogMaxSizeMB = 10
	}
	if cfg.Logging.LogMaxBackups <= 0 {
		cfg.Logging.LogMaxBackups = 5
	}
	if cfg.Logging.LogMaxAgeDays <= 0 {
		cfg.Logging.LogMaxAgeDays = 30
	}
	if cfg.Logging.LogLevel == "" {
		cfg.Logging.LogLevel = "info"
	}
}

// defaultListenAddresses is the replacement used when listen_addresses is
// empty or omitted from the config file.
var defaultListenAddresses = []string{"0.0.0.0", "::"} //nolint:gochecknoglobals

func applyDownstreamDefaults(cfg *Config) {
	if len(cfg.Downstream.Plain.ListenAddresses) == 0 {
		cfg.Downstream.Plain.ListenAddresses = defaultListenAddresses
	}
	if cfg.Downstream.Plain.Port <= 0 {
		cfg.Downstream.Plain.Port = 5353
	}
	if len(cfg.Downstream.DoT.ListenAddresses) == 0 {
		cfg.Downstream.DoT.ListenAddresses = defaultListenAddresses
	}
	if cfg.Downstream.DoT.Port <= 0 {
		cfg.Downstream.DoT.Port = 8853
	}
	if len(cfg.Downstream.DoH.ListenAddresses) == 0 {
		cfg.Downstream.DoH.ListenAddresses = defaultListenAddresses
	}
	if cfg.Downstream.DoH.Port <= 0 {
		cfg.Downstream.DoH.Port = 4433
	}
}

func applyWhitelistDefaults(cfg *Config) {
	if cfg.Whitelist.ResolverAddress == "" {
		cfg.Whitelist.ResolverAddress = "https://1.1.1.1/dns-query"
	}
	if cfg.Whitelist.ResolverProtocol == "" {
		cfg.Whitelist.ResolverProtocol = "doh"
	}
}

func applyPrivacyDefaults(cfg *Config) {
	if cfg.Privacy.ECS.Mode == "" {
		cfg.Privacy.ECS.Mode = "strip"
	}
	if cfg.Privacy.Cookies.Mode == "" {
		cfg.Privacy.Cookies.Mode = "reoriginate"
	}
	if cfg.Privacy.NSID.Mode == "" {
		cfg.Privacy.NSID.Mode = "strip"
	}
}

func applyTCPKeepaliveDefaults(cfg *Config) {
	if cfg.TCPKeepalive.ClientTimeoutSec <= 0 {
		cfg.TCPKeepalive.ClientTimeoutSec = 120
	}
	if cfg.TCPKeepalive.UpstreamTimeoutSec <= 0 {
		cfg.TCPKeepalive.UpstreamTimeoutSec = 120
	}
}

// DefaultConfigContent returns the content of the default configuration file
// with detailed documentation comments.
func DefaultConfigContent() string {
	return `# DNSieve - DNS Filtering Proxy Configuration
# See docs/configuration.md for detailed documentation.
#
# Default config location:
#   Linux/macOS: /etc/dnsieve/config.toml
#   Windows:     <exe_dir>/config/config.toml
#   Docker:      /app/config/config.toml
#
# Override with: dnsieve --cfgfile /path/to/config.toml


# =============================================================================
# Upstream DNS Servers
# =============================================================================
# DNSieve queries all configured upstream servers concurrently.
# If ANY upstream signals a domain is blocked, the blocked response is
# returned to the client. Priority order is top-to-bottom (first = highest).
#
# Supported protocols:
#   "doh" - DNS-over-HTTPS (RFC 8484), encrypted
#   "dot" - DNS-over-TLS (RFC 7858), encrypted
#   "udp" - Plain DNS over UDP with TCP fallback, unencrypted
#
# Using more than 3 upstream servers may slow down DNS resolution.
# Per-upstream verify_certificates overrides the global setting.
# Set to false only if you trust the upstream and understand the risk.

[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"

# Examples of additional upstreams:
# [[upstream]]
# address = "https://dns.adguard-dns.com/dns-query"
# protocol = "doh"
#
# [[upstream]]
# address = "dns.quad9.net:853"
# protocol = "dot"
#
# [[upstream]]
# address = "9.9.9.9:53"
# protocol = "udp"
#
# [[upstream]]
# address = "https://some-internal-dns.example.com/dns-query"
# protocol = "doh"
# verify_certificates = false   # Use only for trusted internal servers


# =============================================================================
# Upstream Settings
# =============================================================================

[upstream_settings]
# Timeout for each upstream query in milliseconds.
timeout_ms = 2000

# Minimum time to wait before accepting an early block response.
# This prevents a single fast upstream from dominating before others respond.
min_wait_ms = 200

# Whether to verify TLS certificates for DoH and DoT upstream servers.
# Default: true. Set to false only if you know what you are doing.
verify_certificates = true

# Bootstrap DNS servers used to resolve DoH/DoT hostnames.
# Comma-separated list of IP:port addresses queried in parallel;
# the fastest response wins. Defaults to both Quad9 anycast IPs.
# Set to empty string to use the system resolver instead.
bootstrap_dns = "9.9.9.9:53,149.112.112.112:53"

# Address family used when the bootstrap DNS resolves DoH/DoT hostnames.
# The bootstrap lookup races an A query and a AAAA query (RFC 6555 Happy
# Eyeballs) and connects to whichever responds first. On hosts where one
# address family has no outbound connectivity the wrong address type can
# win, causing every upstream connection to fail.
#
#   "auto" -- race A and AAAA, fastest wins (default; best for dual-stack)
#   "ipv4" -- query only A records  (use on IPv4-only hosts / containers)
#   "ipv6" -- query only AAAA records (use on IPv6-only hosts)
#
# This setting only affects how upstream hostnames are resolved. The
# encrypted DNS traffic itself flows over whatever address is returned.
# Leave as "auto" on dual-stack hosts.
bootstrap_ip_family = "ipv4"

# Controls whether and how often upstream hostnames are re-resolved after
# the initial startup resolution.
#
#   -1   -- Disabled (default). The hostname is resolved once at startup
#            and never again. This is the standard behaviour for DNS proxy
#            software. Use this when your upstreams have stable IPs that
#            rarely or never change.
#
#    0   -- TTL-based. The resolved IP is considered valid for the full TTL
#            of the DNS record returned during resolution. When a new
#            connection must be opened after the TTL expires, the hostname
#            is re-resolved via bootstrap DNS. A background refresh is
#            triggered when cache.renew_percent of the TTL remains (default
#            10%) so the new address is usually ready before the old one
#            expires, avoiding any slowdown on connection setup. A floor of
#            30 seconds is enforced so that very short TTLs do not cause
#            excessive bootstrap queries. No open connections are closed
#            forcibly.
#
#   N>0  -- Fixed interval in seconds (1 to 2147483647). The IP is
#            considered valid for N seconds. Re-resolution happens only
#            when a new connection needs to be established after the
#            interval has elapsed. A background refresh begins when
#            cache.renew_percent of the interval remains (default 10%) to
#            keep the address fresh. No open connections are closed.
#            Minimum sensible value: 60.
#
# All modes reuse the same bootstrap_dns and bootstrap_ip_family settings
# that were active at startup.
upstream_ttl = -1


# =============================================================================
# TLS Certificate (shared by DoT and DoH downstream listeners)
# =============================================================================
# Provide a certificate via file paths or base64-encoded PEM content.
# This certificate is used by both DoT and DoH listeners when TLS is needed.
# DoH can run without a certificate if use_plaintext_http = true (for
# reverse proxy setups like nginx).

[tls]
# cert_file = "/etc/dnsieve/cert.pem"
# key_file = "/etc/dnsieve/key.pem"

# Alternatively, embed certificates directly (base64-encoded PEM):
# cert_base64 = ""
# key_base64 = ""


# =============================================================================
# Downstream Listeners
# =============================================================================

[downstream.plain]
enabled = true
listen_addresses = ["0.0.0.0", "::"]
# Default port is 5353 to avoid requiring elevated privileges.
# Change to 53 for production use (requires root/admin or CAP_NET_BIND_SERVICE).
port = 5353

[downstream.dot]
enabled = false
listen_addresses = ["0.0.0.0", "::"]
# Default port is 8853 to avoid requiring elevated privileges. Standard DoT port is 853.
port = 8853

[downstream.doh]
enabled = false
listen_addresses = ["0.0.0.0", "::"]
# Default port is 4433 to avoid requiring elevated privileges. Standard DoH port is 443.
port = 4433

# Set to true to serve DoH over plain HTTP instead of HTTPS.
# Useful when running behind a reverse proxy (e.g., nginx) that handles TLS.
# No TLS certificate is required when this is enabled.
use_plaintext_http = false


# =============================================================================
# Cache Settings
# =============================================================================
# DNSieve caches DNS responses using an LRU (Least Recently Used) eviction
# policy. Cache TTLs are based on upstream DNS response TTLs.
#
# Memory usage: each cached entry uses approximately 500-1500 bytes depending
# on the DNS response size. Rough estimates:
#   10,000 entries ~ 5-15 MB    (suitable for ~20 users, 30 devices)
#   50,000 entries ~ 25-75 MB   (suitable for ~100 users, 200 devices)
#  100,000 entries ~ 50-150 MB  (suitable for ~500 users, 1000 devices)
#
# For a business with 100 employees on 1 computer each plus ~1900 servers,
# consider 50,000-100,000 entries depending on available memory.

[cache]
enabled = true

# Maximum number of cached entries (LRU eviction when full).
# See memory estimates above to size appropriately for your environment.
max_entries = 10000

# TTL for blocked domain responses in seconds (default: 24 hours).
# Blocked domains are cached aggressively since they rarely change.
blocked_ttl = 86400

# Minimum TTL floor in seconds. If an upstream DNS response has a TTL
# shorter than this value, the minimum TTL is used instead.
# Very short TTLs (under 60s) can cause frequent re-queries and slow
# down DNS resolution. Recommended: 60-300.
min_ttl = 60

# Background cache refresh threshold as a percentage of the entry's total TTL.
# When a client requests a cached entry with less than renew_percent of its TTL
# remaining, DNSieve returns the cached result and quietly re-queries all
# upstream servers in the background. The response is only committed to cache
# if all upstream servers respond and the result is cacheable (same block
# consensus rules apply). If the result is not cacheable, the old entry stays
# until it naturally expires.
# This value also controls when the upstream hostname resolver starts a
# background re-resolution (see upstream_settings.upstream_ttl).
# 0 disables background refresh. Range: 0-99. Default: 10.
renew_percent = 10


# =============================================================================
# Blocking Mode
# =============================================================================
# Controls how DNSieve responds when an upstream DNS server signals that a
# domain is blocked (malware, phishing, tracking, etc.).
#
# Both Pi-hole and Technitium DNS Server recommend "null" mode as the default.
# See docs/configuration.md for a detailed comparison of each mode.
#
# All modes include Extended DNS Error (EDE) code 15 "Blocked" (RFC 8914)
# with extra text identifying which upstream service detected the block.
# Example EDE extra text: "Blocked (dns.quad9.net)"

[blocking]
# Blocking response mode:
#
#   "null"      - (Default, recommended) NOERROR with 0.0.0.0 for A queries
#                 and :: for AAAA queries. Other query types get empty NODATA.
#                 Clients see an immediate connection failure with no timeout.
#                 0.0.0.0 is "this host on this network" (RFC 1122 Section
#                 3.2.1.3). :: is the IPv6 unspecified address (RFC 4291
#                 Section 2.5.2). Connections fail instantly with "connection
#                 refused" -- no HTTP timeout, no retry storm.
#
#   "nxdomain"  - NXDOMAIN with empty answer. Tells clients the domain does
#                 not exist. Some clients retry more aggressively with this
#                 mode compared to "null".
#
#   "nodata"    - NOERROR with empty answer. Tells clients the domain exists
#                 but has no records for the requested type. Better client
#                 acceptance than NXDOMAIN in some environments.
#
#   "refused"   - REFUSED with empty answer. Tells clients the server refuses
#                 the query. WARNING: some clients may fall back to another
#                 DNS resolver, bypassing this proxy entirely.
mode = "null"


# =============================================================================
# Logging
# =============================================================================
# Log output goes to both stdout and a log file.
# Default log file location:
#   Linux/macOS: /var/log/dnsieve/dnsieve.log
#   Windows:     <exe_dir>/log/dnsieve.log
#   Docker:      /app/log/dnsieve.log
#
# Override with: dnsieve --logdir /path/to/logs/

[logging]
# Log level: "debug", "info", "warn", "error"
# "debug" logs individual queries, cache hits/misses, upstream responses,
# block detection details, and protocol-level events.
log_level = "info"

# Maximum log file size in MB before rotation.
log_max_size_mb = 10

# Number of rotated log files to keep.
log_max_backups = 5

# Maximum age of rotated log files in days.
log_max_age_days = 30

# Maximum log lines per second (flood protection, 0 = unlimited).
log_flood_limit_ps = 100

# Threshold in milliseconds for logging slow upstream responses.
# Upstream queries exceeding this duration are logged as warnings.
# Set to 0 to disable slow upstream warnings.
slow_upstream_ms = 200


# =============================================================================
# Whitelist
# =============================================================================
# Domains listed in whitelist files are resolved using a dedicated non-blocking
# resolver (default: Cloudflare 1.1.1.1 DoH) and bypass all blocking upstreams.
# The whitelist is disabled by default.
#
# List file format (one domain per line):
#   "example.com"      - exact match only (subdomains NOT matched)
#   "*.example.com"    - matches example.com AND all subdomains
#   Lines starting with # or ! are comments
#   Hosts-file format auto-detected: "0.0.0.0 domain" or "127.0.0.1 domain"
#
# list_files supports glob patterns (like nginx/ssh conf.d):
#   list_files = ["/etc/dnsieve/whitelist/*.list"]
#   list_files = ["/etc/dnsieve/whitelist/custom.list"]
#
# Windows paths -- use forward slashes or double backslashes inside strings:
#   list_files = ["C:/dnsieve/lists/whitelist.txt"]
#   list_files = ["C:\\dnsieve\\lists\\whitelist.txt"]
#   list_files = ["C:/dnsieve/lists/wl-*.txt"]
#
# list_ttl controls automatic reload (in seconds):
#   0 = disabled (default), no automatic reload
#   >0 = check for file changes every N seconds, reload if modified

[whitelist]
enabled = false

# Glob patterns for whitelist files.
# list_files = ["/etc/dnsieve/whitelist/*.list"]
# list_files = ["C:/dnsieve/lists/whitelist.txt"]   # Windows example
list_files = []

# Automatic reload interval in seconds (0 = disabled).
list_ttl = 0

# The resolver used for whitelisted lookups.
# Default: Cloudflare 1.1.1.1 DoH (does not filter or block).
resolver_address = "https://1.1.1.1/dns-query"
resolver_protocol = "doh"


# =============================================================================
# Blacklist
# =============================================================================
# Domains listed in blacklist files are blocked locally without querying
# upstream servers. The blocked response uses the same mode as [blocking].
# The blacklist is disabled by default.
#
# List file format is identical to whitelist (see above).
#
# Note: blacklisting/whitelisting is not the primary purpose of this program.
# It is provided for cases where you need to block specific domains that your
# upstream filtering does not cover. Large blocklists are not officially
# supported; consider a dedicated tool like Pi-hole for comprehensive
# DNS-level ad blocking.

[blacklist]
enabled = false

# Glob patterns for blacklist files.
# list_files = ["/etc/dnsieve/blacklist/*.list"]
# list_files = ["C:/dnsieve/lists/blacklist.txt"]   # Windows example
list_files = []

# Automatic reload interval in seconds (0 = disabled).
list_ttl = 0


# =============================================================================
# Privacy Settings
# =============================================================================
# Controls how DNSieve handles privacy-sensitive EDNS0 options when proxying
# queries between LAN clients and upstream DNS servers.
#
# Since this proxy sits between your LAN and remote upstream servers, these
# settings help you control what information is leaked to upstreams.

[privacy.ecs]
# EDNS Client Subnet (RFC 7871) handling.
# Controls whether client subnet information is sent to upstream DNS servers.
#
# Options:
#   "strip"      - Remove ECS from all forwarded queries. Best for privacy.
#                  Upstream servers will not receive client location hints.
#                  This is the recommended default for a LAN proxy.
#   "forward"    - Forward client ECS verbatim to upstream servers.
#                  Reduces privacy but may improve CDN routing accuracy.
#   "substitute" - Replace client ECS with a specific subnet you provide.
#                  Useful when you want CDN optimization for a specific
#                  location without revealing individual client addresses.
#
# Default: "strip" (best privacy for LAN-to-remote proxy setups)
mode = "strip"

# Only used when mode = "substitute". Specify a subnet in CIDR notation
# (e.g., "203.0.113.0/24" for IPv4 or "2001:db8::/32" for IPv6).
# subnet = "203.0.113.0/24"

[privacy.cookies]
# DNS Cookies (RFC 7873) handling.
# DNS cookies provide lightweight transaction authentication between
# DNS clients and servers.
#
# Options:
#   "reoriginate"  - Maintain independent cookie state per upstream server.
#                    The proxy generates its own client cookies for each
#                    upstream, processes server cookies independently, and
#                    strips client cookies from downstream responses.
#                    Provides full cookie security between proxy and upstreams.
#   "strip"        - Remove all DNS cookies from forwarded queries and
#                    responses. Upstream servers will not see cookie data.
#
# Default: "reoriginate"
mode = "reoriginate"

[privacy.nsid]
# Name Server Identifier (RFC 5001) handling.
# NSID allows clients to request the identity of the DNS server.
#
# Options:
#   "strip"      - Remove NSID option from forwarded queries.
#                  Upstream servers will not receive NSID requests.
#                  Recommended default for privacy.
#   "forward"    - Forward NSID requests to upstream servers verbatim
#                  and return their NSID responses to clients.
#   "substitute" - Intercept NSID requests and return the proxy's own
#                  identifier (configured below) instead of forwarding.
#
# Default: "strip"
mode = "strip"

# Only used when mode = "substitute". The identifier string to return.
# value = "dnsieve-proxy-01"


# =============================================================================
# TCP Keepalive (RFC 7828)
# =============================================================================
# Controls idle timeout values for TCP/TLS connections.
# The proxy negotiates keepalive independently with clients and upstreams.

[tcp_keepalive]
# Idle timeout advertised to downstream clients (in seconds).
# Clients are told they can keep TCP/TLS connections open for this long.
client_timeout_sec = 120

# Idle timeout used when connecting to upstream servers (in seconds).
upstream_timeout_sec = 120


# =============================================================================
# Discovery of Designated Resolvers (RFC 9461 / RFC 9462)
# =============================================================================
# When enabled, the proxy responds to _dns.resolver.arpa SVCB queries
# with its own DoT/DoH endpoints, allowing clients to discover and
# upgrade to encrypted DNS automatically.

[ddr]
enabled = false
`
}
