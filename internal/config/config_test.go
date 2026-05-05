// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if len(cfg.Upstream) != 2 {
		t.Errorf("expected 2 default upstream servers, got %d", len(cfg.Upstream))
	}

	if cfg.UpstreamSettings.TimeoutMS != 2000 {
		t.Errorf("expected default timeout 2000ms, got %d", cfg.UpstreamSettings.TimeoutMS)
	}

	if cfg.UpstreamSettings.MinWaitMS != 200 {
		t.Errorf("expected default min_wait 200ms, got %d", cfg.UpstreamSettings.MinWaitMS)
	}

	if !cfg.UpstreamSettings.VerifyCertificates {
		t.Error("verify_certificates should default to true")
	}

	if !cfg.Downstream.Plain.Enabled {
		t.Error("plain DNS should be enabled by default")
	}

	if cfg.Downstream.Plain.Port != 5353 {
		t.Errorf("expected plain DNS port 5353, got %d", cfg.Downstream.Plain.Port)
	}

	if cfg.Downstream.DoT.Enabled {
		t.Error("DoT should be disabled by default")
	}

	if cfg.Downstream.DoH.Enabled {
		t.Error("DoH should be disabled by default")
	}

	// All listeners should default to both IPv4 and IPv6 wildcard addresses.
	wantAddrs := []string{"0.0.0.0", "::"}
	for i, a := range cfg.Downstream.Plain.ListenAddresses {
		if i >= len(wantAddrs) || a != wantAddrs[i] {
			t.Errorf("plain listen_addresses[%d]: want %q got %q", i, wantAddrs[i], a)
		}
	}
	if len(cfg.Downstream.Plain.ListenAddresses) != len(wantAddrs) {
		t.Errorf("plain listen_addresses: want %v got %v", wantAddrs, cfg.Downstream.Plain.ListenAddresses)
	}

	if !cfg.Cache.Enabled {
		t.Error("cache should be enabled by default")
	}

	if cfg.Cache.MaxEntries != 10000 {
		t.Errorf("expected default max_entries 10000, got %d", cfg.Cache.MaxEntries)
	}

	if cfg.Logging.LogLevel != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.Logging.LogLevel)
	}
}

func TestLoad_NoFile_ReturnsError(t *testing.T) {
	// Create a temp dir with no config file
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "nonexistent.toml")

	_, _, err := Load(cfgPath)
	if err == nil {
		t.Fatal("expected error when config file does not exist")
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")

	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 500
verify_certificates = false

[downstream.plain]
enabled = true
listen_addresses = ["127.0.0.1"]
port = 5353

[cache]
enabled = true
max_entries = 5000
blocked_ttl = 43200
min_ttl = 5

[logging]
log_level = "debug"
log_max_size_mb = 20
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, path, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if path != cfgPath {
		t.Errorf("expected path %s, got %s", cfgPath, path)
	}

	if len(cfg.Upstream) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(cfg.Upstream))
	}

	if cfg.Upstream[0].Address != "https://dns.example.com/dns-query" {
		t.Errorf("unexpected address: %s", cfg.Upstream[0].Address)
	}

	if cfg.UpstreamSettings.TimeoutMS != 5000 {
		t.Errorf("expected timeout 5000, got %d", cfg.UpstreamSettings.TimeoutMS)
	}

	if cfg.UpstreamSettings.VerifyCertificates {
		t.Error("verify_certificates should be false")
	}

	if len(cfg.Downstream.Plain.ListenAddresses) != 1 || cfg.Downstream.Plain.ListenAddresses[0] != "127.0.0.1" {
		t.Errorf("expected listen_addresses [127.0.0.1], got %v", cfg.Downstream.Plain.ListenAddresses)
	}

	if cfg.Downstream.Plain.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Downstream.Plain.Port)
	}

	if cfg.Cache.MaxEntries != 5000 {
		t.Errorf("expected 5000 max entries, got %d", cfg.Cache.MaxEntries)
	}

	if cfg.Logging.LogLevel != "debug" {
		t.Errorf("expected debug log level, got %s", cfg.Logging.LogLevel)
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "bad.toml")

	content := `this is not valid toml [[[`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err := Load(cfgPath)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestLoad_PartialConfig_AppliesDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "partial.toml")

	// Only set upstream, leave everything else to defaults
	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Upstream should be the 1 we specified
	if len(cfg.Upstream) != 1 {
		t.Errorf("expected 1 upstream, got %d", len(cfg.Upstream))
	}

	// Everything else should have defaults applied
	if cfg.UpstreamSettings.TimeoutMS != 2000 {
		t.Errorf("timeout should default to 2000, got %d", cfg.UpstreamSettings.TimeoutMS)
	}

	if cfg.Cache.MaxEntries != 10000 {
		t.Errorf("max_entries should default to 10000, got %d", cfg.Cache.MaxEntries)
	}

	if cfg.Logging.LogLevel != "info" {
		t.Errorf("log_level should default to info, got %q", cfg.Logging.LogLevel)
	}
}

func TestApplyDefaults_ZeroValues(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	if cfg.UpstreamSettings.TimeoutMS != 2000 {
		t.Errorf("expected timeout 2000, got %d", cfg.UpstreamSettings.TimeoutMS)
	}
	if cfg.UpstreamSettings.MinWaitMS != 200 {
		t.Errorf("expected min_wait 200, got %d", cfg.UpstreamSettings.MinWaitMS)
	}
	if cfg.Cache.MaxEntries != 10000 {
		t.Errorf("expected max_entries 10000, got %d", cfg.Cache.MaxEntries)
	}
	if cfg.Cache.RenewPercent != 0 {
		t.Errorf("expected renew_percent 0 (disabled) when starting from zero struct, got %d", cfg.Cache.RenewPercent)
	}

	if cfg.Downstream.Plain.Port != 5353 {
		t.Errorf("expected port 5353, got %d", cfg.Downstream.Plain.Port)
	}
}

func TestConfigFilePath_CustomOverride(t *testing.T) {
	// Save and restore
	old := customCfgFile
	defer func() { customCfgFile = old }()

	SetConfigFile("/custom/path/config.toml")
	if got := ConfigFilePath(); got != "/custom/path/config.toml" {
		t.Errorf("expected /custom/path/config.toml, got %s", got)
	}
}

func TestDefaultConfig_RenewPercent(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Cache.RenewPercent != 10 {
		t.Errorf("expected default renew_percent 10, got %d", cfg.Cache.RenewPercent)
	}
}

func TestApplyDefaults_RenewPercent_ZeroPreserved(t *testing.T) {
	cfg := &Config{}
	cfg.Cache.RenewPercent = 0
	applyCacheDefaults(cfg)
	if cfg.Cache.RenewPercent != 0 {
		t.Errorf("applyCacheDefaults: RenewPercent=0 should be preserved (disables refresh), got %d", cfg.Cache.RenewPercent)
	}
}

func TestApplyDefaults_RenewPercent_NonZeroPreserved(t *testing.T) {
	cfg := &Config{}
	cfg.Cache.RenewPercent = 25
	applyCacheDefaults(cfg)
	if cfg.Cache.RenewPercent != 25 {
		t.Errorf("applyCacheDefaults: RenewPercent=25 should be preserved, got %d", cfg.Cache.RenewPercent)
	}
}

func TestDefaultConfig_SlowUpstreamMS(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Logging.SlowUpstreamMS != 200 {
		t.Errorf("expected default slow_upstream_ms 200, got %d", cfg.Logging.SlowUpstreamMS)
	}
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

func TestValidate_OK(t *testing.T) {
	cfg := DefaultConfig()
	warns, errs := cfg.Validate()
	for _, e := range errs {
		t.Errorf("unexpected error: %s", e)
	}
	// Port 5353 and plain DNS might produce a warning -- that is OK
	_ = warns
}

func TestValidate_NoUpstream(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstream = nil
	_, errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if contains(e, "no upstream") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'no upstream' error")
	}
}

func TestValidate_NoListeners(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Downstream.Plain.Enabled = false
	_, errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if contains(e, "no downstream") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'no downstream listeners' error")
	}
}

func TestValidate_CacheRenewPercent_TooHigh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.RenewPercent = 100
	_, errs := cfg.Validate()
	if !hasError(errs, "renew_percent") {
		t.Errorf("expected renew_percent error for value 100, got: %v", errs)
	}
}

func TestValidate_CacheRenewPercent_Negative(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.RenewPercent = -1
	_, errs := cfg.Validate()
	if !hasError(errs, "renew_percent") {
		t.Errorf("expected renew_percent error for value -1, got: %v", errs)
	}
}

func TestValidate_CacheRenewPercent_Zero_IsDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.RenewPercent = 0 // 0 disables background refresh; must be valid
	_, errs := cfg.Validate()
	if hasError(errs, "renew_percent") {
		t.Error("renew_percent=0 should be valid (disables background refresh)")
	}
}

func TestValidate_CacheRenewPercent_BoundaryValues(t *testing.T) {
	tests := []struct {
		value   int
		wantErr bool
	}{
		{0, false},  // disables background refresh
		{1, false},  // minimum
		{25, false}, // mid-range
		{50, false}, // halfway
		{99, false}, // maximum
		{100, true}, // too high
		{-1, true},  // negative
		{200, true}, // way too high
	}
	for _, tc := range tests {
		cfg := DefaultConfig()
		cfg.Cache.RenewPercent = tc.value
		_, errs := cfg.Validate()
		gotErr := hasError(errs, "renew_percent")
		if gotErr != tc.wantErr {
			t.Errorf("renew_percent=%d: wantErr=%v gotErr=%v (errs=%v)", tc.value, tc.wantErr, gotErr, errs)
		}
	}
}

func TestValidate_CacheNegativeMaxEntries(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.MaxEntries = -1
	_, errs := cfg.Validate()
	if !hasError(errs, "max_entries") {
		t.Errorf("expected max_entries error, got: %v", errs)
	}
}

func TestValidate_CacheNegativeBlockedTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.BlockedTTL = -100
	_, errs := cfg.Validate()
	if !hasError(errs, "blocked_ttl") {
		t.Errorf("expected blocked_ttl error, got: %v", errs)
	}
}

func TestValidate_CacheNegativeMinTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cache.MinTTL = -1
	_, errs := cfg.Validate()
	if !hasError(errs, "min_ttl") {
		t.Errorf("expected min_ttl error, got: %v", errs)
	}
}

func TestValidate_LogLevel_Invalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.LogLevel = "verbose"
	_, errs := cfg.Validate()
	if !hasError(errs, "log_level") {
		t.Errorf("expected log_level error for 'verbose', got: %v", errs)
	}
}

func TestValidate_BootstrapIPFamily_Invalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UpstreamSettings.BootstrapIPFamily = "both"
	_, errs := cfg.Validate()
	if !hasError(errs, "bootstrap_ip_family") {
		t.Errorf("expected bootstrap_ip_family error for 'both', got: %v", errs)
	}
}

func TestValidate_BootstrapIPFamily_Valid(t *testing.T) {
	for _, val := range []string{"", "auto", "ipv4", "ipv6"} {
		cfg := DefaultConfig()
		cfg.UpstreamSettings.BootstrapIPFamily = val
		_, errs := cfg.Validate()
		if hasError(errs, "bootstrap_ip_family") {
			t.Errorf("bootstrap_ip_family=%q should be valid, got errors: %v", val, errs)
		}
	}
}

func TestValidate_LogLevel_Valid(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cfg := DefaultConfig()
		cfg.Logging.LogLevel = level
		_, errs := cfg.Validate()
		if hasError(errs, "log_level") {
			t.Errorf("log_level=%q should be valid, got errors: %v", level, errs)
		}
	}
}

func TestValidate_SlowUpstreamMS_Negative_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.SlowUpstreamMS = -50
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "slow_upstream_ms") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected slow_upstream_ms warning for negative value, got: %v", warns)
	}
}

func TestValidate_LogMaxSizeMB_Negative(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.LogMaxSizeMB = -1
	_, errs := cfg.Validate()
	if !hasError(errs, "log_max_size_mb") {
		t.Errorf("expected log_max_size_mb error, got: %v", errs)
	}
}

func TestValidate_DownstreamPort_TooHigh(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(cfg *Config)
		fragment string
	}{
		{"plain port too high", func(c *Config) { c.Downstream.Plain.Port = 70000 }, "plain port"},
		{"dot port too high", func(c *Config) {
			c.Downstream.DoT.Enabled = true
			c.TLS.CertFile = "cert.pem"
			c.TLS.KeyFile = "key.pem"
			c.Downstream.DoT.Port = 99999
		}, "dot port"},
		{"doh port too high", func(c *Config) {
			c.Downstream.DoH.Enabled = true
			c.Downstream.DoH.UsePlaintextHTTP = true
			c.Downstream.DoH.Port = 99999
		}, "doh port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.setup(cfg)
			_, errs := cfg.Validate()
			if !hasError(errs, tc.fragment) {
				t.Errorf("expected port error containing %q, got: %v", tc.fragment, errs)
			}
		})
	}
}

func TestValidate_MinWaitVsTimeout_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UpstreamSettings.TimeoutMS = 500
	cfg.UpstreamSettings.MinWaitMS = 600 // greater than timeout
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "min_wait_ms") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected min_wait_ms warning when >= timeout_ms, got: %v", warns)
	}
}

func TestValidate_EmptyUpstreamAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstream = append(cfg.Upstream, UpstreamServer{Address: "", Protocol: "doh"})
	_, errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if contains(e, "address is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty address error, got: %v", errs)
	}
}

func TestValidate_UnsupportedProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstream = []UpstreamServer{{Address: "9.9.9.9:53", Protocol: "tcp"}}
	_, errs := cfg.Validate()
	if !hasError(errs, "unsupported protocol") {
		t.Errorf("expected unsupported protocol error, got: %v", errs)
	}
}

func TestValidate_PlainDNS_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstream = []UpstreamServer{{Address: "9.9.9.9:53", Protocol: "udp"}}
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "unencrypted") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected plain DNS unencrypted warning, got: %v", warns)
	}
}

func TestValidate_WhitelistNoListFiles_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Whitelist.Enabled = true
	// No list_files configured
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "list_files is not configured") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no list_files warning, got: %v", warns)
	}
}

func TestValidate_WhitelistInvalidProtocol_Error(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{"whitelist.txt"}
	cfg.Whitelist.ResolverProtocol = "grpc"
	_, errs := cfg.Validate()
	found := false
	for _, e := range errs {
		if contains(e, "resolver_protocol") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected resolver_protocol error, got: %v", errs)
	}
}

func TestValidate_WhitelistNegativeListTTL_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Whitelist.Enabled = true
	cfg.Whitelist.ListFiles = []string{"whitelist.txt"}
	cfg.Whitelist.ListTTL = -30
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "list_ttl") && contains(w, "negative") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected negative list_ttl warning, got: %v", warns)
	}
}

func TestValidate_BlacklistNegativeListTTL_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Blacklist.Enabled = true
	cfg.Blacklist.ListFiles = []string{"blacklist.txt"}
	cfg.Blacklist.ListTTL = -5
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "list_ttl") && contains(w, "negative") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected negative list_ttl warning, got: %v", warns)
	}
}

func TestValidate_LowTimeout_Warning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UpstreamSettings.TimeoutMS = 50
	warns, _ := cfg.Validate()
	found := false
	for _, w := range warns {
		if contains(w, "timeout_ms") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected low timeout warning, got: %v", warns)
	}
}

// ---------------------------------------------------------------------------
// Privacy: Cookies default mode
// ---------------------------------------------------------------------------

func TestDefaultConfig_CookiesDefaultIsReoriginate(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Privacy.Cookies.Mode != "reoriginate" {
		t.Errorf("privacy.cookies.mode default = %q, want \"reoriginate\"", cfg.Privacy.Cookies.Mode)
	}
}

func TestDefaultConfigContent_CookiesModeIsReoriginate(t *testing.T) {
	content := DefaultConfigContent()
	// The generated config file must set cookies mode to "reoriginate", not "strip".
	if !strings.Contains(content, "mode = \"reoriginate\"") {
		t.Error("DefaultConfigContent must contain mode = \"reoriginate\" for [privacy.cookies]")
	}
	// Verify the cookies section does not revert to the old "strip" default.
	// Find the [privacy.cookies] section and check the mode line within it.
	cookiesIdx := strings.Index(content, "[privacy.cookies]")
	nsidIdx := strings.Index(content, "[privacy.nsid]")
	if cookiesIdx == -1 || nsidIdx == -1 {
		t.Fatal("DefaultConfigContent missing [privacy.cookies] or [privacy.nsid] section")
	}
	cookiesSection := content[cookiesIdx:nsidIdx]
	if strings.Contains(cookiesSection, "mode = \"strip\"") {
		t.Error("DefaultConfigContent [privacy.cookies] section must not contain mode = \"strip\"")
	}
}

func TestApplyDefaults_CookiesModeReoriginate(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if cfg.Privacy.Cookies.Mode != "reoriginate" {
		t.Errorf("applyDefaults: privacy.cookies.mode = %q, want \"reoriginate\"", cfg.Privacy.Cookies.Mode)
	}
}

func TestApplyDefaults_CookiesMode_ExistingValuePreserved(t *testing.T) {
	cfg := &Config{}
	cfg.Privacy.Cookies.Mode = "strip"
	applyDefaults(cfg)
	if cfg.Privacy.Cookies.Mode != "strip" {
		t.Errorf("applyDefaults should not override existing value, got %q", cfg.Privacy.Cookies.Mode)
	}
}

func TestLoad_NoCookiesSection_DefaultsToReoriginate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "nocookies.toml")

	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Privacy.Cookies.Mode != "reoriginate" {
		t.Errorf("privacy.cookies.mode = %q, want \"reoriginate\" when omitted from config", cfg.Privacy.Cookies.Mode)
	}
}

func TestLoad_ExplicitCookiesModeStrip(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "cookies_strip.toml")

	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"

[privacy.cookies]
mode = "strip"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Privacy.Cookies.Mode != "strip" {
		t.Errorf("privacy.cookies.mode = %q, want \"strip\"", cfg.Privacy.Cookies.Mode)
	}
}

func TestLoad_ExplicitCookiesModeReoriginate(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "cookies_reoriginate.toml")

	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"

[privacy.cookies]
mode = "reoriginate"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.Privacy.Cookies.Mode != "reoriginate" {
		t.Errorf("privacy.cookies.mode = %q, want \"reoriginate\"", cfg.Privacy.Cookies.Mode)
	}
}

func TestValidate_CookiesMode_Invalid(t *testing.T) {
	for _, bad := range []string{"forward", "passthrough", "proxy", ""} {
		cfg := DefaultConfig()
		cfg.Privacy.Cookies.Mode = bad
		_, errs := cfg.Validate()
		if !hasError(errs, "privacy.cookies.mode") {
			t.Errorf("expected validation error for cookies mode %q, got: %v", bad, errs)
		}
	}
}

func TestValidate_CookiesMode_ValidModes(t *testing.T) {
	for _, mode := range []string{"strip", "reoriginate"} {
		cfg := DefaultConfig()
		cfg.Privacy.Cookies.Mode = mode
		_, errs := cfg.Validate()
		if hasError(errs, "privacy.cookies.mode") {
			t.Errorf("cookies mode %q should be valid, got errors: %v", mode, errs)
		}
	}
}

// ---------------------------------------------------------------------------
// upstream_ttl tests
// ---------------------------------------------------------------------------

func TestDefaultConfig_UpstreamTTL_IsMinusOne(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.UpstreamSettings.UpstreamTTL != -1 {
		t.Errorf("default upstream_ttl=%d, want -1 (disabled)",
			cfg.UpstreamSettings.UpstreamTTL)
	}
}

func TestLoad_UpstreamTTL_Disabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"

[upstream_settings]
upstream_ttl = -1
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.UpstreamSettings.UpstreamTTL != -1 {
		t.Errorf("got %d, want -1", cfg.UpstreamSettings.UpstreamTTL)
	}
}

func TestLoad_UpstreamTTL_TTLBased(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"

[upstream_settings]
upstream_ttl = 0
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.UpstreamSettings.UpstreamTTL != 0 {
		t.Errorf("got %d, want 0 (TTL-based)", cfg.UpstreamSettings.UpstreamTTL)
	}
}

func TestLoad_UpstreamTTL_FixedInterval(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"

[upstream_settings]
upstream_ttl = 300
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.UpstreamSettings.UpstreamTTL != 300 {
		t.Errorf("got %d, want 300", cfg.UpstreamSettings.UpstreamTTL)
	}
}

func TestLoad_UpstreamTTL_AbsentUsesDefault(t *testing.T) {
	// When the field is absent from the config file, the DefaultConfig value
	// of -1 (disabled) must be preserved.
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	content := `
[[upstream]]
address = "https://dns.example.com/dns-query"
protocol = "doh"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, _, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.UpstreamSettings.UpstreamTTL != -1 {
		t.Errorf("absent field: got %d, want -1 (default disabled)",
			cfg.UpstreamSettings.UpstreamTTL)
	}
}

func TestValidate_UpstreamTTL_Valid(t *testing.T) {
	tests := []int{-1, 0, 1, 60, 300, 3600, 86400, 1<<31 - 1}
	for _, v := range tests {
		cfg := DefaultConfig()
		cfg.UpstreamSettings.UpstreamTTL = v
		_, errs := cfg.Validate()
		if hasError(errs, "upstream_ttl") {
			t.Errorf("value %d should be valid, got errors: %v", v, errs)
		}
	}
}

func TestValidate_UpstreamTTL_BelowMinus1_IsError(t *testing.T) {
	for _, v := range []int{-2, -100, -1000} {
		cfg := DefaultConfig()
		cfg.UpstreamSettings.UpstreamTTL = v
		_, errs := cfg.Validate()
		if !hasError(errs, "upstream_ttl") {
			t.Errorf("value %d should produce an error but did not", v)
		}
	}
}

func TestValidate_UpstreamTTL_ExceedsMax_IsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UpstreamSettings.UpstreamTTL = 1 << 31 // math.MaxInt32 + 1
	_, errs := cfg.Validate()
	if !hasError(errs, "upstream_ttl") {
		t.Errorf("value exceeding max should produce an error but did not")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

func hasError(errs []string, fragment string) bool {
	for _, e := range errs {
		if contains(e, fragment) {
			return true
		}
	}
	return false
}
