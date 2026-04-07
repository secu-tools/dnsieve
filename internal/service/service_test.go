// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package service

import (
	"testing"
)

func TestServiceName_Default(t *testing.T) {
	cfg := &ServiceConfig{}
	if got := cfg.ServiceName(); got != "dnsieve" {
		t.Errorf("ServiceName() = %q, want %q", got, "dnsieve")
	}
}

func TestServiceName_WithLabel(t *testing.T) {
	cfg := &ServiceConfig{DisplayLabel: "home"}
	if got := cfg.ServiceName(); got != "dnsieve_home" {
		t.Errorf("ServiceName() = %q, want %q", got, "dnsieve_home")
	}
}

func TestDisplayName_Default(t *testing.T) {
	cfg := &ServiceConfig{}
	if got := cfg.DisplayName(); got != "DNSieve DNS Filtering Proxy" {
		t.Errorf("DisplayName() = %q, want %q", got, "DNSieve DNS Filtering Proxy")
	}
}

func TestDisplayName_WithLabel(t *testing.T) {
	cfg := &ServiceConfig{DisplayLabel: "office"}
	expected := "DNSieve DNS Filtering Proxy (office)"
	if got := cfg.DisplayName(); got != expected {
		t.Errorf("DisplayName() = %q, want %q", got, expected)
	}
}

func TestServerArgs_Empty(t *testing.T) {
	cfg := &ServiceConfig{}
	args := cfg.ServerArgs()
	if len(args) != 0 {
		t.Errorf("ServerArgs() = %v, want empty", args)
	}
}

func TestServerArgs_CfgFileOnly(t *testing.T) {
	cfg := &ServiceConfig{CfgFile: "/etc/dnsieve/config.toml"}
	args := cfg.ServerArgs()
	if len(args) != 2 || args[0] != "--cfgfile" || args[1] != "/etc/dnsieve/config.toml" {
		t.Errorf("ServerArgs() = %v, want [--cfgfile /etc/dnsieve/config.toml]", args)
	}
}

func TestServerArgs_LogDirOnly(t *testing.T) {
	cfg := &ServiceConfig{LogDir: "/var/log/dnsieve"}
	args := cfg.ServerArgs()
	if len(args) != 2 || args[0] != "--logdir" || args[1] != "/var/log/dnsieve" {
		t.Errorf("ServerArgs() = %v, want [--logdir /var/log/dnsieve]", args)
	}
}

func TestServerArgs_Both(t *testing.T) {
	cfg := &ServiceConfig{
		CfgFile: "/etc/dnsieve/config.toml",
		LogDir:  "/var/log/dnsieve",
	}
	args := cfg.ServerArgs()
	if len(args) != 4 {
		t.Fatalf("ServerArgs() len = %d, want 4", len(args))
	}
	if args[0] != "--cfgfile" || args[1] != "/etc/dnsieve/config.toml" {
		t.Errorf("unexpected cfgfile args: %v", args[:2])
	}
	if args[2] != "--logdir" || args[3] != "/var/log/dnsieve" {
		t.Errorf("unexpected logdir args: %v", args[2:])
	}
}

func TestSanitizeServiceLabel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"home", "home"},
		{"my-server", "my-server"},
		{"my_server_01", "my_server_01"},
		{"has spaces", "has_spaces"},
		{"special!@#$chars", "special____chars"},
		{"", "default"},
		{"  trimmed  ", "trimmed"},
		{"non-ascii-unicode", "non-ascii-unicode"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeServiceLabel(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeServiceLabel(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestResolveExePath_WithExplicitPath(t *testing.T) {
	cfg := &ServiceConfig{ExePath: "/usr/local/bin/dnsieve"}
	got, err := cfg.resolveExePath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/usr/local/bin/dnsieve" {
		t.Errorf("resolveExePath() = %q, want %q", got, "/usr/local/bin/dnsieve")
	}
}

func TestResolveExePath_AutoDetect(t *testing.T) {
	cfg := &ServiceConfig{}
	got, err := cfg.resolveExePath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Error("resolveExePath() returned empty string")
	}
}
