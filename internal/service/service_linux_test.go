// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package service

import "testing"

func TestPathUnderTmp(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/tmp", true},
		{"/tmp/dnsieve", true},
		{"/tmp/dnsieve/smoke_1/dnsieve", true},
		{"/etc/dnsieve", false},
		{"/var/log/dnsieve", false},
		{"/usr/local/bin/dnsieve", false},
		// Edge case: path that shares a prefix but is not under /tmp.
		{"/tmpfiles/dnsieve", false},
	}
	for _, tt := range tests {
		got := pathUnderTmp(tt.path)
		if got != tt.want {
			t.Errorf("pathUnderTmp(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathUnderHome(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/home/alice/dnsieve", true},
		{"/home/alice", true},
		{"/root", true},
		{"/root/config", true},
		{"/run/user/1000/dnsieve", true},
		{"/etc/dnsieve", false},
		{"/var/log/dnsieve", false},
		{"/usr/local/bin/dnsieve", false},
		{"/tmp/dnsieve", false},
		// Edge cases: paths that share a prefix but are not under home.
		{"/homes/dnsieve", false},
		{"/rootdir/config", false},
	}
	for _, tt := range tests {
		got := pathUnderHome(tt.path)
		if got != tt.want {
			t.Errorf("pathUnderHome(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
