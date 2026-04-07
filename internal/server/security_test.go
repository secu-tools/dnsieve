// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/logging"
)

// TestReadDOHWireQuery_POST_BodyLimit verifies oversized POST payloads are
// bounded by the configured reader limit.
func TestReadDOHWireQuery_POST_BodyLimit(t *testing.T) {
	body := bytes.Repeat([]byte{0x41}, 70000)
	r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/dns-message")

	wire, status, msg := readDOHWireQuery(r)
	if status != http.StatusOK {
		t.Fatalf("status=%d msg=%q, want 200", status, msg)
	}
	if len(wire) != 65535 {
		t.Errorf("wire length=%d, want 65535 limit", len(wire))
	}
}

// TestParseQueryType_Bounds verifies numeric and named query types are parsed
// safely, including out-of-range values.
func TestParseQueryType_Bounds(t *testing.T) {
	tests := []struct {
		in   string
		want uint16
	}{
		{"A", dns.TypeA},
		{"AAAA", dns.TypeAAAA},
		{"65", 65},
		{"65535", 65535},
		{"70000", 0},
		{"not-a-type", 0},
	}

	for _, tc := range tests {
		got := parseQueryType(tc.in)
		if got != tc.want {
			t.Errorf("parseQueryType(%q)=%d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestBuildQueryFromJSONParams_InvalidType ensures invalid type values are
// rejected with a client error.
func TestBuildQueryFromJSONParams_InvalidType(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=not-a-valid-type", nil)
	_, status, _ := buildQueryFromJSONParams(r)
	if status != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", status)
	}
}

// TestBuildQueryFromJSONParams_CommandLikeInput ensures command-like strings
// are treated as plain data and handled without panics.
func TestBuildQueryFromJSONParams_CommandLikeInput(t *testing.T) {
	v := url.Values{}
	v.Set("name", "cmd-rm-rf.example.com")
	v.Set("type", "A")
	r := httptest.NewRequest(http.MethodGet, "/dns-query?"+v.Encode(), nil)

	wire, status, msg := buildQueryFromJSONParams(r)
	if status != http.StatusOK {
		t.Fatalf("status=%d msg=%q, want 200", status, msg)
	}

	resp := new(dns.Msg)
	resp.Data = wire
	if err := resp.Unpack(); err != nil {
		t.Fatalf("built JSON query should be unpackable: %v", err)
	}
}

// TestDohHandler_InvalidDNSWireReturnsBadRequest verifies malformed wire
// payloads are rejected with 400 and do not cause internal errors.
func TestDohHandler_InvalidDNSWireReturnsBadRequest(t *testing.T) {
	h := newTestHandler(t, nil)
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test")

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{0x01, 0x02, 0x03}))
	req.Header.Set("Content-Type", "application/dns-message")
	w := httptest.NewRecorder()

	dohHandler(w, req, h, logger)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
}
