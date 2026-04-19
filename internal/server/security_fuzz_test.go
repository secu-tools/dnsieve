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
)

// FuzzReadDOHWireQueryPOSTLimit fuzzes POST DoH payload handling to ensure
// oversized bodies are bounded and malformed data never causes panics.
func FuzzReadDOHWireQueryPOSTLimit(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add(bytes.Repeat([]byte{0x41}, 1024))
	f.Add(bytes.Repeat([]byte{0x42}, 70000))

	f.Fuzz(func(t *testing.T, body []byte) {
		if t.Context().Err() != nil {
			return
		}
		r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/dns-message")

		wire, status, _ := readDOHWireQuery(r)
		if status == http.StatusOK && len(wire) > 65535 {
			t.Errorf("wire length=%d exceeds DoH body limit", len(wire))
		}
	})
}

// FuzzBuildQueryFromJSONParamsNoPanic fuzzes ?name= and ?type= parsing for the
// DoH JSON API and verifies successful outputs are valid DNS wire messages.
func FuzzBuildQueryFromJSONParamsNoPanic(f *testing.F) {
	f.Add("example.com", "A", "0")
	f.Add("example.com", "AAAA", "1")
	f.Add("_dns.resolver.arpa", "SVCB", "true")
	f.Add("cmd-rm-rf.example.com", "65", "false")
	f.Add("", "A", "0")

	f.Fuzz(func(t *testing.T, name, qtype, doFlag string) {
		if t.Context().Err() != nil {
			return
		}
		vals := url.Values{}
		if name != "" {
			vals.Set("name", name)
		}
		if qtype != "" {
			vals.Set("type", qtype)
		}
		if doFlag != "" {
			vals.Set("do", doFlag)
		}

		r := httptest.NewRequest(http.MethodGet, "/dns-query?"+vals.Encode(), nil)
		wire, status, _ := buildQueryFromJSONParams(r)

		switch status {
		case http.StatusOK, http.StatusBadRequest, http.StatusInternalServerError:
		default:
			t.Errorf("unexpected status=%d", status)
		}

		if status == http.StatusOK {
			msg := new(dns.Msg)
			msg.Data = wire
			if err := msg.Unpack(); err != nil {
				t.Fatalf("successful JSON query build produced invalid wire: %v", err)
			}
		}
	})
}

// FuzzParseQueryType ensures type parsing is robust for arbitrary strings.
func FuzzParseQueryType(f *testing.F) {
	f.Add("A")
	f.Add("AAAA")
	f.Add("SVCB")
	f.Add("65")
	f.Add("65535")
	f.Add("not-a-type")

	f.Fuzz(func(t *testing.T, in string) {
		if t.Context().Err() != nil {
			return
		}
		_ = parseQueryType(in)
	})
}

// FuzzDoHPayloadParsing verifies that arbitrary DoH payload parsing
// safely handles malformed DNS queries and doesn't crash or panic.
// This tests to prevent buffer overflow or remote code execution via
// malformed DNS questions.
func FuzzDoHPayloadParsing(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add(bytes.Repeat([]byte{0x41}, 512))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if t.Context().Err() != nil {
			return
		}
		msg := new(dns.Msg)
		msg.Data = payload
		err := msg.Unpack()
		if err == nil { // Valid message was parsed
			if len(msg.Question) > 0 {
				_ = msg.Question[0].Header().Name
			}
		}
	})
}

// FuzzParseJSONQueryAdvanced injects malicious payloads to simulate mutation
// and remote execution attempts onto the JSON parser
// checking unexpected values logic (empty, excessively large, weird types).
func FuzzParseJSONQueryAdvanced(f *testing.F) {
	f.Add("''''''", "1=1", "DROP TABLE users")
	f.Add("<script>alert(1)</script>", "ANY", "yes")
	f.Add(string(bytes.Repeat([]byte("A"), 8000)), "255", "1")
	f.Add("example.com", "999999", "bool")
	f.Add("example.com", "TXT", "0")
	f.Add("../../../etc/passwd", "A", "true")
	f.Add("; rm -rf /", "MX", "false")
	f.Add("\x00\x00\x00", "\x00", "\x00")

	f.Fuzz(func(t *testing.T, name, qtype, doFlag string) {
		if t.Context().Err() != nil {
			return
		}
		vals := url.Values{}
		if name != "" {
			vals.Set("name", name)
		}
		if qtype != "" {
			vals.Set("type", qtype)
		}
		if doFlag != "" {
			vals.Set("do", doFlag)
		}

		r := httptest.NewRequest(http.MethodGet, "/dns-query?"+vals.Encode(), nil)
		_, status, _ := buildQueryFromJSONParams(r)

		// Expected standard HTTP status codes
		switch status {
		case http.StatusOK, http.StatusBadRequest, http.StatusInternalServerError:
		// success/expected validation rejections
		default:
			t.Errorf("unexpected status=%d on mutation/RCE inputs", status)
		}
	})
}
