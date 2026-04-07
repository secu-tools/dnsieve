// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

// ============================================================
// Protocol: Plain DNS (UDP + TCP) -- RFC 1035
// ============================================================

// TestE2E_PlainDNS_UDP_A verifies basic A query resolution over UDP.
func TestE2E_PlainDNS_UDP_A(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP A: rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("UDP A: expected at least one answer")
	}
	if !resp.RecursionAvailable {
		t.Error("RFC 1035: RA bit must be set by a recursive server")
	}
	if len(resp.Question) == 0 || !strings.EqualFold(resp.Question[0].Header().Name, "example.com.") {
		t.Error("RFC 1035: Question section must be echoed in response")
	}
	t.Logf("UDP A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_PlainDNS_UDP_AAAA verifies AAAA query resolution over UDP.
func TestE2E_PlainDNS_UDP_AAAA(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP AAAA: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("UDP AAAA: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_PlainDNS_TCP verifies A query over TCP.
func TestE2E_PlainDNS_TCP(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryTCP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("TCP A: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("TCP A: expected at least one answer")
	}
	t.Logf("TCP A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_PlainDNS_TCP_LargeResponse verifies TCP handles large responses.
func TestE2E_PlainDNS_TCP_LargeResponse(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryTCP(t, port, "google.com", dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("TCP TXT: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("TCP TXT: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_PlainDNS_NXDOMAIN verifies NXDOMAIN for non-existent domain.
func TestE2E_PlainDNS_NXDOMAIN(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "this-domain-definitely-does-not-exist-dnsieve-e2e.example.com", dns.TypeA)
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		t.Error("NXDOMAIN: expected NXDOMAIN or empty NOERROR, got answers")
	}
	t.Logf("NXDOMAIN: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestE2E_PlainDNS_MX verifies MX record resolution.
func TestE2E_PlainDNS_MX(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "gmail.com", dns.TypeMX)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("MX: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("MX: answers=%d", len(resp.Answer))
}

// TestE2E_PlainDNS_CaseInsensitivity verifies queries are case-insensitive (RFC 4343).
func TestE2E_PlainDNS_CaseInsensitivity(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	variants := []string{"example.com", "EXAMPLE.COM", "Example.Com", "eXaMpLe.CoM"}
	for _, name := range variants {
		resp := queryUDP(t, port, name, dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("RFC 4343: case %q: rcode = %s", name, dns.RcodeToString[resp.Rcode])
		}
	}
}

// TestE2E_PlainDNS_BindPort verifies the server listens on the configured high port.
func TestE2E_PlainDNS_BindPort(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	t.Logf("server bound to port %d", port)
	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("bind port test: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_RecordTypes verifies the proxy handles different record types.
func TestE2E_RecordTypes(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	tests := []struct {
		name   string
		domain string
		qtype  uint16
		tcp    bool // use TCP for potentially large responses
	}{
		{"A", "google.com", dns.TypeA, false},
		{"AAAA", "google.com", dns.TypeAAAA, false},
		{"MX", "gmail.com", dns.TypeMX, false},
		{"TXT", "google.com", dns.TypeTXT, true}, // TXT can exceed UDP buffer
		{"NS", "google.com", dns.TypeNS, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var resp *dns.Msg
			if tc.tcp {
				resp = queryTCP(t, port, tc.domain, tc.qtype)
			} else {
				resp = queryUDP(t, port, tc.domain, tc.qtype)
			}
			t.Logf("%s %s: rcode=%s answers=%d", tc.name, tc.domain, dns.RcodeToString[resp.Rcode], len(resp.Answer))
		})
	}
}

// ============================================================
// Protocol: DNS-over-HTTPS (DoH) -- RFC 8484
// ============================================================

// TestE2E_DoH_PlainHTTP_POST verifies DoH POST over plaintext HTTP.
func TestE2E_DoH_PlainHTTP_POST(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := plainConfig(plainPort)
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cancel := startServer(t, cfg)
	defer cancel()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", dohPort)
	resp := queryDoHPost(t, baseURL, "example.com", dns.TypeA, plainHTTPClient())
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH POST: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoH POST: no answers")
	}
	t.Logf("DoH POST: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_DoH_PlainHTTP_GET verifies DoH GET over plaintext HTTP.
func TestE2E_DoH_PlainHTTP_GET(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := plainConfig(plainPort)
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cancel := startServer(t, cfg)
	defer cancel()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", dohPort)
	resp := queryDoHGet(t, baseURL, "example.com", dns.TypeA, plainHTTPClient())
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH GET: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("DoH GET: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_DoH_HTTPS tests DoH over TLS with a self-signed certificate.
func TestE2E_DoH_HTTPS(t *testing.T) {
	cert := generateSelfSignedCert(t)
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := plainConfig(plainPort)
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = false
	cfg.TLS.CertBase64 = cert.certB64
	cfg.TLS.KeyBase64 = cert.keyB64
	cancel := startServer(t, cfg)
	defer cancel()

	baseURL := fmt.Sprintf("https://127.0.0.1:%d", dohPort)
	resp := queryDoHPost(t, baseURL, "example.com", dns.TypeA, insecureTLSClient())
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH HTTPS POST: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoH HTTPS POST: no answers")
	}
	t.Logf("DoH HTTPS POST: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_DoH_IDZero verifies that DoH response DNS message ID is 0 per RFC 8484.
func TestE2E_DoH_IDZero(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := plainConfig(plainPort)
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cancel := startServer(t, cfg)
	defer cancel()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", dohPort)
	resp := queryDoHPost(t, baseURL, "example.com", dns.TypeA, plainHTTPClient())
	if resp.ID != 0 {
		t.Errorf("RFC 8484: DoH response ID = %d, want 0", resp.ID)
	}
}

// TestE2E_DoH_MethodNotAllowed verifies that DoH rejects unsupported HTTP methods.
func TestE2E_DoH_MethodNotAllowed(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := plainConfig(plainPort)
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cancel := startServer(t, cfg)
	defer cancel()

	url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", dohPort)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := plainHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("DELETE request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Errorf("DoH: DELETE should not be allowed, got HTTP %d", resp.StatusCode)
	}
	t.Logf("DoH DELETE: status=%d", resp.StatusCode)
}

// TestE2E_DoH_AAAA verifies AAAA queries work over DoH.
func TestE2E_DoH_AAAA(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := dohHTTPConfig(plainPort, dohPort)
	cancel := startServer(t, cfg)
	defer cancel()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", dohPort)
	resp := queryDoHPost(t, baseURL, "example.com", dns.TypeAAAA, plainHTTPClient())
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH AAAA: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("DoH AAAA: answers=%d", len(resp.Answer))
}

// TestE2E_DoH_NXDOMAIN verifies NXDOMAIN is properly returned over DoH.
func TestE2E_DoH_NXDOMAIN(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := dohHTTPConfig(plainPort, dohPort)
	cancel := startServer(t, cfg)
	defer cancel()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", dohPort)
	resp := queryDoHPost(t, baseURL, "this-definitelynotexist32759.example.com", dns.TypeA, plainHTTPClient())
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		t.Error("DoH NXDOMAIN: expected NXDOMAIN or empty NOERROR, got answers")
	}
	t.Logf("DoH NXDOMAIN: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestE2E_DoH_ContentType verifies that DoH responses use the correct content type.
func TestE2E_DoH_ContentType(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := dohHTTPConfig(plainPort, dohPort)
	cancel := startServer(t, cfg)
	defer cancel()

	query := makePlainQuery("example.com", dns.TypeA)
	query.ID = 0
	if err := query.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", dohPort)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(query.Data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := plainHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DoH content type: HTTP %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		t.Errorf("DoH Content-Type = %q, want application/dns-message", ct)
	}
}

// ============================================================
// Protocol: DNS-over-TLS (DoT) -- RFC 7858
// ============================================================

// TestE2E_DoT_BasicQuery verifies A query resolution over DoT.
func TestE2E_DoT_BasicQuery(t *testing.T) {
	cert := generateSelfSignedCert(t)
	dotPort := findFreePort(t)

	cfg := dotOnlyConfig(dotPort, cert)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryDoT(t, dotPort, "example.com", dns.TypeA, insecureDoTTLS())
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoT A: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoT A: no answers")
	}
	t.Logf("DoT A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_DoT_AAAA verifies AAAA query over DoT.
func TestE2E_DoT_AAAA(t *testing.T) {
	cert := generateSelfSignedCert(t)
	dotPort := findFreePort(t)

	cfg := dotOnlyConfig(dotPort, cert)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryDoT(t, dotPort, "example.com", dns.TypeAAAA, insecureDoTTLS())
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoT AAAA: rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("DoT AAAA: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_DoT_MultipleQueries verifies multiple sequential queries over DoT.
func TestE2E_DoT_MultipleQueries(t *testing.T) {
	cert := generateSelfSignedCert(t)
	dotPort := findFreePort(t)

	cfg := dotOnlyConfig(dotPort, cert)
	cancel := startServer(t, cfg)
	defer cancel()

	domains := []string{"example.com", "google.com", "cloudflare.com"}
	for _, domain := range domains {
		resp := queryDoT(t, dotPort, domain, dns.TypeA, insecureDoTTLS())
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("DoT %s: rcode = %s", domain, dns.RcodeToString[resp.Rcode])
		}
	}
}

// ============================================================
// All three protocols simultaneously
// ============================================================

// TestE2E_AllProtocols verifies plain, DoT, and DoH work concurrently.
func TestE2E_AllProtocols(t *testing.T) {
	cert := generateSelfSignedCert(t)
	plainPort := findFreePort(t)
	dotPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = plainPort
	cfg.Downstream.DoT.Enabled = true
	cfg.Downstream.DoT.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoT.Port = dotPort
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cfg.TLS.CertBase64 = cert.certB64
	cfg.TLS.KeyBase64 = cert.keyB64
	cfg.UpstreamSettings.TimeoutMS = 5000

	cancel := startServer(t, cfg)
	defer cancel()

	t.Run("UDP", func(t *testing.T) {
		resp := queryUDP(t, plainPort, "example.com", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("UDP: rcode=%s", dns.RcodeToString[resp.Rcode])
		}
	})
	t.Run("DoT", func(t *testing.T) {
		resp := queryDoT(t, dotPort, "example.com", dns.TypeA, insecureDoTTLS())
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("DoT: rcode=%s", dns.RcodeToString[resp.Rcode])
		}
	})
	t.Run("DoH", func(t *testing.T) {
		baseURL := fmt.Sprintf("http://127.0.0.1:%d", dohPort)
		resp := queryDoHPost(t, baseURL, "example.com", dns.TypeA, plainHTTPClient())
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("DoH: rcode=%s", dns.RcodeToString[resp.Rcode])
		}
	})
}
