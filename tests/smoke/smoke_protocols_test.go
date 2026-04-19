// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build smoke

package smoke_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// selfSignedCert holds an in-memory self-signed certificate and its base64-
// encoded PEM representations for embedding in config files.
type selfSignedCert struct {
	certB64 string
	keyB64  string
	pool    *x509.CertPool
}

// generateCert creates a self-signed ECDSA certificate for 127.0.0.1.
func generateCert(t *testing.T) *selfSignedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dnsieve-smoke"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	return &selfSignedCert{
		certB64: base64.StdEncoding.EncodeToString(certPEM),
		keyB64:  base64.StdEncoding.EncodeToString(keyPEM),
		pool:    pool,
	}
}

// dohConfig returns a TOML config that enables plain DoH on dohPort.
func dohConfig(plainPort, dohPort int) string {
	return fmt.Sprintf(`[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 200
verify_certificates = true
%s
[downstream.plain]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.dot]
enabled = false

[downstream.doh]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d
use_plaintext_http = true

[cache]
enabled = true
max_entries = 1000
`, bootstrapIPFamilyTOML(), plainPort, dohPort)
}

// dotConfig returns a TOML config that enables DoT with the given certificate.
func dotConfig(plainPort, dotPort int, cert *selfSignedCert) string {
	return fmt.Sprintf(`[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 200
verify_certificates = true
%s
[tls]
cert_base64 = %q
key_base64  = %q

[downstream.plain]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.dot]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.doh]
enabled = false

[cache]
enabled = true
max_entries = 1000
`, bootstrapIPFamilyTOML(), cert.certB64, cert.keyB64, plainPort, dotPort)
}

// doHPost sends a DNS message to the DoH endpoint and returns the response.
// It retries up to 3 times (with 1 s / 2 s backoff) on HTTP transport errors
// and on SERVFAIL responses.
func doHPost(t *testing.T, dohPort int, name string, qtype uint16) *dns.Msg {
	t.Helper()
	const maxAttempts = 3
	url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", dohPort)
	client := &http.Client{Timeout: 25 * time.Second}
	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		msg := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
		msg.RecursionDesired = true
		msg.ID = 0
		if err := msg.Pack(); err != nil {
			t.Fatalf("pack DoH query: %v", err)
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(msg.Data))
		if err != nil {
			t.Fatalf("create DoH request: %v", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		httpResp, err := client.Do(req)
		if err != nil {
			lastErr = err
			t.Logf("DoH POST %s (attempt %d/%d): %v", name, attempt, maxAttempts, err)
		} else {
			body, readErr := io.ReadAll(io.LimitReader(httpResp.Body, 65535))
			httpResp.Body.Close()
			if readErr != nil {
				t.Fatalf("read DoH body: %v", readErr)
			}
			if httpResp.StatusCode != http.StatusOK {
				lastErr = fmt.Errorf("HTTP %d", httpResp.StatusCode)
				t.Logf("DoH POST %s (attempt %d/%d): HTTP %d", name, attempt, maxAttempts, httpResp.StatusCode)
			} else {
				result := new(dns.Msg)
				result.Data = body
				if err := result.Unpack(); err != nil {
					t.Fatalf("unpack DoH response: %v", err)
				}
				if result.Rcode == dns.RcodeServerFailure && attempt < maxAttempts {
					lastResp = result
					t.Logf("DoH POST %s (attempt %d/%d): SERVFAIL, retrying", name, attempt, maxAttempts)
				} else {
					return result
				}
			}
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if lastErr != nil {
		t.Fatalf("DoH POST %s: all %d attempts failed: %v", name, maxAttempts, lastErr)
	}
	return lastResp
}

// doTQueryOnce performs a single DoT query attempt. Returns the DNS response or
// a non-nil error if the network operation fails.
func doTQueryOnce(t *testing.T, addr string, name string, qtype uint16, tlsCfg *tls.Config) (*dns.Msg, error) {
	t.Helper()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		tlsCfg,
	)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
	msg.RecursionDesired = true
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack DoT query: %v", err)
	}

	// RFC 7858: 2-byte big-endian length prefix.
	frame := make([]byte, 2+len(msg.Data))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(msg.Data)))
	copy(frame[2:], msg.Data)

	conn.SetDeadline(time.Now().Add(20 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		return nil, err
	}

	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, err
	}

	result := new(dns.Msg)
	result.Data = respData
	if err := result.Unpack(); err != nil {
		t.Fatalf("DoT unpack: %v", err)
	}
	return result, nil
}

// doTQuery sends a DNS query over DoT using a raw TLS connection with the
// 2-byte length-prefixed framing required by RFC 7858.
// It retries up to 3 times (with 1 s / 2 s backoff) on dial/read errors
// and on SERVFAIL responses.
func doTQuery(t *testing.T, dotPort int, name string, qtype uint16, pool *x509.CertPool) *dns.Msg {
	t.Helper()
	const maxAttempts = 3
	addr := fmt.Sprintf("127.0.0.1:%d", dotPort)
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	}
	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := doTQueryOnce(t, addr, name, qtype, tlsCfg)
		if err != nil {
			lastErr = err
			t.Logf("DoT query %s (attempt %d/%d): %v", name, attempt, maxAttempts, err)
			if attempt < maxAttempts {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
			continue
		}
		if result.Rcode == dns.RcodeServerFailure && attempt < maxAttempts {
			lastResp = result
			t.Logf("DoT query %s (attempt %d/%d): SERVFAIL, retrying", name, attempt, maxAttempts)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		return result
	}
	if lastErr != nil {
		t.Fatalf("DoT query %s: all %d attempts failed: %v", name, maxAttempts, lastErr)
	}
	return lastResp
}

// TestSmoke_DoH_POST verifies a DNS query over plaintext DoH (HTTP POST) works.
func TestSmoke_DoH_POST(t *testing.T) {
	dir := smokeTempDir(t)
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)
	cfgPath := writeConfig(t, dir, dohConfig(plainPort, dohPort))
	startBinary(t, cfgPath, plainPort)

	if !waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", dohPort), 20*time.Second) {
		t.Fatal("DoH port did not open within 20s")
	}

	resp := doHPost(t, dohPort, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH POST: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoH POST: no answers")
	}
	t.Logf("DoH POST: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestSmoke_DoH_ContentType verifies the DoH response Content-Type header.
func TestSmoke_DoH_ContentType(t *testing.T) {
	dir := smokeTempDir(t)
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)
	cfgPath := writeConfig(t, dir, dohConfig(plainPort, dohPort))
	startBinary(t, cfgPath, plainPort)

	if !waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", dohPort), 20*time.Second) {
		t.Fatal("DoH port did not open within 20s")
	}

	msg := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	msg.ID = 0
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack query: %v", err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", dohPort)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(msg.Data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DoH content-type: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DoH content-type: HTTP %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		t.Errorf("Content-Type = %q, want application/dns-message", ct)
	}
}

// TestSmoke_DoT_BasicQuery verifies a DNS A query over DoT against the binary.
func TestSmoke_DoT_BasicQuery(t *testing.T) {
	dir := smokeTempDir(t)
	cert := generateCert(t)
	plainPort := findFreePort(t)
	dotPort := findFreePort(t)
	cfgPath := writeConfig(t, dir, dotConfig(plainPort, dotPort, cert))
	startBinary(t, cfgPath, plainPort)

	if !waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", dotPort), 20*time.Second) {
		t.Fatal("DoT port did not open within 20s")
	}

	resp := doTQuery(t, dotPort, "example.com", dns.TypeA, cert.pool)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoT A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoT A: no answers")
	}
	t.Logf("DoT A: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestSmoke_AllProtocols verifies plain DNS, DoH, and DoT all work
// concurrently through a single running binary instance.
func TestSmoke_AllProtocols(t *testing.T) {
	dir := smokeTempDir(t)
	cert := generateCert(t)
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)
	dotPort := findFreePort(t)

	cfg := fmt.Sprintf(`[[upstream]]
address = "https://dns.quad9.net/dns-query"
protocol = "doh"

[[upstream]]
address = "https://security.cloudflare-dns.com/dns-query"
protocol = "doh"

[upstream_settings]
timeout_ms = 5000
min_wait_ms = 200
verify_certificates = true
%s
[tls]
cert_base64 = %q
key_base64  = %q

[downstream.plain]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.dot]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d

[downstream.doh]
enabled = true
listen_addresses = ["127.0.0.1"]
port = %d
use_plaintext_http = true

[cache]
enabled = true
max_entries = 1000
`, bootstrapIPFamilyTOML(), cert.certB64, cert.keyB64, plainPort, dotPort, dohPort)

	cfgPath := writeConfig(t, dir, cfg)
	startBinary(t, cfgPath, plainPort)

	if !waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", dohPort), 20*time.Second) {
		t.Fatal("DoH port did not open within 20s")
	}
	if !waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", dotPort), 20*time.Second) {
		t.Fatal("DoT port did not open within 20s")
	}

	t.Run("UDP", func(t *testing.T) {
		resp := queryUDP(t, plainPort, "example.com", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("UDP: rcode=%s", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("DoH", func(t *testing.T) {
		resp := doHPost(t, dohPort, "example.com", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("DoH: rcode=%s", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("DoT", func(t *testing.T) {
		resp := doTQuery(t, dotPort, "example.com", dns.TypeA, cert.pool)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("DoT: rcode=%s", dns.RcodeToString[resp.Rcode])
		}
	})
}
