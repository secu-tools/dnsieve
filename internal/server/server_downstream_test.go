// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package server

// server_downstream_test.go provides wire-level unit tests for all three
// downstream listener protocols (plain DNS, DoT, DoH).
//
// Each test starts the real listener (ServePlain / ServeDoT / ServeDoH) backed
// by a mock upstream client, sends a well-formed DNS query over the wire, and
// verifies that the response is correct.  No internet connection is required
// and no compiled binary is needed -- everything runs in-process.
//
// Covered scenarios:
//
//   - Plain DNS: UDP query, TCP query, SERVFAIL (all upstreams fail), cache
//     hit, blocked domain, AAAA query, multiple sequential queries
//
//   - DoT: TLS query, blocked domain, multiple sequential queries, query ID
//     echoed back
//
//   - DoH (HTTP): POST query, GET query, blocked domain, Content-Type header,
//     query ID restored, concurrent queries
//
//   - DoH (HTTPS/TLS): POST query, blocked domain
//
// These tests run as part of the standard unit test suite:
//
//
//	go test -v -count=1 ./internal/server/

import (
	"bytes"
	"context"
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
	"net/netip"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// ---- certificate helper -----------------------------------------------------

// downstreamCert holds base64-encoded PEM cert/key for the server config and
// an x509.CertPool that TLS clients can use to verify the certificate.
type downstreamCert struct {
	certB64 string
	keyB64  string
	pool    *x509.CertPool
}

// genDownstreamCert generates a self-signed ECDSA P-256 certificate valid for
// 127.0.0.1.  The cert and key are returned as base64-encoded PEM because
// that is the format server.loadTLSConfig expects.
func genDownstreamCert(t *testing.T) downstreamCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genDownstreamCert: generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dnsieve-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("genDownstreamCert: create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("genDownstreamCert: marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("genDownstreamCert: parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return downstreamCert{
		certB64: base64.StdEncoding.EncodeToString(certPEM),
		keyB64:  base64.StdEncoding.EncodeToString(keyPEM),
		pool:    pool,
	}
}

// ---- port and wait helpers --------------------------------------------------

// downstreamFreePort returns an available local TCP port by binding port 0 and
// immediately releasing it.
func downstreamFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("downstreamFreePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitForTCPPort polls addr until a TCP connection succeeds or 3 seconds pass.
func waitForTCPPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start within 3s", addr)
}

// ---- DNS query helpers -------------------------------------------------------

// sendUDPDNSQuery sends a packed DNS message over UDP and returns the response.
func sendUDPDNSQuery(t *testing.T, addr string, q *dns.Msg) *dns.Msg {
	t.Helper()
	if err := q.Pack(); err != nil {
		t.Fatalf("sendUDPDNSQuery: pack: %v", err)
	}
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("sendUDPDNSQuery: dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	if _, err := conn.Write(q.Data); err != nil {
		t.Fatalf("sendUDPDNSQuery: write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("sendUDPDNSQuery: read: %v", err)
	}
	resp := new(dns.Msg)
	resp.Data = buf[:n]
	if err := resp.Unpack(); err != nil {
		t.Fatalf("sendUDPDNSQuery: unpack: %v", err)
	}
	return resp
}

// sendTCPDNSQuery sends a DNS message over plain TCP with RFC 7766 length
// framing (2-byte big-endian length prefix).
func sendTCPDNSQuery(t *testing.T, addr string, q *dns.Msg) *dns.Msg {
	t.Helper()
	if err := q.Pack(); err != nil {
		t.Fatalf("sendTCPDNSQuery: pack: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("sendTCPDNSQuery: dial: %v", err)
	}
	defer conn.Close()
	return exchangeDNSOverTCPConn(t, conn, q.Data)
}

// sendDoTQuery connects over TLS and exchanges a DNS message using RFC 7858
// 2-byte length framing.
func sendDoTQuery(t *testing.T, addr string, q *dns.Msg, pool *x509.CertPool) *dns.Msg {
	t.Helper()
	if err := q.Pack(); err != nil {
		t.Fatalf("sendDoTQuery: pack: %v", err)
	}
	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", addr, tlsCfg,
	)
	if err != nil {
		t.Fatalf("sendDoTQuery: TLS dial %s: %v", addr, err)
	}
	defer conn.Close()
	return exchangeDNSOverTCPConn(t, conn, q.Data)
}

// exchangeDNSOverTCPConn writes wire data with a 2-byte big-endian length
// prefix and reads the length-prefixed response.  Used by TCP and DoT helpers.
func exchangeDNSOverTCPConn(t *testing.T, conn net.Conn, wire []byte) *dns.Msg {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("exchangeDNSOverTCPConn: write: %v", err)
	}

	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		t.Fatalf("exchangeDNSOverTCPConn: read length: %v", err)
	}
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		t.Fatalf("exchangeDNSOverTCPConn: read body: %v", err)
	}
	resp := new(dns.Msg)
	resp.Data = respData
	if err := resp.Unpack(); err != nil {
		t.Fatalf("exchangeDNSOverTCPConn: unpack: %v", err)
	}
	return resp
}

// sendDoHPost sends an RFC 8484 HTTP POST query to baseURL/dns-query.
// Sets ID=0 in wire (RFC 8484 requirement) and restores origID in response.
func sendDoHPost(t *testing.T, baseURL string, q *dns.Msg, hc *http.Client) *dns.Msg {
	t.Helper()
	origID := q.ID
	q.ID = 0
	if err := q.Pack(); err != nil {
		t.Fatalf("sendDoHPost: pack: %v", err)
	}
	url := baseURL + "/dns-query"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(q.Data))
	if err != nil {
		t.Fatalf("sendDoHPost: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("sendDoHPost: POST %s: %v", url, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("sendDoHPost: HTTP %d", httpResp.StatusCode)
	}
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("sendDoHPost: read body: %v", err)
	}
	resp := new(dns.Msg)
	resp.Data = body
	if err := resp.Unpack(); err != nil {
		t.Fatalf("sendDoHPost: unpack: %v", err)
	}
	resp.ID = origID
	return resp
}

// sendDoHGet sends an RFC 8484 GET query (?dns=<base64url>) to baseURL/dns-query.
func sendDoHGet(t *testing.T, baseURL string, q *dns.Msg, hc *http.Client) *dns.Msg {
	t.Helper()
	origID := q.ID
	q.ID = 0
	if err := q.Pack(); err != nil {
		t.Fatalf("sendDoHGet: pack: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(q.Data)
	url := fmt.Sprintf("%s/dns-query?dns=%s", baseURL, encoded)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("sendDoHGet: build request: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("sendDoHGet: GET %s: %v", url, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("sendDoHGet: HTTP %d", httpResp.StatusCode)
	}
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatalf("sendDoHGet: read body: %v", err)
	}
	resp := new(dns.Msg)
	resp.Data = body
	if err := resp.Unpack(); err != nil {
		t.Fatalf("sendDoHGet: unpack: %v", err)
	}
	resp.ID = origID
	return resp
}

// ---- listener start helpers --------------------------------------------------

// startPlainListenerOnPort starts ServePlain on 127.0.0.1:<port> in a
// background goroutine, waits until the TCP socket accepts connections, and
// registers a cleanup function that cancels the server context.
func startPlainListenerOnPort(t *testing.T, handler *Handler, port int) {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-plain")
	go func() {
		if err := ServePlain(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServePlain stopped: %v", err)
		}
	}()
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", port))
}

// startDoTListenerOnPort starts ServeDoT on 127.0.0.1:<port> using the
// provided self-signed certificate.
func startDoTListenerOnPort(t *testing.T, handler *Handler, port int, cd downstreamCert) {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Downstream.DoT.Enabled = true
	cfg.Downstream.DoT.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoT.Port = port
	cfg.TLS.CertBase64 = cd.certB64
	cfg.TLS.KeyBase64 = cd.keyB64

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-dot")
	go func() {
		if err := ServeDoT(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServeDoT stopped: %v", err)
		}
	}()
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", port))
}

// startDoHListenerOnPort starts ServeDoH on 127.0.0.1:<port> and returns the
// base URL for sending queries.  plainHTTP=true uses HTTP; false uses HTTPS
// with the provided certificate.  cd may be nil when plainHTTP is true.
func startDoHListenerOnPort(t *testing.T, handler *Handler, port int, plainHTTP bool, cd *downstreamCert) string {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = port
	cfg.Downstream.DoH.UsePlaintextHTTP = plainHTTP

	if !plainHTTP && cd != nil {
		cfg.TLS.CertBase64 = cd.certB64
		cfg.TLS.KeyBase64 = cd.keyB64
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "test-doh")
	go func() {
		if err := ServeDoH(ctx, handler, cfg, logger); err != nil {
			t.Logf("ServeDoH stopped: %v", err)
		}
	}()
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", port))

	scheme := "http"
	if !plainHTTP {
		scheme = "https"
	}
	return fmt.Sprintf("%s://127.0.0.1:%d", scheme, port)
}

// ---- ServePlain tests --------------------------------------------------------

// TestServePlain_UDP_SuccessPath verifies that a plain DNS UDP query reaches
// the mock upstream and returns NOERROR with at least one answer.
func TestServePlain_UDP_SuccessPath(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendUDPDNSQuery(t, fmt.Sprintf("127.0.0.1:%d", port), makeQuery("example.com", dns.TypeA))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("UDP A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("UDP A: expected at least one answer")
	}
}

// TestServePlain_TCP_SuccessPath verifies that a plain DNS TCP query reaches
// the mock upstream and returns NOERROR with at least one answer.
func TestServePlain_TCP_SuccessPath(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendTCPDNSQuery(t, fmt.Sprintf("127.0.0.1:%d", port), makeQuery("example.com", dns.TypeA))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("TCP A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("TCP A: expected at least one answer")
	}
}

// TestServePlain_AllUpstreamsFail verifies that when no upstream clients are
// configured the listener returns SERVFAIL rather than silently dropping the
// query.  newTestHandler(t, nil) creates a resolver with zero clients, so
// Resolve returns a SERVFAIL result.
func TestServePlain_AllUpstreamsFail(t *testing.T) {
	handler := newTestHandler(t, nil)

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendUDPDNSQuery(t, fmt.Sprintf("127.0.0.1:%d", port), makeQuery("nxresp.example.com", dns.TypeA))
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %s", dns.RcodeToString[resp.Rcode])
	}
}

// TestServePlain_CacheHit verifies that a second identical query is served
// directly from the cache without hitting the upstream.
func TestServePlain_CacheHit(t *testing.T) {
	q := makeQuery("cached.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// First query: populates the cache.
	r1 := sendUDPDNSQuery(t, addr, makeQuery("cached.example.com", dns.TypeA))
	if r1.Rcode != dns.RcodeSuccess {
		t.Fatalf("first query: rcode=%s", dns.RcodeToString[r1.Rcode])
	}

	// Second query: served from cache; different ID must be echoed back.
	q2 := dnsutil.SetQuestion(new(dns.Msg), "cached.example.com.", dns.TypeA)
	q2.ID = 9999
	r2 := sendUDPDNSQuery(t, addr, q2)
	if r2.Rcode != dns.RcodeSuccess {
		t.Fatalf("cached query: rcode=%s", dns.RcodeToString[r2.Rcode])
	}
	if r2.ID != 9999 {
		t.Errorf("cached response ID=%d, want 9999", r2.ID)
	}
}

// TestServePlain_BlockedQuery verifies that when the upstream signals a blocked
// domain (0.0.0.0 answer), the listener returns REFUSED with EDE Blocked to
// the client, bypassing DNSSEC validation on validating resolvers (dnsmasq).
func TestServePlain_BlockedQuery(t *testing.T) {
	q := makeQuery("blocked.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendUDPDNSQuery(
		t,
		fmt.Sprintf("127.0.0.1:%d", port),
		makeQuery("blocked.example.com", dns.TypeA),
	)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("blocked UDP: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("blocked UDP: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked UDP: expected EDE Blocked (RFC 8914 code 15) in response")
	}
}

// TestServePlain_AAAA_Query verifies AAAA queries are forwarded and answered
// correctly.
func TestServePlain_AAAA_Query(t *testing.T) {
	q := makeQuery("example.com", dns.TypeAAAA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendUDPDNSQuery(t, fmt.Sprintf("127.0.0.1:%d", port), makeQuery("example.com", dns.TypeAAAA))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestServePlain_MultipleSequential verifies the plain listener handles several
// UDP queries in sequence from the same address without misbehaving.
func TestServePlain_MultipleSequential(t *testing.T) {
	q := makeQuery("seq.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := range 5 {
		msg := makeQuery("seq.example.com", dns.TypeA)
		msg.ID = uint16(100 + i)
		resp := sendUDPDNSQuery(t, addr, msg)
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("query %d: rcode=%s", i, dns.RcodeToString[resp.Rcode])
		}
	}
}

// ---- ServeDoT tests ----------------------------------------------------------

// TestServeDoT_SuccessfulQuery verifies that a DNS-over-TLS query returns
// NOERROR with at least one answer.
func TestServeDoT_SuccessfulQuery(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	cert := genDownstreamCert(t)
	port := downstreamFreePort(t)
	startDoTListenerOnPort(t, handler, port, cert)

	resp := sendDoTQuery(
		t, fmt.Sprintf("127.0.0.1:%d", port),
		makeQuery("example.com", dns.TypeA), cert.pool,
	)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoT A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoT A: expected at least one answer")
	}
}

// TestServeDoT_BlockedQuery verifies that the DoT listener returns REFUSED
// with EDE Blocked for a blocked domain.
func TestServeDoT_BlockedQuery(t *testing.T) {
	q := makeQuery("blocked.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(q)})

	cert := genDownstreamCert(t)
	port := downstreamFreePort(t)
	startDoTListenerOnPort(t, handler, port, cert)

	resp := sendDoTQuery(
		t, fmt.Sprintf("127.0.0.1:%d", port),
		makeQuery("blocked.example.com", dns.TypeA), cert.pool,
	)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("DoT blocked: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("DoT blocked: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("DoT blocked: expected EDE Blocked (RFC 8914 code 15) in response")
	}
}

// TestServeDoT_IDEchoed verifies that the DoT listener echoes the client's
// query ID in the response.
func TestServeDoT_IDEchoed(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	cert := genDownstreamCert(t)
	port := downstreamFreePort(t)
	startDoTListenerOnPort(t, handler, port, cert)

	msg := makeQuery("example.com", dns.TypeA)
	msg.ID = 0x1234
	resp := sendDoTQuery(t, fmt.Sprintf("127.0.0.1:%d", port), msg, cert.pool)
	if resp.ID != 0x1234 {
		t.Errorf("DoT: response ID=%04x, want 1234", resp.ID)
	}
}

// TestServeDoT_MultipleSequential verifies the DoT listener handles several
// sequential queries, each over a fresh TLS connection.
func TestServeDoT_MultipleSequential(t *testing.T) {
	q := makeQuery("seq.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	cert := genDownstreamCert(t)
	port := downstreamFreePort(t)
	startDoTListenerOnPort(t, handler, port, cert)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := range 3 {
		msg := makeQuery("seq.example.com", dns.TypeA)
		msg.ID = uint16(200 + i)
		resp := sendDoTQuery(t, addr, msg, cert.pool)
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("DoT seq %d: rcode=%s", i, dns.RcodeToString[resp.Rcode])
		}
	}
}

// ---- ServeDoH tests (plaintext HTTP) -----------------------------------------

// TestServeDoH_POST_SuccessPath verifies that an RFC 8484 POST request to the
// DoH listener returns NOERROR with at least one answer.
func TestServeDoH_POST_SuccessPath(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, true, nil)

	hc := &http.Client{Timeout: 5 * time.Second}
	resp := sendDoHPost(t, baseURL, makeQuery("example.com", dns.TypeA), hc)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH POST A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoH POST A: expected at least one answer")
	}
}

// TestServeDoH_GET_SuccessPath verifies that an RFC 8484 GET request with the
// ?dns= parameter returns NOERROR.
func TestServeDoH_GET_SuccessPath(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, true, nil)

	hc := &http.Client{Timeout: 5 * time.Second}
	resp := sendDoHGet(t, baseURL, makeQuery("example.com", dns.TypeA), hc)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH GET A: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
}

// TestServeDoH_BlockedQuery verifies the DoH listener returns REFUSED with
// EDE Blocked for a blocked domain.
func TestServeDoH_BlockedQuery(t *testing.T) {
	q := makeQuery("blocked.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(q)})

	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, true, nil)

	hc := &http.Client{Timeout: 5 * time.Second}
	resp := sendDoHPost(t, baseURL, makeQuery("blocked.example.com", dns.TypeA), hc)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("DoH blocked: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("DoH blocked: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("DoH blocked: expected EDE Blocked (RFC 8914 code 15) in response")
	}
}

// TestServeDoH_ContentTypeHeader verifies the response carries the RFC 8484
// Content-Type: application/dns-message header.
func TestServeDoH_ContentTypeHeader(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, true, nil)

	qMsg := makeQuery("example.com", dns.TypeA)
	qMsg.ID = 0
	if err := qMsg.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	url := baseURL + "/dns-query"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(qMsg.Data))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	hc := &http.Client{Timeout: 5 * time.Second}
	httpResp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	httpResp.Body.Close()

	ct := httpResp.Header.Get("Content-Type")
	if ct != "application/dns-message" {
		t.Errorf("Content-Type=%q, want application/dns-message", ct)
	}
}

// TestServeDoH_IDRestored verifies that the DoH listener restores the original
// query ID even though the RFC 8484 wire format uses ID=0.
func TestServeDoH_IDRestored(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, true, nil)

	hc := &http.Client{Timeout: 5 * time.Second}
	msg := makeQuery("example.com", dns.TypeA)
	msg.ID = 0x5678
	resp := sendDoHPost(t, baseURL, msg, hc)

	// sendDoHPost transmits ID=0 in wire and restores origID in resp.
	if resp.ID != 0x5678 {
		t.Errorf("DoH ID: got %04x, want 5678", resp.ID)
	}
}

// TestServeDoH_ConcurrentQueries verifies the DoH listener handles concurrent
// requests from multiple goroutines without corruption.
func TestServeDoH_ConcurrentQueries(t *testing.T) {
	q := makeQuery("concurrent.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, true, nil)

	const workers = 8
	hc := &http.Client{Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	errs := make(chan string, workers)

	for i := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := makeQuery("concurrent.example.com", dns.TypeA)
			msg.ID = uint16(id + 1)
			resp := sendDoHPost(t, baseURL, msg, hc)
			if resp.Rcode != dns.RcodeSuccess {
				errs <- fmt.Sprintf("worker %d: rcode=%s", id, dns.RcodeToString[resp.Rcode])
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// ---- ServeDoH tests (HTTPS/TLS) ---------------------------------------------

// TestServeDoH_HTTPS_POST verifies the DoH listener works over TLS when a
// self-signed certificate is configured.
func TestServeDoH_HTTPS_POST(t *testing.T) {
	q := makeQuery("example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeNormalResp(q)})

	cert := genDownstreamCert(t)
	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, false, &cert)

	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    cert.pool,
				ServerName: "127.0.0.1",
			},
		},
	}
	resp := sendDoHPost(t, baseURL, makeQuery("example.com", dns.TypeA), hc)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DoH HTTPS POST: rcode=%s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatal("DoH HTTPS POST: expected at least one answer")
	}
}

// TestServeDoH_HTTPS_BlockedQuery verifies the HTTPS DoH listener correctly
// returns REFUSED with EDE Blocked for a blocked domain.
func TestServeDoH_HTTPS_BlockedQuery(t *testing.T) {
	q := makeQuery("blocked.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(q)})

	cert := genDownstreamCert(t)
	port := downstreamFreePort(t)
	baseURL := startDoHListenerOnPort(t, handler, port, false, &cert)

	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    cert.pool,
				ServerName: "127.0.0.1",
			},
		},
	}
	resp := sendDoHPost(t, baseURL, makeQuery("blocked.example.com", dns.TypeA), hc)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("HTTPS DoH blocked: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("HTTPS DoH blocked: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("HTTPS DoH blocked: expected EDE Blocked (RFC 8914 code 15) in response")
	}
}

// TestServePlain_BlockedAAAA_REFUSED verifies that a blocked AAAA query also
// results in REFUSED with EDE Blocked (no :: answer).
func TestServePlain_BlockedAAAA_REFUSED(t *testing.T) {
	q := makeQuery("blocked6.example.com", dns.TypeAAAA)

	// Simulate an upstream returning :: for a blocked AAAA query.
	upstreamResp := new(dns.Msg)
	dnsutil.SetReply(upstreamResp, q)
	upstreamResp.Answer = append(upstreamResp.Answer, &dns.AAAA{
		Hdr:  dns.Header{Name: "blocked6.example.com.", Class: dns.ClassINET, TTL: 300},
		AAAA: rdata.AAAA{Addr: netip.IPv6Unspecified()},
	})
	handler := newTestHandler(t, []*dns.Msg{upstreamResp})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendUDPDNSQuery(
		t,
		fmt.Sprintf("127.0.0.1:%d", port),
		makeQuery("blocked6.example.com", dns.TypeAAAA),
	)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("blocked AAAA UDP: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("blocked AAAA UDP: expected no answer records, got %d", len(resp.Answer))
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked AAAA UDP: expected EDE Blocked (code 15)")
	}
}

// TestServePlain_BlockedEDE_TCP verifies the EDE Blocked option survives TCP framing.
func TestServePlain_BlockedEDE_TCP(t *testing.T) {
	q := makeQuery("blocked.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	resp := sendTCPDNSQuery(
		t,
		fmt.Sprintf("127.0.0.1:%d", port),
		makeQuery("blocked.example.com", dns.TypeA),
	)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("blocked TCP: rcode=%s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if !hasEDEBlocked(resp) {
		t.Error("blocked TCP: expected EDE Blocked (code 15)")
	}
}

// TestServePlain_BlockedCached_REFUSED verifies that a blocked domain served
// from cache still returns REFUSED with EDE Blocked.
func TestServePlain_BlockedCached_REFUSED(t *testing.T) {
	q := makeQuery("cached-blocked.example.com", dns.TypeA)
	handler := newTestHandler(t, []*dns.Msg{makeBlockedResp(q)})

	port := downstreamFreePort(t)
	startPlainListenerOnPort(t, handler, port)

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// First query: upstream is hit --result is cached.
	r1 := sendUDPDNSQuery(t, addr, makeQuery("cached-blocked.example.com", dns.TypeA))
	if r1.Rcode != dns.RcodeRefused {
		t.Fatalf("first blocked query: rcode=%s, want REFUSED", dns.RcodeToString[r1.Rcode])
	}

	// Second query: served from cache.
	r2 := sendUDPDNSQuery(t, addr, makeQuery("cached-blocked.example.com", dns.TypeA))
	if r2.Rcode != dns.RcodeRefused {
		t.Fatalf("cached blocked query: rcode=%s, want REFUSED", dns.RcodeToString[r2.Rcode])
	}
	if len(r2.Answer) != 0 {
		t.Errorf("cached blocked query: expected no answer records, got %d", len(r2.Answer))
	}
	if !hasEDEBlocked(r2) {
		t.Error("cached blocked query: expected EDE Blocked (code 15)")
	}
}
