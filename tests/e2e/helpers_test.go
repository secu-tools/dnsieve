// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

// Package e2e contains end-to-end tests for DNSieve.
// These tests start a real DNSieve proxy with various configurations and
// validate its behaviour by sending queries over all supported protocols.
//
// Run with: go test -tags e2e -v ./tests/e2e/ -timeout 300s
package e2e

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
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/cache"
	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
	"github.com/secu-tools/dnsieve/internal/server"
	"github.com/secu-tools/dnsieve/internal/upstream"
)

// testCert holds a self-signed certificate for use in tests.
type testCert struct {
	certPEM []byte
	keyPEM  []byte
	certB64 string
	keyB64  string
	tlsPool *x509.CertPool
}

// knownBlockedDomain is a domain blocked by the default upstreams (Quad9 + Cloudflare security).
const knownBlockedDomain = "isitphishing.org"

// queryTimeout is the per-query deadline used throughout e2e tests.
const queryTimeout = 25 * time.Second

// generateSelfSignedCert creates a self-signed ECDSA certificate for localhost.
func generateSelfSignedCert(t *testing.T) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dnsieve-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
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

	return &testCert{
		certPEM: certPEM,
		keyPEM:  keyPEM,
		certB64: base64.StdEncoding.EncodeToString(certPEM),
		keyB64:  base64.StdEncoding.EncodeToString(keyPEM),
		tlsPool: pool,
	}
}

// findFreePort returns an available TCP port on localhost.
func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// serverPorts holds the ports assigned to each listener.
type serverPorts struct {
	plain int
	dot   int
	dohH  int // plaintext HTTP DoH
	dohS  int // HTTPS DoH
}

// startServer starts a DNSieve proxy with the given config and returns the
// ports it is listening on and a cancel function to stop the server.
// Only listeners whose port is non-zero (and protocol is enabled) are started.
func startServer(t *testing.T, cfg *config.Config) context.CancelFunc {
	t.Helper()
	logger := logging.NewStdoutOnly(logging.DefaultConfig(), "e2e")

	resolver, err := upstream.NewResolver(cfg, logger)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	var wlResolver *upstream.WhitelistResolver
	if cfg.Whitelist.Enabled {
		wlResolver, err = upstream.NewWhitelistResolver(&cfg.Whitelist, cfg.UpstreamSettings.VerifyCertificates)
		if err != nil {
			t.Fatalf("create whitelist resolver: %v", err)
		}
	}

	c := cache.New(
		cfg.Cache.MaxEntries,
		cfg.Cache.BlockedTTL,
		cfg.Cache.MinTTL,
		cfg.Cache.RenewPercent,
	)

	handler := server.NewHandler(resolver, wlResolver, c, logger, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	if cfg.Downstream.Plain.Enabled {
		go func() {
			if serveErr := server.ServePlain(ctx, handler, cfg, logger); serveErr != nil {
				logger.Debugf("plain server stopped: %v", serveErr)
			}
		}()
		waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Downstream.Plain.Port))
	}

	if cfg.Downstream.DoT.Enabled {
		go func() {
			if serveErr := server.ServeDoT(ctx, handler, cfg, logger); serveErr != nil {
				logger.Debugf("dot server stopped: %v", serveErr)
			}
		}()
		waitForPort(t, "tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Downstream.DoT.Port))
	}

	if cfg.Downstream.DoH.Enabled {
		go func() {
			if serveErr := server.ServeDoH(ctx, handler, cfg, logger); serveErr != nil {
				logger.Debugf("doh server stopped: %v", serveErr)
			}
		}()
		var dohProto string
		if cfg.Downstream.DoH.UsePlaintextHTTP {
			dohProto = "tcp"
		} else {
			dohProto = "tcp"
		}
		waitForPort(t, dohProto, fmt.Sprintf("127.0.0.1:%d", cfg.Downstream.DoH.Port))
	}

	return cancel
}

// waitForPort probes the address until it accepts connections or times out.
func waitForPort(t *testing.T, network, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout(network, addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("warning: server at %s may not be fully ready", addr)
}

// plainConfig returns a minimal plain-DNS-only config for tests.
func plainConfig(port int) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = port
	cfg.Downstream.DoT.Enabled = false
	cfg.Downstream.DoH.Enabled = false
	cfg.UpstreamSettings.TimeoutMS = 5000
	cfg.UpstreamSettings.MinWaitMS = 200
	return cfg
}

// makePlainQuery creates a DNS query message for the given name and type.
func makePlainQuery(name string, qtype uint16) *dns.Msg {
	q := dnsutil.SetQuestion(new(dns.Msg), dnsutil.Fqdn(name), qtype)
	q.RecursionDesired = true
	return q
}

// maxQueryAttempts is the number of times a query helper will retry on
// transient failures (transport errors or SERVFAIL from an upstream).
const maxQueryAttempts = 3

// queryUDP sends a DNS query over UDP and returns the response.
func queryUDP(t *testing.T, port int, name string, qtype uint16) *dns.Msg {
	t.Helper()
	return queryWithTransport(t, port, "udp", name, qtype)
}

// queryTCP sends a DNS query over TCP and returns the response.
func queryTCP(t *testing.T, port int, name string, qtype uint16) *dns.Msg {
	t.Helper()
	return queryWithTransport(t, port, "tcp", name, qtype)
}

func queryWithTransport(t *testing.T, port int, transport, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := dns.NewClient()
	c.Transport.ReadTimeout = 20 * time.Second
	c.Transport.WriteTimeout = 5 * time.Second

	query := makePlainQuery(name, qtype)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxQueryAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		resp, _, err := c.Exchange(ctx, query, transport, addr)
		cancel()
		if err != nil {
			lastErr = err
			t.Logf("query %s %s over %s (attempt %d/%d): %v", name, dns.TypeToString[qtype], transport, attempt, maxQueryAttempts, err)
		} else if resp.Rcode == dns.RcodeServerFailure && attempt < maxQueryAttempts {
			lastResp = resp
			t.Logf("query %s %s over %s (attempt %d/%d): SERVFAIL, retrying", name, dns.TypeToString[qtype], transport, attempt, maxQueryAttempts)
		} else {
			return resp
		}
		if attempt < maxQueryAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if lastErr != nil {
		t.Fatalf("query %s %s over %s port %d: all %d attempts failed: %v", name, dns.TypeToString[qtype], transport, port, maxQueryAttempts, lastErr)
	}
	return lastResp
}

// queryUDPLargeBuffer sends a UDP DNS query advertising a 4096-byte buffer and
// tolerates overflow/truncation errors from the OS or DNS library. It returns
// (nil, err) when the response could not be unpacked due to truncation, which
// is acceptable for queries that may produce large ANY responses.
func queryUDPLargeBuffer(t *testing.T, port int, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()
	query := makePlainQuery(name, qtype)
	query.UDPSize = 4096

	c := dns.NewClient()
	c.Transport.ReadTimeout = 20 * time.Second
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	return resp, err
}

// queryUDPWithOPT sends a DNS query with a custom OPT record over UDP.
func queryUDPWithOPT(t *testing.T, port int, name string, qtype uint16, udpSize uint16) *dns.Msg {
	t.Helper()
	query := makePlainQuery(name, qtype)
	query.UDPSize = udpSize

	c := dns.NewClient()
	c.Transport.ReadTimeout = 20 * time.Second
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("query %s %s (UDPSize=%d): %v", name, dns.TypeToString[qtype], udpSize, err)
	}
	return resp
}

// queryWithNSID sends a DNS query with an NSID option over UDP.
func queryWithNSID(t *testing.T, port int, name string, qtype uint16) *dns.Msg {
	t.Helper()
	query := makePlainQuery(name, qtype)
	// Add NSID option to request NSID from server
	query.Pseudo = append(query.Pseudo, &dns.NSID{})

	c := dns.NewClient()
	c.Transport.ReadTimeout = 20 * time.Second
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("query %s %s with NSID: %v", name, dns.TypeToString[qtype], err)
	}
	return resp
}

// queryWithECS sends a DNS query with an ECS option over UDP.
func queryWithECS(t *testing.T, port int, name string, qtype uint16, subnet string) *dns.Msg {
	t.Helper()

	query := makePlainQuery(name, qtype)

	prefix, err := parsePrefix(subnet)
	if err != nil {
		t.Fatalf("parse ECS subnet %s: %v", subnet, err)
	}
	ecs := &dns.SUBNET{
		Address: prefix.addr,
		Netmask: uint8(prefix.bits),
		Scope:   0,
	}
	if prefix.is4 {
		ecs.Family = 1
	} else {
		ecs.Family = 2
	}
	query.Pseudo = append(query.Pseudo, ecs)

	c := dns.NewClient()
	c.Transport.ReadTimeout = 20 * time.Second
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("query %s with ECS %s: %v", name, subnet, err)
	}
	return resp
}

// queryWithCookie sends a DNS query with a client cookie over UDP.
func queryWithCookie(t *testing.T, port int, name string, qtype uint16, clientCookie string) *dns.Msg {
	t.Helper()

	query := makePlainQuery(name, qtype)
	query.Pseudo = append(query.Pseudo, &dns.COOKIE{Cookie: clientCookie})

	c := dns.NewClient()
	c.Transport.ReadTimeout = 20 * time.Second
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("query %s with cookie: %v", name, err)
	}
	return resp
}

// queryDoHPost sends a DNS query over HTTP DoH (POST).
// It retries up to maxQueryAttempts times on transport errors and SERVFAIL.
func queryDoHPost(t *testing.T, baseURL, name string, qtype uint16, httpClient *http.Client) *dns.Msg {
	t.Helper()

	url := baseURL + "/dns-query"
	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxQueryAttempts; attempt++ {
		query := makePlainQuery(name, qtype)
		query.ID = 0 // RFC 8484 s4.1
		if err := query.Pack(); err != nil {
			t.Fatalf("pack query: %v", err)
		}

		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(query.Data))
		if err != nil {
			t.Fatalf("create DoH POST request: %v", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		req = req.WithContext(ctx)

		resp, httpErr := httpClient.Do(req)
		cancel()
		if httpErr != nil {
			lastErr = httpErr
			t.Logf("DoH POST %s (attempt %d/%d): %v", name, attempt, maxQueryAttempts, httpErr)
		} else {
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
				t.Logf("DoH POST %s (attempt %d/%d): HTTP %d, retrying", name, attempt, maxQueryAttempts, resp.StatusCode)
			} else {
				ct := resp.Header.Get("Content-Type")
				if ct != "application/dns-message" {
					resp.Body.Close()
					t.Fatalf("DoH POST Content-Type = %q, want application/dns-message", ct)
				}
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65535))
				resp.Body.Close()
				if readErr != nil {
					t.Fatalf("read DoH POST body: %v", readErr)
				}
				msg := new(dns.Msg)
				msg.Data = body
				if err := msg.Unpack(); err != nil {
					t.Fatalf("unpack DoH POST response: %v", err)
				}
				if msg.Rcode == dns.RcodeServerFailure && attempt < maxQueryAttempts {
					lastResp = msg
					t.Logf("DoH POST %s (attempt %d/%d): SERVFAIL, retrying", name, attempt, maxQueryAttempts)
				} else {
					return msg
				}
			}
		}
		if attempt < maxQueryAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if lastErr != nil {
		t.Fatalf("DoH POST to %s: all %d attempts failed: %v", url, maxQueryAttempts, lastErr)
	}
	return lastResp
}

// queryDoHGet sends a DNS query over HTTP DoH (GET).
// It retries up to maxQueryAttempts times on transport errors and SERVFAIL.
func queryDoHGet(t *testing.T, baseURL, name string, qtype uint16, httpClient *http.Client) *dns.Msg {
	t.Helper()

	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxQueryAttempts; attempt++ {
		query := makePlainQuery(name, qtype)
		query.ID = 0
		if err := query.Pack(); err != nil {
			t.Fatalf("pack query: %v", err)
		}

		encoded := base64.RawURLEncoding.EncodeToString(query.Data)
		url := fmt.Sprintf("%s/dns-query?dns=%s", baseURL, encoded)

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("create DoH GET request: %v", err)
		}
		req.Header.Set("Accept", "application/dns-message")

		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		req = req.WithContext(ctx)

		resp, httpErr := httpClient.Do(req)
		cancel()
		if httpErr != nil {
			lastErr = httpErr
			t.Logf("DoH GET %s (attempt %d/%d): %v", name, attempt, maxQueryAttempts, httpErr)
		} else {
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
				t.Logf("DoH GET %s (attempt %d/%d): HTTP %d, retrying", name, attempt, maxQueryAttempts, resp.StatusCode)
			} else {
				body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65535))
				resp.Body.Close()
				if readErr != nil {
					t.Fatalf("read DoH GET body: %v", readErr)
				}
				msg := new(dns.Msg)
				msg.Data = body
				if err := msg.Unpack(); err != nil {
					t.Fatalf("unpack DoH GET response: %v", err)
				}
				if msg.Rcode == dns.RcodeServerFailure && attempt < maxQueryAttempts {
					lastResp = msg
					t.Logf("DoH GET %s (attempt %d/%d): SERVFAIL, retrying", name, attempt, maxQueryAttempts)
				} else {
					return msg
				}
			}
		}
		if attempt < maxQueryAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	if lastErr != nil {
		t.Fatalf("DoH GET from %s: all %d attempts failed: %v", baseURL, maxQueryAttempts, lastErr)
	}
	return lastResp
}

// queryDoTOnce performs a single DoT query attempt. It returns the response
// on success, or a non-nil error if dialling, writing, or reading fails.
func queryDoTOnce(t *testing.T, addr string, name string, qtype uint16, tlsCfg *tls.Config) (*dns.Msg, error) {
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

	query := makePlainQuery(name, qtype)
	if err := query.Pack(); err != nil {
		t.Fatalf("pack DoT query: %v", err)
	}

	msg := make([]byte, 2+len(query.Data))
	binary.BigEndian.PutUint16(msg[:2], uint16(len(query.Data)))
	copy(msg[2:], query.Data)

	conn.SetDeadline(time.Now().Add(20 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(msg); err != nil {
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

	resp := new(dns.Msg)
	resp.Data = respData
	if err := resp.Unpack(); err != nil {
		t.Fatalf("DoT unpack: %v", err)
	}
	return resp, nil
}

// queryDoT sends a DNS query over DoT and returns the response.
// It retries up to maxQueryAttempts times on transport errors and SERVFAIL.
func queryDoT(t *testing.T, port int, name string, qtype uint16, tlsCfg *tls.Config) *dns.Msg {
	t.Helper()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var lastErr error
	var lastResp *dns.Msg
	for attempt := 1; attempt <= maxQueryAttempts; attempt++ {
		resp, err := queryDoTOnce(t, addr, name, qtype, tlsCfg)
		if err != nil {
			lastErr = err
			t.Logf("DoT query %s (attempt %d/%d): %v", name, attempt, maxQueryAttempts, err)
			if attempt < maxQueryAttempts {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure && attempt < maxQueryAttempts {
			lastResp = resp
			t.Logf("DoT %s (attempt %d/%d): SERVFAIL, retrying", name, attempt, maxQueryAttempts)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		return resp
	}
	if lastErr != nil {
		t.Fatalf("DoT query %s: all %d attempts failed: %v", name, maxQueryAttempts, lastErr)
	}
	return lastResp
}

// insecureTLSClient returns a *http.Client that skips certificate verification.
// This is only for testing against servers with self-signed certificates.
func insecureTLSClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 25 * time.Second,
	}
}

// plainHTTPClient returns a plain HTTP client (no TLS).
func plainHTTPClient() *http.Client {
	return &http.Client{Timeout: 25 * time.Second}
}

// insecureDoTTLS returns a tls.Config that skips verification for DoT tests.
func insecureDoTTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

// findECS searches an OPT record for an ECS option in the Pseudo section.
func findECS(msg *dns.Msg) *dns.SUBNET {
	for _, rr := range msg.Pseudo {
		if s, ok := rr.(*dns.SUBNET); ok {
			return s
		}
	}
	return nil
}

// findNSID searches a message for an NSID option.
func findNSID(msg *dns.Msg) *dns.NSID {
	for _, rr := range msg.Pseudo {
		if n, ok := rr.(*dns.NSID); ok {
			return n
		}
	}
	return nil
}

// findCookie searches a message for a COOKIE option.
func findCookie(msg *dns.Msg) *dns.COOKIE {
	for _, rr := range msg.Pseudo {
		if c, ok := rr.(*dns.COOKIE); ok {
			return c
		}
	}
	return nil
}

// findTCPKeepalive searches a message for a TCP keepalive option.
func findTCPKeepalive(msg *dns.Msg) *dns.TCPKEEPALIVE {
	for _, rr := range msg.Pseudo {
		if k, ok := rr.(*dns.TCPKEEPALIVE); ok {
			return k
		}
	}
	return nil
}

// isBlockedIPv4 returns true if the response represents a blocked A query.
// In default "null" mode: NOERROR with 0.0.0.0 answer and EDE Blocked.
// In other modes: EDE Blocked is the primary signal regardless of rcode.
func isBlockedIPv4(resp *dns.Msg) bool {
	return isBlockedResponse(resp)
}

// isBlockedIPv6 returns true if the response represents a blocked AAAA query.
// In default "null" mode: NOERROR with :: answer and EDE Blocked.
// In other modes: EDE Blocked is the primary signal regardless of rcode.
func isBlockedIPv6(resp *dns.Msg) bool {
	return isBlockedResponse(resp)
}

// isBlockedResponse checks for any blocking mode by looking for EDE Blocked.
// All blocking modes (null, nxdomain, nodata, refused) include EDE code 15.
func isBlockedResponse(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	return hasEDEBlocked(resp)
}

// hasEDEBlocked reports whether the message contains an EDE option with
// InfoCode == ExtendedErrorBlocked (15) per RFC 8914.
func hasEDEBlocked(msg *dns.Msg) bool {
	for _, rr := range msg.Pseudo {
		if ede, ok := rr.(*dns.EDE); ok && ede.InfoCode == dns.ExtendedErrorBlocked {
			return true
		}
	}
	return false
}

// prefixInfo holds parsed prefix info for building ECS options.
type prefixInfo struct {
	addr netip.Addr
	bits int
	is4  bool
}

func parsePrefix(subnet string) (prefixInfo, error) {
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return prefixInfo{}, err
	}
	bits, _ := ipnet.Mask.Size()
	is4 := ip.To4() != nil
	if is4 {
		addr, ok := netip.AddrFromSlice(ip.To4())
		if !ok {
			return prefixInfo{}, fmt.Errorf("invalid IPv4 address: %v", ip)
		}
		return prefixInfo{addr: addr.Unmap(), bits: bits, is4: true}, nil
	}
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return prefixInfo{}, fmt.Errorf("invalid IPv6 address: %v", ip)
	}
	return prefixInfo{addr: addr, bits: bits, is4: false}, nil
}

// dotOnlyConfig returns a config with only DoT enabled.
func dotOnlyConfig(port int, cert *testCert) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = false
	cfg.Downstream.DoH.Enabled = false
	cfg.Downstream.DoT.Enabled = true
	cfg.Downstream.DoT.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoT.Port = port
	cfg.TLS.CertBase64 = cert.certB64
	cfg.TLS.KeyBase64 = cert.keyB64
	cfg.UpstreamSettings.TimeoutMS = 5000
	return cfg
}

// dohHTTPConfig returns a config with plain + DoH (plaintext HTTP) enabled.
func dohHTTPConfig(plainPort, dohPort int) *config.Config {
	cfg := plainConfig(plainPort)
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	return cfg
}
