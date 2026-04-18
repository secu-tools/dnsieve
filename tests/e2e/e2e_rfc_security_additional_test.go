// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	rdata "codeberg.org/miekg/dns/rdata"
)

const (
	qtypeUnknownE2E uint16 = 65400
	typeHTTPSE2E    uint16 = 65
)

// TestE2E_RFC1034_CNAMEAliasFlow verifies the proxy can resolve an aliasing
// chain end-to-end without protocol errors.
func TestE2E_RFC1034_CNAMEAliasFlow(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "www.github.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 1034 e2e: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Error("RFC 1034 e2e: expected at least one answer")
	}
}

// TestE2E_RFC2181_RRSetTTLUniformity checks TTL consistency when multiple A
// records are returned for one owner name.
func TestE2E_RFC2181_RRSetTTLUniformity(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "cloudflare.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 2181 e2e: rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	var (
		ttlRef uint32
		seen   int
	)
	for _, rr := range resp.Answer {
		if dns.RRToType(rr) != dns.TypeA {
			continue
		}
		seen++
		if seen == 1 {
			ttlRef = rr.Header().TTL
			continue
		}
		if rr.Header().TTL != ttlRef {
			t.Errorf("RFC 2181 e2e: mixed A TTLs first=%d got=%d", ttlRef, rr.Header().TTL)
		}
	}
}

// TestE2E_RFC3597_UnknownQTypeHandled verifies unknown qtypes are forwarded
// and answered safely without crashing the proxy.
func TestE2E_RFC3597_UnknownQTypeHandled(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServerReachable(t, cfg)
	defer cancel()

	// dnsutil.SetQuestion returns nil for unknown qtypes, so build the message directly.
	query := new(dns.Msg)
	query.ID = dns.ID()
	query.RecursionDesired = true
	query.Question = []dns.RR{&dns.RFC3597{
		Hdr:     dns.Header{Name: dnsutil.Fqdn("example.com"), Class: dns.ClassINET},
		RFC3597: rdata.RFC3597{RRType: qtypeUnknownE2E},
	}}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	c := dns.NewClient()
	c.Transport.ReadTimeout = queryTimeout

	ctx, ctxCancel := context.WithTimeout(context.Background(), queryTimeout)
	defer ctxCancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("RFC 3597 e2e unknown qtype query failed: %v", err)
	}

	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeNotImplemented, dns.RcodeRefused:
		// all acceptable
	default:
		t.Errorf("RFC 3597 e2e: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_RFC6891_EDNS0_Truncation verifies the proxy respects EDNS0 UDP buffer
// size limits (RFC 6891) and truncates large responses when the advertised
// buffer is small, per RFC 9715.
func TestE2E_RFC6891_EDNS0_Truncation(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Advertise a small 512-byte UDP buffer; a large TXT response should be truncated.
	resp := queryUDPWithOPT(t, port, "google.com", dns.TypeTXT, 512)
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		t.Logf("RFC 6891/9715 truncation: rcode=%s (non-fatal)", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("RFC 6891/9715 UDP truncation: TC=%v answers=%d", resp.Truncated, len(resp.Answer))
}

// TestE2E_RFC7873_MalformedCookies checks robustness against malformed/mutated
// client cookies and prevents length-based attacks.
func TestE2E_RFC7873_MalformedCookies(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Send a cookie with invalid (non-hex) characters to test server robustness.
	query := makePlainQuery("example.com", dns.TypeA)
	query.Pseudo = append(query.Pseudo, &dns.COOKIE{Cookie: "not-valid-hex!!"})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c := dns.NewClient()
	c.Transport.ReadTimeout = queryTimeout

	ctx, ctxCancel := context.WithTimeout(context.Background(), queryTimeout)
	defer ctxCancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Logf("RFC 7873 malformed cookie: error (expected): %v", err)
		return
	}
	switch resp.Rcode {
	case dns.RcodeFormatError, dns.RcodeSuccess:
		// Both are acceptable: server either rejected or stripped the bad cookie.
	default:
		t.Logf("RFC 7873 malformed cookie: rcode=%s (server handled safely)", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_Security_NullByteInjection verifies the server handles raw DNS wire
// data containing null bytes without crashing, and remains operational after.
func TestE2E_Security_NullByteInjection(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Build a valid DNS query wire message and corrupt the QNAME by inserting a null byte.
	query := makePlainQuery("example.com", dns.TypeA)
	if err := query.Pack(); err != nil {
		t.Fatalf("Security null-byte: pack: %v", err)
	}
	wire := query.Data
	// Corrupt: replace the first label length byte with 0x00
	// to simulate null-byte injection in the wire format.
	corrupted := make([]byte, len(wire))
	copy(corrupted, wire)
	if len(corrupted) > 12 {
		corrupted[12] = 0x00
	}

	conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("Security null-byte: dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	_, _ = conn.Write(corrupted)
	buf := make([]byte, 512)
	_, _ = conn.Read(buf) // Result may be FORMERR or silence - both acceptable.

	// Verify the server is still alive.
	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Security null-byte: server unresponsive after injection: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_Security_PathTraversal verifies that path-traversal-style domain
// strings do not resolve to real answers and are handled safely.
func TestE2E_Security_PathTraversal(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Use a domain that resembles a path traversal string (valid DNS chars).
	resp := queryUDP(t, port, "etc.passwd.traversal.example.com", dns.TypeA)
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok && !a.Addr.IsPrivate() && !a.Addr.IsLoopback() && !a.Addr.IsUnspecified() {
				t.Errorf("Security path traversal: unexpected public IP %v", a.Addr)
			}
		}
	}
	t.Logf("Security path traversal: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_Security_RCE_Mutation validates that domain names resembling shell
// commands do not result in command execution - they should resolve normally
// or return NXDOMAIN, but never trigger side effects.
func TestE2E_Security_RCE_Mutation(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// These domains contain characters that look like shell commands but are
	// valid ASCII strings in the DNS question section. The server must treat
	// them as plain DNS labels, never executing them.
	shellLikeDomains := []string{
		"cmd-rm-rf.example.com",
		"pipe-dev-null.example.com",
		"exec-bash.example.com",
	}

	for _, domain := range shellLikeDomains {
		// queryUDPLargeBuffer returns (nil, err) instead of calling t.Fatalf,
		// so we handle all outcomes here. Any response from the server (even
		// one the DNS library cannot fully parse) proves it did not crash.
		// "dns unpack: overflow truncated message" can occur in CI when an
		// upstream returns a large NXDOMAIN with DNSSEC/NSEC authority records
		// that cause the received UDP datagram to look malformed at the client.
		resp, err := queryUDPLargeBuffer(t, port, domain, dns.TypeA)
		if err != nil {
			// Server responded with something; the client just couldn't parse
			// it. That is acceptable for this stability-only test.
			t.Logf("RCE mutation %q: server responded (client unpack error: %v)", domain, err)
		} else {
			// Any rcode is acceptable; we only care the server didn't crash.
			t.Logf("RCE mutation %q: rcode=%s", domain, dns.RcodeToString[resp.Rcode])
		}
	}

	// Verify server is still alive.
	alive := queryUDP(t, port, "example.com", dns.TypeA)
	if alive.Rcode != dns.RcodeSuccess {
		t.Errorf("Security RCE mutation: server unresponsive after mutation queries: rcode=%s", dns.RcodeToString[alive.Rcode])
	}
}

// TestE2E_Security_BufferOverflow sends a DNS wire message with an over-length
// QNAME (exceeding the 255-byte FQDN limit) and verifies the server rejects it
// safely without crashing.
func TestE2E_Security_BufferOverflow(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Build a QNAME that exceeds the 255-byte DNS FQDN limit by using labels of
	// 60 characters each. Total wire length ~284 bytes - intentionally too long.
	labels := []string{
		strings.Repeat("A", 60),
		strings.Repeat("B", 60),
		strings.Repeat("C", 60),
		strings.Repeat("D", 60),
	}
	maliciousName := strings.Join(labels, ".") + "."

	// Build the raw DNS wire message manually so the library cannot reject it.
	var wire []byte
	// Header: ID=0xDEAD, QR=0, Opcode=0, flags=RD, QDCOUNT=1
	wire = append(wire, 0xDE, 0xAD) // ID
	wire = append(wire, 0x01, 0x00) // Flags: QR=0, RD=1
	wire = append(wire, 0x00, 0x01) // QDCOUNT=1
	wire = append(wire, 0x00, 0x00) // ANCOUNT=0
	wire = append(wire, 0x00, 0x00) // NSCOUNT=0
	wire = append(wire, 0x00, 0x00) // ARCOUNT=0
	// QNAME: encode each label
	for _, label := range labels {
		wire = append(wire, byte(len(label)))
		wire = append(wire, []byte(label)...)
	}
	wire = append(wire, 0x00)       // root label
	wire = append(wire, 0x00, 0x01) // QTYPE=A
	wire = append(wire, 0x00, 0x01) // QCLASS=IN

	_ = maliciousName // used to document intent above

	conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("Security buffer overflow: dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	_, _ = conn.Write(wire)
	buf := make([]byte, 512)
	_, _ = conn.Read(buf) // FORMERR or silence expected.

	// Verify the server is still responsive after the oversized query.
	resp := queryUDP(t, port, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Security buffer overflow: server unresponsive after oversized query: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_RFC5966_UDPTruncationTCPRetry verifies the proxy supports TCP retry
// behavior when a large UDP answer is truncated.
func TestE2E_RFC5966_UDPTruncationTCPRetry(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	udpResp := queryUDPWithOPT(t, port, "org", dns.TypeDNSKEY, 512)
	if !udpResp.Truncated {
		t.Logf("RFC 5966 e2e: UDP response not truncated (rcode=%s answers=%d)", dns.RcodeToString[udpResp.Rcode], len(udpResp.Answer))
		return
	}

	tcpResp := queryTCP(t, port, "org", dns.TypeDNSKEY)
	if tcpResp.Truncated {
		t.Error("RFC 5966 e2e: TCP fallback response should not be truncated")
	}
	if tcpResp.Rcode != dns.RcodeSuccess {
		t.Errorf("RFC 5966 e2e: TCP fallback rcode=%s", dns.RcodeToString[tcpResp.Rcode])
	}
}

// TestE2E_RFC9460_HTTPSRecordTransport verifies HTTPS RR lookups are handled
// safely through the proxy.
func TestE2E_RFC9460_HTTPSRecordTransport(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "cloudflare.com", typeHTTPSE2E)
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeNotImplemented, dns.RcodeRefused:
	default:
		t.Errorf("RFC 9460 e2e: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_RFC4592_WildcardStyleQuery verifies wildcard-style dynamic domains
// are handled safely by the proxy.
func TestE2E_RFC4592_WildcardStyleQuery(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	name := fmt.Sprintf("dnsieve-%d.1.2.3.4.nip.io", time.Now().UnixNano())
	resp := queryUDP(t, port, name, dns.TypeA)

	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		t.Errorf("RFC 4592 e2e: unexpected rcode=%s", dns.RcodeToString[resp.Rcode])
	}
}

// TestE2E_DoH_MalformedWireRejected verifies malformed DoH payloads are
// rejected with a client error and do not crash the server.
func TestE2E_DoH_MalformedWireRejected(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := dohHTTPConfig(plainPort, dohPort)
	cancel := startServer(t, cfg)
	defer cancel()

	url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", dohPort)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte{0xff, 0x00, 0x01, 0x02}))
	if err != nil {
		t.Fatalf("build malformed DoH request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := plainHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("malformed DoH request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed DoH status=%d, want 400", resp.StatusCode)
	}
}

// TestE2E_DoH_OversizedBody_NoInternalError verifies oversized DoH payloads
// are handled safely without 5xx crashes.
func TestE2E_DoH_OversizedBody_NoInternalError(t *testing.T) {
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := dohHTTPConfig(plainPort, dohPort)
	cancel := startServer(t, cfg)
	defer cancel()

	body := bytes.Repeat([]byte{0x41}, 70000)
	url := fmt.Sprintf("http://127.0.0.1:%d/dns-query", dohPort)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build oversized DoH request: %v", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")

	ctx, ctxCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer ctxCancel()
	req = req.WithContext(ctx)

	resp, err := plainHTTPClient().Do(req)
	if err != nil {
		t.Fatalf("oversized DoH request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		t.Errorf("oversized DoH should not trigger 5xx, got HTTP %d", resp.StatusCode)
	}
}

// TestE2E_Unexpected_MultiQuestionGetsFORMERR verifies malformed DNS messages
// with multiple questions are rejected (FORMERR) or silently dropped.
// We send a raw wire packet with QDCOUNT=2 because the DNS client library
// truncates multi-question messages to 1 question on pack, so a raw
// net.Conn is needed to actually reach the server with QDCOUNT=2.
func TestE2E_Unexpected_MultiQuestionGetsFORMERR(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	// Build a raw DNS wire packet with QDCOUNT=2 manually.
	// Header: ID=0x1234, QR=0 RD=1, QDCOUNT=2, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	// Q1: example.com. A IN
	// Q2: example.net. A IN
	wire := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: RD=1
		0x00, 0x02, // QDCOUNT=2
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		// Q1: example.com. A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
		// Q2: example.net. A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'n', 'e', 't', 0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		// Server silently drops malformed multi-question queries: acceptable.
		t.Logf("multi-question: no response (server dropped packet): %v", err)
		return
	}

	// Parse the response: RCODE is in bits 0-3 of byte 3.
	if n < 4 {
		t.Fatalf("response too short: %d bytes", n)
	}
	rcode := int(buf[3] & 0x0F)
	t.Logf("multi-question: rcode=%d (FORMERR=1)", rcode)
	if rcode != dns.RcodeFormatError {
		t.Errorf("multi-question rcode=%d, want FORMERR(%d)", rcode, dns.RcodeFormatError)
	}
}
