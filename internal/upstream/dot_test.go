// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// generateSelfSignedCert generates a self-signed ECDSA certificate for 127.0.0.1.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// startTLSDNSServer starts a local TLS server that handles DNS-over-TCP queries
// using the standard 2-byte length prefix framing (RFC 7858 / DNS-over-TCP).
// The handler is called for each incoming DNS message to produce a response.
// Returning nil from handler closes the connection without writing a response.
// Returns the listener address (host:port).
func startTLSDNSServer(t *testing.T, cert tls.Certificate, handler func(q *dns.Msg) *dns.Msg) string {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("start TLS listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveDNSTCPConn(conn, handler)
		}
	}()

	return ln.Addr().String()
}

// serveDNSTCPConn reads DNS messages from a TCP (or TLS) connection and writes
// responses.  Messages use the standard 2-byte big-endian length prefix.
func serveDNSTCPConn(conn net.Conn, handler func(q *dns.Msg) *dns.Msg) {
	defer conn.Close()
	for {
		// Read the 2-byte message length.
		var msgLen uint16
		if err := binary.Read(conn, binary.BigEndian, &msgLen); err != nil {
			return
		}
		// Read exactly msgLen bytes.
		buf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		// Parse the query.
		q := new(dns.Msg)
		q.Data = buf
		if err := q.Unpack(); err != nil {
			return
		}
		// Generate the response.
		resp := handler(q)
		if resp == nil {
			return // handler signals: close without responding
		}
		if err := resp.Pack(); err != nil {
			return
		}
		// Write 2-byte length prefix + response.
		out := make([]byte, 2+len(resp.Data))
		binary.BigEndian.PutUint16(out, uint16(len(resp.Data)))
		copy(out[2:], resp.Data)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// makeSuccessResponse returns a valid A-record response for the given query.
func makeSuccessResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{
			Name:  query.Question[0].Header().Name,
			Class: dns.ClassINET,
			TTL:   300,
		},
		A: rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	})
	return resp
}

// --- Constructor tests ---

// TestNewDoTClient_BareIPv4DefaultPort verifies that a raw IPv4 address without
// a port gets the default DoT port (853) appended.
func TestNewDoTClient_BareIPv4DefaultPort(t *testing.T) {
	c, err := NewDoTClient("1.1.1.1", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "1.1.1.1:853" {
		t.Errorf("got %q, want 1.1.1.1:853", c.address)
	}
}

// TestNewDoTClient_HostnameWithPort verifies that a hostname:port address
// preserves the port and uses the hostname as the TLS ServerName.
func TestNewDoTClient_HostnameWithPort(t *testing.T) {
	c, err := NewDoTClient("dns.example.com:853", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "dns.example.com:853" {
		t.Errorf("got %q, want dns.example.com:853", c.address)
	}
	if c.tlsConfig.ServerName != "dns.example.com" {
		t.Errorf("ServerName = %q, want dns.example.com", c.tlsConfig.ServerName)
	}
}

// TestNewDoTClient_VerifyCertTrue verifies that verifyCert=true sets
// InsecureSkipVerify to false (certificate verification is enabled).
func TestNewDoTClient_VerifyCertTrue(t *testing.T) {
	c, err := NewDoTClient("1.1.1.1:853", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.tlsConfig.InsecureSkipVerify {
		t.Error("verifyCert=true should set InsecureSkipVerify=false")
	}
}

// TestNewDoTClient_VerifyCertFalse verifies that verifyCert=false sets
// InsecureSkipVerify to true (certificate verification is disabled).
func TestNewDoTClient_VerifyCertFalse(t *testing.T) {
	c, err := NewDoTClient("1.1.1.1:853", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.tlsConfig.InsecureSkipVerify {
		t.Error("verifyCert=false should set InsecureSkipVerify=true")
	}
}

// --- String ---

func TestDoTClient_String(t *testing.T) {
	c, err := NewDoTClient("1.1.1.1:853", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := c.String()
	if !strings.Contains(s, "1.1.1.1:853") {
		t.Errorf("String() should contain address, got %q", s)
	}
	if !strings.Contains(s, "DoT") {
		t.Errorf("String() should contain DoT, got %q", s)
	}
}

// --- Query tests (against a local mock TLS DNS server) ---

// TestDoTClient_SuccessfulQuery verifies that a basic A-record query succeeds
// against a local TLS server that returns a proper response.
func TestDoTClient_SuccessfulQuery(t *testing.T) {
	cert := generateSelfSignedCert(t)
	addr := startTLSDNSServer(t, cert, makeSuccessResponse)

	// verifyCert=false so the client accepts our self-signed cert.
	client, err := NewDoTClient(addr, false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR (%d)", resp.Rcode, dns.RcodeSuccess)
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one answer")
	}
}

// TestDoTClient_SuccessfulAAAAQuery verifies that an AAAA query works.
func TestDoTClient_SuccessfulAAAAQuery(t *testing.T) {
	cert := generateSelfSignedCert(t)
	addr := startTLSDNSServer(t, cert, func(q *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, q)
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.Header{
				Name:  q.Question[0].Header().Name,
				Class: dns.ClassINET,
				TTL:   300,
			},
			AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
		})
		return resp
	})

	client, err := NewDoTClient(addr, false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeAAAA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one answer")
	}
}

// TestDoTClient_NXDomainResponse verifies that NXDOMAIN is returned correctly.
func TestDoTClient_NXDomainResponse(t *testing.T) {
	cert := generateSelfSignedCert(t)
	addr := startTLSDNSServer(t, cert, func(q *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, q)
		resp.Rcode = dns.RcodeNameError
		return resp
	})

	client, err := NewDoTClient(addr, false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "nonexistent.example.com.", dns.TypeA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN (%d)", resp.Rcode, dns.RcodeNameError)
	}
}

// TestDoTClient_ServerClosesConnection verifies that closing the connection
// before sending a response produces a non-nil error.
func TestDoTClient_ServerClosesConnection(t *testing.T) {
	cert := generateSelfSignedCert(t)
	// Handler returns nil, which causes serveDNSTCPConn to close without responding.
	addr := startTLSDNSServer(t, cert, func(q *dns.Msg) *dns.Msg {
		return nil
	})

	client, err := NewDoTClient(addr, false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error when server closes connection without responding")
	}
}

// TestDoTClient_ContextAlreadyExpired verifies that an already-expired context
// returns an error before the dial is attempted.
func TestDoTClient_ContextAlreadyExpired(t *testing.T) {
	cert := generateSelfSignedCert(t)
	addr := startTLSDNSServer(t, cert, makeSuccessResponse)

	client, err := NewDoTClient(addr, false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for expired context")
	}
}

// TestDoTClient_UnreachableServer verifies that dialing an unreachable address
// returns a non-nil error.
func TestDoTClient_UnreachableServer(t *testing.T) {
	// Port 1 should be unreachable.
	client, err := NewDoTClient("127.0.0.1:1", false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// TestDoTClient_NoAddressInError verifies that the error returned by Query
// does not repeat the upstream address. The address is already present in
// DoTClient.String() so including it again in the error is redundant.
func TestDoTClient_NoAddressInError(t *testing.T) {
	client, err := NewDoTClient("127.0.0.1:1", false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error should not repeat the upstream address, got: %q", err.Error())
	}
}

// TestShortNetError verifies that shortNetError strips source and destination
// addresses from a *net.OpError while preserving the Op, Net and inner error.
func TestShortNetError(t *testing.T) {
	inner := fmt.Errorf("i/o timeout")
	netErr := &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.ParseIP("172.18.0.3"), Port: 38498},
		Addr:   &net.TCPAddr{IP: net.ParseIP("155.138.130.135"), Port: 853},
		Err:    inner,
	}

	got := shortNetError(netErr)

	gotStr := got.Error()
	if strings.Contains(gotStr, "172.18.0.3") {
		t.Errorf("shortNetError should strip source address, got: %q", gotStr)
	}
	if strings.Contains(gotStr, "155.138.130.135") {
		t.Errorf("shortNetError should strip destination address, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "read") {
		t.Errorf("shortNetError should keep Op, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "tcp") {
		t.Errorf("shortNetError should keep Net, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "i/o timeout") {
		t.Errorf("shortNetError should keep inner error, got: %q", gotStr)
	}
}

// TestShortNetError_NonNetOpError verifies that shortNetError returns
// non-*net.OpError values unchanged.
func TestShortNetError_NonNetOpError(t *testing.T) {
	plain := fmt.Errorf("connection reset by peer")
	got := shortNetError(plain)
	if got.Error() != plain.Error() {
		t.Errorf("shortNetError should return non-net.OpError unchanged, got: %q", got.Error())
	}
}

// TestDoTClient_MultipleSequentialQueries verifies that the client can issue
// multiple queries in sequence (each query creates a new connection).
func TestDoTClient_MultipleSequentialQueries(t *testing.T) {
	cert := generateSelfSignedCert(t)
	addr := startTLSDNSServer(t, cert, makeSuccessResponse)

	client, err := NewDoTClient(addr, false)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}

	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
		resp, err := client.Query(ctx, query)
		cancel()
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("query %d: unexpected rcode %d", i, resp.Rcode)
		}
	}
}

// TestDoTClient_WithBootstrap verifies that NewDoTClient resolves a hostname
// using the provided bootstrap DNS and stores an IP address.
func TestDoTClient_WithBootstrap(t *testing.T) {
	// Use a mock bootstrap server that resolves any name to 127.0.0.1.
	bootstrapAddr := startMockBootstrapServer(t, "127.0.0.1", false)

	// "dns.example.test" is not a real hostname; the bootstrap should resolve it.
	c, err := NewDoTClient("dns.example.test:853", false, bootstrapAddr)
	if err != nil {
		t.Fatalf("NewDoTClient with bootstrap: %v", err)
	}
	// After bootstrap resolution, the address should use the resolved IP.
	if !strings.HasPrefix(c.address, "127.0.0.1") {
		t.Errorf("expected address to start with 127.0.0.1 after bootstrap, got %q", c.address)
	}
	// The TLS ServerName should still be the original hostname.
	if c.tlsConfig.ServerName != "dns.example.test" {
		t.Errorf("ServerName = %q, want dns.example.test", c.tlsConfig.ServerName)
	}
}

// TestDoTClient_BootstrapFailureFallback verifies that when bootstrap resolution
// fails, the original address is preserved and no error is returned from the
// constructor.
func TestDoTClient_BootstrapFailureFallback(t *testing.T) {
	// Bootstrap server at port 1 is unreachable.
	c, err := NewDoTClient("dns.example.test:853", false, "127.0.0.1:1")
	if err != nil {
		t.Fatalf("NewDoTClient should not fail on bootstrap timeout: %v", err)
	}
	// Original address must be preserved.
	if c.address != "dns.example.test:853" {
		t.Errorf("address = %q, want dns.example.test:853", c.address)
	}
}
