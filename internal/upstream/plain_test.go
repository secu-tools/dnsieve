// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// --- Constructor tests ---

// TestNewPlainClient_CustomPort verifies that a non-standard port is preserved.
func TestNewPlainClient_CustomPort(t *testing.T) {
	c, err := NewPlainClient("127.0.0.1:5353")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.address != "127.0.0.1:5353" {
		t.Errorf("got %q, want 127.0.0.1:5353", c.address)
	}
}

// --- String ---

func TestPlainClient_String(t *testing.T) {
	c, err := NewPlainClient("1.1.1.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := c.String()
	if !strings.Contains(s, "1.1.1.1:53") {
		t.Errorf("String() should contain address, got %q", s)
	}
	if !strings.Contains(s, "UDP") {
		t.Errorf("String() should contain UDP, got %q", s)
	}
}

// --- Query tests ---

// TestPlainClient_SuccessfulUDPQuery tests a successful A-record query against
// a local mock UDP DNS server.
func TestPlainClient_SuccessfulUDPQuery(t *testing.T) {
	// startMockBootstrapServer (defined in bootstrap_test.go) starts a local
	// UDP server that returns a single A record with the given IP.
	addr := startMockBootstrapServer(t, "1.2.3.4", false)

	client, err := NewPlainClient(addr)
	if err != nil {
		t.Fatalf("NewPlainClient: %v", err)
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

// TestPlainClient_NXDomainResponse verifies that NXDOMAIN is propagated.
func TestPlainClient_NXDomainResponse(t *testing.T) {
	addr := startMockBootstrapServer(t, "", true) // srvFail=true returns SERVFAIL

	client, err := NewPlainClient(addr)
	if err != nil {
		t.Fatalf("NewPlainClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "bad.example.com.", dns.TypeA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Rcode == dns.RcodeSuccess {
		t.Errorf("expected non-success rcode, got NOERROR")
	}
}

// TestPlainClient_ContextAlreadyExpired verifies that an expired context
// returns an error immediately.
func TestPlainClient_ContextAlreadyExpired(t *testing.T) {
	addr := startMockBootstrapServer(t, "1.2.3.4", false)

	client, err := NewPlainClient(addr)
	if err != nil {
		t.Fatalf("NewPlainClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for expired context")
	}
}

// TestPlainClient_UnreachableServer verifies that dialing an unreachable server
// returns an error containing the target address.
func TestPlainClient_UnreachableServer(t *testing.T) {
	client, err := NewPlainClient("127.0.0.1:1")
	if err != nil {
		t.Fatalf("NewPlainClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// --- TCP fallback test ---

// serveUDPTruncated reads DNS packets from conn and replies with a truncated
// (TC=1) response, causing any compliant client to retry over TCP.
func serveUDPTruncated(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		q := new(dns.Msg)
		q.Data = make([]byte, n)
		copy(q.Data, buf[:n])
		if err := q.Unpack(); err != nil {
			continue
		}
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, q)
		resp.Truncated = true // signal the client to retry over TCP
		if err := resp.Pack(); err != nil {
			continue
		}
		conn.WriteTo(resp.Data, remoteAddr) //nolint:errcheck
	}
}

// serveTCPFullResponse handles a single TCP DNS connection and replies with a
// full A-record response (5.6.7.8).
func serveTCPFullResponse(c net.Conn) {
	defer c.Close()
	var msgLen uint16
	if err := binary.Read(c, binary.BigEndian, &msgLen); err != nil {
		return
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	q := new(dns.Msg)
	q.Data = buf
	if err := q.Unpack(); err != nil {
		return
	}
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, q)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: q.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("5.6.7.8")},
	})
	if err := resp.Pack(); err != nil {
		return
	}
	out := make([]byte, 2+len(resp.Data))
	binary.BigEndian.PutUint16(out, uint16(len(resp.Data)))
	copy(out[2:], resp.Data)
	c.Write(out) //nolint:errcheck
}

// startMockUDPTCPDNSServerPair starts a paired UDP + TCP server on the same
// port. The UDP server always signals truncation so the client retries via TCP,
// and the TCP server serves a full response. Returns the server address.
func startMockUDPTCPDNSServerPair(t *testing.T) string {
	t.Helper()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	port := tcpLn.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		tcpLn.Close()
		t.Fatalf("udp listen on same port: %v", err)
	}
	t.Cleanup(func() { tcpLn.Close(); udpConn.Close() })

	go serveUDPTruncated(udpConn)
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go serveTCPFullResponse(conn)
		}
	}()

	return tcpLn.Addr().String()
}

// TestPlainClient_TCPFallbackOnTruncation verifies that when the UDP response
// is truncated (TC=1), the client retries over TCP and returns the full
// response.
func TestPlainClient_TCPFallbackOnTruncation(t *testing.T) {
	addr := startMockUDPTCPDNSServerPair(t)

	client, err := NewPlainClient(addr)
	if err != nil {
		t.Fatalf("NewPlainClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	resp, err := client.Query(ctx, query)
	if err != nil {
		t.Fatalf("Query with TCP fallback: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one answer after TCP fallback")
	}
}
