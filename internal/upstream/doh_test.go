// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// doHRoundTripFunc is an http.RoundTripper backed by a plain function.
// Used in tests to inject controlled network behaviour without a real server.
type doHRoundTripFunc func(*http.Request) (*http.Response, error)

func (f doHRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// makeDNSResponseBytes returns the wire-format bytes for a successful A-record
// response to the given query.
func makeDNSResponseBytes(t *testing.T, query *dns.Msg) []byte {
	t.Helper()
	resp := new(dns.Msg)
	dnsutil.SetReply(resp, query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.Header{Name: query.Question[0].Header().Name, Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("1.2.3.4")},
	})
	if err := resp.Pack(); err != nil {
		t.Fatalf("pack DNS response: %v", err)
	}
	return resp.Data
}

// TestDoHClient_SuccessfulQuery verifies a well-behaved DoH server.
func TestDoHClient_SuccessfulQuery(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeDNSResponseBytes(t, query))
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	// Replace the HTTP client with one that trusts the test TLS cert.
	client.httpClient = srv.Client()

	resp, err := client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", resp.Rcode)
	}
}

// TestDoHClient_EOFRetrySucceeds verifies that when the first POST gets an
// unexpected EOF (stale keep-alive), the client retries and succeeds.
func TestDoHClient_EOFRetrySucceeds(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "retry.example.com.", dns.TypeA)
	var calls atomic.Int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			// Simulate an abrupt close on the first request (EOF to client).
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("ResponseWriter does not implement http.Hijacker")
				return
			}
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeDNSResponseBytes(t, query))
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	resp, err := client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected a response after retry")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("expected 2 calls (initial + retry), got %d", n)
	}
}

// TestDoHClient_EOFRetryFails verifies that when both the first and retry POST
// get EOF, the error is returned to the caller and exactly two attempts were
// made (one initial, one retry -- no more).
func TestDoHClient_EOFRetryFails(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "eoffail.example.com.", dns.TypeA)
	var calls atomic.Int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// Always close the connection immediately.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("ResponseWriter does not implement http.Hijacker")
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	_, err = client.Query(context.Background(), query)
	if err == nil {
		t.Fatal("expected an error but got nil")
	}
	// Exactly 2 calls: the initial attempt + exactly one retry.
	if n := calls.Load(); n != 2 {
		t.Errorf("expected exactly 2 calls (initial + one retry), got %d", n)
	}
}

// TestDoHClient_EOFRetrySkippedOnCancelledContext verifies that when the
// context is cancelled at the same moment an EOF is returned, the
// ctx.Err() == nil guard in Query prevents the retry.
func TestDoHClient_EOFRetrySkippedOnCancelledContext(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "cancelled.example.com.", dns.TypeA)
	var calls atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())

	client := &DoHClient{
		url: "https://dns.example.test/dns-query",
		httpClient: &http.Client{
			Transport: doHRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				// Cancel the context then return EOF, simulating the context
				// expiring during the in-flight request.
				cancel()
				return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: io.ErrUnexpectedEOF}
			}),
		},
	}

	_, err := client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected an error")
	}
	// The first call produced an EOF and cancelled the context.
	// ctx.Err() != nil must prevent the retry: exactly 1 call expected.
	if n := calls.Load(); n != 1 {
		t.Errorf("expected exactly 1 call (retry suppressed by cancelled context), got %d", n)
	}
}

// TestDoHClient_NoURLInError verifies that the error returned by Query does
// not contain the upstream URL more than once. The URL is already present in
// DoHClient.String() so repeating it in the error message is just noise.
func TestDoHClient_NoURLInError(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	target := "https://dns.example.test/dns-query"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Create client pointing at a URL that simply refuses all connections.
	client := &DoHClient{
		url:        target,
		httpClient: &http.Client{},
	}

	_, err := client.Query(context.Background(), query)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}

	errMsg := err.Error()
	count := strings.Count(errMsg, target)
	if count > 1 {
		t.Errorf("URL appears %d times in error message, want at most 1: %q", count, errMsg)
	}
}

// TestIsEOFError verifies the isEOFError helper.
func TestIsEOFError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare EOF", io.EOF, true},
		{"bare unexpected EOF", io.ErrUnexpectedEOF, true},
		{"wrapped url.Error EOF", &url.Error{Op: "Post", URL: "http://x", Err: io.EOF}, true},
		{"wrapped url.Error unexpected EOF", &url.Error{Op: "Post", URL: "http://x", Err: io.ErrUnexpectedEOF}, true},
		{"unrelated error", fmt.Errorf("connection refused"), false},
		{"net error", &net.OpError{Op: "dial", Err: fmt.Errorf("refused")}, false},
		// url.Error wrapping net.OpError wrapping unexpected-EOF: a real chain
		// produced when net/http reads a response from a closed connection.
		{"url.Error > net.OpError > unexpected EOF",
			&url.Error{Op: "Post", URL: "http://x", Err: &net.OpError{Op: "read", Err: io.ErrUnexpectedEOF}},
			true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isEOFError(tc.err)
			if got != tc.want {
				t.Errorf("isEOFError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestShortHTTPError verifies that shortHTTPError strips the URL from
// *url.Error while preserving the underlying cause.
func TestShortHTTPError(t *testing.T) {
	inner := fmt.Errorf("unexpected EOF")
	urlErr := &url.Error{Op: "Post", URL: "https://dns.example.test/dns-query", Err: inner}

	got := shortHTTPError(urlErr)

	gotStr := got.Error()
	if strings.Contains(gotStr, "https://dns.example.test/dns-query") {
		t.Errorf("shortHTTPError should strip URL from error, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "Post") {
		t.Errorf("shortHTTPError should keep the HTTP method, got: %q", gotStr)
	}
	if !strings.Contains(gotStr, "unexpected EOF") {
		t.Errorf("shortHTTPError should keep the inner error, got: %q", gotStr)
	}
}

// TestDoHClient_NonOKStatus verifies the HTTP status-code error does not
// repeat the upstream URL.
func TestDoHClient_NonOKStatus(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	_, err = client.Query(context.Background(), query)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("expected status code 503 in error, got: %q", err.Error())
	}
	// URL must not appear in the error message.
	if strings.Contains(err.Error(), srv.URL) {
		t.Errorf("URL should not appear in status error, got: %q", err.Error())
	}
}

// makeDoHHTTPResponse builds a minimal valid HTTP 200 response whose body is
// the wire-format bytes of msg.  The caller must have packed msg already or
// let this function do it.  Used by RoundTripper-based tests.
func makeDoHHTTPResponse(msg *dns.Msg) (*http.Response, error) {
	if err := msg.Pack(); err != nil {
		return nil, err
	}
	body := make([]byte, len(msg.Data))
	copy(body, msg.Data)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/dns-message"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

// --- Constructor tests (parity with DoT / plain) ---

// TestNewDoHClient_VerifyCertTrue verifies that verifyCert=true sets
// InsecureSkipVerify=false on the underlying TLS configuration.
func TestNewDoHClient_VerifyCertTrue(t *testing.T) {
	c, err := NewDoHClient("https://dns.example.com/dns-query", true, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("verifyCert=true should set InsecureSkipVerify=false")
	}
}

// TestNewDoHClient_VerifyCertFalse verifies that verifyCert=false sets
// InsecureSkipVerify=true on the underlying TLS configuration.
func TestNewDoHClient_VerifyCertFalse(t *testing.T) {
	c, err := NewDoHClient("https://dns.example.com/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("verifyCert=false should set InsecureSkipVerify=true")
	}
}

// --- String ---

// TestDoHClient_String verifies the String() output contains the URL and
// the protocol identifier.
func TestDoHClient_String(t *testing.T) {
	c, err := NewDoHClient("https://dns.quad9.net/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := c.String()
	if !strings.Contains(s, "dns.quad9.net") {
		t.Errorf("String() should contain URL, got %q", s)
	}
	if !strings.Contains(s, "DoH") {
		t.Errorf("String() should contain DoH, got %q", s)
	}
}

// --- Query tests (parity with DoT / plain) ---

// TestDoHClient_AAAAQuery verifies that an AAAA record query over DoH works.
func TestDoHClient_AAAAQuery(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeAAAA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")},
		})
		if err := resp.Pack(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.Data)
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	resp, err := client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Error("expected at least one AAAA answer")
	}
}

// TestDoHClient_NXDomainResponse verifies that an NXDOMAIN response from the
// DoH server is propagated to the caller without error.
func TestDoHClient_NXDomainResponse(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "nonexistent.example.com.", dns.TypeA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.Rcode = dns.RcodeNameError
		if err := resp.Pack(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.Data)
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	resp, err := client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN (%d)", resp.Rcode, dns.RcodeNameError)
	}
}

// TestDoHClient_ContextAlreadyExpired verifies that an already-expired context
// returns an error without reaching the server.
func TestDoHClient_ContextAlreadyExpired(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for expired context")
	}
}

// TestDoHClient_UnreachableServer verifies that a connection to an unreachable
// address returns an error.
func TestDoHClient_UnreachableServer(t *testing.T) {
	client, err := NewDoHClient("https://127.0.0.1:1/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_, err = client.Query(ctx, query)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// TestDoHClient_MultipleSequentialQueries verifies that repeat queries through
// the same client (keep-alive reuse) all succeed.
func TestDoHClient_MultipleSequentialQueries(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeDNSResponseBytes(t, query))
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	for i := 0; i < 3; i++ {
		resp, err := client.Query(context.Background(), query)
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("query %d: unexpected rcode %d", i, resp.Rcode)
		}
	}
}

// --- RFC 8484 protocol compliance ---

// TestDoHClient_DNSIDZeroInWireFormat verifies that the DNS query sent in the
// HTTP POST body carries ID=0, as required by RFC 8484 section 4.1.
func TestDoHClient_DNSIDZeroInWireFormat(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.ID = 12345 // non-zero ID on the caller's message

	var capturedBody []byte
	client := &DoHClient{
		url: "https://dns.example.test/dns-query",
		httpClient: &http.Client{
			Transport: doHRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				capturedBody, _ = io.ReadAll(r.Body)
				dnsResp := new(dns.Msg)
				dnsutil.SetReply(dnsResp, query)
				dnsResp.ID = 0
				httpResp, err := makeDoHHTTPResponse(dnsResp)
				if err != nil {
					return nil, err
				}
				return httpResp, nil
			}),
		},
	}

	_, err := client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(capturedBody) == 0 {
		t.Fatal("no request body captured")
	}
	wireMsg := new(dns.Msg)
	wireMsg.Data = capturedBody
	if err := wireMsg.Unpack(); err != nil {
		t.Fatalf("unpack captured wire bytes: %v", err)
	}
	if wireMsg.ID != 0 {
		t.Errorf("wire format ID = %d, want 0 (RFC 8484 section 4.1)", wireMsg.ID)
	}
}

// TestDoHClient_ResponseIDRestored verifies that the response message ID is
// set back to the original query ID.  DoH servers send responses with ID=0;
// the client must restore the caller's ID so the response can be matched.
func TestDoHClient_ResponseIDRestored(t *testing.T) {
	const originalID = uint16(9876)
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	query.ID = originalID

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a response with ID=0, as a conforming DoH server would.
		resp := new(dns.Msg)
		dnsutil.SetReply(resp, query)
		resp.ID = 0
		if err := resp.Pack(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp.Data)
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	resp, err := client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if resp.ID != originalID {
		t.Errorf("response ID = %d, want %d (original query ID must be restored)", resp.ID, originalID)
	}
}

// TestDoHClient_HTTPHeaders verifies that the client sends the required HTTP
// headers per RFC 8484: both Content-Type and Accept must be
// application/dns-message.
func TestDoHClient_HTTPHeaders(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	var contentType, accept string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		accept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeDNSResponseBytes(t, query))
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	_, err = client.Query(context.Background(), query)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if contentType != "application/dns-message" {
		t.Errorf("Content-Type = %q, want application/dns-message", contentType)
	}
	if accept != "application/dns-message" {
		t.Errorf("Accept = %q, want application/dns-message", accept)
	}
}

// TestDoHClient_MalformedResponseBody verifies that a response body that
// cannot be unpacked as DNS returns an error rather than silently succeeding.
func TestDoHClient_MalformedResponseBody(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		// Send garbage that is not a valid DNS message.
		_, _ = w.Write([]byte{0xff, 0xfe, 0xfd, 0xfc, 0x00, 0x01})
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	_, err = client.Query(context.Background(), query)
	if err == nil {
		t.Fatal("expected error for malformed DNS response body")
	}
}

// TestDoHClient_ConcurrentQueries verifies that concurrent queries from
// multiple goroutines complete without error and each response carries the
// correct query ID (no cross-contamination between concurrent requests).
func TestDoHClient_ConcurrentQueries(t *testing.T) {
	query := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeDNSResponseBytes(t, query))
	}))
	defer srv.Close()

	client, err := NewDoHClient(srv.URL+"/dns-query", false, "auto", resolveDisabled, 10, nil)
	if err != nil {
		t.Fatalf("NewDoHClient: %v", err)
	}
	client.httpClient = srv.Client()

	const goroutines = 5
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
			q.ID = uint16(n + 1)
			resp, err := client.Query(context.Background(), q)
			if err != nil {
				errs[n] = err
				return
			}
			if resp.ID != q.ID {
				errs[n] = fmt.Errorf("goroutine %d: response ID %d does not match query ID %d", n, resp.ID, q.ID)
			}
		}(i)
	}
	wg.Wait()
	for n, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", n, err)
		}
	}
}
