// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"codeberg.org/miekg/dns"
)

// DoHClient implements DNS-over-HTTPS (RFC 8484) using HTTP/2 POST
// with application/dns-message content type.
type DoHClient struct {
	url        string
	httpClient *http.Client
}

// NewDoHClient creates a DoH client for the given server URL.
// bootstrapIPs is an optional list of host:port addresses used to resolve
// the DoH server hostname instead of the system resolver.
// ipFamily controls bootstrap address-family selection: "ipv4", "ipv6", or
// "auto" (default) to race both as per RFC 6555.
func NewDoHClient(url string, verifyCert bool, ipFamily string, bootstrapIPs ...string) (*DoHClient, error) {
	if url == "" {
		return nil, fmt.Errorf("empty DoH URL")
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifyCert, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	if len(bootstrapIPs) > 0 {
		transport.DialContext = makeBootstrapDialer(bootstrapIPs, ipFamily)
	}

	return &DoHClient{
		url: url,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}, nil
}

// Query sends a DNS query via DoH POST and returns the response.
// Per RFC 8484: POST with Content-Type: application/dns-message,
// body = raw DNS wire format with ID set to 0.
//
// If the first request fails with an EOF error (idle keep-alive connection
// closed by the server), a single retry is performed. net/http does not
// automatically retry POST requests because POST is not idempotent.
func (c *DoHClient) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 section 4.1: DNS ID must be 0 in wire format.
	// msg is produced by edns.PrepareUpstreamQuery which builds a fresh
	// *dns.Msg (msgPool == nil), so this Copy() does NOT inherit the server's
	// buffer pool and cannot trigger the pool-corruption described in
	// PrepareUpstreamQuery.
	queryMsg := msg.Copy()
	queryMsg.ID = 0
	// Nil Data so Pack allocates a fresh buffer; the Copy shares the
	// underlying Data slice with msg, and packing two copies concurrently
	// would race on that backing array.
	queryMsg.Data = nil

	if err := queryMsg.Pack(); err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}
	wireQuery := make([]byte, len(queryMsg.Data))
	copy(wireQuery, queryMsg.Data)

	resp, err := c.doPost(ctx, wireQuery)
	if err != nil {
		// net/http does not retry POST on EOF (POST is not idempotent by the
		// HTTP spec). When a keep-alive connection is reused but the server has
		// already closed its end, we get io.ErrUnexpectedEOF. Retry once if the
		// context is still valid.
		if isEOFError(err) && ctx.Err() == nil {
			resp, err = c.doPost(ctx, wireQuery)
		}
		if err != nil {
			return nil, shortHTTPError(err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	dnsResp := new(dns.Msg)
	dnsResp.Data = body
	if err := dnsResp.Unpack(); err != nil {
		return nil, fmt.Errorf("unpack DoH response: %w", err)
	}

	// Restore original ID. Also clear Data so the caller always has a
	// consistent message: struct fields authoritative, wire bytes generated
	// on demand by the next Pack/WriteTo call.
	dnsResp.ID = msg.ID
	dnsResp.Data = nil

	return dnsResp, nil
}

// doPost constructs and sends an HTTP POST request to the DoH endpoint.
// The caller must close the response body when err is nil.
func (c *DoHClient) doPost(ctx context.Context, wireQuery []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(wireQuery))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return c.httpClient.Do(req)
}

// isEOFError reports whether err is an EOF or unexpected-EOF on the connection.
// net/http wraps transport errors in *url.Error; both wrapped and bare forms
// are checked.
func isEOFError(err error) bool {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return errors.Is(urlErr.Err, io.EOF) || errors.Is(urlErr.Err, io.ErrUnexpectedEOF)
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// shortHTTPError strips the request URL from a *url.Error returned by net/http.
// The URL is already present in DoHClient.String(), so including it again in the
// error message creates redundant log output. For other error types the original
// error is returned unchanged.
func shortHTTPError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

// String returns a description of this client.
func (c *DoHClient) String() string {
	return fmt.Sprintf("DoH(%s)", c.url)
}
