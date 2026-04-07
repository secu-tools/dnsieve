// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// ServeDoH starts DNS-over-HTTPS listeners on every configured address.
// All addresses share the same port. It blocks until the context is cancelled.
// Returns an error immediately if any address/port cannot be bound.
// Per RFC 8484: supports both POST (application/dns-message) and
// GET (?dns=<base64url>) methods. Supports HTTP/2 natively via Go's
// net/http TLS handling.
func ServeDoH(ctx context.Context, handler *Handler, cfg *config.Config, logger *logging.Logger) error {
	addrs := cfg.Downstream.DoH.ListenAddresses
	port := cfg.Downstream.DoH.Port
	if err := serveDoHAddresses(ctx, handler, addrs, port, cfg, logger); err != nil {
		return fmt.Errorf("DoH: %w", err)
	}
	return nil
}

// serveDoHAddresses starts an HTTP(S) server for each address in addrs on the
// given port. All servers share the same request mux. Returns an error if any
// address fails to bind.
func serveDoHAddresses(ctx context.Context, handler *Handler, addrs []string, port int, cfg *config.Config, logger *logging.Logger) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no listen addresses configured")
	}

	// Build request mux once; shared across all listeners.
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		dohHandler(w, r, handler, logger)
	})

	portStr := fmt.Sprintf("%d", port)
	servers := make([]*http.Server, 0, len(addrs))
	runErrCh := make(chan error, len(addrs))

	// Phase 1: bind each address synchronously so bind errors surface early.
	// Use tcp4/tcp6 to prevent dual-stack socket conflicts when both 0.0.0.0
	// and :: are configured (see networkForIP).
	for _, ip := range addrs {
		addr := net.JoinHostPort(ip, portStr)
		tcpNet, _ := networkForIP(ip)

		srv := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    4096,
		}

		if err := startDOHListenerGoroutine(srv, addr, tcpNet, cfg, logger, runErrCh); err != nil {
			return err
		}
		servers = append(servers, srv)
	}

	// Phase 2: wait for context cancellation or an unexpected runtime error.
	select {
	case <-ctx.Done():
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		for _, srv := range servers {
			if err := srv.Shutdown(shutCtx); err != nil {
				logger.Warnf("DoH server shutdown error: %v", err)
			}
		}
		return nil
	case err := <-runErrCh:
		return err
	}
}

// startDOHListenerGoroutine binds the TCP port synchronously (so the caller
// can rely on the port being open on return) and then hands the listener to
// http.Server.Serve in a background goroutine. Any serve error is forwarded
// to errCh; the initial listen error is returned directly so callers get
// immediate feedback without needing to poll errCh.
// tcpNet must be "tcp4" or "tcp6" to prevent dual-stack socket conflicts.
func startDOHListenerGoroutine(srv *http.Server, addr, tcpNet string, cfg *config.Config, logger *logging.Logger, errCh chan<- error) error {
	if cfg.Downstream.DoH.UsePlaintextHTTP {
		ln, err := net.Listen(tcpNet, addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		go func() {
			logger.Infof("DoH (HTTP plaintext) listening on %s", addr)
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("HTTP %s: %w", addr, err)
			}
		}()
		return nil
	}

	tlsCfg, err := loadTLSConfig(
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
		cfg.TLS.CertBase64,
		cfg.TLS.KeyBase64,
	)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}
	srv.TLSConfig = tlsCfg

	ln, err := net.Listen(tcpNet, addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	go func() {
		logger.Infof("DoH (HTTPS/HTTP2) listening on %s", addr)
		if err := srv.Serve(newTLSListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTPS %s: %w", addr, err)
		}
	}()
	return nil
}

// readDOHWireQuery extracts the raw DNS wire query from a DoH HTTP request.
// Supports:
//   - POST with Content-Type: application/dns-message (RFC 8484)
//   - GET with ?dns=<base64url> (RFC 8484)
//   - GET with ?name=<domain>&type=<type> with Accept: application/dns-json
//     (Google JSON DNS API, widely supported by clients)
func readDOHWireQuery(r *http.Request) ([]byte, int, string) {
	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			return nil, http.StatusUnsupportedMediaType, "Unsupported Media Type. POST must use Content-Type: application/dns-message."
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			return nil, http.StatusBadRequest, "Failed to read request body."
		}
		return body, http.StatusOK, ""
	case http.MethodGet:
		// RFC 8484: ?dns=<base64url>
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam != "" {
			wire, err := decodeBase64URL(dnsParam)
			if err != nil {
				return nil, http.StatusBadRequest, "Invalid base64url in ?dns= parameter."
			}
			return wire, http.StatusOK, ""
		}
		// JSON API: ?name=<domain>&type=<type>
		nameParam := r.URL.Query().Get("name")
		if nameParam != "" {
			wire, code, msg := buildQueryFromJSONParams(r)
			return wire, code, msg
		}
		return nil, http.StatusBadRequest, "Missing ?dns= or ?name= parameter. Use ?dns=<base64url> (RFC 8484) or ?name=<domain>&type=<type> (JSON API)."
	default:
		return nil, http.StatusMethodNotAllowed, "Method not allowed. DoH supports GET and POST only."
	}
}

// isJSONAccept returns true if the Accept header indicates DNS JSON format.
func isJSONAccept(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/dns-json")
}

// buildQueryFromJSONParams constructs a DNS wire query from ?name= and ?type=
// query parameters (Google JSON DNS API format).
func buildQueryFromJSONParams(r *http.Request) ([]byte, int, string) {
	name := r.URL.Query().Get("name")
	if name == "" {
		return nil, http.StatusBadRequest, "Missing ?name= parameter."
	}
	typeStr := r.URL.Query().Get("type")
	if typeStr == "" {
		typeStr = "A"
	}

	qtype := parseQueryType(typeStr)
	if qtype == 0 {
		return nil, http.StatusBadRequest, "Invalid type parameter."
	}

	name = dnsutil.Fqdn(name)
	query := dnsutil.SetQuestion(new(dns.Msg), name, qtype)
	if query == nil {
		// dnsutil.SetQuestion returns nil when qtype is valid (non-zero) but
		// not registered in dns.TypeToRR (e.g. meta-qtypes like ANY/255).
		return nil, http.StatusBadRequest, "Unsupported DNS type."
	}
	query.ID = 0 // RFC 8484 s4.1

	// Check for DO (DNSSEC) flag
	if doParam := r.URL.Query().Get("do"); doParam == "1" || strings.EqualFold(doParam, "true") {
		opt := &dns.OPT{}
		opt.Hdr.Name = "."
		opt.SetUDPSize(4096)
		opt.SetSecurity(true)
		query.Pseudo = append(query.Pseudo, opt)
	}

	if err := query.Pack(); err != nil {
		return nil, http.StatusInternalServerError, "Failed to build DNS query."
	}
	return query.Data, http.StatusOK, ""
}

// parseQueryType converts a type string (e.g., "A", "AAAA", "28") to a
// DNS type number.
func parseQueryType(s string) uint16 {
	// Try numeric first
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(n)
	}
	// Try standard name
	if t, ok := dns.StringToType[strings.ToUpper(s)]; ok {
		return t
	}
	return 0
}

// dohHandler processes a single DoH request per RFC 8484.
// Also supports the JSON DNS API (application/dns-json).
func dohHandler(w http.ResponseWriter, r *http.Request, handler *Handler, logger *logging.Logger) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Errorf("Panic in DoH handler: %v", rec)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()

	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	wantJSON := isJSONAccept(r)

	wireQuery, statusCode, errMsg := readDOHWireQuery(r)
	if statusCode != http.StatusOK {
		http.Error(w, errMsg, statusCode)
		return
	}

	// Parse the query
	query := new(dns.Msg)
	query.Data = wireQuery
	if err := query.Unpack(); err != nil {
		http.Error(w, "Invalid DNS message.", http.StatusBadRequest)
		return
	}

	// Save the client's DNS ID; RFC 8484: DNS ID should be 0 in wire format
	clientID := query.ID
	query.ID = 0

	resp := handler.HandleQuery(r.Context(), query)
	resp.ID = clientID

	// RFC 7828: TCP keepalive for DoH (always TCP-based)
	handler.edns.PrepareClientResponse(resp, true)

	// RFC 3225: echo back the client's DO bit in the response EDNS OPT.
	resp.Security = edns.ClientRequestsDNSSEC(query)

	if wantJSON {
		writeJSONResponse(w, resp, logger)
		return
	}

	if err := resp.Pack(); err != nil {
		logger.Warnf("Failed to pack DNS response: %v", err)
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	// RFC 8484 s5.1: use no-store for error responses that must not be
	// cached by intermediaries (SERVFAIL, REFUSED, etc.).
	if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", computeMaxAge(resp)))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(resp.Data); err != nil {
		logger.Debugf("Failed to write DoH response: %v", err)
	}
}

// decodeBase64URL decodes base64url (RFC 4648 section 5) with or without
// padding, as required by RFC 8484.
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// computeMaxAge extracts the minimum TTL from a DNS response for the
// Cache-Control header.
func computeMaxAge(msg *dns.Msg) int {
	min := 1800
	for _, rr := range msg.Answer {
		ttl := int(rr.Header().TTL)
		if ttl < min {
			min = ttl
		}
	}
	for _, rr := range msg.Ns {
		ttl := int(rr.Header().TTL)
		if ttl < min {
			min = ttl
		}
	}
	if min < 1 {
		min = 1
	}
	return min
}

// newTLSListener wraps a net.Listener with TLS.
func newTLSListener(ln net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(ln, cfg)
}

// --- JSON DNS API (application/dns-json) ---

// dnsJSONResponse is the JSON API response format compatible with
// Google/Cloudflare JSON DNS APIs.
type dnsJSONResponse struct {
	Status     int         `json:"Status"`
	TC         bool        `json:"TC"`
	RD         bool        `json:"RD"`
	RA         bool        `json:"RA"`
	AD         bool        `json:"AD"`
	CD         bool        `json:"CD"`
	Question   []dnsJSONRR `json:"Question,omitempty"`
	Answer     []dnsJSONRR `json:"Answer,omitempty"`
	Authority  []dnsJSONRR `json:"Authority,omitempty"`
	Additional []dnsJSONRR `json:"Additional,omitempty"`
	Comment    string      `json:"Comment,omitempty"`
}

type dnsJSONRR struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL,omitempty"`
	Data string `json:"data,omitempty"`
}

func writeJSONResponse(w http.ResponseWriter, resp *dns.Msg, logger *logging.Logger) {
	jr := dnsJSONResponse{
		Status: int(resp.Rcode),
		TC:     resp.Truncated,
		RD:     resp.RecursionDesired,
		RA:     resp.RecursionAvailable,
		AD:     resp.AuthenticatedData,
		CD:     resp.CheckingDisabled,
	}

	for _, q := range resp.Question {
		jr.Question = append(jr.Question, dnsJSONRR{
			Name: q.Header().Name,
			Type: dns.RRToType(q),
		})
	}
	jr.Answer = rrToJSON(resp.Answer)
	jr.Authority = rrToJSON(resp.Ns)
	jr.Additional = rrToJSON(resp.Extra)

	w.Header().Set("Content-Type", "application/dns-json")
	if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
		w.Header().Set("Cache-Control", "no-store")
	} else {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", computeMaxAge(resp)))
	}
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	if err := enc.Encode(jr); err != nil {
		logger.Debugf("Failed to write JSON DoH response: %v", err)
	}
}

func rrToJSON(rrs []dns.RR) []dnsJSONRR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dnsJSONRR, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, dnsJSONRR{
			Name: rr.Header().Name,
			Type: dns.RRToType(rr),
			TTL:  rr.Header().TTL,
			Data: rrDataString(rr),
		})
	}
	return out
}

// rrDataString returns the RDATA portion of an RR as a string.
func rrDataString(rr dns.RR) string {
	s := rr.String()
	// The String() format is "owner TTL CLASS TYPE rdata..."
	// We want everything after the type field.
	parts := strings.Fields(s)
	if len(parts) < 5 {
		return s
	}
	return strings.Join(parts[4:], " ")
}
