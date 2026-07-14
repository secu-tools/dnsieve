// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/edns"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// plainHandler adapts our Handler to the dns.Handler interface.
type plainHandler struct {
	handler  *Handler
	protocol string // "plain" or "dot"
}

func (h *plainHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			h.handler.logger.Errorf("Panic in DNS handler: %v", rec)
			resp := new(dns.Msg)
			resp.Response = true
			resp.Rcode = dns.RcodeServerFailure
			if r != nil {
				resp.ID = r.ID
				resp.Question = r.Question
			}
			if _, err := resp.WriteTo(w); err != nil {
				h.handler.logger.Warnf("Failed to write panic SERVFAIL: %v", err)
			}
		}
	}()

	// The DNS library's server does a partial unpack (question only) before
	// calling ServeDNS. Complete the unpack so that EDNS options (ECS, NSID,
	// cookies, DO bit, buffer size) are available in r.Pseudo and r.Security.
	if err := r.Unpack(); err != nil {
		h.handler.logger.Warnf("Failed to complete DNS message unpack: %v", err)
	}

	// Attach client metadata to the context for structured logging.
	ip, port := parseRemoteAddr(w.RemoteAddr())
	proto := h.protocol
	if proto == "" {
		proto = "plain"
	}
	ctx = WithClientMeta(ctx, &ClientMeta{IP: ip, Port: port, Protocol: proto})

	isTCP := isTransportTCP(w)

	resp := h.handler.HandleQuery(ctx, r)

	// RFC 7828: add TCP keepalive to TCP/TLS responses.
	// RFC 9715: advertise the proxy's UDP buffer size in all responses.
	// RFC 6891: only emit an OPT record when the client sent one.
	// RFC 7830/8467: add padding to TCP responses when client requested it.
	h.handler.edns.PrepareClientResponse(resp, isTCP, edns.ClientHasEDNS(r), edns.ClientHasPadding(r))

	// RFC 3225: echo back the client's DO bit in the response EDNS OPT.
	// The proxy always queries upstream with DO=1 for DNSSEC validation, but
	// the response to the client must reflect what the client originally asked.
	resp.Security = edns.ClientRequestsDNSSEC(r)

	// RFC 6891/9715: truncate if response exceeds the client's advertised UDP buffer.
	if !isTCP && edns.NeedsTruncation(resp, false, r.UDPSize) {
		resp = edns.MakeTruncatedResponse(r)
	}

	// Clear pre-packed wire bytes so WriteTo calls Pack() fresh.
	// DoH upstreams return Data with ID=0 (RFC 8484); the struct ID is
	// updated by HandleQuery, but Data must also reflect the change.
	resp.Data = nil
	if _, err := resp.WriteTo(w); err != nil {
		h.handler.logger.Warnf("Failed to write DNS response: %v", err)
	}
}

// isTransportTCP returns true if the ResponseWriter is using TCP.
func isTransportTCP(w dns.ResponseWriter) bool {
	if addr := w.RemoteAddr(); addr != nil {
		_, ok := addr.(*net.TCPAddr)
		return ok
	}
	return false
}

// networkForIP returns explicit TCP and UDP network type strings for the given
// listen IP address. Using "tcp6"/"udp6" for IPv6 addresses and "tcp4"/"udp4"
// for IPv4 addresses prevents dual-stack socket conflicts on systems where
// binding "::" with a generic "tcp"/"udp" socket also claims 0.0.0.0, causing
// a "bind: address already in use" error when both addresses are configured.
func networkForIP(ip string) (tcpNet, udpNet string) {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return "tcp6", "udp6"
	}
	return "tcp4", "udp4"
}

// cleanBindErr strips the redundant "listen proto addr: " prefix that
// net.OpError adds when a server fails to bind a socket. The caller already
// reports the protocol and address, so the net.OpError wrapper is pure
// duplication. Returns the underlying syscall error when available.
func cleanBindErr(err error) error {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return err
	}
	var sErr *os.SyscallError
	if errors.As(opErr.Err, &sErr) {
		return sErr.Err
	}
	if opErr.Err != nil {
		return opErr.Err
	}
	return err
}

// ServePlain starts UDP and TCP DNS listeners on every configured address.
// All addresses share the same port. It blocks until the context is cancelled.
// Returns an error immediately if any address/port cannot be bound.
func ServePlain(ctx context.Context, handler *Handler, cfg *config.Config, logger *logging.Logger) error {
	addrs := cfg.Downstream.Plain.ListenAddresses
	port := cfg.Downstream.Plain.Port
	if err := servePlainAddresses(ctx, handler, addrs, port, logger); err != nil {
		return fmt.Errorf("plain DNS: %w", err)
	}
	return nil
}

// servePlainAddresses starts UDP+TCP listeners for each address in addrs on
// the given port. It returns an error if any address fails to bind. All
// successfully started servers are shut down when ctx is cancelled.
func servePlainAddresses(ctx context.Context, handler *Handler, addrs []string, port int, logger *logging.Logger) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no listen addresses configured")
	}

	ph := &plainHandler{handler: handler, protocol: "plain"}

	type serverPair struct {
		udp *dns.Server
		tcp *dns.Server
	}

	pairs := make([]serverPair, 0, len(addrs))
	portStr := fmt.Sprintf("%d", port)

	// shutdownStarted shuts down all successfully-bound pairs and the two
	// servers for the current address (which may not yet be in pairs).
	// Called on early bind error to prevent goroutine leaks.
	//
	// udpReady/tcpReady are closed by NotifyStartedFunc when the server is up.
	// udpFailed/tcpFailed are closed when ListenAndServe returns with an error.
	// We wait for init() to complete on both servers before calling Shutdown()
	// to prevent a DATA RACE between ListenAndServe's internal init() writes
	// and Shutdown's reads (detected by -race on the bind-failure error path).
	shutdownStarted := func(udpSrv, tcpSrv *dns.Server,
		udpReady, udpFailed, tcpReady, tcpFailed <-chan struct{}) {
		waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
		defer waitCancel()
		// Wait for UDP init() to finish (success -> udpReady, failure -> udpFailed).
		select {
		case <-udpReady:
		case <-udpFailed:
		case <-waitCtx.Done():
		}
		// Wait for TCP init() to finish.
		select {
		case <-tcpReady:
		case <-tcpFailed:
		case <-waitCtx.Done():
		}
		shutCtx, shutCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutCancel()
		for _, p := range pairs {
			p.udp.Shutdown(shutCtx)
			p.tcp.Shutdown(shutCtx)
		}
		if udpSrv != nil {
			udpSrv.Shutdown(shutCtx)
		}
		if tcpSrv != nil {
			tcpSrv.Shutdown(shutCtx)
		}
	}

	// Phase 1: bind all sockets synchronously so that any bind failure is
	// returned before any goroutines are started.
	for _, ip := range addrs {
		addr := net.JoinHostPort(ip, portStr)
		tcpNet, udpNet := networkForIP(ip)

		udpReady := make(chan struct{})
		tcpReady := make(chan struct{})

		udpSrv := &dns.Server{
			Addr:              addr,
			Net:               udpNet,
			Handler:           ph,
			NotifyStartedFunc: func(_ context.Context) { close(udpReady) },
		}
		tcpSrv := &dns.Server{
			Addr:              addr,
			Net:               tcpNet,
			Handler:           ph,
			NotifyStartedFunc: func(_ context.Context) { close(tcpReady) },
		}

		udpFailed := make(chan struct{})
		tcpFailed := make(chan struct{})

		errCh := make(chan error, 2)

		go func() {
			if err := udpSrv.ListenAndServe(); err != nil {
				close(udpFailed)
				errCh <- fmt.Errorf("bind UDP %s: %w", addr, cleanBindErr(err))
			}
		}()
		go func() {
			if err := tcpSrv.ListenAndServe(); err != nil {
				close(tcpFailed)
				errCh <- fmt.Errorf("bind TCP %s: %w", addr, cleanBindErr(err))
			}
		}()

		// Wait until both servers are ready or the first error occurs.
		udpRdy, tcpRdy := udpReady, tcpReady
		for udpRdy != nil || tcpRdy != nil {
			select {
			case <-udpRdy:
				udpRdy = nil
				logger.Infof("Plain DNS (UDP) listening on %s", addr)
			case <-tcpRdy:
				tcpRdy = nil
				logger.Infof("Plain DNS (TCP) listening on %s", addr)
			case err := <-errCh:
				// Shut down any already-started servers in the background so the
				// error is returned immediately and callers are not blocked.
				go shutdownStarted(udpSrv, tcpSrv, udpReady, udpFailed, tcpReady, tcpFailed)
				return err
			}
		}

		pairs = append(pairs, serverPair{udp: udpSrv, tcp: tcpSrv})
	}

	// Phase 2: wait for context cancellation.
	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	for _, p := range pairs {
		p.udp.Shutdown(shutCtx)
		p.tcp.Shutdown(shutCtx)
	}
	return nil
}
