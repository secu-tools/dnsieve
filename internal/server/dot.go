// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"time"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
	"github.com/secu-tools/dnsieve/internal/logging"
)

// ServeDoT starts DNS-over-TLS listeners on every configured address.
// All addresses share the same port. It blocks until the context is cancelled.
// Returns an error immediately if any address/port cannot be bound.
// Per RFC 7858: DNS messages are sent over TLS using standard TCP wire
// format (2-byte length prefix). Default port is 853.
func ServeDoT(ctx context.Context, handler *Handler, cfg *config.Config, logger *logging.Logger) error {
	tlsCfg, err := loadTLSConfig(
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
		cfg.TLS.CertBase64,
		cfg.TLS.KeyBase64,
	)
	if err != nil {
		return fmt.Errorf("DoT: TLS config: %w", err)
	}

	addrs := cfg.Downstream.DoT.ListenAddresses
	port := cfg.Downstream.DoT.Port
	if err := serveDoTAddresses(ctx, handler, addrs, port, tlsCfg, logger); err != nil {
		return fmt.Errorf("DoT: %w", err)
	}
	return nil
}

// serveDoTAddresses starts a TLS-TCP DNS server for each address in addrs on
// the given port. Returns an error if any address fails to bind.
func serveDoTAddresses(ctx context.Context, handler *Handler, addrs []string, port int, tlsCfg *tls.Config, logger *logging.Logger) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no listen addresses configured")
	}

	ph := &plainHandler{handler: handler}
	portStr := fmt.Sprintf("%d", port)
	servers := make([]*dns.Server, 0, len(addrs))

	// Phase 1: bind all sockets synchronously so bind errors surface early.
	// Use tcp4/tcp6 to prevent dual-stack socket conflicts when both 0.0.0.0
	// and :: are configured (see networkForIP).
	for _, ip := range addrs {
		addr := net.JoinHostPort(ip, portStr)
		tcpNet, _ := networkForIP(ip)

		ready := make(chan struct{})
		srv := &dns.Server{
			Addr:              addr,
			Net:               tcpNet,
			TLSConfig:         tlsCfg,
			Handler:           ph,
			NotifyStartedFunc: func(_ context.Context) { close(ready) },
		}

		errCh := make(chan error, 1)
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				errCh <- fmt.Errorf("bind TCP %s: %w", addr, err)
			}
		}()

		select {
		case <-ready:
			logger.Infof("DoT (DNS-over-TLS) listening on %s", addr)
		case err := <-errCh:
			return err
		}

		servers = append(servers, srv)
	}

	// Phase 2: wait for context cancellation.
	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	for _, srv := range servers {
		srv.Shutdown(shutCtx)
	}
	return nil
}

// loadTLSConfig creates a tls.Config from either file paths or base64-encoded
// PEM data. File paths take precedence over base64 content.
func loadTLSConfig(certFile, keyFile, certB64, keyB64 string) (*tls.Config, error) {
	var certPEM, keyPEM []byte

	if certFile != "" && keyFile != "" {
		var err error
		certPEM, err = os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("read cert file %s: %w", certFile, err)
		}
		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file %s: %w", keyFile, err)
		}
	} else if certB64 != "" && keyB64 != "" {
		var err error
		certPEM, err = base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			return nil, fmt.Errorf("decode cert base64: %w", err)
		}
		keyPEM, err = base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("decode key base64: %w", err)
		}
	} else {
		return nil, fmt.Errorf("TLS certificate and key are required. " +
			"Provide cert_file/key_file or cert_base64/key_base64 in config")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites are automatically included by Go.
			// Below are strong TLS 1.2 cipher suites only.
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
	}, nil
}
