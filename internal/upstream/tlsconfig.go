// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import "crypto/tls"

// sessionCacheSize bounds the per-client TLS session cache. crypto/tls keys it
// by ServerName and each client talks to one upstream, so this is never full.
const sessionCacheSize = 4

// newUpstreamTLSConfig builds the TLS client configuration shared by the DoT
// and DoH upstream transports, so the two cannot drift apart on protocol
// version, cipher suites or curves.
//
// serverName sets SNI and is the session-cache key. DoT passes the upstream
// hostname; DoH passes "" and lets net/http derive it from the request URL.
func newUpstreamTLSConfig(serverName string, verifyCert bool) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
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
		// RFC 8446 Section 2.2 / RFC 5077: resume instead of a full handshake
		// when the idle pool cannot serve a request. Resumption omits the
		// certificate chain, the bulk of the handshake.
		ClientSessionCache: tls.NewLRUClientSessionCache(sessionCacheSize),
	}
}
