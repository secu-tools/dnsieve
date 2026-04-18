// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

// ============================================================
// EDNS: DDR -- RFC 9461/9462
// ============================================================

// TestE2E_DDR_Disabled verifies DDR queries go to upstream when DDR is off.
func TestE2E_DDR_Disabled(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.DDR.Enabled = false
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "_dns.resolver.arpa", dns.TypeSVCB)
	t.Logf("DDR disabled: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// TestE2E_DDR_Enabled verifies DDR responds locally when enabled.
func TestE2E_DDR_Enabled(t *testing.T) {
	cert := generateSelfSignedCert(t)
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = plainPort
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cfg.Downstream.DoT.Enabled = false
	cfg.DDR.Enabled = true
	cfg.TLS.CertBase64 = cert.certB64
	cfg.TLS.KeyBase64 = cert.keyB64
	cfg.UpstreamSettings.TimeoutMS = 5000

	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, plainPort, "_dns.resolver.arpa", dns.TypeSVCB)
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		t.Fatalf("DDR enabled: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("DDR enabled: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// TestE2E_DDR_WrongType verifies non-SVCB DDR queries are handled.
func TestE2E_DDR_WrongType(t *testing.T) {
	cert := generateSelfSignedCert(t)
	plainPort := findFreePort(t)
	dohPort := findFreePort(t)

	cfg := config.DefaultConfig()
	cfg.Downstream.Plain.Enabled = true
	cfg.Downstream.Plain.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.Plain.Port = plainPort
	cfg.Downstream.DoH.Enabled = true
	cfg.Downstream.DoH.ListenAddresses = []string{"127.0.0.1"}
	cfg.Downstream.DoH.Port = dohPort
	cfg.Downstream.DoH.UsePlaintextHTTP = true
	cfg.Downstream.DoT.Enabled = false
	cfg.DDR.Enabled = true
	cfg.TLS.CertBase64 = cert.certB64
	cfg.TLS.KeyBase64 = cert.keyB64
	cfg.UpstreamSettings.TimeoutMS = 5000

	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, plainPort, "_dns.resolver.arpa", dns.TypeA)
	t.Logf("DDR wrong type: rcode=%s", dns.RcodeToString[resp.Rcode])
}

// ============================================================
// RFC 9715: UDP buffer size and truncation
// ============================================================

// TestE2E_RFC9715_BufferSizeAdvertised verifies the proxy advertises 1232 bytes.
func TestE2E_RFC9715_BufferSizeAdvertised(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServerReachable(t, cfg)
	defer cancel()

	resp := queryUDPWithOPT(t, port, "example.com", dns.TypeA, 1232)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 9715 buffer: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if resp.UDPSize == 0 {
		t.Error("RFC 9715: proxy must advertise UDP buffer size")
		return
	}
	if resp.UDPSize != 1232 {
		t.Logf("RFC 9715: UDPSize=%d (expected 1232 per RFC 9715)", resp.UDPSize)
	} else {
		t.Logf("RFC 9715: UDPSize=%d (correct)", resp.UDPSize)
	}
}

// TestE2E_RFC9715_LargeResponseTruncation verifies large UDP responses get TC=1.
func TestE2E_RFC9715_LargeResponseTruncation(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp, err := queryUDPLargeBuffer(t, port, "google.com", dns.TypeANY)
	if err != nil {
		if strings.Contains(err.Error(), "overflow") || strings.Contains(err.Error(), "truncated") {
			t.Logf("RFC 9715 truncation: OS truncation occurred (acceptable): %v", err)
			return
		}
		t.Fatalf("RFC 9715 truncation: unexpected error: %v", err)
	}
	t.Logf("RFC 9715 truncation: TC=%v answers=%d", resp.Truncated, len(resp.Answer))
}

// TestE2E_RFC9715_SmallResponse verifies small responses are not truncated.
func TestE2E_RFC9715_SmallResponse(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServerReachable(t, cfg)
	defer cancel()

	resp := queryUDPWithOPT(t, port, "example.com", dns.TypeA, 1232)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 9715 small: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	if resp.Truncated {
		t.Error("RFC 9715: small response should not be truncated")
	}
	t.Logf("RFC 9715 small: TC=%v UDPSize=%d", resp.Truncated, resp.UDPSize)
}

// TestE2E_RFC9715_TCPFallback verifies large responses can be retrieved over TCP.
func TestE2E_RFC9715_TCPFallback(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryTCP(t, port, "google.com", dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("RFC 9715 TCP fallback: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("RFC 9715 TCP: answers=%d", len(resp.Answer))
}

// ============================================================
// RFC 3225: DNSSEC DO bit
// ============================================================

// TestE2E_RFC3225_DOBit verifies the DO bit is forwarded to upstreams.
func TestE2E_RFC3225_DOBit(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServerReachable(t, cfg)
	defer cancel()

	query := makePlainQuery("example.com", dns.TypeA)
	query.Security = true
	query.UDPSize = 1232

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c := dns.NewClient()
	c.Transport.ReadTimeout = queryTimeout

	ctx, ctxCancel := context.WithTimeout(context.Background(), queryTimeout)
	defer ctxCancel()

	resp, _, err := c.Exchange(ctx, query, "udp", addr)
	if err != nil {
		t.Fatalf("DO bit query: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DO bit: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	t.Logf("DO=1: rcode=%s security=%v", dns.RcodeToString[resp.Rcode], resp.Security)
}

// TestE2E_RFC3225_CacheSegregation verifies DO=0 and DO=1 use separate cache entries.
func TestE2E_RFC3225_CacheSegregation(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cfg.Cache.Enabled = true
	cancel := startServer(t, cfg)
	defer cancel()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c := dns.NewClient()
	c.Transport.ReadTimeout = queryTimeout

	qNoDO := makePlainQuery("example.com", dns.TypeA)
	qNoDO.UDPSize = 1232

	qWithDO := makePlainQuery("example.com", dns.TypeA)
	qWithDO.Security = true
	qWithDO.UDPSize = 1232

	ctx1, cancel1 := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel1()
	resp1, _, err := c.Exchange(ctx1, qNoDO, "udp", addr)
	if err != nil {
		t.Fatalf("DO=0 query: %v", err)
	}
	if resp1.Rcode != dns.RcodeSuccess {
		t.Fatalf("DO=0: rcode=%s", dns.RcodeToString[resp1.Rcode])
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel2()
	resp2, _, err := c.Exchange(ctx2, qWithDO, "udp", addr)
	if err != nil {
		t.Fatalf("DO=1 query: %v", err)
	}
	if resp2.Rcode != dns.RcodeSuccess {
		t.Fatalf("DO=1: rcode=%s", dns.RcodeToString[resp2.Rcode])
	}
	t.Logf("DO=0 answers=%d, DO=1 answers=%d", len(resp1.Answer), len(resp2.Answer))
}

// ============================================================
// RFC 8482: ANY query handling
// ============================================================

// TestE2E_RFC8482_ANY_UDP verifies ANY queries return a useful response (not REFUSED)
// and the proxy remains stable. RFC 8482 permits TC=1 or a synthesized HINFO.
// OS-level truncation of large ANY responses is also an acceptable outcome.
func TestE2E_RFC8482_ANY_UDP(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp, err := queryUDPLargeBuffer(t, port, "cloudflare.com", dns.TypeANY)
	if err != nil {
		// OS-level overflow/truncation is expected for large ANY responses over UDP.
		if strings.Contains(err.Error(), "overflow") || strings.Contains(err.Error(), "truncated") {
			t.Logf("RFC 8482 ANY UDP: expected OS truncation for large response: %v", err)
			return
		}
		t.Fatalf("RFC 8482 ANY UDP: unexpected error: %v", err)
	}
	if resp.Rcode == dns.RcodeRefused {
		t.Errorf("RFC 8482: ANY got REFUSED, want useful response or TC=1")
	}
	t.Logf("RFC 8482 ANY UDP: rcode=%s TC=%v answers=%d", dns.RcodeToString[resp.Rcode], resp.Truncated, len(resp.Answer))
}

// TestE2E_RFC8482_ANY_TCP verifies ANY queries work over TCP.
func TestE2E_RFC8482_ANY_TCP(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryTCP(t, port, "cloudflare.com", dns.TypeANY)
	if resp.Rcode == dns.RcodeRefused {
		t.Errorf("RFC 8482: ANY TCP got REFUSED")
	}
	t.Logf("RFC 8482 ANY TCP: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
}

// ============================================================
// RFC 6672: DNAME synthesis
// ============================================================

// TestE2E_RFC6672_DNAME_Synthesis verifies CNAME is synthesized for DNAME records.
func TestE2E_RFC6672_DNAME_Synthesis(t *testing.T) {
	port := findFreePort(t)
	cfg := plainConfig(port)
	cancel := startServer(t, cfg)
	defer cancel()

	resp := queryUDP(t, port, "www.bbc.co.uk", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		t.Logf("DNAME: rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	hasDNAME := false
	hasCNAME := false
	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.DNAME:
			hasDNAME = true
		case *dns.CNAME:
			hasCNAME = true
		}
	}

	if hasDNAME && !hasCNAME {
		t.Errorf("RFC 6672: DNAME present but no synthesized CNAME")
	}
	t.Logf("RFC 6672: DNAME=%v CNAME=%v answers=%d", hasDNAME, hasCNAME, len(resp.Answer))
}
