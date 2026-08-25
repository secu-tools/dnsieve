// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// countingTLSServer starts a DoT test server that counts accepted connections.
// The accept count is what matters for upstream data volume: each connection
// costs a handshake far larger than the DNS message it carries.
func countingTLSServer(t *testing.T, handler func(q *dns.Msg) *dns.Msg) (addr string, accepts func() int64) {
	t.Helper()
	var count atomic.Int64
	addr = startTLSDNSServerHook(t, generateSelfSignedCert(t), handler, func(net.Conn) {
		count.Add(1)
	})
	return addr, count.Load
}

// newTestDoTClient builds a DoTClient aimed at a local test server, skipping
// certificate verification for the self-signed test certificate.
func newTestDoTClient(t *testing.T, addr string) *DoTClient {
	t.Helper()
	c, err := NewDoTClient(addr, false, "auto", resolveDisabled, 0, nil)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func testQuery(name string) *dns.Msg {
	return dnsutil.SetQuestion(new(dns.Msg), name, dns.TypeA)
}

// query runs one DoT query with a bounded context.
func query(c *DoTClient, name string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.Query(ctx, testQuery(name))
}

// Core regression test: DoT once dialled a new TLS connection per query, so N
// queries cost N full handshakes (RFC 7858 Section 3.4 requires reuse).
func TestDoTReusesConnectionAcrossQueries(t *testing.T) {
	addr, accepts := countingTLSServer(t, makeSuccessResponse)
	c := newTestDoTClient(t, addr)

	const queries = 20
	for i := 0; i < queries; i++ {
		resp, err := query(c, "example.com.")
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if resp == nil || len(resp.Answer) == 0 {
			t.Fatalf("query %d: empty response", i)
		}
	}

	if got := accepts(); got != 1 {
		t.Errorf("server accepted %d connections for %d sequential queries, want 1", got, queries)
	}

	dials, reuses := c.pool.stats()
	if dials != 1 {
		t.Errorf("dials = %d, want 1", dials)
	}
	if reuses != queries-1 {
		t.Errorf("reuses = %d, want %d", reuses, queries-1)
	}
}

// TestDoTConcurrentQueriesBoundedByPool verifies that concurrent load does not
// degenerate into one connection per query.
func TestDoTConcurrentQueriesBoundedByPool(t *testing.T) {
	addr, accepts := countingTLSServer(t, makeSuccessResponse)
	c := newTestDoTClient(t, addr)

	// Warm the pool so the steady-state path is measured.
	if _, err := query(c, "warm.example.com."); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	const rounds, workers = 10, 4
	var wg sync.WaitGroup
	errs := make(chan error, rounds*workers)
	for r := 0; r < rounds; r++ {
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := query(c, "example.com."); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
	}
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent query: %v", err)
	}

	total := int64(rounds*workers + 1)
	// Concurrency can force extra dials up to the pool size, but the count
	// must stay far below one connection per query.
	if got := accepts(); got > int64(defaultMaxIdleConns)+1 {
		t.Errorf("server accepted %d connections for %d queries, want <= %d",
			got, total, defaultMaxIdleConns+1)
	}
}

// The upstream closes a pooled connection while idle; the next query must
// redial transparently rather than surfacing an error.
func TestDoTRecoversFromServerClosedConnection(t *testing.T) {
	var conns sync.Map // net.Conn -> struct{}
	addr := startTLSDNSServerHook(t, generateSelfSignedCert(t), makeSuccessResponse, func(conn net.Conn) {
		conns.Store(conn, struct{}{})
	})
	c := newTestDoTClient(t, addr)

	if _, err := query(c, "first.example.com."); err != nil {
		t.Fatalf("first query: %v", err)
	}

	// Simulate the peer dropping the idle connection.
	conns.Range(func(k, _ any) bool {
		k.(net.Conn).Close()
		return true
	})
	// Give the close time to propagate to the client side.
	time.Sleep(50 * time.Millisecond)

	resp, err := query(c, "second.example.com.")
	if err != nil {
		t.Fatalf("query after peer close must transparently redial, got: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("empty response after redial")
	}
}

// A connection whose exchange failed must never be pooled: its protocol state
// is unknown and reuse would desynchronise a later query's framing.
func TestDoTDoesNotPoolConnectionAfterError(t *testing.T) {
	// The handler returns nil, which makes the test server close the
	// connection without writing a response.
	addr, _ := countingTLSServer(t, func(*dns.Msg) *dns.Msg { return nil })
	c := newTestDoTClient(t, addr)

	if _, err := query(c, "example.com."); err == nil {
		t.Fatal("expected an error when the server closes without responding")
	}

	if got := c.pool.get(addr); got != nil {
		t.Error("a failed connection was returned to the pool")
	}
}

// TestDoTQueryTimeoutExpired verifies that an already-expired context is
// rejected before any connection work happens.
func TestDoTQueryTimeoutExpired(t *testing.T) {
	addr, accepts := countingTLSServer(t, makeSuccessResponse)
	c := newTestDoTClient(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()

	if _, err := c.Query(ctx, testQuery("example.com.")); err == nil {
		t.Fatal("expected an error for an expired context")
	}
	if got := accepts(); got != 0 {
		t.Errorf("server accepted %d connections for an expired context, want 0", got)
	}
}

// TestQueryTimeoutDefaults checks the deadline derivation helper.
func TestQueryTimeoutDefaults(t *testing.T) {
	got, err := queryTimeout(context.Background())
	if err != nil {
		t.Fatalf("queryTimeout: %v", err)
	}
	if got != defaultQueryTimeout {
		t.Errorf("timeout = %v, want %v", got, defaultQueryTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	got, err = queryTimeout(ctx)
	if err != nil {
		t.Fatalf("queryTimeout: %v", err)
	}
	if got <= 0 || got > time.Hour {
		t.Errorf("timeout = %v, want a positive value <= 1h", got)
	}

	expired, cancelExpired := context.WithTimeout(context.Background(), -time.Second)
	defer cancelExpired()
	if _, err := queryTimeout(expired); err == nil {
		t.Error("expected an error for an expired context")
	}
}

// When a new connection is unavoidable, resumption avoids re-sending the
// certificate chain, which dominates DoT handshake bytes.
func TestDoTSessionCacheConfigured(t *testing.T) {
	c, err := NewDoTClient("dns.example.com:853", true, "auto", resolveDisabled, 0, nil)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}
	defer c.Close()
	if c.tlsConfig.ClientSessionCache == nil {
		t.Error("ClientSessionCache is nil; every new connection would perform a full handshake")
	}
}

// Regression test for a leak: internal/speed probes a throwaway client per
// upstream at startup and drops it. Expiry was once evaluated only inside
// get(), so such a pool held its sockets until process exit.
func TestDoTAbandonedClientReleasesConnections(t *testing.T) {
	addr, _ := countingTLSServer(t, makeSuccessResponse)

	c, err := NewDoTClient(addr, false, "auto", resolveDisabled, 0, nil)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}
	// Shorten the idle window so the test does not wait defaultIdleTimeout.
	c.pool = newConnPool(defaultMaxIdleConns, 20*time.Millisecond)

	if _, err := query(c, "example.com."); err != nil {
		t.Fatalf("query: %v", err)
	}
	if idle := c.pool.idleLen(); idle != 1 {
		t.Fatalf("pooled connections after one query = %d, want 1", idle)
	}

	// From here the client is never queried again and never closed, exactly as
	// the startup probe leaves it. The pool must still release its sockets.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.pool.idleLen() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("abandoned client still holds %d pooled connection(s) past the idle timeout", c.pool.idleLen())
}

// TestDoTCloseReleasesPooledConnections covers the explicit lifecycle path now
// that Client carries Close().
func TestDoTCloseReleasesPooledConnections(t *testing.T) {
	addr, _ := countingTLSServer(t, makeSuccessResponse)
	c, err := NewDoTClient(addr, false, "auto", resolveDisabled, 0, nil)
	if err != nil {
		t.Fatalf("NewDoTClient: %v", err)
	}
	if _, err := query(c, "example.com."); err != nil {
		t.Fatalf("query: %v", err)
	}

	c.Close()

	if got := c.pool.get(addr); got != nil {
		t.Error("Close() left a connection in the pool")
	}
	c.Close() // must be safe to call twice
}

// Guards the retry path: ExchangeWithConn aliases its reply buffer onto
// msg.Data, so a failed attempt can leave the query bytes overwritten and the
// retry would transmit them. Query clears Data so the retry re-packs.
func TestDoTRetryAfterPooledFailureSendsCorrectQuery(t *testing.T) {
	var n atomic.Int64
	var lastQname atomic.Value
	lastQname.Store("")

	addr, _ := countingTLSServer(t, func(q *dns.Msg) *dns.Msg {
		i := n.Add(1)
		if len(q.Question) > 0 {
			lastQname.Store(q.Question[0].Header().Name)
		}
		resp := makeSuccessResponse(q)
		if i == 2 {
			// Second query lands on the pooled connection; a mismatched ID
			// fails the exchange without closing the stream at EOF.
			resp.ID = q.ID + 1
		}
		return resp
	})
	c := newTestDoTClient(t, addr)

	if _, err := query(c, "first.example.com."); err != nil {
		t.Fatalf("warmup: %v", err)
	}
	if _, err := query(c, "second.example.com."); err != nil {
		t.Fatalf("retry on a fresh connection should succeed, got: %v", err)
	}

	if got := lastQname.Load().(string); got != "second.example.com." {
		t.Errorf("retry transmitted qname %q, want %q", got, "second.example.com.")
	}
}

// After a failed pooled attempt the message must not carry stale wire bytes
// into the retry.
func TestDoTQueryClearsDataForRepack(t *testing.T) {
	var n atomic.Int64
	addr, _ := countingTLSServer(t, func(q *dns.Msg) *dns.Msg {
		resp := makeSuccessResponse(q)
		if n.Add(1) == 2 {
			resp.ID = q.ID + 1
		}
		return resp
	})
	c := newTestDoTClient(t, addr)

	if _, err := query(c, "warm.example.com."); err != nil {
		t.Fatalf("warmup: %v", err)
	}

	msg := dnsutil.SetQuestion(new(dns.Msg), "check.example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Query(ctx, msg)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatal("empty response after retry")
	}
	// The answer must correspond to the question actually asked.
	if len(resp.Question) > 0 && resp.Question[0].Header().Name != "check.example.com." {
		t.Errorf("response question = %q, want check.example.com.", resp.Question[0].Header().Name)
	}
}
