// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const testAddr = "10.0.0.1:853"

// fakeConn is a net.Conn stub that records whether it was closed.
type fakeConn struct {
	net.Conn
	closed atomic.Bool
}

func (f *fakeConn) Close() error {
	f.closed.Store(true)
	return nil
}

// newTestPool returns a pool with a long idle timeout, so the reaper never
// fires during a test that is not about expiry.
func newTestPool(maxIdle int) *connPool {
	return newConnPool(maxIdle, time.Minute)
}

func TestConnPoolReusesConnection(t *testing.T) {
	p := newTestPool(4)
	c := &fakeConn{}

	p.put(testAddr, c)
	got := p.get(testAddr)

	if got != net.Conn(c) {
		t.Fatalf("get() = %v, want the pooled connection", got)
	}
	if c.closed.Load() {
		t.Error("pooled connection was closed instead of reused")
	}
	if _, reuses := p.stats(); reuses != 1 {
		t.Errorf("reuses = %d, want 1", reuses)
	}
}

func TestConnPoolEmptyReturnsNil(t *testing.T) {
	p := newTestPool(4)
	if got := p.get(testAddr); got != nil {
		t.Errorf("get() on empty pool = %v, want nil", got)
	}
}

func TestConnPoolClosesOverflow(t *testing.T) {
	p := newTestPool(2)
	a, b, c := &fakeConn{}, &fakeConn{}, &fakeConn{}

	p.put(testAddr, a)
	p.put(testAddr, b)
	p.put(testAddr, c) // exceeds maxIdle

	if !c.closed.Load() {
		t.Error("overflow connection was not closed")
	}
	if a.closed.Load() || b.closed.Load() {
		t.Error("pooled connections were closed while under the cap")
	}
}

func TestConnPoolReturnsMostRecentFirst(t *testing.T) {
	// The most recently returned connection has had the least time to be
	// closed by the peer, so it must be handed out first.
	p := newTestPool(4)
	older, newer := &fakeConn{}, &fakeConn{}
	p.put(testAddr, older)
	p.put(testAddr, newer)

	if got := p.get(testAddr); got != net.Conn(newer) {
		t.Error("get() did not return the most recently pooled connection")
	}
}

func TestConnPoolCloseClosesIdleAndBlocksReuse(t *testing.T) {
	p := newTestPool(4)
	c := &fakeConn{}
	p.put(testAddr, c)

	p.close()

	if !c.closed.Load() {
		t.Error("close() did not close the idle connection")
	}
	if got := p.get(testAddr); got != nil {
		t.Errorf("get() after close = %v, want nil", got)
	}

	// put() on a closed pool must close the connection rather than retain it.
	c2 := &fakeConn{}
	p.put(testAddr, c2)
	if !c2.closed.Load() {
		t.Error("put() on a closed pool did not close the connection")
	}
}

func TestConnPoolCloseIsIdempotent(t *testing.T) {
	p := newTestPool(4)
	p.put(testAddr, &fakeConn{})
	p.close()
	p.close() // must not panic or double-close
}

func TestConnPoolPutNilIsNoop(t *testing.T) {
	p := newTestPool(4)
	p.put(testAddr, nil)
	if got := p.get(testAddr); got != nil {
		t.Errorf("get() = %v, want nil after put(nil)", got)
	}
}

// Re-resolution moves an upstream to a new IP: connections to the old peer
// must never carry a query to the new one.
func TestConnPoolDiscardsConnectionsOnAddressChange(t *testing.T) {
	p := newTestPool(4)
	old := &fakeConn{}
	p.put("10.0.0.1:853", old)

	if got := p.get("10.0.0.2:853"); got != nil {
		t.Error("get() for a new address returned a connection to the old one")
	}
	if !old.closed.Load() {
		t.Error("connection to the previous address was not closed")
	}

	// The pool stays usable for the new address.
	fresh := &fakeConn{}
	p.put("10.0.0.2:853", fresh)
	if got := p.get("10.0.0.2:853"); got != net.Conn(fresh) {
		t.Error("pool did not serve a connection for the new address")
	}
}

// A connection returned after the upstream address has already moved.
func TestConnPoolPutRejectsStaleAddress(t *testing.T) {
	p := newTestPool(4)
	p.get("10.0.0.2:853") // adopt the new address

	stale := &fakeConn{}
	p.put("10.0.0.1:853", stale)

	if !stale.closed.Load() {
		t.Error("a connection for a stale address was pooled instead of closed")
	}
}

// Regression test for a leak: expiry was once evaluated only inside get(), so
// a pool that stopped receiving traffic held its sockets until process exit.
func TestConnPoolReapsIdleConnections(t *testing.T) {
	p := newConnPool(4, 20*time.Millisecond)
	c := &fakeConn{}
	p.put(testAddr, c)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.closed.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !c.closed.Load() {
		t.Fatal("idle connection was not reaped; idleTimeout does not bound socket lifetime")
	}
	if got := p.get(testAddr); got != nil {
		t.Errorf("get() = %v, want nil after the connection was reaped", got)
	}
}

// Guards the race between the reaper firing and a caller taking the same
// connection out of the pool.
func TestConnPoolReapDoesNotCloseReusedConnection(t *testing.T) {
	p := newConnPool(4, time.Hour)
	c := &fakeConn{}
	p.put(testAddr, c)

	got := p.get(testAddr)
	if got == nil {
		t.Fatal("expected the pooled connection")
	}

	// The connection is checked out; its reaper must have been stopped.
	time.Sleep(20 * time.Millisecond)
	if c.closed.Load() {
		t.Error("a checked-out connection was closed by the reaper")
	}
}

// TestConnPoolConcurrentAccess exercises the pool from many goroutines so that
// `go test -race` can detect unsynchronised access.
func TestConnPoolConcurrentAccess(t *testing.T) {
	p := newTestPool(8)
	done := make(chan struct{})

	for i := 0; i < 16; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				if c := p.get(testAddr); c != nil {
					p.put(testAddr, c)
				} else {
					p.put(testAddr, &fakeConn{})
				}
				p.stats()
			}
		}()
	}
	for i := 0; i < 16; i++ {
		<-done
	}
	p.close()
}
