// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Connection-pool tuning for DoT. RFC 7858 Section 3.4: clients SHOULD reuse
// one TLS connection for many queries. A fresh connection costs a TCP plus a
// full TLS handshake -- several kilobytes, mostly certificate chain -- to carry
// a sub-200-byte DNS message.
const (
	// defaultMaxIdleConns caps idle connections per upstream. One in-flight
	// query holds one connection, so this must cover the widest burst of
	// concurrent queries: anything above the cap is closed after a single use
	// and re-handshaked on the next burst. Measured at burst width 40, a cap
	// of 16 opened 137 connections to carry 200 queries where 64 opened 41.
	// Overridden by upstream_settings.max_idle_conns; see SetMaxIdleConns.
	defaultMaxIdleConns = 128

	// defaultIdleTimeout bounds how long an unused connection stays pooled.
	// Measured idle lifetime before the peer closes: Cloudflare about 30s,
	// Quad9 about 15s, and neither advertises an edns-tcp-keepalive timeout
	// to negotiate against. Pooling for longer than the peer holds the socket
	// only hands the next caller a dead connection.
	defaultIdleTimeout = 30 * time.Second
)

// configuredMaxIdle overrides defaultMaxIdleConns when positive. It is set
// once from the configuration during startup, before any upstream client is
// built, and read whenever a client creates its pool. Stored atomically so a
// late reader can never observe a torn value.
var configuredMaxIdle atomic.Int32

// SetMaxIdleConns sets the per-upstream idle connection cap for clients
// created afterwards. A value of zero or less keeps defaultMaxIdleConns.
// Call it before constructing any upstream client; existing pools keep the
// size they were built with.
func SetMaxIdleConns(n int) {
	if n <= 0 {
		configuredMaxIdle.Store(0)
		return
	}
	configuredMaxIdle.Store(int32(n))
}

// effectiveMaxIdleConns is the cap new pools should use.
func effectiveMaxIdleConns() int {
	if n := configuredMaxIdle.Load(); n > 0 {
		return int(n)
	}
	return defaultMaxIdleConns
}

// pooledConn is an idle connection waiting to be reused. reaper closes it once
// idleTimeout elapses.
type pooledConn struct {
	conn   net.Conn
	reaper *time.Timer
}

// connPool holds reusable connections for one upstream. It owns the address
// they point at, so a re-resolution to a new IP discards the old connections.
//
// Safe for concurrent use. The zero value is not usable; call newConnPool.
type connPool struct {
	mu     sync.Mutex
	idle   []*pooledConn
	addr   string
	closed bool

	maxIdle     int
	idleTimeout time.Duration

	// Counters for tests and diagnostics; accessed without holding mu.
	dials  atomic.Int64
	reuses atomic.Int64
}

// newConnPool creates a pool. maxIdle and idleTimeout must be positive.
func newConnPool(maxIdle int, idleTimeout time.Duration) *connPool {
	return &connPool{maxIdle: maxIdle, idleTimeout: idleTimeout}
}

// get returns an idle connection for addr, or nil when none is available.
// A change of addr discards every pooled connection: they point at the previous
// peer. The most recently returned connection is handed out first, having had
// the least time to be closed by the peer.
func (p *connPool) get(addr string) net.Conn {
	var stale []*pooledConn
	var conn net.Conn

	p.mu.Lock()
	if !p.closed {
		if p.addr != addr {
			stale, p.idle, p.addr = p.idle, nil, addr
		}
		for len(p.idle) > 0 {
			last := len(p.idle) - 1
			pc := p.idle[last]
			p.idle[last] = nil // let the backing array release the connection
			p.idle = p.idle[:last]
			// Stop() returning false means the reaper already fired and is
			// closing this connection, so skip it.
			if !pc.reaper.Stop() {
				continue
			}
			p.reuses.Add(1)
			conn = pc.conn
			break
		}
	}
	p.mu.Unlock()

	closeAll(stale)
	return conn
}

// put returns a connection to the pool, closing it instead when the pool is
// full or closed, or when addr no longer matches the address the pool serves.
// Only connections in a clean protocol state may be returned; see
// (*DoTClient).exchange.
func (p *connPool) put(addr string, conn net.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	// Adopt the address on first use. Once set, a mismatch means the upstream
	// moved and this connection points at the previous peer.
	if p.addr == "" {
		p.addr = addr
	}
	if p.closed || p.addr != addr || len(p.idle) >= p.maxIdle {
		p.mu.Unlock()
		conn.Close()
		return
	}
	// The timer is what makes idleTimeout a bound rather than a filter: a pool
	// that stops receiving traffic -- including one whose owner was dropped
	// without Close() -- would otherwise hold its sockets until process exit.
	pc := &pooledConn{conn: conn}
	pc.reaper = time.AfterFunc(p.idleTimeout, func() { p.reap(pc) })
	p.idle = append(p.idle, pc)
	p.mu.Unlock()
}

// reap removes and closes a connection whose idle timeout has elapsed.
func (p *connPool) reap(target *pooledConn) {
	p.mu.Lock()
	for i, pc := range p.idle {
		if pc == target {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
	target.conn.Close()
}

// idleLen reports how many connections are currently pooled.
func (p *connPool) idleLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

// markDial records that a new connection had to be dialled.
func (p *connPool) markDial() { p.dials.Add(1) }

// stats reports how many connections were dialled and how many pooled
// connections were reused.
func (p *connPool) stats() (dials, reuses int64) {
	return p.dials.Load(), p.reuses.Load()
}

// drain closes every idle connection but keeps the pool usable.
func (p *connPool) drain() {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	closeAll(idle)
}

// close closes every idle connection and prevents further reuse. Checked-out
// connections are closed when their caller returns them. Safe to call twice.
func (p *connPool) close() {
	// Set closed first so no put() can repopulate the pool behind the drain.
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	p.drain()
}

// closeAll stops each connection's reaper and closes it.
func closeAll(conns []*pooledConn) {
	for _, pc := range conns {
		pc.reaper.Stop()
		pc.conn.Close()
	}
}
