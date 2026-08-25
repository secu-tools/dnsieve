// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package upstream

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"

	"github.com/secu-tools/dnsieve/internal/config"
)

// closeTrackingClient records whether Close was called.
type closeTrackingClient struct {
	name   string
	closed int
}

func (c *closeTrackingClient) Query(context.Context, *dns.Msg) (*dns.Msg, error) {
	return nil, context.Canceled
}
func (c *closeTrackingClient) String() string { return c.name }
func (c *closeTrackingClient) Close()         { c.closed++ }

// Guards the lifecycle contract. Before Close was on the Client interface,
// Resolver held []Client and structurally could not release pooled sockets.
func TestResolverCloseClosesEveryClient(t *testing.T) {
	a := &closeTrackingClient{name: "a"}
	b := &closeTrackingClient{name: "b"}
	r := NewResolverFromClients([]Client{a, b}, 0, 0, nil)

	r.Close()

	if a.closed != 1 || b.closed != 1 {
		t.Errorf("closed counts = (%d, %d), want (1, 1)", a.closed, b.closed)
	}
}

// The second owner of an upstream client: Stop() once shut down only the
// domain-list watcher, leaving this client's pooled connections open.
func TestWhitelistResolverStopClosesClient(t *testing.T) {
	c := &closeTrackingClient{name: "whitelist"}
	w := NewWhitelistResolverFromClient(c, &config.WhitelistConfig{Enabled: true}, nil)

	w.Stop()

	if c.closed != 1 {
		t.Errorf("whitelist client closed %d times, want 1", c.closed)
	}
}

// Stop() must work on the nil resolver returned when the whitelist is off.
func TestWhitelistResolverStopNilSafe(t *testing.T) {
	var w *WhitelistResolver
	w.Stop() // must not panic

	// A resolver with no client must also be safe.
	NewWhitelistResolverFromClient(nil, &config.WhitelistConfig{Enabled: true}, nil).Stop()
}

// Fails to compile if a new upstream transport skips lifecycle support.
func TestEveryClientImplementationHasClose(t *testing.T) {
	var _ Client = (*DoTClient)(nil)
	var _ Client = (*DoHClient)(nil)
	var _ Client = (*PlainClient)(nil)
}
