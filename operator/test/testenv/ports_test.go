// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"net"
	"strconv"
	"testing"
)

// FreeAddr picks a port below the kernel's ephemeral range (#452): the
// client side of every outgoing connection takes one from that range, so
// a port picked there and closed can be taken before the operator binds
// it (the scale test's "bind: address already in use"). The port is free
// on every interface, as the distribution server binds it, and no two
// calls return the same one.
func TestFreeAddr(t *testing.T) {
	low, _ := ephemeralRange()
	seen := map[string]bool{}
	for range 20 {
		addr := FreeAddr(t)
		host, port, err := net.SplitHostPort(addr)
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("FreeAddr %q", addr)
		}
		if p, _ := strconv.Atoi(port); p >= low || p < 1024 {
			t.Errorf("port %d, want 1024 to %d", p, low-1)
		}
		if seen[port] {
			t.Errorf("port %s returned twice", port)
		}
		seen[port] = true
		l, err := net.Listen("tcp", ":"+port)
		if err != nil {
			t.Errorf("port %s isn't free on every interface: %v", port, err)
			continue
		}
		_ = l.Close()
	}
}
