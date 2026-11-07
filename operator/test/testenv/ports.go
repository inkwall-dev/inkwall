// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var (
	portsMu sync.Mutex
	taken   = map[int]bool{}
)

// FreeAddr returns "127.0.0.1:<port>" for a port a test's server can bind,
// on every interface, a moment later. The port is below the kernel's
// ephemeral range, from which every outgoing connection takes its local
// port: a free port picked inside it can be taken by a connection before
// the server binds it (#452). No two calls in a process return the same.
func FreeAddr(t testing.TB) string {
	t.Helper()
	low, _ := ephemeralRange()
	portsMu.Lock()
	defer portsMu.Unlock()
	for range 1000 {
		// #nosec G404 -- a test port, not a secret
		p := 10000 + rand.IntN(low-10000)
		if taken[p] {
			continue
		}
		l, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			continue
		}
		_ = l.Close()
		taken[p] = true
		return fmt.Sprintf("127.0.0.1:%d", p)
	}
	t.Fatalf("no free port below %d", low)
	return ""
}

// ephemeralRange is the kernel's range of local ports for outgoing
// connections; Linux's default when it can't be read.
func ephemeralRange() (low, high int) {
	low, high = 32768, 60999
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return low, high
	}
	f := strings.Fields(string(raw))
	if len(f) == 2 {
		l, err1 := strconv.Atoi(f[0])
		h, err2 := strconv.Atoi(f[1])
		if err1 == nil && err2 == nil && l > 10000 {
			return l, h
		}
	}
	return low, high
}
