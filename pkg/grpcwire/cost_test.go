// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package grpcwire

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// deepGroups is depth groups, each in the one before, each with a number
// before the next.
func deepGroups(depth int) []byte {
	var b []byte
	for range depth {
		b = protowire.AppendTag(b, 1, protowire.StartGroupType)
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, 1<<40)
	}
	for range depth {
		b = protowire.AppendTag(b, 1, protowire.EndGroupType)
	}
	return b
}

// wideGroups is size bytes of groups side by side, each with a string.
func wideGroups(size int) []byte {
	var b []byte
	for len(b) < size {
		b = append(b, group(1, pb(2, "abc"))...)
	}
	return b
}

// fastest is the shortest of a few runs of Strings on msg.
func fastest(msg []byte) time.Duration {
	best := time.Duration(1<<63 - 1)
	for range 5 {
		start := time.Now()
		Strings(msg, DefaultLimits, nil)
		best = min(best, time.Since(start))
	}
	return best
}

// TestStringsGroupsCost: reading groups costs about their bytes, however
// deep they are nested. Each group's tags were read again for each group
// around it: 9,000 nested groups (81 KB) took 49 seconds.
func TestStringsGroupsCost(t *testing.T) {
	// Far above what the reading takes, even with -race, far below what
	// it took.
	const budget = 3 * time.Second
	for _, tt := range []struct {
		name string
		msg  []byte
	}{
		{"9000 deep", deepGroups(9000)},
		{"deepest protowire reads", deepGroups(protowire.DefaultRecursionLimit - 1)},
		{"1 MiB side by side", wideGroups(1 << 20)},
		{"in a submessage", pb(1, deepGroups(9000))},
	} {
		start := time.Now()
		_, ok := Strings(tt.msg, DefaultLimits, nil)
		if d := time.Since(start); d > budget {
			t.Errorf("%s: %d bytes read in %v, more than %v", tt.name, len(tt.msg), d, budget)
		}
		if ok {
			t.Errorf("%s: read whole, past the limits", tt.name)
		}
	}

	// Linear: 8 times the bytes take about 8 times as long, not 64.
	for _, tt := range []struct {
		name       string
		small, big []byte
	}{
		{"deep", deepGroups(1000), deepGroups(8000)},
		{"side by side", wideGroups(128 << 10), wideGroups(1 << 20)},
	} {
		small, big := fastest(tt.small), fastest(tt.big)
		if big > 24*small+10*time.Millisecond {
			t.Errorf("%s: %d bytes in %v, %d bytes in %v: more than linear", tt.name, len(tt.small), small, len(tt.big), big)
		}
	}
}

// betweenNested is between as it read groups: each group's bytes again for
// each group around it.
func betweenNested(out, msg []byte) []byte {
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeField(msg)
		switch typ {
		case protowire.BytesType:
			_, _, tag := protowire.ConsumeTag(msg)
			v, _ := protowire.ConsumeBytes(msg[tag:])
			out = append(out, msg[:n-len(v)]...)
		case protowire.StartGroupType:
			_, _, tag := protowire.ConsumeTag(msg)
			v, _ := protowire.ConsumeGroup(num, msg[tag:])
			out = append(out, msg[:tag]...)
			out = betweenNested(out, v)
			out = append(out, msg[tag+len(v):n]...)
		default:
			out = append(out, msg[:n]...)
		}
		msg = msg[n:]
	}
	return out
}

// TestBetween: between reads a message tag by tag as it did group by group.
func TestBetween(t *testing.T) {
	fixed := protowire.AppendTag(nil, 5, protowire.Fixed64Type)
	fixed = protowire.AppendFixed64(fixed, 0x2720524f2031)
	fixed32 := protowire.AppendTag(nil, 6, protowire.Fixed32Type)
	fixed32 = protowire.AppendFixed32(fixed32, 0x41424344)
	for _, msg := range [][]byte{
		nil,
		pb(1, "a", 2, uint64(300)),
		group(1, pb(2, "in", 3, group(4, pb(1, "deeper")))),
		append(append(pb(1, pb(2, "x")), fixed...), group(7, append(fixed32, group(8, nil)...))...),
		append(group(1, pb(2, "abc")), group(3, deepGroups(20))...),
		deepGroups(50),
		wideGroups(1000),
	} {
		if got, want := between(msg), betweenNested(nil, msg); !bytes.Equal(got, want) {
			t.Errorf("between(%x) = %x, want %x", msg, got, want)
		}
	}
}
