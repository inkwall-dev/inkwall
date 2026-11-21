// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package mmdbtest writes small MaxMind DB files for tests (design 0011
// §10): a search tree of 24-bit records and a data section of country
// records, per the MaxMind DB spec (https://maxmind.github.io/MaxMind-DB/).
// It writes IPv6 databases with IPv4 aliases, as the vendors' are, and,
// through Tree, broken ones on purpose: trees whose nodes share children,
// pointers out of bounds.
package mmdbtest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
)

// Record is a network's data. An empty field is left out of the record.
type Record struct {
	// Country is country.iso_code.
	Country string
	// Registered is registered_country.iso_code.
	Registered string
	// Continent is continent.code: a record with only a continent has no
	// country.
	Continent string
}

// Network maps a prefix to a record; a nil Record is an explicit network
// without data.
type Network struct {
	Prefix netip.Prefix
	Record *Record
}

// DB describes a database.
type DB struct {
	// IPVersion is 4 or 6; 0 is 6.
	IPVersion int
	// Type is the database_type; "" is Test-Country.
	Type string
	// BuildEpoch is the build_epoch.
	BuildEpoch uint64
	// Networks are inserted in order, a later one overriding an earlier
	// one where they overlap. IPv4 prefixes go under ::/96 in an IPv6
	// database.
	Networks []Network
	// Aliases are IPv6 prefixes whose tree record points to the IPv4
	// subtree, ::/96, as MaxMind's ::ffff:0:0/96, 2001::/32 and 2002::/16
	// do. Set after the networks.
	Aliases []netip.Prefix
}

// MaxMindAliases are the aliases MaxMind's writer makes.
var MaxMindAliases = []netip.Prefix{
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// ref is a tree record: a node, a data record (data >= 0), or empty.
type ref struct {
	n    *node
	data int
}

var empty = ref{data: -1}

type node struct{ kids [2]ref }

func bit(a [16]byte, i int) int { return int(a[i/8]>>(7-i%8)) & 1 }

// Bytes writes the database.
func (d DB) Bytes() ([]byte, error) {
	v6 := d.IPVersion != 4
	root := &node{kids: [2]ref{empty, empty}}
	var records []Record
	index := map[Record]int{}
	// walk returns the record at the end of prefix p's path, splitting
	// leaves on the way.
	walk := func(a [16]byte, bits int) *ref {
		r := &ref{n: root}
		for i := range bits {
			if r.n == nil {
				leaf := *r
				*r = ref{n: &node{kids: [2]ref{leaf, leaf}}}
			}
			r = &r.n.kids[bit(a, i)]
		}
		return r
	}
	addr := func(p netip.Prefix) ([16]byte, int, error) {
		if p.Addr().Is4() {
			if !v6 {
				var a [16]byte
				copy(a[:], p.Addr().AsSlice())
				return a, p.Bits(), nil
			}
			var a [16]byte
			copy(a[12:], p.Addr().AsSlice())
			return a, 96 + p.Bits(), nil
		}
		if !v6 {
			return [16]byte{}, 0, fmt.Errorf("IPv6 network %s in an IPv4 database", p)
		}
		return p.Addr().As16(), p.Bits(), nil
	}
	for _, nw := range d.Networks {
		a, bits, err := addr(nw.Prefix.Masked())
		if err != nil {
			return nil, err
		}
		if bits == 0 {
			return nil, fmt.Errorf("network %s: the whole tree", nw.Prefix)
		}
		target := empty
		if nw.Record != nil {
			i, ok := index[*nw.Record]
			if !ok {
				i = len(records)
				records = append(records, *nw.Record)
				index[*nw.Record] = i
			}
			target = ref{data: i}
		}
		*walk(a, bits) = target
	}
	if len(d.Aliases) > 0 {
		if !v6 {
			return nil, fmt.Errorf("aliases in an IPv4 database")
		}
		v4 := walk([16]byte{}, 96)
		if v4.n == nil {
			leaf := *v4
			*v4 = ref{n: &node{kids: [2]ref{leaf, leaf}}}
		}
		for _, p := range d.Aliases {
			*walk(p.Masked().Addr().As16(), p.Bits()) = ref{n: v4.n}
		}
	}
	// Number the nodes breadth first, each once, and write the records the
	// tree still points to: Verify refuses data nothing points to.
	ids := map[*node]int{}
	order := []*node{root}
	ids[root] = 0
	var data bytes.Buffer
	offsets := make([]int, len(records))
	for i := range offsets {
		offsets[i] = -1
	}
	for i := 0; i < len(order); i++ {
		for _, k := range order[i].kids {
			if k.n != nil {
				if _, ok := ids[k.n]; !ok {
					ids[k.n] = len(order)
					order = append(order, k.n)
				}
			} else if k.data >= 0 && offsets[k.data] < 0 {
				offsets[k.data] = data.Len()
				records[k.data].encode(&data)
			}
		}
	}
	t := Tree{IPVersion: 6, Type: d.Type, BuildEpoch: d.BuildEpoch, Data: data.Bytes()}
	if !v6 {
		t.IPVersion = 4
	}
	n := uint32(len(order)) // #nosec G115 -- a test's tree
	value := func(r ref) uint32 {
		switch {
		case r.n != nil:
			return uint32(ids[r.n]) // #nosec G115 -- a test's tree
		case r.data < 0:
			return n
		}
		return n + 16 + uint32(offsets[r.data]) // #nosec G115 -- a test's data
	}
	for _, nd := range order {
		t.Nodes = append(t.Nodes, [2]uint32{value(nd.kids[0]), value(nd.kids[1])})
	}
	return t.Bytes(), nil
}

// Tree is a database written as it is given: its nodes' records, as the
// format stores them (a node's number, len(Nodes) for empty, or
// len(Nodes) + 16 + an offset in Data), and its data section. Nothing is
// checked, so a test can write any tree, shared children and bad pointers
// included.
type Tree struct {
	IPVersion  int
	Type       string
	BuildEpoch uint64
	Nodes      [][2]uint32
	Data       []byte
	// NodeCount, if set, is the node_count written instead of len(Nodes).
	NodeCount uint32
}

// Bytes writes the tree.
func (t Tree) Bytes() []byte {
	var b bytes.Buffer
	for _, nd := range t.Nodes {
		for _, v := range nd {
			b.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)}) // #nosec G115 -- a 24-bit record
		}
	}
	b.Write(make([]byte, 16))
	b.Write(t.Data)
	b.WriteString("\xab\xcd\xefMaxMind.com")
	typ := t.Type
	if typ == "" {
		typ = "Test-Country"
	}
	count := t.NodeCount
	if count == 0 {
		count = uint32(len(t.Nodes)) // #nosec G115 -- a test's tree
	}
	ipv := t.IPVersion
	if ipv == 0 {
		ipv = 6
	}
	writeMap(&b, []kv{
		{"binary_format_major_version", uint16v(2)},
		{"binary_format_minor_version", uint16v(0)},
		{"build_epoch", uint64v(t.BuildEpoch)},
		{"database_type", str(typ)},
		{"description", mapv([]kv{{"en", str("Inkwall test database")}})},
		{"ip_version", uint16v(uint64(ipv))}, // #nosec G115 -- 4 or 6
		{"languages", array{str("en")}},
		{"node_count", uint32v(count)},
		{"record_size", uint16v(24)},
	})
	return b.Bytes()
}

// SharedChildren is a tree of depth nodes, each node's two children the
// next node, the last one's both empty, or both data when withData: a tree
// Verify accepts (it checks each node once) whose walk yields 2^depth
// networks. With depth over 96, it is an IPv6 database deeper than the
// IPv4 subtree; the walk never ends on its own.
func SharedChildren(depth int, withData bool) []byte {
	var data bytes.Buffer
	if withData {
		Record{Country: "XA"}.encode(&data)
	}
	n := uint32(depth) // #nosec G115 -- a test's tree
	t := Tree{IPVersion: 6, Data: data.Bytes()}
	for i := range n {
		next := i + 1
		if i == n-1 {
			next = n
			if withData {
				next = n + 16
			}
		}
		t.Nodes = append(t.Nodes, [2]uint32{next, next})
	}
	return t.Bytes()
}

// SharedAliases is an IPv6 database whose ::/96 subtree is one empty node
// and whose 8000::/1 half is a chain of depth nodes, each node's two
// children the next node, the last one's both the IPv4 subtree: 2^depth
// aliases, which a walk that skips aliases skips without yielding.
func SharedAliases(depth int) []byte { return sharedAliases(depth, false) }

// AlternatingAliases is SharedAliases with the last node's children the
// IPv4 subtree and an empty leaf: 2^depth aliases, each followed by an
// empty network, so a walk that skips aliases sees a gap per network.
func AlternatingAliases(depth int) []byte { return sharedAliases(depth, true) }

func sharedAliases(depth int, alternate bool) []byte {
	const v4 = 96               // the IPv4 subtree's node, at depth 96
	n := uint32(v4 + 1 + depth) // #nosec G115 -- a test's tree
	t := Tree{IPVersion: 6}
	for i := range uint32(v4) {
		right := n // empty
		if i == 0 {
			right = v4 + 1
		}
		t.Nodes = append(t.Nodes, [2]uint32{i + 1, right})
	}
	t.Nodes = append(t.Nodes, [2]uint32{n, n})
	for j := range uint32(depth) { // #nosec G115 -- a test's tree
		next := v4 + 1 + j + 1
		if j == uint32(depth)-1 { // #nosec G115 -- a test's tree
			if alternate {
				t.Nodes = append(t.Nodes, [2]uint32{v4, n})
				break
			}
			next = v4
		}
		t.Nodes = append(t.Nodes, [2]uint32{next, next})
	}
	return t.Bytes()
}

func (r Record) encode(b *bytes.Buffer) {
	var m []kv
	if r.Continent != "" {
		m = append(m, kv{"continent", mapv([]kv{{"code", str(r.Continent)}})})
	}
	if r.Country != "" {
		m = append(m, kv{"country", mapv([]kv{{"iso_code", str(r.Country)}})})
	}
	if r.Registered != "" {
		m = append(m, kv{"registered_country", mapv([]kv{{"iso_code", str(r.Registered)}})})
	}
	writeMap(b, m)
}

// Data section values.
type (
	value interface{ write(*bytes.Buffer) }
	kv    struct {
		k string
		v value
	}
	str   string
	mapv  []kv
	array []value
	uintv struct {
		typ, size int
		v         uint64
	}
)

func uint16v(v uint64) value { return uintv{5, 2, v} }
func uint32v(v uint32) value { return uintv{6, 4, uint64(v)} }
func uint64v(v uint64) value { return uintv{9, 8, v} }

// control writes a field's control byte(s): its type and size.
//
//nolint:gosec // G115: a test writer's small values, and broken ones on purpose
func control(b *bytes.Buffer, typ, size int) {
	var first byte
	var ext []byte
	if typ > 7 {
		ext = []byte{byte(typ - 7)}
	} else {
		first = byte(typ << 5)
	}
	var extra []byte
	switch {
	case size < 29:
		first |= byte(size)
	case size < 29+256:
		first |= 29
		extra = []byte{byte(size - 29)}
	case size < 285+65536:
		first |= 30
		extra = binary.BigEndian.AppendUint16(nil, uint16(size-285))
	default:
		first |= 31
		s := size - 65821
		extra = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
	}
	b.WriteByte(first)
	b.Write(ext)
	b.Write(extra)
}

func (s str) write(b *bytes.Buffer) { control(b, 2, len(s)); b.WriteString(string(s)) }

func (m mapv) write(b *bytes.Buffer) { writeMap(b, m) }

func writeMap(b *bytes.Buffer, m []kv) {
	control(b, 7, len(m))
	for _, e := range m {
		str(e.k).write(b)
		e.v.write(b)
	}
}

func (a array) write(b *bytes.Buffer) {
	control(b, 11, len(a))
	for _, v := range a {
		v.write(b)
	}
}

func (u uintv) write(b *bytes.Buffer) {
	raw := binary.BigEndian.AppendUint64(nil, u.v)
	raw = raw[8-u.size:]
	for len(raw) > 0 && raw[0] == 0 {
		raw = raw[1:]
	}
	control(b, u.typ, len(raw))
	b.Write(raw)
}

// Flip returns db with the bytes at the given offsets (modulo its length)
// inverted: a broken database for the fuzz seeds.
func Flip(db []byte, offsets ...int) []byte {
	out := slices.Clone(db)
	for _, o := range offsets {
		if len(out) > 0 {
			out[o%len(out)] ^= 0xff
		}
	}
	return out
}
