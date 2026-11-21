// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// fakeMatch is a types.MatchData.
type fakeMatch struct {
	v          variables.RuleVariable
	key, value string
	level      int
}

func (m fakeMatch) Variable() variables.RuleVariable { return m.v }
func (m fakeMatch) Key() string                      { return m.key }
func (m fakeMatch) Value() string                    { return m.value }
func (m fakeMatch) Message() string                  { return "" }
func (m fakeMatch) Data() string                     { return "" }
func (m fakeMatch) ChainLevel() int                  { return m.level }

func match(v variables.RuleVariable, key, value string, level int) types.MatchData {
	return fakeMatch{v, key, value, level}
}

func where(md types.MatchData) string {
	if md == nil {
		return "<nil>"
	}
	return md.Variable().Name() + ":" + md.Key()
}

func TestMatchPoint(t *testing.T) {
	headers := []types.MatchData{
		match(variables.RequestHeadersNames, "Accept", "accept", 0),
		match(variables.RequestHeadersNames, "X-Http-Method-Override", "x-http-method-override", 0),
	}
	tests := []struct {
		name string
		mds  []types.MatchData
		want string
	}{
		{"none", nil, "<nil>"},
		{"SecAction", []types.MatchData{match(variables.Unknown, "", "", 0)}, "<nil>"},
		{"one match", []types.MatchData{match(variables.Args, "q", "1' or 1=1", 0)}, "ARGS:q"},
		{
			"920450: TX key ends in _<value>",
			append(headers[:2:2], match(variables.TX, "header_name_920450_x-http-method-override", "/x-http-method-override/", 1)),
			"REQUEST_HEADERS_NAMES:X-Http-Method-Override",
		},
		{
			"931130: TX key ends in _<VARIABLE:key>",
			[]types.MatchData{
				match(variables.Args, "a", "https://shop.example.com/", 0),
				match(variables.Args, "b", "https://evil.example.net/", 0),
				match(variables.TX, "rfi_parameter_args:b", ".evil.example.net/", 1),
			},
			"ARGS:b",
		},
		{
			"TX suffix only after _",
			[]types.MatchData{
				match(variables.Args, "a", "name", 0),
				match(variables.Args, "b", "other", 0),
				match(variables.TX, "x_surname", "1", 1),
			},
			"ARGS:a", // the first: "surname" ends in "name", not after _
		},
		{
			"MATCHED_VARS: the variable's own name",
			[]types.MatchData{
				match(variables.Args, "b", "ab--cd-", 0),
				match(variables.Args, "a", "1';--", 0),
				match(variables.MatchedVars, "ARGS:a", "1';--", 1),
			},
			"ARGS:a",
		},
		{
			// x's value is the end of do_system's key, after _: a TX key
			// would name x; MATCHED_VARS names do_system (#775).
			"MATCHED_VARS: a key ending in _<another's value>",
			[]types.MatchData{
				match(variables.Args, "x", "system", 0),
				match(variables.Args, "do_system", "system ( )", 0),
				match(variables.MatchedVars, "args:do_system", "system ( )", 1),
			},
			"ARGS:do_system",
		},
		{
			"MATCHED_VARS: key before value",
			[]types.MatchData{
				match(variables.Args, "a", "same", 0),
				match(variables.Args, "b", "same", 0),
				match(variables.MatchedVars, "ARGS:b", "same", 1),
			},
			"ARGS:b",
		},
		{
			"value, @within's /<value>/",
			[]types.MatchData{
				match(variables.Args, "a", "one", 0),
				match(variables.Args, "b", "TWO", 0),
				match(variables.TX, "seen", "/two/", 1),
			},
			"ARGS:b",
		},
		{
			// 920180-style: the chain checks another collection.
			"chain on another collection: the first",
			[]types.MatchData{
				match(variables.Args, "a", "x", 0),
				match(variables.Args, "b", "y", 0),
				match(variables.RequestMethod, "", "POST", 1),
			},
			"ARGS:a",
		},
		{
			// 941310-style: the chained rule transforms the value otherwise.
			"transformed otherwise: the first",
			[]types.MatchData{
				match(variables.Args, "a", "¼x¾", 0),
				match(variables.Args, "b", "¼/x¾", 0),
				match(variables.TX, "z", "</x>", 1),
			},
			"ARGS:a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := where(matchPoint(tt.mds)); got != tt.want {
				t.Errorf("matchPoint = %s, want %s", got, tt.want)
			}
		})
	}
}

// Past chainBudget comparisons, the first match is reported.
func TestMatchPointBudget(t *testing.T) {
	mds := rfiMatches(1000)
	if got := where(matchPoint(mds)); got != "ARGS:a0" {
		t.Errorf("matchPoint = %s, want the first, ARGS:a0", got)
	}
	mds = rfiMatches(20)
	if got := where(matchPoint(mds)); got != "ARGS:a10" {
		t.Errorf("matchPoint = %s, want ARGS:a10", got)
	}
}

// rfiMatches is 931130 with n URL arguments, the first half on-site and the
// second off-site, which the chain keeps.
func rfiMatches(n int) []types.MatchData {
	var mds []types.MatchData
	for i := range n {
		mds = append(mds, match(variables.Args, fmt.Sprintf("a%d", i), "https://x.example/", 0))
	}
	for i := n / 2; i < n; i++ {
		mds = append(mds, match(variables.TX, fmt.Sprintf("rfi_parameter_args:a%d", i), ".x.example/", 1))
	}
	return mds
}

// 1,000 URL arguments: bounded time, no allocation.
func BenchmarkMatchPoint(b *testing.B) {
	mds := rfiMatches(1000)
	if n := testing.AllocsPerRun(10, func() { matchPoint(mds) }); n != 0 {
		b.Fatalf("%v allocations", n)
	}
	b.ReportAllocs()
	for b.Loop() {
		matchPoint(mds)
	}
}
