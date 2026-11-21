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

// The first chained match names its level-0 match within the budget, however
// many arguments: 931130's first off-site URL is found in n/2+1 pairs. Past
// chainBudget pairs, the best found so far is reported, or the first match.
func TestMatchPointBudget(t *testing.T) {
	for n, want := range map[int]string{20: "ARGS:a10", 1000: "ARGS:a500"} {
		if got := where(matchPoint(rfiMatches(n))); got != want {
			t.Errorf("%d arguments: matchPoint = %s, want %s", n, got, want)
		}
	}
	// Many chained matches that name nothing: the budget runs out.
	if got := where(matchPoint(nothingNamed(1000))); got != "ARGS:a0" {
		t.Errorf("nothing named: matchPoint = %s, want the first, ARGS:a0", got)
	}
	// What was found before the budget ran out: a value.
	mds := nothingNamed(1000)
	mds = append(mds[:1000:1000], append([]types.MatchData{match(variables.TX, "v", "/v3/", 1)}, mds[1000:]...)...)
	if got := where(matchPoint(mds)); got != "ARGS:a3" {
		t.Errorf("a value, then nothing: matchPoint = %s, want ARGS:a3", got)
	}
}

// A header named after the TX variable of another (920450's
// header_name_920450_<name>) doesn't steer which header is named: the one
// the TX value holds wins, and of two TX key suffixes, the longer.
func TestMatchPointSteering(t *testing.T) {
	steer := match(variables.RequestHeadersNames, "920450_X-Http-Method-Override", "920450_x-http-method-override", 0)
	restricted := match(variables.RequestHeadersNames, "X-Http-Method-Override", "x-http-method-override", 0)
	c := match(variables.TX, "header_name_920450_x-http-method-override", "/x-http-method-override/", 1)
	for _, mds := range [][]types.MatchData{{steer, restricted, c}, {restricted, steer, c}} {
		if got := where(matchPoint(mds)); got != "REQUEST_HEADERS_NAMES:X-Http-Method-Override" {
			t.Errorf("matchPoint = %s, want the restricted header", got)
		}
	}
	// Without the value: the longer suffix.
	c = match(variables.TX, "header_name_920450_x-http-method-override", "1", 1)
	for _, mds := range [][]types.MatchData{{steer, restricted, c}, {restricted, steer, c}} {
		if got := where(matchPoint(mds)); got != "REQUEST_HEADERS_NAMES:920450_X-Http-Method-Override" {
			t.Errorf("no value: matchPoint = %s, want the longer suffix", got)
		}
	}
}

// nothingNamed is n level-0 matches and n chained ones that name none.
func nothingNamed(n int) []types.MatchData {
	var mds []types.MatchData
	for i := range n {
		mds = append(mds, match(variables.Args, fmt.Sprintf("a%d", i), fmt.Sprintf("v%d", i), 0))
	}
	for i := range n {
		mds = append(mds, match(variables.TX, fmt.Sprintf("k%d", i), "-", 1))
	}
	return mds
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

// 1,000 arguments: bounded time, no allocation, for 931130's URLs and for
// chained matches that name nothing (the budget runs out).
func BenchmarkMatchPoint(b *testing.B) {
	for name, mds := range map[string][]types.MatchData{"rfi": rfiMatches(1000), "nothing": nothingNamed(1000)} {
		b.Run(name, func(b *testing.B) {
			if n := testing.AllocsPerRun(10, func() { matchPoint(mds) }); n != 0 {
				b.Fatalf("%v allocations", n)
			}
			b.ReportAllocs()
			for b.Loop() {
				matchPoint(mds)
			}
		})
	}
}
