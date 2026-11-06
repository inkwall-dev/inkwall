// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/request"
)

// targetRules are custom rules on each collection an exclusion can name.
// (The cookie's value is in the Cookie header too, so the header rule looks
// for another value.)
const targetRules = `SecRule REQUEST_COOKIES "@contains cookie-attack" "id:100001,phase:1,deny,status:403,log"
SecRule REQUEST_HEADERS "@contains header-attack" "id:100002,phase:1,deny,status:403,log"
SecRule ARGS_NAMES "@rx ^[pqr]$" "id:100003,phase:2,deny,status:403,log"`

// negatingTargetRules negate those collections themselves, with spare
// capacity in Coraza's negation slices.
const negatingTargetRules = `SecRule REQUEST_COOKIES|!REQUEST_COOKIES:z1|!REQUEST_COOKIES:z2|!REQUEST_COOKIES:z3 "@contains cookie-attack" "id:100001,phase:1,deny,status:403,log"
SecRule REQUEST_HEADERS|!REQUEST_HEADERS:z1|!REQUEST_HEADERS:z2|!REQUEST_HEADERS:z3 "@contains header-attack" "id:100002,phase:1,deny,status:403,log"
SecRule ARGS_NAMES|!ARGS_NAMES:z1|!ARGS_NAMES:z2|!ARGS_NAMES:z3 "@rx ^[pqr]$" "id:100003,phase:2,deny,status:403,log"`

type targetCase struct {
	path                string
	cookie, header, arg string // the attack is in this cookie, header or argument name
}

func (c targetCase) request() *request.Request {
	uri := c.path
	if c.arg != "" {
		uri += "?" + c.arg + "=1"
	}
	h := http.Header{}
	if c.cookie != "" {
		h.Set("Cookie", c.cookie+"=cookie-attack")
	}
	if c.header != "" {
		h.Set(c.header, "header-attack")
	}
	return newRequest("GET", uri, h, "")
}

var targetExclusions = []Exclusion{
	{RuleIDs: []int{100001}, Cookie: "Session"},
	{RuleIDs: []int{100002}, Header: "X-Token"},
	{RuleIDs: []int{100003}, ArgumentName: "q"},
	{RuleIDs: []int{100001}, Path: "/a", Cookie: "pref"},
	{RuleIDs: []int{100002}, Path: "/a", Header: "Referer"},
	{RuleIDs: []int{100003}, Path: "/a/*", ArgumentName: "p"},
}

func checkTargets(t *testing.T, e *Evaluator) {
	t.Helper()
	for _, c := range []struct {
		targetCase
		blocked bool
	}{
		{targetCase{path: "/x", cookie: "session"}, false},
		{targetCase{path: "/x", cookie: "other"}, true},
		{targetCase{path: "/x", header: "X-Token"}, false},
		{targetCase{path: "/x", header: "X-Other"}, true},
		{targetCase{path: "/x", arg: "q"}, false},
		{targetCase{path: "/x", arg: "r"}, true},
		{targetCase{path: "/a", cookie: "pref"}, false},
		{targetCase{path: "/b", cookie: "pref"}, true},
		{targetCase{path: "/a", header: "Referer"}, false},
		{targetCase{path: "/b", header: "Referer"}, true},
		{targetCase{path: "/a/1", arg: "p"}, false},
		{targetCase{path: "/b/1", arg: "p"}, true},
	} {
		res, err := e.Evaluate(context.Background(), c.request())
		if err != nil {
			t.Fatal(err)
		}
		if res.Interrupted != c.blocked {
			t.Errorf("%+v: blocked=%v, want %v (matched %v)", c.targetCase, res.Interrupted, c.blocked, res.MatchedRuleIDs)
		}
	}
}

// TestExclusionTargets: cookie, header and argument name exclusions turn a
// rule off for that cookie, header or name only, everywhere or on a path.
func TestExclusionTargets(t *testing.T) {
	e, err := New(Config{DisableCRS: true, Directives: targetRules, Exclusions: targetExclusions})
	if err != nil {
		t.Fatal(err)
	}
	if e.variants != nil {
		t.Error("rules that negate nothing compiled variants")
	}
	checkTargets(t, e)
}

// leaksTargets runs each evaluator's requests concurrently and counts those
// that weren't blocked.
func leaksTargets(t *testing.T, cases map[*Evaluator][]targetCase) int {
	t.Helper()
	var wg sync.WaitGroup
	var mu sync.Mutex
	leaked := 0
	for e, reqs := range cases {
		for _, c := range reqs {
			for range 4 {
				wg.Go(func() {
					for range 200 {
						res, err := e.Evaluate(context.Background(), c.request())
						if err != nil {
							t.Error(err)
							return
						}
						if !res.Interrupted {
							mu.Lock()
							leaked++
							mu.Unlock()
						}
					}
				})
			}
		}
	}
	wg.Wait()
	return leaked
}

// TestExclusionTargetsWithNegatingRules: rules that negate the collection
// themselves get the exclusions compiled in (Coraza appends a transaction's
// target exclusions to the rule's own negations in place), so concurrent
// requests and policies never swap them.
func TestExclusionTargetsWithNegatingRules(t *testing.T) {
	e, err := New(Config{DisableCRS: true, Directives: negatingTargetRules, Exclusions: targetExclusions})
	if err != nil {
		t.Fatal(err)
	}
	if e.variants == nil {
		t.Error("exclusions applied per transaction to rules that negate their collection")
	}
	checkTargets(t, e)
	shared, err := New(Config{DisableCRS: true, Directives: negatingTargetRules})
	if err != nil {
		t.Fatal(err)
	}
	a, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100002}, Header: "X-A"}, {RuleIDs: []int{100001}, Cookie: "a"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := shared.WithExclusions([]Exclusion{{RuleIDs: []int{100002}, Header: "X-B"}, {RuleIDs: []int{100001}, Cookie: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if n := leaksTargets(t, map[*Evaluator][]targetCase{
		a:      {{path: "/x", header: "X-B"}, {path: "/x", cookie: "b"}},
		b:      {{path: "/x", header: "X-A"}, {path: "/x", cookie: "a"}},
		shared: {{path: "/x", header: "X-A"}, {path: "/x", cookie: "a"}},
		e:      {{path: "/b", header: "Referer"}, {path: "/x", arg: "p"}},
	}); n != 0 {
		t.Errorf("%d requests got another request's or policy's exclusions", n)
	}
}

// TestExclusionTargetsWithTheCRS: the CRS negates some request headers in
// some rules; header exclusions are compiled in for those rules only.
func TestExclusionTargetsWithTheCRS(t *testing.T) {
	neg, err := crsNegations()
	if err != nil {
		t.Fatal(err)
	}
	negating, plain := 0, 0
	for _, id := range mustCRSRuleIDs(t) {
		if neg.rules[varHeaders][id] {
			if negating == 0 {
				negating = id
			}
		} else if plain == 0 && id >= 920000 {
			plain = id
		}
	}
	if negating == 0 || plain == 0 {
		t.Fatalf("rules negating headers %d, not %d", negating, plain)
	}
	base, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := base.WithExclusions([]Exclusion{{RuleIDs: []int{plain}, Header: "X-A"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.variants != nil {
		t.Errorf("a header exclusion on rule %d, which negates no header, compiled variants", plain)
	}
	e, err = base.WithExclusions([]Exclusion{{RuleIDs: []int{negating}, Header: "X-A"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.variants == nil {
		t.Errorf("a header exclusion on rule %d, which negates headers, applied per transaction", negating)
	}
	// The scanner rule reads User-Agent: excluded for it, sqlmap passes.
	scanner := newRequest("GET", "/", http.Header{"User-Agent": {"sqlmap/1.7.2#stable (https://sqlmap.org)"}}, "")
	e, err = base.WithExclusions([]Exclusion{{RuleIDs: []int{913100}, Header: "User-Agent"}})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := e.Evaluate(context.Background(), scanner); err != nil || res.Interrupted {
		t.Errorf("913100 excluded for User-Agent: %+v, %v, want allowed", res, err)
	}
	if res, err := base.Evaluate(context.Background(), scanner); err != nil || !res.Interrupted {
		t.Errorf("no exclusion: %+v, %v, want blocked", res, err)
	}
}

func mustCRSRuleIDs(t *testing.T) []int {
	t.Helper()
	ids, err := CRSRuleIDs()
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestCRSNegationsSeeEveryRule: the CRS negations parsed from its files
// include every rule whose own SecLang (as Coraza compiled it) negates the
// collection.
func TestCRSNegationsSeeEveryRule(t *testing.T) {
	neg, err := crsNegations()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[variableName]int{}
	_, err = compile(Config{}, func(r ruleMetadata) {
		for v, rx := range negationPatterns {
			if rx.MatchString(r.Raw()) {
				seen[v]++
				if !neg.rules[v][r.ID()] {
					t.Errorf("rule %d negates %s, missing from the parsed negations", r.ID(), v)
				}
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen[varHeaders] == 0 || len(neg.rules[varHeaders]) < seen[varHeaders] {
		t.Errorf("header negations: %d compiled, %d parsed", seen[varHeaders], len(neg.rules[varHeaders]))
	}
}

func TestExclusionTargetsRejected(t *testing.T) {
	for _, e := range []Exclusion{
		{RuleIDs: []int{1}, Cookie: "a b"},
		{RuleIDs: []int{1}, Header: "X:Y"},
		{RuleIDs: []int{1}, Header: `X"`},
		{RuleIDs: []int{1}, ArgumentName: "a|b"},
		{RuleIDs: []int{1}, Argument: "a", Cookie: "b"},
		{RuleIDs: []int{1}, Header: "a", ArgumentName: "b"},
	} {
		if _, err := compileExclusions([]Exclusion{e}); err == nil {
			t.Errorf("%+v accepted", e)
		}
	}
}
