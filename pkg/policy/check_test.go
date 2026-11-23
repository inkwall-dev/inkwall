// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"testing"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// TestChecksRefuseWhatCompileRefuses: what Compile refuses of a policy,
// the checks the operator runs (CheckSettings, RuleChecker.Check) refuse
// too: one policy Compile refused would make the engine refuse the whole
// bundle.
func TestChecksRefuseWhatCompileRefuses(t *testing.T) {
	route := func(host string) []*bundlev1.RouteMatch { return []*bundlev1.RouteMatch{{Host: host}} }
	crs := &bundlev1.RuleSet{Id: "builtin/crs", Source: &bundlev1.RuleSet_Builtin{Builtin: bundlev1.BuiltinRuleSet_BUILTIN_RULE_SET_CRS_V4}}
	removes := &bundlev1.RuleSet{Id: "WAFRuleSet/ns/r", Source: &bundlev1.RuleSet_Seclang{Seclang: "# !args\nSecRuleRemoveById 942100"}}
	var allow []string
	for i := range 160000 {
		allow = append(allow, fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255))
	}
	for _, tt := range []struct {
		name     string
		p        *bundlev1.Policy
		ruleSets []*bundlev1.RuleSet
	}{
		// WAFIPLists, each within its limit, merged.
		{"IP lists over the total", &bundlev1.Policy{IpLists: &bundlev1.IPLists{Allow: allow}}, nil},
		{"IP deny lists over the total", &bundlev1.Policy{IpLists: &bundlev1.IPLists{Deny: allow}}, nil},
		// An exclusion on a rule the policy's SecLang removes, with "!args"
		// anywhere in it.
		{"exclusion on a removed rule", &bundlev1.Policy{
			RuleSets:   []*bundlev1.RuleSetBinding{{RuleSetId: crs.Id}, {RuleSetId: removes.Id}},
			Exclusions: []*bundlev1.Exclusion{{RuleIds: []uint32{942100}, Argument: "foo"}},
		}, []*bundlev1.RuleSet{crs, removes}},
		{"skip path not clean", &bundlev1.Policy{SkipPaths: []string{"/a/../b"}}, nil},
		{"deny response", &bundlev1.Policy{DenyResponse: &bundlev1.DenyResponse{ContentType: "image/png", Body: "x"}}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Id, tt.p.Routes = "ns/q", route("a.example")
			other := &bundlev1.Policy{Id: "other/p", Routes: route("b.example")}
			_, err := Compile(&bundlev1.Bundle{Version: 1, Policies: []*bundlev1.Policy{tt.p, other}, RuleSets: tt.ruleSets}, Options{})
			if err == nil {
				t.Fatal("Compile accepts it")
			}
			checked := CheckSettings(tt.p, tt.ruleSets)
			if checked == nil {
				checked = NewRuleChecker().Check(tt.p, tt.ruleSets)
			}
			if checked == nil {
				t.Fatalf("Compile refuses it (%v), the checks don't", err)
			}
		})
	}
}

// TestRuleCheckerPrune: a RuleChecker keeps the results the last
// resolution asked for, however many: a second resolution of 4200
// combinations compiles none of them again (with a bound, one of more than
// it would compile them all, each time); Prune drops the others.
func TestRuleCheckerPrune(t *testing.T) {
	const n = 4200
	c := NewRuleChecker()
	resolve := func(n int) {
		for i := range n {
			rs := &bundlev1.RuleSet{Id: fmt.Sprintf("WAFRuleSet/ns/r%d", i),
				Source: &bundlev1.RuleSet_Seclang{Seclang: fmt.Sprintf(`SecRule ARGS "@contains x" "id:%d,phase:1,pass,nolog"`, 100000+i)}}
			p := &bundlev1.Policy{Id: fmt.Sprintf("ns/p%d", i), RuleSets: []*bundlev1.RuleSetBinding{{RuleSetId: rs.Id}}}
			if err := c.Check(p, []*bundlev1.RuleSet{rs}); err != nil {
				t.Fatal(err)
			}
		}
		c.Prune()
	}
	resolve(n)
	if c.compiles != n {
		t.Fatalf("%d compiles, want %d", c.compiles, n)
	}
	resolve(n)
	if c.compiles != n {
		t.Errorf("the second resolution compiled %d combinations again", c.compiles-n)
	}
	resolve(n / 2)
	if len(c.errs) != n/2 {
		t.Errorf("%d results kept, want the %d asked for", len(c.errs), n/2)
	}
}
