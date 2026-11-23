// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
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
	for _, tt := range []struct {
		name     string
		p        *bundlev1.Policy
		ruleSets []*bundlev1.RuleSet
	}{
		// An exclusion on a rule the policy's SecLang removes, with "!args"
		// anywhere in it.
		{"exclusion on a removed rule", &bundlev1.Policy{
			RuleSets:   []*bundlev1.RuleSetBinding{{RuleSetId: crs.Id}, {RuleSetId: removes.Id}},
			Exclusions: []*bundlev1.Exclusion{{RuleIds: []uint32{942100}, Argument: "foo"}},
		}, []*bundlev1.RuleSet{crs, removes}},
		{"skip path not clean", &bundlev1.Policy{SkipPaths: []string{"/a/../b"}}, nil},
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
