// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package conversion

import (
	"slices"
	"strings"
	"testing"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// A v1alpha1 list name is a WAFIPList reference in v1, and back.
func TestIPListRoundTrip(t *testing.T) {
	names := []wafv1alpha1.IPListName{"monitors", "abusers"}
	refs := IPListReferences(names)
	want := []IPListReference{{Kind: KindWAFIPList, Name: "monitors"}, {Kind: KindWAFIPList, Name: "abusers"}}
	if !slices.Equal(refs, want) {
		t.Fatalf("IPListReferences = %v, want %v", refs, want)
	}
	back, err := IPListNames(refs)
	if err != nil || !slices.Equal(back, names) {
		t.Fatalf("IPListNames = %v, %v; want %v", back, err, names)
	}
	// Unset stays unset; a v1 reference without a kind is a WAFIPList (the
	// v1 default).
	if IPListReferences(nil) != nil {
		t.Error("nil names became references")
	}
	if n, err := IPListNames(nil); n != nil || err != nil {
		t.Errorf("IPListNames(nil) = %v, %v", n, err)
	}
	if n, err := IPListNames([]IPListReference{{Name: "x"}}); err != nil || !slices.Equal(n, []wafv1alpha1.IPListName{"x"}) {
		t.Errorf("no kind: %v, %v", n, err)
	}
}

// A ClusterWAFIPList has no v1alpha1 form: refused, not dropped.
func TestClusterIPListHasNoV1alpha1Form(t *testing.T) {
	_, err := IPListNames([]IPListReference{{Kind: KindWAFIPList, Name: "a"}, {Kind: KindClusterWAFIPList, Name: "tor-exits"}})
	if err == nil || !strings.Contains(err.Error(), "ClusterWAFIPList tor-exits") {
		t.Fatalf("err %v, want one naming ClusterWAFIPList tor-exits", err)
	}
}

func TestRuleSetNamespace(t *testing.T) {
	ref := func(ns string) wafv1alpha1.RuleSetRef {
		return wafv1alpha1.RuleSetRef{Kind: "WAFRuleSet", Name: "rules", Namespace: ns} //nolint:staticcheck // the deprecated field
	}
	for _, ns := range []string{"", "shop"} {
		if err := RuleSetNamespace(ref(ns), "shop"); err != nil {
			t.Errorf("namespace %q: %v", ns, err)
		}
	}
	if err := RuleSetNamespace(ref("security"), "shop"); err == nil || !strings.Contains(err.Error(), "WAFRuleSet security/rules") {
		t.Errorf("another namespace: %v", err)
	}
}
