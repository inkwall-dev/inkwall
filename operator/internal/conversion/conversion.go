// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package conversion holds what the WAFPolicy conversion webhook needs when
// v1 is served next to v1alpha1 (#708, #64). Only WAFPolicy changes shape
// at v1; the other kinds convert with conversion: None. Nothing serves v1
// yet: these types and functions fix the v1 shapes now, so that what v1
// freezes is decided, and tested, before v1.0.0.
//
// What changes, v1alpha1 to v1:
//
//   - spec.ipLists.allow[] and .deny[]: a WAFIPList name ("abusers")
//     becomes a reference, {kind: WAFIPList, name: abusers}, so that a
//     cluster-wide ClusterWAFIPList can be added later without a breaking
//     change (IPListReference).
//   - spec.ruleSets[].ref.namespace: dropped. It can only name the
//     policy's own namespace (the resolver refuses any other), so dropping
//     it loses nothing; cross-namespace references would come back with a
//     grant kind (RuleSetNamespace).
//   - spec.ruleSets[].paranoiaLevel and .inboundAnomalyThreshold: moved
//     to crs (#714).
package conversion

import (
	"fmt"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// IPListKind is the kind of an IP list a v1 policy references.
// +kubebuilder:validation:Enum=WAFIPList;ClusterWAFIPList
type IPListKind string

// The IP list kinds. Only WAFIPList exists; ClusterWAFIPList is planned
// (docs/design/0004 §3, 0002 §4.2).
const (
	KindWAFIPList        IPListKind = "WAFIPList"
	KindClusterWAFIPList IPListKind = "ClusterWAFIPList"
)

// IPListReference is the v1 item of spec.ipLists.allow and .deny. The
// lists are +listType=map, keyed by kind and name.
type IPListReference struct {
	// Kind is WAFIPList, in the policy's namespace (the default), or
	// ClusterWAFIPList.
	// +kubebuilder:default=WAFIPList
	// +optional
	Kind IPListKind `json:"kind,omitempty"`

	// Name of the list.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// IPListReferences converts v1alpha1 list names to v1 references: each
// names a WAFIPList.
func IPListReferences(names []wafv1alpha1.IPListName) []IPListReference {
	if names == nil {
		return nil
	}
	refs := make([]IPListReference, 0, len(names))
	for _, n := range names {
		refs = append(refs, IPListReference{Kind: KindWAFIPList, Name: string(n)})
	}
	return refs
}

// IPListNames converts v1 references back to v1alpha1 names. v1alpha1 can
// only name a WAFIPList, so a ClusterWAFIPList, once it exists, has no
// v1alpha1 form: an error, which the conversion webhook returns rather
// than drop the reference.
func IPListNames(refs []IPListReference) ([]wafv1alpha1.IPListName, error) {
	if refs == nil {
		return nil, nil
	}
	names := make([]wafv1alpha1.IPListName, 0, len(refs))
	for _, r := range refs {
		if r.Kind != "" && r.Kind != KindWAFIPList {
			return nil, fmt.Errorf("%s %s can't be expressed in waf.inkwall.dev/v1alpha1, which names only WAFIPLists: use v1", r.Kind, r.Name)
		}
		names = append(names, wafv1alpha1.IPListName(r.Name))
	}
	return names, nil
}

// RuleSetNamespace checks that v1 loses nothing by dropping a v1alpha1
// rule set reference's namespace: unset, or the policy's own. Another
// namespace is an error: such a policy was never Accepted, v1 couldn't say
// it, and converting it as the policy's namespace could bind a different
// rule set, so the v1.0 upgrade preflight refuses while one exists (the
// webhook warns of it from 0.7.0).
func RuleSetNamespace(ref wafv1alpha1.RuleSetRef, policyNamespace string) error {
	ns := ref.Namespace //nolint:staticcheck // checks the deprecated field
	if ns == "" || ns == policyNamespace {
		return nil
	}
	return fmt.Errorf("%s %s/%s: rule sets in other namespaces can't be used, and v1 has no namespace field; bind it from its own namespace or use a ClusterWAFRuleSet",
		ref.Kind, ns, ref.Name)
}
