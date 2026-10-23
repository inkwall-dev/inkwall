// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package v1alpha1 holds the Inkwall Kubernetes API (group waf.inkwall.dev):
// the cluster configuration, the policies app teams attach to their routes,
// and the rule sets those policies use. Design: docs/design/0002 §4.2 and
// docs/design/0004 §3.
//
// +kubebuilder:object:generate=true
// +groupName=waf.inkwall.dev
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the API group and version of these types.
	GroupVersion = schema.GroupVersion{Group: "waf.inkwall.dev", Version: "v1alpha1"}

	// SchemeBuilder registers the types with a runtime.Scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types to a runtime.Scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion,
		&InkwallConfig{}, &InkwallConfigList{},
		&WAFPolicy{}, &WAFPolicyList{},
		&WAFRuleSet{}, &WAFRuleSetList{},
		&ClusterWAFRuleSet{}, &ClusterWAFRuleSetList{},
	)
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
