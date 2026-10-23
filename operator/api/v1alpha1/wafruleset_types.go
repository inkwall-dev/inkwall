// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BuiltinRuleSet names a rule set shipped inside the engine image, pinned to
// the engine's version.
// +kubebuilder:validation:Enum=crs-v4
type BuiltinRuleSet string

// BuiltinCRSv4 is the OWASP Core Rule Set v4.
const BuiltinCRSv4 BuiltinRuleSet = "crs-v4"

// ConfigMapKeyRef names a key of a ConfigMap in the rule set's namespace.
type ConfigMapKeyRef struct {
	// Name of the ConfigMap.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Key holding the SecLang rules.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key"`
}

// NamespacedConfigMapKeyRef names a key of a ConfigMap in any namespace.
type NamespacedConfigMapKeyRef struct {
	ConfigMapKeyRef `json:",inline"`

	// Namespace of the ConfigMap.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
}

// RuleSetSource is where a WAFRuleSet's rules come from: exactly one of
// builtin, seclang or configMapRef.
// +kubebuilder:validation:XValidation:rule="[has(self.builtin), has(self.seclang), has(self.configMapRef)].filter(x, x).size() == 1",message="set exactly one of builtin, seclang or configMapRef"
type RuleSetSource struct {
	// Builtin is a rule set shipped in the engine image.
	// +optional
	Builtin BuiltinRuleSet `json:"builtin,omitempty"`

	// SecLang holds the rules inline, at most 256 KiB.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=262144
	// +optional
	SecLang string `json:"seclang,omitempty"`

	// ConfigMapRef reads the rules from a ConfigMap in the rule set's
	// namespace.
	// +optional
	ConfigMapRef *ConfigMapKeyRef `json:"configMapRef,omitempty"`
}

// ClusterRuleSetSource is where a ClusterWAFRuleSet's rules come from:
// exactly one of builtin, seclang or configMapRef.
// +kubebuilder:validation:XValidation:rule="[has(self.builtin), has(self.seclang), has(self.configMapRef)].filter(x, x).size() == 1",message="set exactly one of builtin, seclang or configMapRef"
type ClusterRuleSetSource struct {
	// Builtin is a rule set shipped in the engine image.
	// +optional
	Builtin BuiltinRuleSet `json:"builtin,omitempty"`

	// SecLang holds the rules inline, at most 256 KiB.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=262144
	// +optional
	SecLang string `json:"seclang,omitempty"`

	// ConfigMapRef reads the rules from a ConfigMap.
	// +optional
	ConfigMapRef *NamespacedConfigMapKeyRef `json:"configMapRef,omitempty"`
}

// WAFRuleSetSpec defines a namespaced rule set.
type WAFRuleSetSpec struct {
	// Source of the rules.
	Source RuleSetSource `json:"source"`
}

// ClusterWAFRuleSetSpec defines a cluster-wide rule set.
type ClusterWAFRuleSetSpec struct {
	// Source of the rules.
	Source ClusterRuleSetSource `json:"source"`
}

// RuleSetStatus reports whether a rule set is usable.
type RuleSetStatus struct {
	// ObservedGeneration is the generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions describe the rule set's state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// WAFRuleSet is a set of rules that policies in its namespace can use.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=inkwall,shortName=wafrs
// +kubebuilder:printcolumn:name="Builtin",type=string,JSONPath=`.spec.source.builtin`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type WAFRuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WAFRuleSetSpec `json:"spec"`
	// +optional
	Status RuleSetStatus `json:"status,omitempty"`
}

// WAFRuleSetList is a list of WAFRuleSet.
//
// +kubebuilder:object:root=true
type WAFRuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WAFRuleSet `json:"items"`
}

// ClusterWAFRuleSet is a set of rules that policies in any namespace can use.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=inkwall,shortName=cwafrs
// +kubebuilder:printcolumn:name="Builtin",type=string,JSONPath=`.spec.source.builtin`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ClusterWAFRuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterWAFRuleSetSpec `json:"spec"`
	// +optional
	Status RuleSetStatus `json:"status,omitempty"`
}

// ClusterWAFRuleSetList is a list of ClusterWAFRuleSet.
//
// +kubebuilder:object:root=true
type ClusterWAFRuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterWAFRuleSet `json:"items"`
}
