// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Condition types. Every WAFPolicy reports all four (0004 §3.2); the other
// kinds report Accepted.
const (
	// ConditionAccepted is True when the spec is valid and its references
	// resolve.
	ConditionAccepted = "Accepted"
	// ConditionProgrammed is True when every targeted route's proxy sends
	// traffic to Inkwall.
	ConditionProgrammed = "Programmed"
	// ConditionEnforced is True when every engine serving the targets has
	// applied a bundle containing the current generation.
	ConditionEnforced = "Enforced"
	// ConditionReady is True when Accepted, Programmed and Enforced are.
	ConditionReady = "Ready"
	// ConditionControlPlaneConnected, on the InkwallConfig, says whether the
	// cluster is enrolled and connected to the optional control plane
	// (GitOps and Managed mode only).
	ConditionControlPlaneConnected = "ControlPlaneConnected"
)

// SecretReference names a Secret in a given namespace.
type SecretReference struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
}

// SourceLabel says where a WAFPolicy, WAFRuleSet or ClusterWAFRuleSet comes
// from. In Managed mode the operator writes the control plane's policies
// labelled SourceSaaS (0004 §4.9), and the validating webhook lets no one
// else create, change or delete them, or add or remove the label.
const (
	SourceLabel = "inkwall.dev/source"
	SourceSaaS  = "saas"
)
