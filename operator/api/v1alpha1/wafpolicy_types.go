// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyMode is what the engine does with a request the rules flag.
// +kubebuilder:validation:Enum=Detect;Block
type PolicyMode string

const (
	// PolicyDetect logs the verdict and lets the request through.
	PolicyDetect PolicyMode = "Detect"
	// PolicyBlock rejects the request.
	PolicyBlock PolicyMode = "Block"
)

// FailureMode is what happens to a request that can't be inspected in time
// (timeout, error, overload).
// +kubebuilder:validation:Enum=Open;Closed
type FailureMode string

const (
	// FailOpen lets the request through uninspected.
	FailOpen FailureMode = "Open"
	// FailClosed rejects the request with 503.
	FailClosed FailureMode = "Closed"
)

// OversizeAction is what happens to a body larger than body.maxBytes.
// +kubebuilder:validation:Enum=Allow;Deny
type OversizeAction string

const (
	// OversizeAllow forwards the request with the body uninspected, and logs
	// it.
	OversizeAllow OversizeAction = "Allow"
	// OversizeDeny rejects the request with 413 in Block mode.
	OversizeDeny OversizeAction = "Deny"
)

// WAFPolicySpec is what to enforce on which routes.
type WAFPolicySpec struct {
	// TargetRefs are the routes this policy protects, in the policy's
	// namespace.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(a, self.exists_one(b, b.kind == a.kind && b.name == a.name && (has(b.sectionName) ? b.sectionName : '') == (has(a.sectionName) ? a.sectionName : '')))",message="targetRefs must not repeat a target"
	TargetRefs []TargetRef `json:"targetRefs"`

	// Mode is Detect (log, let through) or Block (reject).
	// +kubebuilder:default=Detect
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`

	// FailureMode is what happens to a request that can't be inspected in
	// time. Unset: Closed in Block mode, Open in Detect mode.
	// +optional
	FailureMode FailureMode `json:"failureMode,omitempty"`

	// Timeout is the inspection deadline per request, at most 1s. Unset:
	// the engine's default (250ms).
	// +kubebuilder:validation:XValidation:rule="duration(self) > duration('0s') && duration(self) <= duration('1s')",message="timeout must be more than 0s and at most 1s"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Skip lists requests that are never inspected.
	// +optional
	Skip *SkipSpec `json:"skip,omitempty"`

	// RuleSets are the rules to run, in order. Empty: the built-in OWASP CRS
	// with its default paranoia level and threshold.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	RuleSets []RuleSetBinding `json:"ruleSets,omitempty"`

	// Exclusions turn rules off where they cause false positives.
	// +kubebuilder:validation:MaxItems=128
	// +optional
	Exclusions []Exclusion `json:"exclusions,omitempty"`

	// Body configures request body inspection.
	// +optional
	Body *BodySpec `json:"body,omitempty"`
}

// TargetRef names a route in the policy's namespace.
// +kubebuilder:validation:XValidation:rule="(self.kind == 'Ingress' && (!has(self.group) || self.group == 'networking.k8s.io')) || (self.kind == 'HTTPRoute' && has(self.group) && self.group == 'gateway.networking.k8s.io') || (self.kind == 'IngressRoute' && has(self.group) && self.group == 'traefik.io')",message="target must be a networking.k8s.io Ingress, a gateway.networking.k8s.io HTTPRoute or a traefik.io IngressRoute"
// +kubebuilder:validation:XValidation:rule="!has(self.sectionName) || self.kind == 'HTTPRoute'",message="sectionName is only allowed for an HTTPRoute"
type TargetRef struct {
	// Group of the target: networking.k8s.io (the default, for Ingress),
	// gateway.networking.k8s.io (for HTTPRoute) or traefik.io (for
	// Traefik's IngressRoute).
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Group string `json:"group,omitempty"`

	// Kind of the target: Ingress, HTTPRoute or IngressRoute. An
	// IngressRoute's hosts and paths come from its routes' match rules,
	// which may combine Host, Path and PathPrefix with &&; a rule with
	// anything else (||, !, other matchers) is not accepted. An HTTPRoute's routes
	// are each of its hostnames (none: any host) with each of its rules'
	// matches, which may have an Exact or PathPrefix path and a method; a
	// match with a RegularExpression path, headers or queryParams is not
	// accepted. Whether a proxy wires HTTPRoute targets depends on its
	// integration.
	// +kubebuilder:validation:Enum=Ingress;HTTPRoute;IngressRoute
	Kind string `json:"kind"`

	// Name of the target.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// SectionName narrows an HTTPRoute target to the rule of that name:
	// only its matches are protected, and it takes precedence over a policy
	// on the whole HTTPRoute. A name no rule has is a missing target.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	SectionName string `json:"sectionName,omitempty"`
}

// PathPattern is an exact path ("/healthz") or a prefix ending in "*"
// ("/static/*"), using only plain ASCII path characters, as the engine
// matches paths (pkg/router).
// +kubebuilder:validation:MaxLength=1024
// +kubebuilder:validation:Pattern=`^/[A-Za-z0-9._~/:@!$&'()+,=-]*\*?$`
type PathPattern string

// SkipSpec lists requests that are never inspected.
type SkipSpec struct {
	// Paths that are never inspected.
	// +kubebuilder:validation:MaxItems=64
	// +optional
	Paths []PathPattern `json:"paths,omitempty"`

	// BodyPaths are paths whose body is not inspected; their headers and URI
	// still are.
	// +kubebuilder:validation:MaxItems=64
	// +optional
	BodyPaths []PathPattern `json:"bodyPaths,omitempty"`
}

// RuleSetBinding uses a rule set in a policy.
type RuleSetBinding struct {
	// Ref is the rule set.
	Ref RuleSetRef `json:"ref"`

	// ParanoiaLevel is the OWASP CRS paranoia level, 1 to 4. Only used by
	// the built-in CRS.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	// +optional
	ParanoiaLevel *int32 `json:"paranoiaLevel,omitempty"`

	// InboundAnomalyThreshold is the OWASP CRS anomaly score at which a
	// request is flagged. Only used by the built-in CRS.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +optional
	InboundAnomalyThreshold *int32 `json:"inboundAnomalyThreshold,omitempty"`
}

// RuleSetRef names a WAFRuleSet or a ClusterWAFRuleSet.
// +kubebuilder:validation:XValidation:rule="self.kind == 'WAFRuleSet' || !has(self.__namespace__)",message="namespace is only allowed for a WAFRuleSet"
type RuleSetRef struct {
	// Kind is WAFRuleSet or ClusterWAFRuleSet.
	// +kubebuilder:validation:Enum=WAFRuleSet;ClusterWAFRuleSet
	Kind string `json:"kind"`

	// Name of the rule set.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace of a WAFRuleSet. Unset: the policy's namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// Exclusion turns rules off, everywhere or only for one path or argument.
type Exclusion struct {
	// RuleIDs are the rules to turn off. An ID no rule has is ignored.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:Minimum=1
	RuleIDs []int32 `json:"ruleIDs"`

	// When narrows the exclusion. Unset: the rules are off for every request
	// this policy covers.
	// +optional
	When *ExclusionMatch `json:"when,omitempty"`
}

// ExclusionMatch narrows an exclusion to a path, an argument, or both.
// +kubebuilder:validation:XValidation:rule="has(self.path) || has(self.argument)",message="when needs a path, an argument, or both"
type ExclusionMatch struct {
	// Path the exclusion applies to.
	// +optional
	Path PathPattern `json:"path,omitempty"`

	// Argument is a query or body argument the rules, and the rules chained
	// to them, stop looking at. With a rule set whose own SecLang negates
	// ARGS targets (!ARGS:name), the policy gets its own compiled rules, and
	// the exclusion covers the rule only, not its chained rules.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.\-\[\]]+$`
	// +optional
	Argument string `json:"argument,omitempty"`
}

// BodySpec configures request body inspection.
type BodySpec struct {
	// Inspect turns body inspection on or off.
	// +kubebuilder:default=true
	// +optional
	Inspect *bool `json:"inspect,omitempty"`

	// MaxBytes is how much of a body is inspected, at most 10 MiB. Unset:
	// the engine's default (64 KiB).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10485760
	// +optional
	MaxBytes *int64 `json:"maxBytes,omitempty"`

	// OnOversize is what happens to a body over maxBytes: Deny (413 in
	// Block mode) or Allow (forwarded uninspected, and logged). Unset: Deny
	// in Block mode, Allow in Detect mode.
	// +optional
	OnOversize OversizeAction `json:"onOversize,omitempty"`
}

// WAFPolicyStatus reports how far the policy got: accepted, programmed into
// the proxy, enforced by every engine (0004 §3.2).
type WAFPolicyStatus struct {
	// ObservedGeneration is the generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// BundleVersion is the first bundle that enforces this generation as it
	// is now: later bundles do too, until one changes the policy (its
	// spec, routes or rule sets) or suspends the cluster. Bundles that
	// change only other policies leave it.
	// +optional
	BundleVersion int64 `json:"bundleVersion,omitempty"`

	// Conditions are Accepted, Programmed, Enforced and Ready.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// WAFPolicy protects routes: which rules run, in which mode, and what
// happens when inspection fails.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=inkwall,shortName=wafp
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Bundle",type=integer,JSONPath=`.status.bundleVersion`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type WAFPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec WAFPolicySpec `json:"spec"`
	// +optional
	Status WAFPolicyStatus `json:"status,omitempty"`
}

// WAFPolicyList is a list of WAFPolicy.
//
// +kubebuilder:object:root=true
type WAFPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WAFPolicy `json:"items"`
}
