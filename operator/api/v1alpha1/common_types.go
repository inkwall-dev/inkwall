// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// Condition types. Every WAFPolicy reports Accepted, Programmed, Enforced
// and Ready (0004 §3.2); WAFRuleSets, ClusterWAFRuleSets and WAFIPLists
// report Accepted; the InkwallConfig reports the conditions below that name
// it.
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
	// ConditionSuspended, on the InkwallConfig, is True while the published
	// bundle suspends inspection (spec.suspend): every engine allows every
	// request.
	ConditionSuspended = "Suspended"
	// ConditionSigningKeyRotation, on the InkwallConfig, is True while a
	// bundle signing key rotation is in progress; its message says what the
	// rotation waits for.
	ConditionSigningKeyRotation = "SigningKeyRotation"
	// ConditionIntegrationsConfigured, on the InkwallConfig, is False when
	// spec.integrations can't be applied (an invalid selector), with why.
	ConditionIntegrationsConfigured = "IntegrationsConfigured"
	// ConditionEngineRollout, on the InkwallConfig, is True while the
	// operator replaces proxy pods for a new engine (spec.engine.rollout:
	// Automatic), and False when it has nothing to replace, is paused
	// (reason Paused, saying why) or the rollout is Manual.
	ConditionEngineRollout = "EngineRollout"
	// ConditionEngineConfigured, on the InkwallConfig, is False when the
	// engine pinned in spec.engine.image is injected without some
	// spec.engine settings, because its release (or a custom build) may
	// not know their flags; the message names them.
	ConditionEngineConfigured = "EngineConfigured"
	// ConditionEventsExported, on the InkwallConfig, says whether every
	// sink of spec.events.export exports from every operator replica;
	// absent without sinks.
	ConditionEventsExported = "EventsExported"
)

// SecretReference names a Secret in the operator's namespace.
type SecretReference struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace of the Secret, which can only be the operator's namespace.
	// Unset: the operator's namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// SourceLabel says where a WAFPolicy, WAFRuleSet, ClusterWAFRuleSet or
// WAFIPList comes from. In Managed mode the operator writes the control plane's policies
// labelled SourceSaaS (0004 §4.9), and the validating webhook lets no one
// else create, change or delete them, or add or remove the label.
const (
	SourceLabel = "inkwall.dev/source"
	SourceSaaS  = "saas"
)

// DenyResponse is the body a denied client gets instead of the engine's
// own (docs/denial-responses.md): an HTML page or a JSON document, served
// with the denial's status (403, 429 with Retry-After, 503, ...) and
// X-Request-Id, which it can't change. The only substitution is
// {{request_id}}, replaced with the request's ID, escaped for the content
// type: nothing else of the request goes in. A denied gRPC call still gets
// its gRPC status and no body.
type DenyResponse struct {
	// ContentType is the body's media type: text/html, text/plain,
	// application/json or application/problem+json, optionally with
	// "; charset=utf-8" (the body is UTF-8 either way).
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:XValidation:rule="self.lowerAscii().matches('^(text/html|text/plain|application/json|application/problem[+]json)( *; *charset=utf-8)?$')",message="contentType must be text/html, text/plain, application/json or application/problem+json, optionally with ; charset=utf-8"
	ContentType string `json:"contentType"`

	// Body is the denial's body, at most 8 KiB of UTF-8. Each
	// {{request_id}} in it is replaced with the request's ID. With a JSON
	// content type, it must be a JSON document.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=8192
	// +kubebuilder:validation:XValidation:rule="size(bytes(self)) <= 8192",message="body must be at most 8 KiB (8192 bytes of UTF-8)"
	Body string `json:"body"`
}
