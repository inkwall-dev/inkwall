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

// GRPCMessagesAction is whether gRPC messages are inspected.
// +kubebuilder:validation:Enum=Inspect;Skip
type GRPCMessagesAction string

const (
	// GRPCMessagesInspect inspects the text in gRPC calls' messages.
	GRPCMessagesInspect GRPCMessagesAction = "Inspect"
	// GRPCMessagesSkip inspects a gRPC call's path and metadata only.
	GRPCMessagesSkip GRPCMessagesAction = "Skip"
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

	// WebSocket is what a WebSocket handshake on the policy's routes must
	// meet, on top of the rules: the origins it may come from, the headers
	// it must have. A handshake that doesn't is denied with 403 in Block
	// mode (logged in Detect mode), and isn't upgraded. Other requests
	// aren't affected. The handshake's URL and headers are inspected by
	// the rules whether this is set or not; the messages after it are not
	// inspected (docs/websocket.md). Engines before 0.4.0 ignore it: the
	// policy isn't Enforced while one is connected.
	// +optional
	WebSocket *WebSocketSpec `json:"webSocket,omitempty"`

	// Responses configures response inspection, for data leaks (the CRS's
	// RESPONSE-95x rules, and the rule sets' rules on RESPONSE_*
	// variables). Unset: responses are not inspected. Envoy Gateway and
	// Istio send responses to the engine; on a route of Traefik (its
	// ForwardAuth can't) or HAProxy, the policy is not Programmed
	// (ResponsesNotInspected).
	// +optional
	Responses *ResponsesSpec `json:"responses,omitempty"`

	// IPLists names WAFIPLists in the policy's namespace whose client
	// addresses are denied, or let through uninspected. A deny list wins
	// over an allow list. They are only as good as the client IP the
	// engine resolves (docs/client-ip.md). Requires engines 0.5.0 or
	// later.
	// +optional
	IPLists *IPListsSpec `json:"ipLists,omitempty"`
}

// IPListsSpec names a policy's IP lists.
type IPListsSpec struct {
	// Allow lists clients whose requests aren't inspected: health checkers,
	// a scanner you run yourself. Their requests are not logged either.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +optional
	Allow []IPListName `json:"allow,omitempty"`

	// Deny lists clients whose requests are denied (403) before any rule,
	// or logged in Detect mode.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +optional
	Deny []IPListName `json:"deny,omitempty"`
}

// IPListName names a WAFIPList.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=253
type IPListName string

// TargetRef names a route in the policy's namespace.
// +kubebuilder:validation:XValidation:rule="(self.kind == 'Ingress' && (!has(self.group) || self.group == 'networking.k8s.io')) || (self.kind == 'HTTPRoute' && has(self.group) && self.group == 'gateway.networking.k8s.io') || (self.kind == 'IngressRoute' && has(self.group) && self.group == 'traefik.io') || (self.kind == 'VirtualService' && has(self.group) && self.group == 'networking.istio.io')",message="target must be a networking.k8s.io Ingress, a gateway.networking.k8s.io HTTPRoute, a traefik.io IngressRoute or a networking.istio.io VirtualService"
// +kubebuilder:validation:XValidation:rule="!has(self.sectionName) || self.kind == 'HTTPRoute'",message="sectionName is only allowed for an HTTPRoute"
type TargetRef struct {
	// Group of the target: networking.k8s.io (the default, for Ingress),
	// gateway.networking.k8s.io (for HTTPRoute), traefik.io (for Traefik's
	// IngressRoute) or networking.istio.io (for Istio's VirtualService).
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Group string `json:"group,omitempty"`

	// Kind of the target: Ingress, HTTPRoute, IngressRoute or
	// VirtualService. An
	// IngressRoute's hosts and paths come from its routes' match rules,
	// which may combine Host, Path and PathPrefix with &&; a rule with
	// anything else (||, !, other matchers) is not accepted. An HTTPRoute's routes
	// are each of its hostnames (none: any host) with each of its rules'
	// matches, which may have an Exact or PathPrefix path and a method; a
	// match with a RegularExpression path, headers or queryParams is not
	// accepted. A VirtualService's routes are each of its hosts ("*": any
	// host) with each of its http routes' matches, which may have an exact
	// or prefix uri and an exact method; a match with anything else (a regex
	// uri, headers, query parameters, ...), a delegate, or a short host name
	// is not accepted. Whether a proxy wires HTTPRoute targets depends
	// on its integration; VirtualService targets are wired through Istio's
	// ingress gateways.
	// +kubebuilder:validation:Enum=Ingress;HTTPRoute;IngressRoute;VirtualService
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

	// CRS sets the OWASP CRS's own settings. Only used by the built-in CRS.
	// Requires engines 0.5.0 or later: older ones ignore it.
	// +optional
	CRS *CRSSettings `json:"crs,omitempty"`
}

// CRSSettings are OWASP CRS settings (its tx variables), applied to each
// request before the CRS's defaults. Unset fields keep the CRS's defaults.
type CRSSettings struct {
	// AllowedMethods replaces the request methods the CRS allows (GET, HEAD,
	// POST and OPTIONS by default; rule 911100). List every method the
	// application serves, for example PUT, PATCH and DELETE for a REST API.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	AllowedMethods []HTTPMethodToken `json:"allowedMethods,omitempty"`

	// AllowedRequestContentTypes replaces the request media types the CRS
	// allows (rule 920420), as type/subtype without parameters, for example
	// application/json. Compared case-insensitively.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	AllowedRequestContentTypes []MediaType `json:"allowedRequestContentTypes,omitempty"`

	// DetectionParanoiaLevel runs the rules above paranoiaLevel, up to this
	// level, without blocking: a request they would have blocked is
	// logged. From paranoiaLevel to 4.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	// +optional
	DetectionParanoiaLevel *int32 `json:"detectionParanoiaLevel,omitempty"`

	// OutboundAnomalyThreshold is the response anomaly score at which a
	// response is blocked (the CRS's default is 4). Only used when the
	// policy inspects responses.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +optional
	OutboundAnomalyThreshold *int32 `json:"outboundAnomalyThreshold,omitempty"`
}

// IsZero reports whether s sets nothing (s may be nil).
func (s *CRSSettings) IsZero() bool {
	return s == nil || len(s.AllowedMethods) == 0 && len(s.AllowedRequestContentTypes) == 0 &&
		s.DetectionParanoiaLevel == nil && s.OutboundAnomalyThreshold == nil
}

// HTTPMethodToken is an HTTP request method, such as PUT.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:Pattern=`^[!#$%&'*+.^_~0-9A-Za-z-]+$`
type HTTPMethodToken string

// MediaType is a media type without parameters, such as application/json.
// +kubebuilder:validation:MinLength=3
// +kubebuilder:validation:MaxLength=129
// +kubebuilder:validation:Pattern=`^[!#$%&'*+.^_~0-9A-Za-z-]+/[!#$%&'*+.^_~0-9A-Za-z-]+$`
type MediaType string

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

// ExclusionMatch narrows an exclusion to a path, to what in the request the
// rules stop looking at (an argument, an argument name, a cookie or a
// header), or both.
// +kubebuilder:validation:XValidation:rule="has(self.path) || has(self.argument) || has(self.argumentName) || has(self.cookie) || has(self.header)",message="when needs a path, or what in the request to stop looking at"
// +kubebuilder:validation:XValidation:rule="[has(self.argument), has(self.argumentName), has(self.cookie), has(self.header)].filter(x, x).size() <= 1",message="at most one of argument, argumentName, cookie and header"
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

	// ArgumentName is a query or body argument whose name (ARGS_NAMES) the
	// rules stop looking at. Requires engines 0.5.0 or later: older ones
	// ignore the exclusion.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.\-\[\]]+$`
	// +optional
	ArgumentName string `json:"argumentName,omitempty"`

	// Cookie is a request cookie (REQUEST_COOKIES) the rules stop looking
	// at, such as a session token. Requires engines 0.5.0 or later.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.\-\[\]]+$`
	// +optional
	Cookie string `json:"cookie,omitempty"`

	// Header is a request header (REQUEST_HEADERS) the rules stop looking
	// at, such as Referer, compared case-insensitively. Requires engines
	// 0.5.0 or later.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.\-\[\]]+$`
	// +optional
	Header string `json:"header,omitempty"`
}

// Target reports whether m narrows its exclusion to an argument name, a
// cookie or a header (m may be nil).
func (m *ExclusionMatch) Target() bool {
	return m != nil && (m.ArgumentName != "" || m.Cookie != "" || m.Header != "")
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

	// GRPCMessages decides whether the text in gRPC calls' messages is
	// inspected: Inspect reads each protobuf message without its schema
	// and gives its text fields to the rules as form arguments; a message
	// that can't be read (cut at maxBytes, compressed other than with
	// gzip, not protobuf) is handled by onOversize. Unset: Skip, only the
	// call's path and metadata are inspected. See docs/grpc.md.
	// +optional
	GRPCMessages GRPCMessagesAction `json:"grpcMessages,omitempty"`
}

// WebSocketSpec is what a WebSocket handshake must meet.
// +kubebuilder:validation:XValidation:rule="!has(self.allowMissingOrigin) || !self.allowMissingOrigin || (has(self.allowedOrigins) && size(self.allowedOrigins) > 0)",message="allowMissingOrigin needs allowedOrigins"
type WebSocketSpec struct {
	// AllowedOrigins are the origins a handshake may come from, against
	// cross-site WebSocket hijacking: a page on another site can open a
	// WebSocket to the application with the user's cookies, and only the
	// Origin header tells. Each is "scheme://host" or "scheme://host:port",
	// lower case, with scheme http or https; a host "*.example.com"
	// matches any subdomain of example.com, not example.com itself. A
	// handshake without Origin is denied unless allowMissingOrigin is set.
	// Empty: any origin.
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	AllowedOrigins []WebSocketOrigin `json:"allowedOrigins,omitempty"`

	// AllowMissingOrigin lets a handshake without an Origin header pass
	// the origin check. Browsers always send Origin; other clients (a
	// mobile app, a service) may not, and aren't the target of cross-site
	// hijacking.
	// +optional
	AllowMissingOrigin bool `json:"allowMissingOrigin,omitempty"`

	// RequiredHeaders are headers a handshake must have, not empty: a
	// token (Authorization), a subprotocol (Sec-WebSocket-Protocol). Their
	// values aren't checked.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +optional
	RequiredHeaders []HeaderName `json:"requiredHeaders,omitempty"`
}

// WebSocketOrigin is an origin, "scheme://host[:port]", lower case; the
// host may start with "*." to match subdomains.
// +kubebuilder:validation:MaxLength=270
// +kubebuilder:validation:Pattern=`^https?://(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$`
type WebSocketOrigin string

// HeaderName is an HTTP header name.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`
type HeaderName string

// ResponsesSpec configures response inspection.
// +kubebuilder:validation:XValidation:rule="(has(self.inspect) && self.inspect) || (!has(self.maxBytes) && !has(self.onOversize))",message="maxBytes and onOversize need inspect: true"
type ResponsesSpec struct {
	// Inspect turns response inspection on: the status and headers, and
	// the body when its media type is text (plain, HTML, XML), JSON or XML.
	// In Block mode a response the rules flag is replaced with the
	// rule's status (403) and a plain-text error.
	// +optional
	Inspect bool `json:"inspect,omitempty"`

	// MaxBytes is how much of a response body is inspected, at most 10
	// MiB. Unset: 64 KiB (each KiB costs about 0.3 ms of inspection: raise
	// timeout with it). A longer body has this much inspected, and then
	// gets onOversize.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10485760
	// +optional
	MaxBytes *int64 `json:"maxBytes,omitempty"`

	// OnOversize is what happens to a response whose body is over maxBytes
	// or can't be inspected (an encoding other than gzip or deflate): Deny
	// (replaced with 502 in Block mode) or Allow (forwarded, and logged).
	// Unset: Deny in Block mode, Allow in Detect mode.
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
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
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
