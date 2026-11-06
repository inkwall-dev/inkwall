// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterMode is where a cluster's policy comes from (0002 §4.1).
// +kubebuilder:validation:Enum=Standalone;GitOps;Managed
type ClusterMode string

const (
	// ModeStandalone takes policy from the CRDs, with no control plane.
	ModeStandalone ClusterMode = "Standalone"
	// ModeGitOps takes policy from the CRDs and mirrors it, read-only, to
	// the control plane.
	ModeGitOps ClusterMode = "GitOps"
	// ModeManaged takes policy from the control plane, which the operator
	// writes as CRDs; edits by anyone else are rejected.
	ModeManaged ClusterMode = "Managed"
)

// AdapterKind is how a proxy hands requests to the engine (0006).
// +kubebuilder:validation:Enum=ExtProc;ExtAuthz;LuaPlugin;AuthURL;ForwardAuth;SPOE;Module
type AdapterKind string

// The adapter kinds.
const (
	AdapterExtProc     AdapterKind = "ExtProc"
	AdapterExtAuthz    AdapterKind = "ExtAuthz"
	AdapterLuaPlugin   AdapterKind = "LuaPlugin"
	AdapterAuthURL     AdapterKind = "AuthURL"
	AdapterForwardAuth AdapterKind = "ForwardAuth"
	AdapterSPOE        AdapterKind = "SPOE"
	AdapterModule      AdapterKind = "Module"
)

// BootstrapMode is what an engine does with requests before it has a policy
// bundle (0004 §4.6).
// +kubebuilder:validation:Enum=AllowAll;DenyAll
type BootstrapMode string

// The bootstrap modes.
const (
	// BootstrapAllowAll lets requests through uninspected: availability
	// first.
	BootstrapAllowAll BootstrapMode = "AllowAll"
	// BootstrapDenyAll rejects them with 503.
	BootstrapDenyAll BootstrapMode = "DenyAll"
)

// InkwallConfigSpec is the cluster-wide configuration.
// +kubebuilder:validation:XValidation:rule="!has(self.mode) || self.mode == 'Standalone' || has(self.controlPlane)",message="controlPlane is required in GitOps and Managed mode"
type InkwallConfigSpec struct {
	// Mode is where policy comes from: Standalone (the CRDs), GitOps (the
	// CRDs, mirrored to the control plane) or Managed (the control plane).
	// +kubebuilder:default=Standalone
	// +optional
	Mode ClusterMode `json:"mode,omitempty"`

	// ControlPlane is the control plane to connect to. Required in GitOps
	// and Managed mode, ignored in Standalone.
	// +optional
	ControlPlane *ControlPlane `json:"controlPlane,omitempty"`

	// Engine configures the engine sidecars the operator injects.
	// +optional
	Engine EngineSpec `json:"engine,omitempty"`

	// Integrations pins how a proxy controller is wired. Controllers are
	// discovered without an entry here; an entry overrides the workload
	// selector or the adapter for one controller.
	// +listType=map
	// +listMapKey=controller
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Integrations []IntegrationSpec `json:"integrations,omitempty"`

	// Suspend switches every engine to allow-all within seconds, without
	// removing anything: the emergency switch (0004 §5).
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// SigningKey configures the key the operator signs policy bundles with.
	// +optional
	SigningKey SigningKeySpec `json:"signingKey,omitempty"`

	// Events configures what the engines' security events carry to the
	// operator (and on to the control plane, when one is connected).
	// +optional
	Events EventsSpec `json:"events,omitempty"`
}

// EventsSpec configures the engines' security events.
type EventsSpec struct {
	// Redact keeps more of what rules matched out of the events.
	// +optional
	Redact RedactSpec `json:"redact,omitempty"`
}

// RedactSpec adds to the redaction every engine applies to the snippets of
// its security events: the up to 64 bytes of what each rule matched. Always
// redacted: cookies, response bodies, the Authorization, Cookie, Set-Cookie
// and Proxy-Authorization headers, and arguments and headers whose names
// look like credentials (password, secret, token, api key, auth, session,
// JWT, card, SSN; see docs/design/0002 §8.3).
type RedactSpec struct {
	// Headers are more header names whose values leave no snippet, matched
	// without regard to case.
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	Headers []HeaderName `json:"headers,omitempty"`

	// Arguments are more argument-name patterns: a match on a query or
	// body argument whose name contains one, without regard to case, leaves
	// no snippet ("email" covers email, user_email and json.user.Email).
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	Arguments []ArgumentPattern `json:"arguments,omitempty"`

	// Snippets set to false sends no snippets at all: events keep the rule
	// and the variable it matched, never what it matched.
	// +kubebuilder:default=true
	// +optional
	Snippets *bool `json:"snippets,omitempty"`
}

// ArgumentPattern is part of an argument name, as WAFPolicy exclusions
// name arguments.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.\-\[\]]+$`
type ArgumentPattern string

// RotateSigningKeyAnnotation on the InkwallConfig requests a rotation of the
// bundle signing key: each new value starts one (a timestamp, say). The
// operator publishes a new key to the engines, switches to it once every
// connected engine trusts it, and retires the old key once every engine
// runs a bundle signed with the new one. A request made during a rotation
// starts another one after it.
const RotateSigningKeyAnnotation = "waf.inkwall.dev/rotate-signing-key"

// SigningKeySpec configures the bundle signing key.
type SigningKeySpec struct {
	// RotationInterval rotates the signing key once it has signed for this
	// long, e.g. 2160h (90 days); at least 1h. Empty: the key rotates only
	// when requested with the waf.inkwall.dev/rotate-signing-key
	// annotation.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1h')",message="rotationInterval must be at least 1h"
	// +optional
	RotationInterval *metav1.Duration `json:"rotationInterval,omitempty"`
}

// ControlPlane is the connection to the optional control plane.
type ControlPlane struct {
	// Endpoint is the control plane's gRPC address, as grpcs://host:port.
	// +kubebuilder:validation:Pattern=`^grpcs://[^/\s]+$`
	// +kubebuilder:validation:MaxLength=512
	Endpoint string `json:"endpoint"`

	// EnrollmentSecretRef is the Secret holding the enrollment token.
	EnrollmentSecretRef SecretReference `json:"enrollmentSecretRef"`
}

// EngineSpec configures the engine sidecars.
type EngineSpec struct {
	// Image is the engine image. Empty means the image released with this
	// operator version.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	Image string `json:"image,omitempty"`

	// Resources of the engine container. Setting no CPU limit is
	// recommended: CPU throttling shows up as tail latency on every request.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// SocketDir is ignored: each integration places the engine's socket
	// itself (Envoy Gateway's in /var/run/inkwall-socket; Traefik reaches
	// the engine over loopback TCP). It stays so that InkwallConfigs that
	// set it remain valid; setting it draws a warning.
	//
	// Deprecated: remove it from the InkwallConfig.
	//
	// +kubebuilder:validation:MaxLength=64
	// +optional
	SocketDir string `json:"socketDir,omitempty"`

	// BootstrapMode is what a new engine does with requests when it has no
	// bundle yet: no cached bundle, the bundle Secret unreadable and the
	// operator unreachable. It waits up to 10 seconds for one before its
	// proxy takes traffic, then allows (AllowAll) or rejects (DenyAll) the
	// requests until a bundle arrives. Applies to pods injected from then
	// on.
	// +kubebuilder:default=AllowAll
	// +optional
	BootstrapMode BootstrapMode `json:"bootstrapMode,omitempty"`

	// LogLevel is the engines' log level: Debug, Info, Warn or Error.
	// Security events are logged at Warn, so Error hides them (they still
	// go to the operator). Unset: the engine's default, Info. Applies to
	// pods injected from then on.
	// +optional
	LogLevel LogLevel `json:"logLevel,omitempty"`

	// ClientIP configures which forwarding headers the engines trust for
	// the client's address, behind an HTTP load balancer that appends it to
	// X-Forwarded-For. Unset: only the proxy beside the engine is trusted.
	// A wrong setting lets clients choose their address: see
	// docs/client-ip.md. Applies to pods injected from then on (Envoy
	// Gateway rolls its pods itself).
	// +optional
	ClientIP *ClientIPSpec `json:"clientIP,omitempty"`
}

// LogLevel is an engine's log level.
// +kubebuilder:validation:Enum=Debug;Info;Warn;Error
type LogLevel string

// Engine log levels.
const (
	LogLevelDebug LogLevel = "Debug"
	LogLevelInfo  LogLevel = "Info"
	LogLevelWarn  LogLevel = "Warn"
	LogLevelError LogLevel = "Error"
)

// ClientIPSpec configures how engines find the client's address.
type ClientIPSpec struct {
	// TrustedProxies are the addresses or CIDR prefixes of proxies in front
	// of the proxy the engine runs beside (load balancers) whose
	// X-Forwarded-For entries are trusted. The loopback is always trusted.
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	// +optional
	TrustedProxies []CIDR `json:"trustedProxies,omitempty"`

	// TrustedHops is how many X-Forwarded-For entries, from the right and
	// after those the proxy beside the engine added, are proxies whatever
	// their address: for load balancers without fixed addresses. 0: none.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	// +optional
	TrustedHops *int32 `json:"trustedHops,omitempty"`
}

// CIDR is an IPv4 or IPv6 prefix (10.0.0.0/8) or address.
// +kubebuilder:validation:MinLength=2
// +kubebuilder:validation:MaxLength=49
// +kubebuilder:validation:Pattern=`^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$`
type CIDR string

// IntegrationSpec overrides discovery for one proxy controller.
type IntegrationSpec struct {
	// Controller is the integration name, such as traefik or ingress-nginx.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Controller string `json:"controller"`

	// Selector matches the controller's proxy pods, when they don't carry
	// the controller's default labels. It must select by something (an
	// empty selector would match every pod). The operator restarts to
	// apply a change; pods already running are injected when they restart.
	// +kubebuilder:validation:XValidation:rule="(has(self.matchLabels) && size(self.matchLabels) > 0) || (has(self.matchExpressions) && size(self.matchExpressions) > 0)",message="selector must not be empty: it would select every pod"
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Adapter is how the proxy hands requests to the engine, when the
	// controller supports several.
	// +optional
	Adapter AdapterKind `json:"adapter,omitempty"`
}

// InkwallConfigStatus is the cluster view.
type InkwallConfigStatus struct {
	// ObservedGeneration is the generation the status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions describe the configuration's state.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Proxies are the proxy controllers the cluster's IngressClasses and
	// GatewayClasses name, and how far Inkwall wires each.
	// +listType=map
	// +listMapKey=controllerName
	// +optional
	Proxies []ProxyStatus `json:"proxies,omitempty"`
}

// Support is how far Inkwall wires a proxy controller's routes (0004 §4.1).
// +kubebuilder:validation:Enum=Full;Partial;Unsupported
type Support string

// The support levels.
const (
	// SupportFull: Inkwall wires the routes of every class of the
	// controller.
	SupportFull Support = "Full"
	// SupportPartial: it wires those of some of its classes; the message
	// says which aren't.
	SupportPartial Support = "Partial"
	// SupportUnsupported: it wires none; a policy on one of its routes is
	// not Programmed (ControllerUnsupported).
	SupportUnsupported Support = "Unsupported"
)

// ProxyStatus is a proxy controller found in the cluster.
type ProxyStatus struct {
	// ControllerName is the controller its classes name: an IngressClass's
	// spec.controller, a GatewayClass's spec.controllerName.
	// +kubebuilder:validation:MaxLength=253
	ControllerName string `json:"controllerName"`

	// Integration is Inkwall's integration for the controller, such as
	// traefik; empty when Inkwall has none.
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Integration string `json:"integration,omitempty"`

	// IngressClasses are the IngressClasses of the controller.
	// +optional
	IngressClasses []string `json:"ingressClasses,omitempty"`

	// GatewayClasses are the GatewayClasses of the controller.
	// +optional
	GatewayClasses []string `json:"gatewayClasses,omitempty"`

	// Support is Full, Partial or Unsupported.
	Support Support `json:"support"`

	// Message says what isn't wired.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Message string `json:"message,omitempty"`
}

// InkwallConfig is the cluster-wide Inkwall configuration. There is one,
// named default.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=inkwall
// +kubebuilder:validation:XValidation:rule="self.metadata.name == 'default'",message="the InkwallConfig must be named default"
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Suspended",type=boolean,JSONPath=`.spec.suspend`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type InkwallConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec InkwallConfigSpec `json:"spec,omitempty"`
	// +optional
	Status InkwallConfigStatus `json:"status,omitempty"`
}

// InkwallConfigList is a list of InkwallConfig.
//
// +kubebuilder:object:root=true
type InkwallConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []InkwallConfig `json:"items"`
}
