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

// AdapterKind is how a proxy hands requests to the engine (0006). Only
// IntegrationSpec's deprecated Adapter uses it: the operator takes each
// integration's adapter from its built-in table, and ExtAuthz, LuaPlugin,
// AuthURL and Module have no implementation. The enum stays so that
// InkwallConfigs that set the field remain valid; v1 drops it.
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

	// Engine configures the engine sidecars the operator injects. Omitted,
	// it is {}, so that its defaults show.
	// +optional
	// +kubebuilder:default={}
	Engine EngineSpec `json:"engine,omitempty"`

	// Integrations pins how a proxy controller is wired. Controllers are
	// discovered without an entry here; an entry overrides the workload
	// selector for one controller.
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
	// Omitted, it is {}, so that its defaults show.
	// +optional
	// +kubebuilder:default={}
	Events EventsSpec `json:"events,omitempty"`
}

// EventsSpec configures the engines' security events.
type EventsSpec struct {
	// Redact keeps more of what rules matched out of the events. Omitted,
	// it is {}, so that its defaults show.
	// +optional
	// +kubebuilder:default={}
	Redact RedactSpec `json:"redact,omitempty"`

	// Export sends the security events to SIEMs and log pipelines, from
	// every operator replica, without the control plane (see
	// docs/siem-export.md). Events carry no more than Redact leaves; a sink
	// can only leave out more.
	// +optional
	Export *ExportSpec `json:"export,omitempty"`
}

// ExportSpec configures the export of security events.
type ExportSpec struct {
	// ClusterName names the cluster in every exported event, beside its ID
	// (the kube-system Namespace's UID).
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +optional
	ClusterName string `json:"clusterName,omitempty"`

	// Sinks are where the events go, at most 4. None: no export.
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:XValidation:rule="self.all(a, self.exists_one(b, b.name == a.name))",message="sinks must not repeat a name"
	// +listType=atomic
	// +optional
	Sinks []EventSink `json:"sinks,omitempty"`
}

// EventSink is one export destination: OTLP logs or JSON over HTTP.
// +kubebuilder:validation:XValidation:rule="has(self.otlp) != has(self.json)",message="a sink needs exactly one of otlp and json"
// +kubebuilder:validation:XValidation:rule="(has(self.insecure) && self.insecure) || !((has(self.otlp) && self.otlp.endpoint.matches('^(grpc|http)://')) || (has(self.json) && has(self.json.url) && self.json.url.startsWith('http://')))",message="a plaintext endpoint (http://, grpc://) needs insecure: true"
// +kubebuilder:validation:XValidation:rule="!has(self.headersSecretRef) || !((has(self.otlp) && self.otlp.endpoint.matches('^(grpc|http)://')) || (has(self.json) && has(self.json.url) && self.json.url.startsWith('http://')))",message="a plaintext endpoint (http://, grpc://) can't have headersSecretRef: credentials never travel in clear"
type EventSink struct {
	// Name identifies the sink: the sink label of the export metrics and
	// the name in the EventsExported condition. Renaming a sink starts it
	// afresh, without the events the old name hadn't sent.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// OTLP sends the events as OpenTelemetry logs, over gRPC or HTTP with
	// protobuf.
	// +optional
	OTLP *OTLPSink `json:"otlp,omitempty"`

	// JSON sends the events as JSON over HTTP(S).
	// +optional
	JSON *JSONSink `json:"json,omitempty"`

	// Compression of the request body. Unset: Gzip.
	// +kubebuilder:default=Gzip
	// +optional
	Compression ExportCompression `json:"compression,omitempty"`

	// Insecure allows a plaintext endpoint (http://, grpc://): for a
	// Collector in the cluster. A plaintext sink can't have
	// headersSecretRef.
	// +optional
	Insecure bool `json:"insecure,omitempty"`

	// TLS configures the connection to an https:// or grpcs:// endpoint.
	// The server's certificate is always verified.
	// +optional
	TLS *SinkTLS `json:"tls,omitempty"`

	// HeadersSecretRef names a Secret in the operator's namespace whose
	// keys are header names and whose values are their values
	// (Authorization: Bearer ..., DD-API-KEY: ...). Over gRPC they are sent
	// as metadata, lower-cased. A changed Secret is used from the next
	// request.
	// +optional
	HeadersSecretRef *LocalSecretReference `json:"headersSecretRef,omitempty"`

	// Batch configures how events are grouped into requests.
	// +optional
	Batch ExportBatch `json:"batch,omitempty"`

	// Timeout is one request's deadline, 1s to 60s. Unset: 10s.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1s') && duration(self) <= duration('60s')",message="timeout must be from 1s to 60s"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// Filter limits the events this sink takes.
	// +optional
	Filter ExportFilter `json:"filter,omitempty"`

	// Omit are fields this sink never gets: Snippets (each match keeps its
	// rule and variable), ClientIP, UserAgent, RequestID.
	// +kubebuilder:validation:MaxItems=4
	// +listType=set
	// +optional
	Omit []ExportOmit `json:"omit,omitempty"`
}

// OTLPSink is an OpenTelemetry (OTLP) logs receiver.
type OTLPSink struct {
	// Endpoint is grpcs://host:port (or grpc://, with insecure) for gRPC,
	// or an https:// (or http://) URL for HTTP with protobuf, used as is:
	// OTLP/HTTP's path, usually /v1/logs, is part of it.
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:Pattern=`^(grpcs?://[^/?#@\s]+|https?://[^/?#@\s]+([/?]\S*)?)$`
	Endpoint string `json:"endpoint"`
}

// JSONSink is an HTTP intake for JSON events.
// +kubebuilder:validation:XValidation:rule="has(self.url) != has(self.urlSecretRef)",message="json needs exactly one of url and urlSecretRef"
type JSONSink struct {
	// URL is the https:// (or http://, with insecure) URL the events are
	// POSTed to, with any path and query. A URL that holds a token belongs
	// in urlSecretRef.
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https?://[^/?#@\s]+([/?]\S*)?$`
	// +optional
	URL string `json:"url,omitempty"`

	// URLSecretRef reads the URL from a Secret's key in the operator's
	// namespace instead, for intakes whose URL holds a token (Sumo Logic,
	// query-string keys). It gets url's checks when the sink starts.
	// +optional
	URLSecretRef *SecretKeyReference `json:"urlSecretRef,omitempty"`

	// Framing is Lines (one event per line, application/x-ndjson) or
	// Array (one JSON array, application/json). Unset: Lines.
	// +kubebuilder:default=Lines
	// +optional
	Framing JSONFraming `json:"framing,omitempty"`
}

// JSONFraming is how JSON events are put in a request body.
// +kubebuilder:validation:Enum=Lines;Array
type JSONFraming string

// The JSON framings.
const (
	JSONLines JSONFraming = "Lines"
	JSONArray JSONFraming = "Array"
)

// ExportCompression is a request body's compression.
// +kubebuilder:validation:Enum=Gzip;None
type ExportCompression string

// The compressions.
const (
	CompressionGzip ExportCompression = "Gzip"
	CompressionNone ExportCompression = "None"
)

// SinkTLS configures a sink's TLS: version 1.2 or later, the server's
// certificate always verified.
type SinkTLS struct {
	// CASecretRef names a Secret in the operator's namespace whose ca.crt
	// holds the CAs trusted for the server. Unset: the system roots.
	// +optional
	CASecretRef *LocalSecretReference `json:"caSecretRef,omitempty"`

	// ClientCertificateSecretRef names a kubernetes.io/tls Secret in the
	// operator's namespace: the client certificate for mutual TLS.
	// +optional
	ClientCertificateSecretRef *LocalSecretReference `json:"clientCertificateSecretRef,omitempty"`

	// ServerName is the name checked in the server's certificate. Unset:
	// the endpoint's host.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?(\.[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?)*$`
	// +optional
	ServerName string `json:"serverName,omitempty"`
}

// ExportBatch configures a sink's requests.
type ExportBatch struct {
	// MaxEvents is the most events per request, 1 to 1,000. Unset: 500.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	// +optional
	MaxEvents *int32 `json:"maxEvents,omitempty"`

	// MaxDelay is the longest an event waits for its request to fill,
	// 100ms to 60s. Unset: 5s.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('100ms') && duration(self) <= duration('60s')",message="maxDelay must be from 100ms to 60s"
	// +optional
	MaxDelay *metav1.Duration `json:"maxDelay,omitempty"`

	// MaxInFlight is how many requests are sent before the first is
	// answered, 1 to 4. Unset: 4.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	// +optional
	MaxInFlight *int32 `json:"maxInFlight,omitempty"`
}

// ExportFilter limits a sink's events.
type ExportFilter struct {
	// Actions are the verdicts this sink takes: Deny, Log. Unset: both.
	// +kubebuilder:validation:MaxItems=2
	// +listType=set
	// +optional
	Actions []ExportAction `json:"actions,omitempty"`

	// PolicyNamespaces takes only the events of policies in these
	// namespaces, as the bundle the replica serves knows them: an event
	// whose policy isn't in the bundle, or that has none, goes only to
	// sinks without this filter. Unset: all.
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	PolicyNamespaces []NamespaceName `json:"policyNamespaces,omitempty"`
}

// ExportAction is a verdict a sink filters on.
// +kubebuilder:validation:Enum=Deny;Log
type ExportAction string

// The actions.
const (
	ExportDeny ExportAction = "Deny"
	ExportLog  ExportAction = "Log"
)

// ExportOmit is a field a sink leaves out.
// +kubebuilder:validation:Enum=Snippets;ClientIP;UserAgent;RequestID
type ExportOmit string

// The fields a sink can omit.
const (
	OmitSnippets  ExportOmit = "Snippets"
	OmitClientIP  ExportOmit = "ClientIP"
	OmitUserAgent ExportOmit = "UserAgent"
	OmitRequestID ExportOmit = "RequestID"
)

// NamespaceName is a Kubernetes namespace's name: a DNS label.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
type NamespaceName string

// LocalSecretReference names a Secret in the operator's namespace.
type LocalSecretReference struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
}

// SecretKeyReference names a key of a Secret in the operator's namespace.
type SecretKeyReference struct {
	// Name of the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Key in the Secret.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
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

	// EnrollmentSecretRef is the Secret holding the enrollment token, in
	// the operator's namespace (its namespace can be left out).
	EnrollmentSecretRef SecretReference `json:"enrollmentSecretRef"`
}

// RolloutPolicy is how proxy pods get a new engine.
// +kubebuilder:validation:Enum=Manual;Automatic
type RolloutPolicy string

// The rollout policies.
const (
	RolloutManual    RolloutPolicy = "Manual"
	RolloutAutomatic RolloutPolicy = "Automatic"
)

// DenialFormat is the body of an engine's denials.
// +kubebuilder:validation:Enum=Text;JSON
type DenialFormat string

// The denial formats.
const (
	// DenialText answers every denied client with plain text.
	DenialText DenialFormat = "Text"
	// DenialJSON answers a denied client that accepts application/json
	// with a JSON body, and any other client with text.
	DenialJSON DenialFormat = "JSON"
)

// EngineSpec configures the engine sidecars.
// +kubebuilder:validation:XValidation:rule="!(has(self.jsonDenials) && self.jsonDenials && has(self.denialFormat) && self.denialFormat == 'Text')",message="jsonDenials: true contradicts denialFormat: Text; remove jsonDenials, which is deprecated"
type EngineSpec struct {
	// Image is the engine image. Empty means the image released with this
	// operator version. An image whose tag is an older release (0.4.1) is
	// injected without the settings below that release doesn't know, and
	// one whose tag isn't a release (latest, a digest alone) without any
	// setting some release doesn't know, so it starts: the EngineConfigured
	// condition names them.
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

	// Rollout is how proxy pods that need a new engine (none: started
	// before Inkwall; or another image than the one configured) get one.
	// Manual: they are reported (PendingRestart) and you restart them.
	// Automatic: the operator evicts them one at a time through the
	// Eviction API, which respects PodDisruptionBudgets, waiting for each
	// replacement to be ready and run the current bundle before the next;
	// it pauses, and says why on the InkwallConfig (EngineRollout), when an
	// eviction is refused or a replacement isn't ready in time. Pods the
	// Pod webhook injects only (Traefik, HAProxy, Istio's ingress gateways):
	// Envoy Gateway and Istio's Gateway API deployments roll their pods
	// themselves.
	// +kubebuilder:default=Manual
	// +optional
	Rollout RolloutPolicy `json:"rollout,omitempty"`

	// PolicyMetrics adds inkwall_policy_requests_total, the engines'
	// requests by policy, for up to 500 policies per engine (the rest count
	// as policy="other"). Off by default: one series per policy, action and
	// reason. Applies to pods injected from then on.
	// +optional
	PolicyMetrics bool `json:"policyMetrics,omitempty"`

	// DenialFormat is the body of the engines' denials. Text: plain text.
	// JSON: a client that accepts application/json gets a JSON body,
	// {"error":"forbidden","status":403,"request_id":...}, and any other
	// client text. Every denial carries X-Request-Id either way. Through
	// Traefik, Envoy Gateway and Istio; HAProxy writes its own denials.
	// Unset: Text, or JSON when the deprecated jsonDenials is true. Applies
	// to pods injected from then on. JSON requires engines 0.5.0 or later.
	// +optional
	DenialFormat DenialFormat `json:"denialFormat,omitempty"`

	// JSONDenials true means denialFormat: JSON, which takes its place. It
	// stays so that InkwallConfigs that set it remain valid; setting or
	// changing it draws a warning, and v1 removes it. It can't be true
	// with denialFormat: Text.
	//
	// Deprecated: use denialFormat.
	//
	// +optional
	JSONDenials bool `json:"jsonDenials,omitempty"`

	// RateLimitKeys is the rate limit buckets each engine holds at once,
	// for every policy's spec.rateLimits: about 48 bytes each, allocated
	// with the first bundle that has limits, and at most a quarter of the
	// engine's memory limit. When the table is full, the buckets closest
	// to full are forgotten (inkwall_rate_limit_evictions_total{kind="active"}).
	// Unset: 262,144 (about 12 MiB). Applies to pods injected from then
	// on. Requires engines 0.7.0 or later.
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=16777216
	// +optional
	RateLimitKeys *int32 `json:"rateLimitKeys,omitempty"`

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
	// Controller is the integration name: traefik, envoy-gateway, istio,
	// istio-ingress or haproxy. The operator ignores an entry for any other
	// controller. It should be a DNS label (lower case letters, digits and
	// "-"): any other name draws a warning, and v1 refuses it.
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

	// Adapter is ignored: the operator takes each integration's adapter
	// from its built-in table, and four of the values (ExtAuthz, LuaPlugin,
	// AuthURL, Module) have no implementation. It stays so that
	// InkwallConfigs that set it remain valid; setting or changing it draws
	// a warning, and v1 removes it.
	//
	// Deprecated: remove it from the InkwallConfig.
	//
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

	// Bundle is the bundle the engines get.
	// +optional
	Bundle *BundleStatus `json:"bundle,omitempty"`

	// Engines counts the connected engines by the bundle they run.
	// +optional
	Engines *EngineCounts `json:"engines,omitempty"`

	// SigningKey is the bundle signing key and its rotation.
	// +optional
	SigningKey *SigningKeyStatus `json:"signingKey,omitempty"`
}

// BundleStatus describes the published bundle.
type BundleStatus struct {
	// Version of the bundle published.
	Version int64 `json:"version"`

	// CompressedBytes is its size as stored, gzip-compressed.
	CompressedBytes int64 `json:"compressedBytes"`

	// LimitBytes is the largest bundle that can be published: past it,
	// policy changes aren't published (BundleTooLarge).
	LimitBytes int64 `json:"limitBytes"`
}

// EngineCounts counts the connected engines, as of the replicas' latest
// engine reports.
type EngineCounts struct {
	// Connected engines.
	Connected int32 `json:"connected"`

	// Current engines run the published bundle.
	Current int32 `json:"current"`

	// Behind engines run an older bundle, and haven't rejected the
	// published one.
	Behind int32 `json:"behind"`

	// Rejected engines rejected the published bundle.
	Rejected int32 `json:"rejected"`

	// Outdated engines are too old for a field some policy sets, which they
	// ignore (EnginesOutdated).
	Outdated int32 `json:"outdated"`
}

// SigningKeyPhase is where a signing key rotation is.
// +kubebuilder:validation:Enum=Idle;Publishing;Retiring
type SigningKeyPhase string

// The phases of a signing key rotation.
const (
	// SigningKeyIdle: one key, which signs.
	SigningKeyIdle SigningKeyPhase = "Idle"
	// SigningKeyPublishing: the next key is published to the engines; the
	// active one still signs.
	SigningKeyPublishing SigningKeyPhase = "Publishing"
	// SigningKeyRetiring: the new key signs; the previous one stays trusted
	// until every engine runs a bundle the new one signed.
	SigningKeyRetiring SigningKeyPhase = "Retiring"
)

// SigningKeyStatus describes the bundle signing key.
type SigningKeyStatus struct {
	// ActiveKeyID is the ID of the key that signs bundles.
	// +kubebuilder:validation:MaxLength=128
	ActiveKeyID string `json:"activeKeyID"`

	// Phase of the rotation.
	Phase SigningKeyPhase `json:"phase"`

	// Since is when the phase began (Publishing, Retiring), or when the
	// active key began to sign (Idle).
	// +optional
	Since *metav1.Time `json:"since,omitempty"`

	// WaitingFor says what the rotation waits for; empty when it waits for
	// nothing.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	WaitingFor string `json:"waitingFor,omitempty"`
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
// +kubebuilder:printcolumn:name="Bundle",type=integer,JSONPath=`.status.bundle.version`
// +kubebuilder:printcolumn:name="Engines",type=integer,JSONPath=`.status.engines.connected`
// +kubebuilder:printcolumn:name="Current",type=integer,JSONPath=`.status.engines.current`
// +kubebuilder:printcolumn:name="Key",type=string,JSONPath=`.status.signingKey.phase`
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
