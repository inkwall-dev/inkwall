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

// GRPCAction is whether a policy lets gRPC calls through.
// +kubebuilder:validation:Enum=Allow;Deny
type GRPCAction string

const (
	// GRPCAllow inspects gRPC calls as gRPC (the default).
	GRPCAllow GRPCAction = "Allow"
	// GRPCDeny denies them: for routes that serve no gRPC.
	GRPCDeny GRPCAction = "Deny"
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

// StreamsAction is whether streamed responses are inspected event by event.
// +kubebuilder:validation:Enum=Inspect;Skip
type StreamsAction string

const (
	// StreamsInspect inspects each event of a Server-Sent Events stream
	// and each message of a gRPC response on its own.
	StreamsInspect StreamsAction = "Inspect"
	// StreamsSkip inspects a stream's status and headers only.
	StreamsSkip StreamsAction = "Skip"
)

// GRPCStreamsMode is how a gRPC call's messages are read: the buffered
// body, or one by one as they come.
// +kubebuilder:validation:Enum=Buffer;PerMessage
type GRPCStreamsMode string

const (
	// GRPCStreamsBuffer inspects the messages in the body the proxy
	// buffers, up to maxBytes in all (the default).
	GRPCStreamsBuffer GRPCStreamsMode = "Buffer"
	// GRPCStreamsPerMessage inspects each message as it comes, up to
	// maxBytes each, through Envoy (#315).
	GRPCStreamsPerMessage GRPCStreamsMode = "PerMessage"
)

// WAFPolicySpec is what to enforce on which routes.
type WAFPolicySpec struct {
	// TargetRefs are the routes this policy protects, in the policy's
	// namespace.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(a, self.exists_one(b, b.kind == a.kind && b.name == a.name && (has(b.sectionName) ? b.sectionName : '') == (has(a.sectionName) ? a.sectionName : '')))",message="targetRefs must not repeat a target"
	// +listType=atomic
	TargetRefs []TargetRef `json:"targetRefs"`

	// Mode is Detect (log, let through) or Block (reject).
	// +kubebuilder:default=Detect
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`

	// FailureMode is what happens to a request that can't be inspected in
	// time. Unset: Closed in Block mode, Open in Detect mode.
	// +optional
	FailureMode FailureMode `json:"failureMode,omitempty"`

	// Timeout is the inspection deadline per request, at most 1s.
	// +kubebuilder:default="250ms"
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
	// +listType=atomic
	RuleSets []RuleSetBinding `json:"ruleSets,omitempty"`

	// Exclusions turn rules off where they cause false positives.
	// +kubebuilder:validation:MaxItems=128
	// +optional
	// +listType=atomic
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
	// variables). Unset: responses are not inspected. Envoy Gateway,
	// Istio and the HAProxy Kubernetes Ingress Controller (once its pods
	// run an engine of 0.6.0 or later) send responses to the engine; on a
	// route of Traefik (its ForwardAuth can't), or of HAProxy before then,
	// the policy is not Programmed (ResponsesNotInspected).
	// +optional
	Responses *ResponsesSpec `json:"responses,omitempty"`

	// IPLists names WAFIPLists in the policy's namespace whose client
	// addresses are denied, or let through uninspected. A deny list wins
	// over an allow list. They are only as good as the client IP the
	// engine resolves (docs/client-ip.md). Requires engines 0.5.0 or
	// later.
	// +optional
	IPLists *IPListsSpec `json:"ipLists,omitempty"`

	// RateLimits limit how many requests a client may send, per engine:
	// over a limit, a request is denied with 429 and Retry-After before the
	// rules (logged in Detect mode). Each engine counts on its own, so a
	// client spread over N engines gets up to N times the limit
	// (docs/rate-limits.md). Clients in an IP allow list, and skipped
	// paths, are never counted. Requires engines 0.7.0 or later.
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:XValidation:rule="self.all(a, self.exists_one(b, b.name == a.name))",message="rateLimits must not repeat a name"
	// +optional
	// +listType=atomic
	RateLimits []RateLimit `json:"rateLimits,omitempty"`

	// DenyResponse is the body of the policy's denials (by a rule, an IP
	// list, the WebSocket or gRPC checks, a rate limit, a request that
	// couldn't be inspected in time, a response replaced), instead of the
	// engine's own text, with the denial's status. Unset: the
	// InkwallConfig's spec.engine.denyResponse, if set. Through Traefik,
	// Envoy Gateway, Istio and the engine's check API; HAProxy writes its
	// own denials. Requires engines 0.7.0 or later.
	// +optional
	DenyResponse *DenyResponse `json:"denyResponse,omitempty"`

	// LLM declares paths of the policy's routes as LLM APIs (OpenAI Chat
	// Completions, Responses or Embeddings, Anthropic Messages): their
	// request bodies are read up to maxBodyBytes, parsed strictly, and
	// checked natively (the model, the prompt's size, the messages, the
	// output limit, the roles and tools a client sends). A body that
	// doesn't parse one way, or fails a check, is denied with 400 (413 for
	// the size caps) in Block mode. The rule sets skip these bodies unless
	// ruleSetBody is Inspect. Requires engines 0.7.0 or later
	// (docs/llm-apis.md).
	// +optional
	LLM *LLMSpec `json:"llm,omitempty"`
}

// LLMFormat is the shape of an LLM API's requests.
// +kubebuilder:validation:Enum=OpenAIChat;OpenAIResponses;OpenAIEmbeddings;AnthropicMessages
type LLMFormat string

const (
	// LLMOpenAIChat is OpenAI's Chat Completions (/v1/chat/completions),
	// as OpenAI-compatible servers (vLLM, Ollama, LiteLLM, llama.cpp)
	// serve it.
	LLMOpenAIChat LLMFormat = "OpenAIChat"
	// LLMOpenAIResponses is OpenAI's Responses (/v1/responses).
	LLMOpenAIResponses LLMFormat = "OpenAIResponses"
	// LLMOpenAIEmbeddings is OpenAI's Embeddings (/v1/embeddings).
	LLMOpenAIEmbeddings LLMFormat = "OpenAIEmbeddings"
	// LLMAnthropicMessages is Anthropic's Messages (/v1/messages).
	LLMAnthropicMessages LLMFormat = "AnthropicMessages"
)

// LLMRuleSetBody is whether the rule sets inspect the bodies of LLM
// endpoints.
// +kubebuilder:validation:Enum=Skip;Inspect
type LLMRuleSetBody string

const (
	// LLMRuleSetBodySkip has the rule sets inspect an endpoint's method, URI,
	// headers and cookies, not its bodies.
	LLMRuleSetBodySkip LLMRuleSetBody = "Skip"
	// LLMRuleSetBodyInspect has them inspect its bodies too, as on any route.
	LLMRuleSetBodyInspect LLMRuleSetBody = "Inspect"
)

// LLMSpec declares a policy's LLM API endpoints and their checks.
type LLMSpec struct {
	// Endpoints are the policy's paths that serve an LLM API, each with
	// its format. Declared, not guessed: gateways and Azure OpenAI serve
	// these APIs on other paths. A path of no endpoint is an ordinary
	// route to the policy.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:XValidation:rule="self.all(e, e.paths.all(p, self.filter(f, p in f.paths).size() == 1))",message="an endpoint path can't be in two endpoints"
	// +listType=atomic
	Endpoints []LLMEndpoint `json:"endpoints"`

	// MaxBodyBytes is the request body read on an endpoint, 1 KiB to 10
	// MiB, instead of body.maxBytes: chat histories and agents' contexts
	// are large. A longer body gets body.onOversize (413 in Block mode by
	// default). The proxy's own buffer still bounds what reaches the
	// engine (docs/llm-apis.md). Unset: 1 MiB.
	// +kubebuilder:validation:Minimum=1024
	// +kubebuilder:validation:Maximum=10485760
	// +optional
	MaxBodyBytes *int64 `json:"maxBodyBytes,omitempty"`

	// RuleSetBody is whether the rule sets (the CRS, SecLang) inspect the
	// endpoints' request and response bodies too. Skip, the default: they
	// inspect the endpoints' method, URI, headers and cookies, and the LLM
	// checks the bodies; prose and pasted code trip the CRS's SQL
	// injection and XSS rules all the time, and its cost on large bodies
	// is out of every latency budget. This changes what the rule sets read
	// on a route that adds spec.llm. Inspect: they inspect the bodies, up
	// to maxBodyBytes, as on any route (unless body.inspect is false).
	// +optional
	RuleSetBody LLMRuleSetBody `json:"ruleSetBody,omitempty"`

	// Request sets the request checks. Unset: only that bodies are
	// well-formed (llm-malformed).
	// +optional
	Request *LLMRequestSpec `json:"request,omitempty"`
}

// LLMEndpoint is paths that serve one LLM API.
type LLMEndpoint struct {
	// Paths are exact paths or prefixes ending in "*", compared as rate
	// limits' match.paths: in ASCII lower case, with one trailing slash
	// ignored. A path the engine can't read one way (percent-encoding,
	// ";", "//", dot segments) is checked as an endpoint of each of the
	// policy's formats. skip.paths and skip.bodyPaths win: a body not read
	// isn't checked.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	Paths []PathPattern `json:"paths"`

	// Format is the shape of the endpoint's requests.
	Format LLMFormat `json:"format"`
}

// LLMRequestSpec are the checks an endpoint's requests must meet. Each
// failed check denies, in Block mode, with 400 (413 for maxPromptBytes and
// maxMessages), in this order: the first decides.
type LLMRequestSpec struct {
	// Models are the models allowed: exact, or a prefix ending in "*",
	// compared in ASCII lower case. A request that names no model, or
	// another one, fails llm-model. Unset: any.
	// +kubebuilder:validation:MaxItems=64
	// +listType=set
	// +optional
	Models []LLMModelPattern `json:"models,omitempty"`

	// MaxPromptBytes caps the UTF-8 bytes of the prompt's text, every
	// message together, 1 to 10 MiB (llm-max-prompt). Images, audio and
	// files count toward maxBodyBytes only.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10485760
	// +optional
	MaxPromptBytes *int64 `json:"maxPromptBytes,omitempty"`

	// MaxMessages caps the messages, input items or embedding inputs of a
	// request, 1 to 100000 (llm-max-messages).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	// +optional
	MaxMessages *int32 `json:"maxMessages,omitempty"`

	// MaxChoices caps n, the answers a chat request asks for, 1 to 128
	// (llm-max-choices).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=128
	// +optional
	MaxChoices *int32 `json:"maxChoices,omitempty"`

	// MaxOutputTokens caps the output limit a request sets (max_tokens,
	// max_completion_tokens, max_output_tokens), 1 to 10000000
	// (llm-max-output-tokens). Inkwall doesn't lower it: a request over
	// the cap is denied.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000000
	// +optional
	MaxOutputTokens *int64 `json:"maxOutputTokens,omitempty"`

	// RequireOutputTokens denies a request that sets no output limit
	// (llm-max-output-tokens): without one, OpenAI-compatible servers
	// generate up to the model's maximum. Embeddings have none to set.
	// +optional
	RequireOutputTokens bool `json:"requireOutputTokens,omitempty"`

	// ClientRoles are the roles of the messages a client may send
	// (llm-client-role); the Responses API's instructions and Anthropic's
	// system count as system, and a role none of these as none of them.
	// A chat front end that adds its own system prompt sets user and
	// assistant: a client that sends system or developer overrides it.
	// Unset: every role.
	// +kubebuilder:validation:MaxItems=5
	// +listType=set
	// +optional
	ClientRoles []LLMRole `json:"clientRoles,omitempty"`

	// Tools are the tools a client may define (llm-tools). Unset: any.
	// +optional
	Tools *LLMToolsSpec `json:"tools,omitempty"`

	// Mode Detect logs the requests that fail a check instead of denying
	// them, on a Block policy. Unset: the policy's mode. Block isn't
	// allowed: the checks can't be stricter than their policy.
	// +kubebuilder:validation:XValidation:rule="self == 'Detect'",message="the LLM checks' mode can only be Detect: they can't be stricter than their policy"
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`
}

// LLMModelPattern is a model ("llama-3.1-8b-instruct") or a prefix ending
// in "*" ("qwen2.5-*"), printable ASCII without spaces.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[!-)+-~]+\*?$`
type LLMModelPattern string

// LLMRole is who wrote a message.
// +kubebuilder:validation:Enum=system;developer;user;assistant;tool
type LLMRole string

// LLMToolsAllow is which tools a client may define.
// +kubebuilder:validation:Enum=Any;None;Listed
type LLMToolsAllow string

const (
	// LLMToolsAny allows any tool.
	LLMToolsAny LLMToolsAllow = "Any"
	// LLMToolsNone allows none.
	LLMToolsNone LLMToolsAllow = "None"
	// LLMToolsListed allows the tools names lists.
	LLMToolsListed LLMToolsAllow = "Listed"
)

// LLMToolsSpec is which tools a client may define.
// +kubebuilder:validation:XValidation:rule="(has(self.allow) && self.allow == 'Listed') == (has(self.names) && size(self.names) > 0)",message="names is required with allow: Listed, and only allowed with it"
type LLMToolsSpec struct {
	// Allow is Any (the default), None, or Listed: the tools names lists.
	// +optional
	Allow LLMToolsAllow `json:"allow,omitempty"`

	// Names are the tools a client may define with Listed: a function's
	// name, or a built-in tool's type when it has no name
	// ("web_search_preview"), compared exactly.
	// +kubebuilder:validation:MaxItems=128
	// +listType=set
	// +optional
	Names []LLMToolName `json:"names,omitempty"`
}

// LLMToolName is a tool's name.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.:/-]+$`
type LLMToolName string

// RateLimit is a token bucket per key: it holds at most burst requests and
// gains requests per period, evenly.
type RateLimit struct {
	// Name names the limit in events and logs; unique in the policy.
	// Renaming a limit starts its buckets again full.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Requests are the requests allowed per period, per key, per engine.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	Requests int64 `json:"requests"`

	// Period is the period of requests, 1s to 1h.
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1s') && duration(self) <= duration('1h')",message="period must be 1s to 1h"
	Period metav1.Duration `json:"period"`

	// Burst is the requests a key may send at once after being idle.
	// Unset: requests.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	// +optional
	Burst *int64 `json:"burst,omitempty"`

	// Key is what the limit counts by. Unset: the client IP.
	// +optional
	Key *RateLimitKey `json:"key,omitempty"`

	// Match narrows the limit to some of the policy's requests. Unset:
	// every request of the policy.
	// +optional
	Match *RateLimitMatch `json:"match,omitempty"`

	// Mode Detect logs the requests over the limit instead of denying
	// them, on a Block policy. Unset: the policy's mode. Block isn't
	// allowed: a limit can't be stricter than its policy.
	// +kubebuilder:validation:XValidation:rule="self == 'Detect'",message="a rate limit's mode can only be Detect: a limit can't be stricter than its policy"
	// +optional
	Mode PolicyMode `json:"mode,omitempty"`
}

// RateLimitKey is what a limit counts by: exactly one of clientIP and
// header.
// +kubebuilder:validation:XValidation:rule="has(self.clientIP) != has(self.header)",message="key needs exactly one of clientIP and header"
type RateLimitKey struct {
	// ClientIP counts by the client address the engine resolves
	// (docs/client-ip.md).
	// +optional
	ClientIP *ClientIPKey `json:"clientIP,omitempty"`

	// Header counts by a request header's value, for fairness between
	// authenticated clients (an API key, a tenant). A client chooses its
	// header's value, so this doesn't stop an attacker: a request without
	// the header is counted by its client IP.
	// +optional
	Header *HeaderKey `json:"header,omitempty"`
}

// ClientIPKey counts by the client address.
type ClientIPKey struct {
	// IPv6PrefixLength counts IPv6 clients by this prefix, 32 to 128;
	// IPv4 clients by their address. Unset: 56.
	// +kubebuilder:validation:Minimum=32
	// +kubebuilder:validation:Maximum=128
	// +optional
	IPv6PrefixLength *int32 `json:"ipv6PrefixLength,omitempty"`
}

// HeaderKey counts by a request header's value.
type HeaderKey struct {
	// Name is the header. Not X-Forwarded-For, Forwarded or Host: count
	// by the client IP instead.
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:XValidation:rule="!(self.lowerAscii() in ['x-forwarded-for', 'forwarded', 'host'])",message="count by clientIP, not by X-Forwarded-For, Forwarded or Host"
	Name HeaderName `json:"name"`
}

// RateLimitMatch narrows a limit to some of the policy's requests.
type RateLimitMatch struct {
	// Paths the limit counts: exact paths or prefixes ending in "*",
	// compared in ASCII lower case with one trailing slash ignored. A path
	// the engine can't read one way (percent-encoding, ";", "//", dot
	// segments) counts against every limit with paths.
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	// +optional
	Paths []PathPattern `json:"paths,omitempty"`

	// Methods the limit counts.
	// +kubebuilder:validation:MaxItems=9
	// +listType=set
	// +optional
	Methods []RateLimitMethod `json:"methods,omitempty"`
}

// RateLimitMethod is a standard HTTP request method.
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;PATCH;DELETE;OPTIONS;CONNECT;TRACE
type RateLimitMethod string

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
	// Paths that are never inspected. A set: a path listed twice draws a
	// warning, and v1 refuses it.
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	// +optional
	Paths []PathPattern `json:"paths,omitempty"`

	// BodyPaths are paths whose body is not inspected; their headers and URI
	// still are. A set: a path listed twice draws a warning, and v1 refuses
	// it.
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	// +optional
	BodyPaths []PathPattern `json:"bodyPaths,omitempty"`
}

// RuleSetBinding uses a rule set in a policy.
// +kubebuilder:validation:XValidation:rule="!has(self.paranoiaLevel) || !has(self.crs) || !has(self.crs.paranoiaLevel)",message="set crs.paranoiaLevel, not also the deprecated paranoiaLevel"
// +kubebuilder:validation:XValidation:rule="!has(self.inboundAnomalyThreshold) || !has(self.crs) || !has(self.crs.inboundAnomalyThreshold)",message="set crs.inboundAnomalyThreshold, not also the deprecated inboundAnomalyThreshold"
type RuleSetBinding struct {
	// Ref is the rule set.
	Ref RuleSetRef `json:"ref"`

	// ParanoiaLevel is crs.paranoiaLevel, which takes its place, and can't
	// be set with it. It stays so that policies that set it remain valid;
	// setting it draws a warning, and v1 moves it to crs.
	//
	// Deprecated: use crs.paranoiaLevel.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	// +optional
	ParanoiaLevel *int32 `json:"paranoiaLevel,omitempty"`

	// InboundAnomalyThreshold is crs.inboundAnomalyThreshold, which takes
	// its place, and can't be set with it. It stays so that policies that
	// set it remain valid; setting it draws a warning, and v1 moves it to
	// crs.
	//
	// Deprecated: use crs.inboundAnomalyThreshold.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +optional
	InboundAnomalyThreshold *int32 `json:"inboundAnomalyThreshold,omitempty"`

	// CRS sets the OWASP CRS's own settings. Only used by the built-in CRS:
	// on another rule set they are ignored, which the Accepted condition
	// says. Every engine applies paranoiaLevel and
	// inboundAnomalyThreshold; the other settings require engines 0.5.0 or
	// later, and older ones ignore them.
	// +optional
	CRS *CRSSettings `json:"crs,omitempty"`

	// Placement is where a SecLang rule set loads: AfterCRS (unset) or
	// BeforeCRS, before the CRS's initialization, so its rules can set
	// the CRS's tx variables or turn CRS rules off with
	// ctl:ruleRemoveById. A BeforeCRS rule set can't use SecRuleRemoveBy*
	// or SecRuleUpdate*, which only reach rules loaded before them. Not
	// for the built-in CRS. Requires engines 0.6.0 or later: older ones
	// load the rule set after the CRS. No API default: a default inside a
	// list item makes GitOps diffs (Argo CD's) show every policy with rule
	// sets out of sync.
	// +optional
	Placement RuleSetPlacement `json:"placement,omitempty"`
}

// RuleSetPlacement is where a rule set loads, relative to the built-in CRS.
// +kubebuilder:validation:Enum=BeforeCRS;AfterCRS
type RuleSetPlacement string

const (
	// PlacementAfterCRS loads the rule set after the CRS (the default).
	PlacementAfterCRS RuleSetPlacement = "AfterCRS"
	// PlacementBeforeCRS loads the rule set before the CRS.
	PlacementBeforeCRS RuleSetPlacement = "BeforeCRS"
)

// CRSSettings are OWASP CRS settings (its tx variables), applied to each
// request before the CRS's defaults. Unset fields keep the CRS's defaults.
type CRSSettings struct {
	// ParanoiaLevel is the OWASP CRS paranoia level, 1 to 4: the rules up
	// to this level can block. Unset: 1.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	// +optional
	ParanoiaLevel *int32 `json:"paranoiaLevel,omitempty"`

	// InboundAnomalyThreshold is the request anomaly score at which a
	// request is flagged (blocked in Block mode). Unset: 5.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	// +optional
	InboundAnomalyThreshold *int32 `json:"inboundAnomalyThreshold,omitempty"`

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

// NeedsEngine050 reports whether s sets any of the settings that need
// engines 0.5.0 or later (s may be nil): its paranoiaLevel and
// inboundAnomalyThreshold, which every engine applies, don't count.
func (s *CRSSettings) NeedsEngine050() bool {
	return s != nil && (len(s.AllowedMethods) > 0 || len(s.AllowedRequestContentTypes) > 0 ||
		s.DetectionParanoiaLevel != nil || s.OutboundAnomalyThreshold != nil)
}

// CRSParanoiaLevel is b's paranoia level: crs.paranoiaLevel, else the
// deprecated paranoiaLevel; nil when neither is set.
func (b *RuleSetBinding) CRSParanoiaLevel() *int32 {
	if b.CRS != nil && b.CRS.ParanoiaLevel != nil {
		return b.CRS.ParanoiaLevel
	}
	return b.ParanoiaLevel
}

// CRSInboundAnomalyThreshold is b's inbound anomaly threshold:
// crs.inboundAnomalyThreshold, else the deprecated inboundAnomalyThreshold;
// nil when neither is set.
func (b *RuleSetBinding) CRSInboundAnomalyThreshold() *int32 {
	if b.CRS != nil && b.CRS.InboundAnomalyThreshold != nil {
		return b.CRS.InboundAnomalyThreshold
	}
	return b.InboundAnomalyThreshold
}

// SetsCRS reports whether b sets any CRS setting, deprecated or not.
func (b *RuleSetBinding) SetsCRS() bool {
	return b.CRSParanoiaLevel() != nil || b.CRSInboundAnomalyThreshold() != nil || b.CRS.NeedsEngine050()
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

	// Namespace of a WAFRuleSet, which can only be the policy's: unset means
	// that, and another namespace is never resolved (the policy isn't
	// Accepted; bind a ClusterWAFRuleSet instead). Setting it draws a
	// warning, and v1 removes it.
	//
	// Deprecated: leave it unset.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// The rule, not the schema, makes ruleIDs required, so that another way to
// name rules (by tag or ID range) only relaxes the rule.

// Exclusion turns rules off, everywhere or only for one path or argument.
// +kubebuilder:validation:XValidation:rule="has(self.ruleIDs)",message="ruleIDs is required"
type Exclusion struct {
	// RuleIDs are the rules to turn off. An ID no rule has is ignored.
	// Required. A set: an ID listed twice draws a warning, and v1 refuses
	// it.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:Minimum=1
	// +listType=atomic
	// +optional
	RuleIDs []int32 `json:"ruleIDs,omitempty"`

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
	// +optional
	Argument ArgumentPattern `json:"argument,omitempty"`

	// ArgumentName is a query or body argument whose name (ARGS_NAMES) the
	// rules stop looking at. Requires engines 0.5.0 or later: older ones
	// ignore the exclusion.
	// +optional
	ArgumentName ArgumentPattern `json:"argumentName,omitempty"`

	// Cookie is a request cookie (REQUEST_COOKIES) the rules stop looking
	// at, such as a session token. Requires engines 0.5.0 or later.
	// +optional
	Cookie ArgumentPattern `json:"cookie,omitempty"`

	// Header is a request header (REQUEST_HEADERS) the rules stop looking
	// at, such as Referer, compared case-insensitively. Requires engines
	// 0.5.0 or later.
	// v1 types it as a header name, refusing [ and ] and allowing the other
	// token characters (!#$%&'*+^|~): a header that isn't one draws a
	// warning.
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
// +kubebuilder:validation:XValidation:rule="!has(self.grpcStreams) || self.grpcStreams != 'PerMessage' || (has(self.grpcMessages) && self.grpcMessages == 'Inspect' && (!has(self.inspect) || self.inspect))",message="grpcStreams: PerMessage needs grpcMessages: Inspect and body inspection"
type BodySpec struct {
	// Inspect turns body inspection on or off.
	// +kubebuilder:default=true
	// +optional
	Inspect *bool `json:"inspect,omitempty"`

	// MaxBytes is how much of a body is inspected, at most 10 MiB. Unset:
	// the engine's --max-body-bytes (64 KiB unless an engine outside the
	// operator's wiring sets it), a default that doesn't change within v1.
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

	// GRPCStreams decides how the messages are read, with grpcMessages:
	// Inspect. PerMessage inspects each message on its own as it comes,
	// up to maxBytes each, so long client streams and bidirectional calls
	// work; the messages before a denied one have already reached the
	// application. Through Envoy Gateway and Istio; other proxies buffer
	// the body as with Buffer. Unset: Buffer, the body the proxy buffers,
	// up to maxBytes in all. Requires engines 0.6.0 or later. See
	// docs/grpc.md.
	// +optional
	GRPCStreams GRPCStreamsMode `json:"grpcStreams,omitempty"`

	// GRPC: Deny refuses requests with a gRPC or gRPC-Web content type
	// (403, or the gRPC status PermissionDenied to a gRPC client; logged in
	// Detect mode), for routes that serve no gRPC. Unset: Allow. Requires
	// engines 0.5.0 or later. See docs/grpc.md.
	// +optional
	GRPC GRPCAction `json:"grpc,omitempty"`
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
// +kubebuilder:validation:XValidation:rule="(has(self.inspect) && self.inspect) || (!has(self.maxBytes) && !has(self.onOversize) && (!has(self.streams) || self.streams == 'Skip'))",message="maxBytes, onOversize and streams: Inspect need inspect: true"
type ResponsesSpec struct {
	// Inspect turns response inspection on: the status and headers, and
	// the body when its media type is text (plain, HTML, XML, CSV),
	// JavaScript, JSON or XML (a +json or +xml type too), malformed, or
	// missing. A request's Range is removed, so the body comes whole.
	// In Block mode a response the rules flag is replaced with the
	// rule's status (403) and a plain-text error.
	// +optional
	Inspect bool `json:"inspect,omitempty"`

	// MaxBytes is how much of a response body is inspected, at most 10
	// MiB. Unset: 64 KiB, the engine's default, which doesn't change
	// within v1 (each KiB costs about 0.3 ms of inspection: raise timeout
	// with it). A longer body has this much inspected, and then gets
	// onOversize.
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

	// Streams is what happens to the body of a streamed response: Server-
	// Sent Events (text/event-stream) and gRPC responses. Inspect: each
	// event, or message, is inspected on its own, up to maxBytes; in Block
	// mode one that leaks ends the stream (the client gets the events
	// before it), and one over maxBytes gets onOversize. Each event is an
	// evaluation, so a token-by-token stream costs many. Skip: only their
	// status and headers are inspected. Through Envoy Gateway and Istio;
	// HAProxy doesn't send their bodies (the policy is then not Programmed
	// on its Ingresses, ResponsesNotInspected), and engines before 0.6.0
	// skip them (the policy is then not Enforced).
	// +kubebuilder:default=Skip
	// +optional
	Streams StreamsAction `json:"streams,omitempty"`
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
