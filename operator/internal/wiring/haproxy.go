// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
	engrules "github.com/inkwall-dev/inkwall/pkg/rules"
)

// The HAProxy Kubernetes Ingress Controller's wiring (0002 §6.4): each
// protected Ingress of its class gets a backend of its own
// (haproxy.org/standalone-backend) that loads the SPOE filter, which calls
// the engine, and denies on its verdict: through its configuration snippet
// (haproxy.org/backend-config-snippet) on controller 3.1 to 3.2, through a
// Backend custom resource of the controller's on 3.4 and later, which
// dropped snippets (haproxybackend.go). The agent's backend and spoe.conf
// are in the controller's pods (injection.InjectHAProxy). The controller
// says nothing about a snippet it drops, or a Backend HAProxy rejects, so a
// route is Programmed only once the operator's probe (Prober) has proven
// the filter on every pod.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch,roleName=inkwall-operator-haproxy
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch,roleName=inkwall-operator-haproxy
//
// The controller's Backend kind is in the role also so that it is the
// integration's own: Traefik's role grants the same Ingress access, and
// the operator tells the integrations it may wire by their roles'
// permissions (access.Denied).

// Annotations of the HAProxy wiring.
const (
	// HAProxySnippetAnnotation and HAProxyStandaloneAnnotation are the
	// controller's.
	HAProxySnippetAnnotation    = "haproxy.org/backend-config-snippet"
	HAProxyStandaloneAnnotation = "haproxy.org/standalone-backend"
	// HAProxyWiredAnnotation marks an Ingress the operator wired; its value
	// is what haproxy.org/standalone-backend was before ("" when unset),
	// restored when it is unwired.
	HAProxyWiredAnnotation = "waf.inkwall.dev/haproxy-wired"

	haproxySnippetBegin = "# inkwall:begin (managed by the Inkwall operator; don't edit)"
	haproxySnippetEnd   = "# inkwall:end"
)

// HAProxy is the wiring of the HAProxy Kubernetes Ingress Controller: its
// Ingresses.
type HAProxy struct {
	Client client.Client
	// APIReader reads targets uncached.
	APIReader client.Reader
	// Pods selects the controller's pods (integrations.Selectors).
	Pods labels.Selector
	// Prober probes the wired routes; nil: none is, and every route stays
	// Unverified.
	Prober *Prober
	// Namespaces are the proxy namespaces: only the controller's pods there
	// say how its Ingresses are wired (nil: every namespace).
	Namespaces integrations.Namespaces
	// Backends watches the operator's Backend custom resources once their
	// CRD is installed, so one deleted or edited is put back at once; nil:
	// only at each reconcile.
	Backends *crdwatch.Kind
}

// Name implements Integration.
func (*HAProxy) Name() string { return integrations.HAProxy.Name }

// Kinds implements Integration.
func (*HAProxy) Kinds() []schema.GroupKind { return []schema.GroupKind{ingressKind} }

// Watch implements Integration: Ingresses (their annotations), classes,
// the controller's pods, the policies' settings (the wiring controller
// watches them), the operator's Backend custom resources, and the probe's
// results.
func (h *HAProxy) Watch(c controller.Controller, cache cache.Cache, eh handler.EventHandler) error {
	for _, obj := range []client.Object{&networkingv1.Ingress{}, &networkingv1.IngressClass{}, &corev1.Pod{}} {
		if err := c.Watch(source.Kind(cache, obj, eh)); err != nil {
			return err
		}
	}
	if h.Backends != nil {
		h.Backends.Add(c, eh, predicate.NewPredicateFuncs(isManaged))
	}
	if h.Prober != nil {
		return c.Watch(source.Channel(h.Prober.Events(), eh))
	}
	return nil
}

// haproxySettings are a route's, from the policies that protect it.
type haproxySettings struct {
	failOpen bool
	body     bool
	// responses: a policy inspects responses.
	responses bool
	// block: a policy is in Block mode.
	block bool
	// maxBody is the largest body.maxBytes of the policies that inspect
	// bodies (the engine's 64 KiB for one that sets none).
	maxBody int64
	// maxResponse is the largest responses.maxBytes of the policies that
	// inspect responses (64 KiB for one that sets none).
	maxResponse int64
}

func haproxySettingsOf(policies []wafv1alpha1.WAFPolicy, ing types.NamespacedName) haproxySettings {
	s := haproxySettings{failOpen: true}
	for i := range policies {
		p := &policies[i]
		if p.Namespace != ing.Namespace || p.DeletionTimestamp != nil ||
			!slices.ContainsFunc(p.Spec.TargetRefs, func(r wafv1alpha1.TargetRef) bool {
				return targetOf(p.Namespace, r).Kind == ingressKind && r.Name == ing.Name
			}) {
			continue
		}
		if b := p.Spec.Body; b == nil || b.Inspect == nil || *b.Inspect {
			s.body = true
			limit := int64(engineBodyBytes)
			if b != nil && b.MaxBytes != nil {
				limit = *b.MaxBytes
			}
			s.maxBody = max(s.maxBody, limit)
		}
		if r := p.Spec.Responses; r != nil && r.Inspect {
			s.responses = true
			limit := int64(engineBodyBytes)
			if r.MaxBytes != nil {
				limit = *r.MaxBytes
			}
			s.maxResponse = max(s.maxResponse, limit)
		}
		s.block = s.block || p.Spec.Mode == wafv1alpha1.PolicyBlock
		mode := cmp.Or(p.Spec.FailureMode, wafv1alpha1.FailOpen)
		if p.Spec.Mode == wafv1alpha1.PolicyBlock && p.Spec.FailureMode == "" {
			mode = wafv1alpha1.FailClosed
		}
		s.failOpen = s.failOpen && mode == wafv1alpha1.FailOpen
	}
	return s
}

// haproxyFrameTooBig are the errors HAProxy's SPOE filter sets (option
// set-on-error) for a message that doesn't fit in one frame, which it
// sends none of (SPOP 2.0 has no fragmentation): 3 when it is larger than
// spoe.conf's max-frame-size (HAProxy's buffer by default), 259 (0x100 +
// 3, from the SPOP connection) when it is larger than the max-frame-size
// the engine announced.
const haproxyFrameTooBig = "3 259"

// haproxyUpgradeRule and haproxyHTTP2SettingsRule forward an upgrade only
// to WebSocket, after the engine's verdict: any other Upgrade (TLS/1.2,
// "h2c, foo", ...) and HTTP2-Settings are removed, so the app can't switch
// the connection to a protocol whose traffic the engine doesn't see.
// req.fhdr reads the whole value, not its comma-separated parts. (HAProxy
// itself drops h2c and h2, and forwards a WebSocket handshake's Upgrade as
// "websocket" alone.)
var (
	haproxyUpgradeRule = haproxyRule{section: "http-request", action: "del-header", header: "upgrade",
		cond: "unless", condTest: "{ req.fhdr_cnt(upgrade) eq 1 } { req.fhdr(upgrade) -m str -i websocket }"}
	haproxyHTTP2SettingsRule = haproxyRule{section: "http-request", action: "del-header", header: "http2-settings"}
)

// HAProxySnippetOptions are what a route's snippet depends on, from its
// policies.
type HAProxySnippetOptions struct {
	// FailOpen: every policy fails open, so no fail-closed rule.
	FailOpen bool
	// Body: a policy inspects bodies, so HAProxy buffers them.
	Body bool
	// Responses: a policy inspects responses, and HAProxy sends them.
	Responses bool
	// Block: a policy is in Block mode.
	Block bool
}

// HAProxySnippet is the operator's part of a protected Ingress's backend
// snippet: the body buffered for the engine when a policy inspects it, the
// SPOE filter, and the rules on its variables: the probe's answer first
// (Prober), then, in Block mode, 413 for a request HAProxy couldn't fit in
// one SPOE frame (txn.inkwall.error 3 or 259: HAProxy sends no part of it, 0006
// §4), handled as oversized whatever the failure mode; failing closed,
// 503 without a verdict, a denied
// gRPC call's answer, and a rule per status the engine denies with; the
// request ID for the app, and any Upgrade but WebSocket's removed. With responses (a policy inspects them, and
// every pod's engine keeps requests for them), the filter is spoe.conf's
// inkwall-responses scope, and the response rules of
// examples/haproxy/haproxy.cfg follow (0006 §4): the request's
// Accept-Encoding removed, the body of a type the rules read waited for,
// the response sent, the probe's response leg answered (#595), and the
// response replaced when the engine denies it or, failing closed, gives no
// verdict.
func HAProxySnippet(o HAProxySnippetOptions) string {
	c := haproxyConfigOf(o)
	lines := []string{haproxySnippetBegin}
	if c.bufferRequest {
		lines = append(lines, "option http-buffer-request")
	}
	lines = append(lines, "filter spoe engine "+c.engine+" config "+injection.HAProxySPOEConf)
	for _, r := range c.rules {
		lines = append(lines, r.String())
	}
	lines = append(lines, haproxySnippetEnd)
	return strings.Join(lines, "\n")
}

// haproxyConfig is the operator's part of a protected Ingress's backend,
// which HAProxySnippet writes as a config snippet (controller 3.1 to 3.2)
// and HAProxyBackendSpec as the controller's Backend custom resource
// (3.4 and later).
type haproxyConfig struct {
	// bufferRequest: option http-buffer-request.
	bufferRequest bool
	// engine is the SPOE filter's engine: spoe.conf's scope.
	engine string
	rules  []haproxyRule
}

// haproxyRule is one http-request, http-response or http-after-response
// rule of haproxyConfig, with the fields the controller's Backend custom
// resource has for it (client-native's models).
type haproxyRule struct {
	// section is http-request, http-response or http-after-response.
	section string
	// action is return, deny, del-header, set-header, set-var,
	// wait-for-body or send-spoe-group.
	action string
	// status is return's and deny's.
	status int
	// contentType, contentFormat and content are return's payload.
	contentType, contentFormat, content string
	// hdrs are return's and deny's headers: name and log-format, quoted.
	hdrs [][2]string
	// header and format are del-header's and set-header's.
	header, format string
	// varScope, varName and expr are set-var's.
	varScope, varName, expr string
	// waitMillis is wait-for-body's time.
	waitMillis int64
	// spoeEngine and spoeGroup are send-spoe-group's.
	spoeEngine, spoeGroup string
	// cond is if or unless ("" for none), condTest its ACLs.
	cond, condTest string
}

// String is the rule as HAProxy's configuration writes it.
func (r haproxyRule) String() string {
	var b strings.Builder
	b.WriteString(r.section)
	switch r.action {
	case "return":
		fmt.Fprintf(&b, " return status %d", r.status)
		if r.contentType != "" {
			b.WriteString(" content-type " + r.contentType)
		}
		if r.contentFormat != "" {
			b.WriteString(" " + r.contentFormat + " " + r.content)
		}
	case "deny":
		fmt.Fprintf(&b, " deny deny_status %d", r.status)
	case "del-header":
		b.WriteString(" del-header " + r.header)
	case "set-header":
		b.WriteString(" set-header " + r.header + " " + r.format)
	case "set-var":
		b.WriteString(" set-var(" + r.varScope + "." + r.varName + ") " + r.expr)
	case "wait-for-body":
		fmt.Fprintf(&b, " wait-for-body time %s", haproxyDuration(r.waitMillis))
	case "send-spoe-group":
		b.WriteString(" send-spoe-group " + r.spoeEngine + " " + r.spoeGroup)
	}
	for _, h := range r.hdrs {
		b.WriteString(" hdr " + h[0] + " " + h[1])
	}
	if r.cond != "" {
		b.WriteString(" " + r.cond + " " + r.condTest)
	}
	return b.String()
}

// haproxyDuration writes milliseconds as HAProxy's configuration does: in
// seconds when whole.
func haproxyDuration(ms int64) string {
	if ms%1000 == 0 {
		return strconv.FormatInt(ms/1000, 10) + "s"
	}
	return strconv.FormatInt(ms, 10) + "ms"
}

// haproxyConfigOf is the operator's part of a protected Ingress's backend
// (HAProxySnippet says what each rule is for).
func haproxyConfigOf(o HAProxySnippetOptions) haproxyConfig {
	failOpen, responses := o.FailOpen, o.Responses
	v := func(name string) string { return "var(txn.inkwall." + name + ")" }
	fmtOf := func(name string) string { return `"%[` + v(name) + `]"` }
	requestID := [2]string{"x-request-id", fmtOf("request_id")}
	c := haproxyConfig{bufferRequest: o.Body, engine: "inkwall"}
	if responses {
		c.engine = injection.HAProxyResponsesScope
	}
	req := func(r haproxyRule) haproxyRule { r.section = "http-request"; return r }
	res := func(r haproxyRule) haproxyRule { r.section = "http-response"; return r }
	found := func(name string) string { return "{ " + v(name) + " -m found }" }
	c.rules = append(c.rules, req(haproxyRule{action: "return", status: haproxyprobe.Status,
		hdrs: [][2]string{{strings.ToLower(haproxyprobe.Header), fmtOf("probe")}}, cond: "if", condTest: found("probe")}))
	if o.Block {
		c.rules = append(c.rules, req(haproxyRule{action: "deny", status: 413, cond: "if", condTest: "{ " + v("error") + " -m int " + haproxyFrameTooBig + " }"}))
	}
	if !failOpen {
		c.rules = append(c.rules, req(haproxyRule{action: "deny", status: 503, cond: "if", condTest: "!" + found("action")}))
	}
	c.rules = append(c.rules,
		req(haproxyRule{action: "return", status: 200,
			hdrs: [][2]string{{"grpc-status", fmtOf("grpc_status")}, {"grpc-message", fmtOf("grpc_message")}, requestID},
			cond: "if", condTest: found("grpc_status")}),
		haproxyRule{section: "http-after-response", action: "set-header", header: "content-type", format: fmtOf("grpc_content_type"),
			cond: "if", condTest: found("grpc_content_type")})
	for _, status := range []int{400, 413, 503} {
		c.rules = append(c.rules, req(haproxyRule{action: "deny", status: status, hdrs: [][2]string{requestID},
			cond: "if", condTest: fmt.Sprintf("{ %s -m int %d }", v("status"), status)}))
	}
	// A rate limit's 429, with its Retry-After (#705); without this rule
	// it would be the 403 below.
	// A SecLang rule's status:429 has no Retry-After: no empty header.
	c.rules = append(c.rules,
		req(haproxyRule{action: "deny", status: 429, hdrs: [][2]string{requestID, {"retry-after", fmtOf("retry_after")}},
			cond: "if", condTest: "{ " + v("status") + " -m int 429 } " + found("retry_after")}),
		req(haproxyRule{action: "deny", status: 429, hdrs: [][2]string{requestID}, cond: "if", condTest: "{ " + v("status") + " -m int 429 }"}),
		req(haproxyRule{action: "deny", status: 403, hdrs: [][2]string{requestID}, cond: "if", condTest: "{ " + v("action") + " -m str deny }"}),
		haproxyUpgradeRule,
		haproxyHTTP2SettingsRule,
		req(haproxyRule{action: "set-header", header: "X-Request-Id", format: fmtOf("request_id"), cond: "if", condTest: found("request_id")}))
	if responses {
		kept := found("responses")
		reply := func(status int, text, cond string) haproxyRule {
			return res(haproxyRule{action: "return", status: status, contentType: "text/plain", contentFormat: "lf-string",
				content: fmt.Sprintf(`"%s. Request ID: %%[%s]"`, text, v("request_id")), hdrs: [][2]string{requestID},
				cond: "if", condTest: cond})
		}
		for _, h := range []string{"accept-encoding", "range", "if-range"} {
			c.rules = append(c.rules, req(haproxyRule{action: "del-header", header: h, cond: "if", condTest: kept}))
		}
		c.rules = append(c.rules,
			res(haproxyRule{action: "set-var", varScope: "txn", varName: "inkwall.response_whole", expr: "bool(1)", cond: "if", condTest: HAProxyReadBody(kept)}),
			res(haproxyRule{action: "wait-for-body", waitMillis: 2000, cond: "if", condTest: found("response_whole")}),
			res(haproxyRule{action: "send-spoe-group", spoeEngine: injection.HAProxyResponsesScope, spoeGroup: injection.HAProxyResponseGroup, cond: "if", condTest: kept}))
		if o.Block {
			// A response HAProxy couldn't fit in one frame: oversized.
			c.rules = append(c.rules, reply(502, "Bad Gateway", kept+" { "+v("error")+" -m int "+haproxyFrameTooBig+" }"))
		}
		c.rules = append(c.rules,
			// The probe's response leg (#595): the engine's answer to its
			// response, in place of the app's.
			res(haproxyRule{action: "return", status: haproxyprobe.Status,
				hdrs: [][2]string{{strings.ToLower(haproxyprobe.Header), fmtOf("response_probe")}}, cond: "if", condTest: found("response_probe")}),
			reply(502, "Bad Gateway", kept+" !"+found("response_action")+" { "+v("response_failure")+" -m str closed }"),
			reply(502, "Bad Gateway", "{ "+v("response_status")+" -m int 502 }"),
			reply(503, "Service Unavailable", "{ "+v("response_status")+" -m int 503 }"),
			reply(403, "Forbidden", "{ "+v("response_action")+" -m str deny }"))
	}
	return c
}

// HAProxyReadBody is the condition, for a response on a route where cond
// holds, that the engine reads its body (rules.ResponseBodyType): a
// Content-Type that isn't one type/subtype (or none), one of
// rules.ResponseBodyTypes, or one with a +json or +xml suffix but for
// gRPC's and Connect's streams. HAProxy's types are a narrower set of
// characters than the engine's, so it waits for a body the engine might
// not read rather than miss one it reads. Such a response gets
// txn.inkwall.response_whole, sent to the engine (spoe.ArgWhole): HAProxy
// waits for its whole body (wait-for-body), up to a full buffer, which the
// engine tells by the frame's size, and answers 504 itself when the body
// doesn't come in time. Without it, the engine counts a body without
// Content-Length as cut.
func HAProxyReadBody(cond string) string {
	types := make([]string, len(engrules.ResponseBodyTypes))
	for i, t := range engrules.ResponseBodyTypes {
		types[i] = strings.ReplaceAll(t, "+", "[+]")
	}
	const ct = "res.fhdr(content-type)"
	valid := `'^` + haproxyTypePart + `/` + haproxyTypePart + `[[:blank:]]*(;|$)'`
	read := `'^(` + strings.Join(types, "|") + `|` + haproxyTypePart + `/[a-z0-9.+_-]*[+](json|xml))[[:blank:]]*(;|$)'`
	return cond + " !{ " + ct + " -m reg -i " + valid + " } || " +
		cond + " { " + ct + " -m reg -i " + read + " } !{ " + ct + " -m beg -i application/grpc application/connect+ }"
}

// haproxyTypePart is a media type's part as HAProxy's response rules match
// it: fewer characters than a token's, so a type with others counts as
// malformed, whose body the engine reads.
const haproxyTypePart = "[a-z0-9.+_-]+"

// withSnippet returns a backend snippet with the operator's part (ours,
// empty: none) first, and the user's lines after it, kept as they were.
func withSnippet(current, ours string) string {
	// The user's text stays byte for byte: only the operator's part, and
	// the newline that joined it to theirs, go.
	user := current
	if i := strings.Index(current, haproxySnippetBegin); i >= 0 {
		if j := strings.Index(current[i:], haproxySnippetEnd); j >= 0 {
			user = current[:i] + strings.TrimPrefix(current[i+j+len(haproxySnippetEnd):], "\n")
		}
	}
	switch {
	case ours == "":
		return user
	case user == "":
		return ours
	}
	return ours + "\n" + user
}

// haproxyPodProblems are why the controller's running pods can't run the
// filter, besides a missing engine (the wiring controller's sidecar check):
// the agent's configuration isn't mounted, or, wired with snippets, they
// are disabled.
func haproxyPodProblems(pods []*corev1.Pod, m haproxyMechanism) []string {
	var out []string
	for _, pod := range pods {
		if !injection.HasEngine(pod) {
			continue
		}
		name := workloadOf(pod)
		if ok, why := injection.HAProxyConfigured(pod); !ok {
			out = append(out, fmt.Sprintf("HAProxy %s: %s", name, why))
		}
		if m != haproxySnippets {
			continue
		}
		for _, c := range pod.Spec.Containers {
			for _, arg := range append(slices.Clone(c.Command), c.Args...) {
				if v, ok := strings.CutPrefix(arg, "--disable-config-snippets="); ok && v != "" && v != "false" {
					for kind := range strings.SplitSeq(v, ",") {
						if kind = strings.TrimSpace(kind); kind == "backend" || kind == "all" {
							out = append(out, fmt.Sprintf("HAProxy %s runs with %s: backend snippets, which load the filter, are ignored", name, arg))
						}
					}
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// haproxyResponsesNotReady are the running pods with the engine whose
// engine doesn't keep requests for their responses, as namespace/name.
func haproxyResponsesNotReady(pods []*corev1.Pod) []string {
	var out []string
	for _, pod := range pods {
		if !injection.HasEngine(pod) {
			continue
		}
		if ok, _ := injection.HAProxyResponsesReady(pod); !ok {
			out = append(out, "pod "+pod.Namespace+"/"+pod.Name)
		}
	}
	slices.Sort(out)
	return out
}

// Wire implements Integration: it wires every protected Ingress of the
// controller's class, and unwires the rest.
func (h *HAProxy) Wire(ctx context.Context, targets map[Target]bool, off bool) (*Result, error) {
	var (
		ingresses networkingv1.IngressList
		classList networkingv1.IngressClassList
		pods      corev1.PodList
		policies  wafv1alpha1.WAFPolicyList
	)
	for _, l := range []client.ObjectList{&ingresses, &classList, &policies} {
		if err := h.Client.List(ctx, l); err != nil {
			return nil, err
		}
	}
	if err := h.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: h.Pods}); err != nil {
		return nil, err
	}
	classes, defaultClass := map[string]string{}, ""
	for i := range classList.Items {
		ic := &classList.Items[i]
		classes[ic.Name] = ic.Spec.Controller
		if IsDefaultClass(ic) {
			defaultClass = ic.Name
		}
	}
	// As Traefik's: nothing is wired while no controller pod runs, as new
	// pods would have no engine to call.
	runningPods := running(pods.Items)
	on := !off && len(runningPods) > 0
	// How each controller's Ingresses are wired, from its own pods: the
	// release says how the filter is loaded, snippets (3.1 to 3.2) or the
	// controller's Backend custom resource (3.4).
	trusted := h.haproxyControllerPods(runningPods)
	crd := -1 // the Backend CRD: unknown until a controller needs it
	groups := map[string]*haproxyGroup{}
	group := func(controller string) *haproxyGroup {
		if g, ok := groups[controller]; ok {
			return g
		}
		g := &haproxyGroup{pods: podsServing(trusted, controller)}
		if crd < 0 {
			crd = 0
			if haproxyBackendCRDInstalled(ctx, h.APIReader) {
				crd = 1
			}
		}
		g.mech, g.versionWhy, g.versionNote = haproxyMechanismOf(g.pods, crd == 1)
		g.problems = haproxyPodProblems(g.pods, g.mech)
		g.buffer = h.buffer(ctx, g.pods, g.mech)
		groups[controller] = g
		return g
	}
	notReady := haproxyResponsesNotReady(runningPods)

	res := &Result{Proxy: "HAProxy", Targets: map[Target]TargetState{}, Pods: pods.Items}
	// HAProxy sends responses once every running pod's engine keeps
	// requests for them: a pod whose engine doesn't would never hear of
	// them, so no Ingress gets the response rules before (0006 §4).
	switch {
	case !on:
	case len(notReady) > 0:
		res.ResponsesWhy = "HAProxy " + strings.Join(notReady, ", ") + " run an engine injected without " + injection.ResponseMessagesFlag +
			" (before 0.6.0, or a pinned spec.engine.image older than 0.6.0): restart them, with an engine of 0.6.0 or later"
	default:
		res.Responses = true
	}
	var (
		errs []error
		jobs []ProbeJob
	)
	// The operator's Backend custom resources still wanted.
	backends := map[types.NamespacedName]bool{}
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		k := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		tg := Target{Kind: ingressKind, Key: k}
		served := Controller(ing, classes, defaultClass)
		mine := integrations.HAProxy.ServesIngresses(served)
		want := targets[tg] && mine && on
		var g *haproxyGroup
		mech := haproxySnippets
		if want {
			g = group(served)
			mech = g.mech
		}
		settings := haproxySettingsOf(policies.Items, k)
		opts := HAProxySnippetOptions{FailOpen: settings.failOpen, Body: settings.body, Responses: settings.responses && res.Responses, Block: settings.block}
		var (
			err error
			// failed is why the Ingress isn't wired, besides err.
			failed      string
			fingerprint string
		)
		switch {
		case want && mech == haproxyUnknown:
			// The operator can't tell how to load the filter: the Ingress
			// stays as it is, wired by a mechanism the controller may no
			// longer read, or not, and the status says why.
			if _, wired := ing.Annotations[HAProxyWiredAnnotation]; wired && ing.Annotations[HAProxyCRBackendAnnotation] == haproxyBackendRef(ing) {
				backends[types.NamespacedName{Namespace: k.Namespace, Name: haproxyBackendName(k.Name)}] = true
			}
		case want && mech == haproxyBackendCR:
			theirs := userCRBackend(ing)
			services, serr := h.serviceCRBackends(ctx, ing)
			switch {
			case theirs != "":
				failed = fmt.Sprintf("Ingress %s names its own Backend custom resource (%s): the controller builds a backend from one Backend custom resource, "+
					"so on controller 3.4 the operator, which loads the filter with its own, can't wire it; remove the annotation, or protect another Ingress", k.Name, theirs)
			case serr != nil:
				failed = fmt.Sprintf("Ingress %s: %v", k.Name, serr)
			case len(services) > 0:
				failed = fmt.Sprintf("Ingress %s routes to %s, which names its own Backend custom resource: the controller takes a Service's over the Ingress's, "+
					"so on controller 3.4 the operator, which loads the filter with its own, can't wire it; remove the Service's annotation, or protect another Ingress",
					k.Name, strings.Join(services, ", "))
			}
			if failed != "" {
				if serr == nil {
					err = annotateHAProxy(ctx, h.Client, ing, "", "")
				}
				break
			}
			// The Backend first, so the controller finds the one the
			// Ingress names. One it can't write leaves the Ingress as it is.
			b := haproxyBackend(ing, opts)
			if why := ensureHAProxyBackend(ctx, h.Client, b); why != "" {
				failed = "Ingress " + k.Name + ": " + why
				if ing.Annotations[HAProxyCRBackendAnnotation] == haproxyBackendRef(ing) {
					backends[client.ObjectKeyFromObject(b)] = true
				}
				break
			}
			backends[client.ObjectKeyFromObject(b)] = true
			err = annotateHAProxy(ctx, h.Client, ing, "", haproxyBackendRef(ing))
			fingerprint = haproxyBackendRef(ing) + "\n" + HAProxySnippet(opts)
		case want:
			err = annotateHAProxy(ctx, h.Client, ing, HAProxySnippet(opts), "")
			fingerprint = ing.Annotations[HAProxySnippetAnnotation]
		default:
			err = annotateHAProxy(ctx, h.Client, ing, "", "")
		}
		if err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("wire Ingress %s: %w", k, err))
		}
		if !targets[tg] {
			continue
		}
		var s TargetState
		switch {
		case !mine:
			c := served
			if c == "" {
				c = "no known IngressClass"
			}
			s.Unsupported = fmt.Sprintf("Ingress %s is served by %s, which Inkwall doesn't wire yet", k.Name, c)
		case !on:
		case mech == haproxyUnknown:
			s.VersionUnsupported = g.versionWhy
		case err != nil:
			s.Failed = fmt.Sprintf("Ingress %s: %v", k.Name, err)
		case failed != "":
			s.Failed = failed
		case len(g.problems) > 0:
			s.Failed = strings.Join(g.problems, "; ")
		}
		s.Wired = want && err == nil && fingerprint != ""
		if s.Wired && s.Failed == "" {
			job := ProbeJob{Route: ProbeRoute{Kind: "Ingress", Key: k}, Proxy: "HAProxy", Fingerprint: fingerprint, Targets: probeTargets(ing)}
			for _, pod := range g.pods {
				job.Pods = append(job.Pods, probePod(pod))
			}
			var probed []ProbeJob
			probed, s.Responses = proveResponses(h.Prober, "Ingress "+k.Name, settings.responses && res.Responses, []ProbeJob{job})
			job = probed[0]
			jobs = append(jobs, job)
			s.Unverified = h.unverified(job)
			if mech == haproxyBackendCR && strings.Contains(s.Unverified, "doesn't run the filter") {
				s.Unverified += "; " + haproxyRejectedHint(ing)
			}
			var notes []string
			if g.versionNote != "" {
				notes = append(notes, g.versionNote)
			}
			if n := haproxyBufferNote(k.Name, g.buffer, mech, settings.body, settings.maxBody, settings.responses && res.Responses, settings.maxResponse); n != "" {
				notes = append(notes, n)
			}
			if mech == haproxyBackendCR {
				if n := haproxyIgnoredNote(ing); n != "" {
					notes = append(notes, n)
				}
			}
			s.Note = strings.Join(notes, "; ")
		}
		res.Targets[tg] = s
	}
	// The Ingresses are unwired: their Backends can go.
	if _, err := pruneHAProxyBackends(ctx, h.Client, backends); err != nil {
		errs = append(errs, err)
	}
	if h.Prober != nil {
		h.Prober.Set(integrations.HAProxy.Name, jobs)
	}
	if len(errs) > 0 {
		log.FromContext(ctx).Error(errors.Join(errs...), "HAProxy Ingresses not wired")
	}
	return res, errors.Join(errs...)
}

// haproxyBufferNote says when HAProxy's buffer lets the engine see less of
// a request or a response than the policies' body.maxBytes or
// responses.maxBytes: HAProxy sends no more than its buffer, and a larger
// body is handled as oversized. "" when it doesn't.
func haproxyBufferNote(ingress string, buffer haproxyBuffer, m haproxyMechanism, body bool, maxBody int64, responses bool, maxResponse int64) string {
	var what, limits, actions []string
	section := "Bodies"
	if body && maxBody > buffer.visible() {
		what, limits, actions = append(what, "a request"), append(limits, fmt.Sprintf("body.maxBytes (%d)", maxBody)), append(actions, "body.onOversize")
	}
	if responses && maxResponse > buffer.visible() {
		what, limits, actions = append(what, "a response"), append(limits, fmt.Sprintf("responses.maxBytes (%d)", maxResponse)), append(actions, "responses.onOversize")
		if len(what) == 1 {
			section = "Responses"
		}
	}
	if len(what) == 0 {
		return ""
	}
	raise := "raise tune.bufsize in the controller ConfigMap's global-config-snippet"
	if m == haproxyBackendCR {
		raise = "raise tune_buffer_options.bufsize in the Global custom resource the controller ConfigMap's cr-global names"
	}
	return fmt.Sprintf("Ingress %s: HAProxy's buffer (tune.bufsize %d, %s) lets the engine see at most about %d bytes of %s, "+
		"headers included, less than its %s: a larger body is handled as oversized (%s); "+
		"%s (docs/haproxy.md, %s)",
		ingress, buffer.bufsize, buffer.source, buffer.visible(), strings.Join(what, " or "),
		strings.Join(limits, " and "), strings.Join(actions, ", "), raise, section)
}

// unverified is why a wired route isn't proven on every pod yet, or "".
func (h *HAProxy) unverified(job ProbeJob) string {
	if h.Prober == nil {
		return fmt.Sprintf("Ingress %s is wired, but the operator doesn't probe HAProxy: the filter is unverified", job.Route.Key.Name)
	}
	return h.Prober.Unverified(job)
}

// Wired implements Integration: the Ingress carries HAProxyWiredAnnotation.
func (h *HAProxy) Wired(ctx context.Context, tg Target) (bool, error) {
	if tg.Kind != ingressKind {
		return false, nil
	}
	var ing networkingv1.Ingress
	switch err := h.APIReader.Get(ctx, tg.Key, &ing); {
	case apierrors.IsNotFound(err):
		return false, nil
	case err != nil:
		return false, err
	}
	_, wired := ing.Annotations[HAProxyWiredAnnotation]
	return wired, nil
}

// Unwire implements Integration: it removes the operator's snippet or
// cr-backend from every Ingress it wired, restores standalone-backend, and
// deletes its Backend custom resources.
func (*HAProxy) Unwire(ctx context.Context, c client.Client) (map[string]int, error) {
	n := map[string]int{}
	var list networkingv1.IngressList
	if err := c.List(ctx, &list); err != nil {
		return n, fmt.Errorf("list Ingresses: %w", err)
	}
	for i := range list.Items {
		ing := &list.Items[i]
		if _, wired := ing.Annotations[HAProxyWiredAnnotation]; !wired {
			continue
		}
		if err := annotateHAProxy(ctx, c, ing, "", ""); client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("unwire Ingress %s/%s: %w", ing.Namespace, ing.Name, err)
		}
		n["Ingress (HAProxy)"]++
	}
	deleted, err := pruneHAProxyBackends(ctx, c, nil)
	if deleted > 0 {
		n["Backend (HAProxy)"] = deleted
	}
	return n, err
}

// haproxyBuffer is HAProxy's request buffer: tune.bufsize, less
// tune.maxrewrite, is the most of a request (headers included) that HAProxy
// sends the engine (0006 §4).
type haproxyBuffer struct {
	bufsize, maxrewrite int64
	// source says where bufsize comes from, for the status.
	source string
}

// visible is the most of a request the engine sees.
func (b haproxyBuffer) visible() int64 { return b.bufsize - b.maxrewrite }

// HAProxy's defaults.
const (
	haproxyDefaultBufsize    = 16384
	haproxyDefaultMaxrewrite = 1024
)

// parseHAProxyBuffer reads tune.bufsize and tune.maxrewrite from a global
// configuration snippet, with HAProxy's size suffixes (k, m, g); the last
// of each wins, as in HAProxy. maxrewrite is at most half the buffer.
func parseHAProxyBuffer(snippet string) haproxyBuffer {
	b := haproxyBuffer{bufsize: haproxyDefaultBufsize, source: "HAProxy's default"}
	maxrewrite := int64(-1)
	for line := range strings.SplitSeq(snippet, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, ok := haproxySize(f[1])
		if !ok {
			continue
		}
		switch f[0] {
		case "tune.bufsize":
			b.bufsize, b.source = n, "from the controller's global-config-snippet"
		case "tune.maxrewrite":
			maxrewrite = n
		}
	}
	if maxrewrite < 0 {
		maxrewrite = haproxyDefaultMaxrewrite
	}
	b.maxrewrite = min(maxrewrite, b.bufsize/2)
	return b
}

// haproxySize parses a size as HAProxy does: a number with an optional k,
// m or g (powers of 1024).
func haproxySize(s string) (int64, bool) {
	mult := int64(1)
	switch strings.ToLower(s[len(s)-1:]) {
	case "k":
		mult = 1 << 10
	case "m":
		mult = 1 << 20
	case "g":
		mult = 1 << 30
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<40)/mult {
		return 0, false
	}
	return n * mult, true
}

// buffer is the smallest buffer of the controller's running pods with the
// engine: from tune.bufsize in the global-config-snippet of the ConfigMap
// each names (--configmap), or, on controller 3.4, which has no snippets,
// in the Global custom resource the ConfigMap's cr-global names; else
// HAProxy's default. A ConfigMap or Global it can't read counts as the
// default.
func (h *HAProxy) buffer(ctx context.Context, pods []*corev1.Pod, m haproxyMechanism) haproxyBuffer {
	out := haproxyBuffer{bufsize: math.MaxInt64}
	seen := map[types.NamespacedName]bool{}
	for _, pod := range pods {
		if !injection.HasEngine(pod) {
			continue
		}
		b := parseHAProxyBuffer("")
		if key, ok := haproxyConfigMap(pod); ok {
			if seen[key] {
				continue
			}
			seen[key] = true
			var cm corev1.ConfigMap
			if err := h.APIReader.Get(ctx, key, &cm); err == nil {
				if m == haproxyBackendCR {
					b = h.globalBuffer(ctx, pod.Namespace, cm.Data["cr-global"])
				} else {
					b = parseHAProxyBuffer(cm.Data["global-config-snippet"])
				}
			}
		}
		if b.visible() < out.visible() || out.bufsize == math.MaxInt64 {
			out = b
		}
	}
	if out.bufsize == math.MaxInt64 {
		return parseHAProxyBuffer("")
	}
	return out
}

// globalBuffer is the buffer the Global custom resource ref
// ("namespace/name", or a name in the controller's namespace) sets.
func (h *HAProxy) globalBuffer(ctx context.Context, namespace, ref string) haproxyBuffer {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return parseHAProxyBuffer("")
	}
	ns, name, found := strings.Cut(ref, "/")
	if !found {
		ns, name = namespace, ref
	}
	g := &unstructured.Unstructured{}
	g.SetGroupVersionKind(HAProxyGlobalGVK)
	if err := h.APIReader.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, g); err != nil {
		return parseHAProxyBuffer("")
	}
	spec, _, _ := unstructured.NestedMap(g.Object, "spec")
	return parseHAProxyGlobal(spec)
}

// haproxyConfigMap is the ConfigMap the controller's container names with
// --configmap (namespace/name).
func haproxyConfigMap(pod *corev1.Pod) (types.NamespacedName, bool) {
	for _, c := range pod.Spec.Containers {
		args := append(slices.Clone(c.Command), c.Args...)
		for i, arg := range args {
			v, ok := strings.CutPrefix(arg, "--configmap=")
			if !ok && arg == "--configmap" && i+1 < len(args) {
				v, ok = args[i+1], true
			}
			if !ok {
				continue
			}
			ns, name, found := strings.Cut(v, "/")
			if !found {
				ns, name = pod.Namespace, v
			}
			return types.NamespacedName{Namespace: ns, Name: name}, name != ""
		}
	}
	return types.NamespacedName{}, false
}
