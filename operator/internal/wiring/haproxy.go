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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// The HAProxy Kubernetes Ingress Controller's wiring (0002 §6.4): each
// protected Ingress of its class gets a backend of its own
// (haproxy.org/standalone-backend) whose configuration snippet
// (haproxy.org/backend-config-snippet) loads the SPOE filter, which calls
// the engine, and denies on its verdict. The agent's backend and spoe.conf
// are in the controller's pods (injection.InjectHAProxy). The controller
// says nothing about a snippet it drops, so a route is Programmed only once
// the operator's probe (Prober) has proven the filter on every pod.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch,roleName=inkwall-operator-haproxy
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch,roleName=inkwall-operator-haproxy
// +kubebuilder:rbac:groups=ingress.v3.haproxy.org,resources=backends,verbs=get;list;watch,roleName=inkwall-operator-haproxy
//
// The controller's Backend kind is in the role only so that it is the
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
}

// Name implements Integration.
func (*HAProxy) Name() string { return integrations.HAProxy.Name }

// Kinds implements Integration.
func (*HAProxy) Kinds() []schema.GroupKind { return []schema.GroupKind{ingressKind} }

// Watch implements Integration: Ingresses (their annotations), classes,
// the controller's pods, the policies' settings (the wiring controller
// watches them), and the probe's results.
func (h *HAProxy) Watch(c controller.Controller, cache cache.Cache, eh handler.EventHandler) error {
	for _, obj := range []client.Object{&networkingv1.Ingress{}, &networkingv1.IngressClass{}, &corev1.Pod{}} {
		if err := c.Watch(source.Kind(cache, obj, eh)); err != nil {
			return err
		}
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
	// maxBody is the largest body.maxBytes of the policies that inspect
	// bodies (the engine's 64 KiB for one that sets none).
	maxBody int64
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
		mode := cmp.Or(p.Spec.FailureMode, wafv1alpha1.FailOpen)
		if p.Spec.Mode == wafv1alpha1.PolicyBlock && p.Spec.FailureMode == "" {
			mode = wafv1alpha1.FailClosed
		}
		s.failOpen = s.failOpen && mode == wafv1alpha1.FailOpen
	}
	return s
}

// HAProxySnippet is the operator's part of a protected Ingress's backend
// snippet: the body buffered for the engine when a policy inspects it, the
// SPOE filter, and the rules on its variables: the probe's answer first
// (Prober), then, failing closed, 503 without a verdict, a denied
// gRPC call's answer, and a rule per status the engine denies with; the
// request ID for the app.
func HAProxySnippet(failOpen, body bool) string {
	lines := []string{haproxySnippetBegin}
	if body {
		lines = append(lines, "option http-buffer-request")
	}
	v := func(name string) string { return "var(txn.inkwall." + name + ")" }
	lines = append(lines,
		"filter spoe engine inkwall config "+injection.HAProxySPOEConf,
		fmt.Sprintf(`http-request return status %d hdr %s "%%[%s]" if { %s -m found }`,
			haproxyprobe.Status, strings.ToLower(haproxyprobe.Header), v("probe"), v("probe")))
	if !failOpen {
		lines = append(lines, "http-request deny deny_status 503 if !{ "+v("action")+" -m found }")
	}
	lines = append(lines,
		`http-request return status 200 hdr grpc-status "%[`+v("grpc_status")+`]" hdr grpc-message "%[`+v("grpc_message")+`]" hdr x-request-id "%[`+v("request_id")+`]" if { `+v("grpc_status")+` -m found }`,
		`http-after-response set-header content-type "%[`+v("grpc_content_type")+`]" if { `+v("grpc_content_type")+` -m found }`)
	for _, status := range []int{400, 413, 503} {
		lines = append(lines, fmt.Sprintf(`http-request deny deny_status %d hdr x-request-id "%%[%s]" if { %s -m int %d }`, status, v("request_id"), v("status"), status))
	}
	lines = append(lines,
		`http-request deny deny_status 403 hdr x-request-id "%[`+v("request_id")+`]" if { `+v("action")+` -m str deny }`,
		`http-request set-header X-Request-Id "%[`+v("request_id")+`]" if { `+v("request_id")+` -m found }`,
		haproxySnippetEnd)
	return strings.Join(lines, "\n")
}

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

// annotateHAProxy wires an Ingress (snippet not empty) or unwires it if the
// operator wired it before.
func annotateHAProxy(ctx context.Context, c client.Client, ing *networkingv1.Ingress, snippet string) error {
	before, wired := ing.Annotations[HAProxyWiredAnnotation]
	if snippet == "" && !wired {
		return nil
	}
	cur := ing.Annotations[HAProxySnippetAnnotation]
	next := withSnippet(cur, snippet)
	if snippet != "" && wired && next == cur && ing.Annotations[HAProxyStandaloneAnnotation] == "true" {
		return nil
	}
	patch := client.MergeFrom(ing.DeepCopy())
	if ing.Annotations == nil {
		ing.Annotations = map[string]string{}
	}
	a := ing.Annotations
	if snippet != "" {
		if !wired {
			a[HAProxyWiredAnnotation] = a[HAProxyStandaloneAnnotation]
		}
		a[HAProxyStandaloneAnnotation] = "true"
		a[HAProxySnippetAnnotation] = next
	} else {
		if before == "" {
			delete(a, HAProxyStandaloneAnnotation)
		} else {
			a[HAProxyStandaloneAnnotation] = before
		}
		if next == "" {
			delete(a, HAProxySnippetAnnotation)
		} else {
			a[HAProxySnippetAnnotation] = next
		}
		delete(a, HAProxyWiredAnnotation)
	}
	return c.Patch(ctx, ing, patch)
}

// haproxyPodProblems are why the controller's running pods can't run the
// filter, besides a missing engine (the wiring controller's sidecar check):
// the agent's configuration isn't mounted, or snippets are disabled.
func haproxyPodProblems(pods []*corev1.Pod) []string {
	var out []string
	for _, pod := range pods {
		if !injection.HasEngine(pod) {
			continue
		}
		name := workloadOf(pod)
		if ok, why := injection.HAProxyConfigured(pod); !ok {
			out = append(out, fmt.Sprintf("HAProxy %s: %s", name, why))
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
	problems := haproxyPodProblems(runningPods)
	buffer := h.buffer(ctx, runningPods)

	res := &Result{Proxy: "HAProxy", Targets: map[Target]TargetState{}, Pods: pods.Items}
	var (
		errs []error
		jobs []ProbeJob
	)
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		k := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		tg := Target{Kind: ingressKind, Key: k}
		mine := integrations.HAProxy.ServesIngresses(Controller(ing, classes, defaultClass))
		want := targets[tg] && mine && on
		snippet := ""
		settings := haproxySettingsOf(policies.Items, k)
		if want {
			snippet = HAProxySnippet(settings.failOpen, settings.body)
		}
		err := annotateHAProxy(ctx, h.Client, ing, snippet)
		if err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("wire Ingress %s: %w", k, err))
		}
		if !targets[tg] {
			continue
		}
		var s TargetState
		switch {
		case !mine:
			c := Controller(ing, classes, defaultClass)
			if c == "" {
				c = "no known IngressClass"
			}
			s.Unsupported = fmt.Sprintf("Ingress %s is served by %s, which Inkwall doesn't wire yet", k.Name, c)
		case err != nil:
			s.Failed = fmt.Sprintf("Ingress %s: %v", k.Name, err)
		case len(problems) > 0:
			s.Failed = strings.Join(problems, "; ")
		}
		s.Wired = want && err == nil
		if s.Wired && s.Failed == "" {
			job := ProbeJob{Route: ProbeRoute{Kind: "Ingress", Key: k}, Proxy: "HAProxy", Fingerprint: ing.Annotations[HAProxySnippetAnnotation], Targets: probeTargets(ing)}
			for _, pod := range runningPods {
				if injection.HasEngine(pod) {
					job.Pods = append(job.Pods, probePod(pod))
				}
			}
			jobs = append(jobs, job)
			s.Unverified = h.unverified(job)
			if settings.body && settings.maxBody > buffer.visible() {
				s.Note = fmt.Sprintf("Ingress %s: HAProxy's buffer (tune.bufsize %d, %s) lets the engine see at most about %d bytes of a request, "+
					"headers included, less than its body.maxBytes (%d): a larger body is handled as oversized (body.onOversize); "+
					"raise tune.bufsize in the controller ConfigMap's global-config-snippet (docs/haproxy.md, Bodies)",
					k.Name, buffer.bufsize, buffer.source, buffer.visible(), settings.maxBody)
			}
		}
		res.Targets[tg] = s
	}
	if h.Prober != nil {
		h.Prober.Set(integrations.HAProxy.Name, jobs)
	}
	if len(errs) > 0 {
		log.FromContext(ctx).Error(errors.Join(errs...), "HAProxy Ingresses not wired")
	}
	return res, errors.Join(errs...)
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

// Unwire implements Integration: it removes the operator's snippet from
// every Ingress it wired, and restores standalone-backend.
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
		if err := annotateHAProxy(ctx, c, ing, ""); client.IgnoreNotFound(err) != nil {
			return n, fmt.Errorf("unwire Ingress %s/%s: %w", ing.Namespace, ing.Name, err)
		}
		n["Ingress (HAProxy)"]++
	}
	return n, nil
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
// each names (--configmap), or HAProxy's default. A ConfigMap it can't
// read counts as the default.
func (h *HAProxy) buffer(ctx context.Context, pods []*corev1.Pod) haproxyBuffer {
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
				b = parseHAProxyBuffer(cm.Data["global-config-snippet"])
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
