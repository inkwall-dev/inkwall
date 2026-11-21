// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// The HAProxy Kubernetes Ingress Controller dropped config snippets in 3.4
// ("MAJOR: annotations: drop support for config snippets"). From 3.4 the
// operator gives each protected Ingress a Backend custom resource of the
// controller's (ingress.v3.haproxy.org), which the Ingress names with
// haproxy.org/cr-backend: the same filter and rules as the snippet, as the
// resource's filter_list and rule lists. The controller then builds the
// Ingress's backend from the resource alone: the backend annotations of the
// Ingress, its Services and the controller's ConfigMap don't apply to it
// (docs/haproxy.md), which the policy's status notes.
//
// +kubebuilder:rbac:groups=ingress.v3.haproxy.org,resources=backends,verbs=get;list;watch;create;update;patch;delete,roleName=inkwall-operator-haproxy
// +kubebuilder:rbac:groups=ingress.v3.haproxy.org,resources=globals,verbs=get,roleName=inkwall-operator-haproxy
// +kubebuilder:rbac:groups="",resources=services,verbs=get,roleName=inkwall-operator-haproxy
//
// globals is cluster-wide, as every integration's role is (a ClusterRole
// the chart grants by rbac.integrations): the controller's namespace,
// where its Global is, isn't known when the chart is installed. The
// operator only gets the one its controller's ConfigMap names. services:
// a protected Ingress's backend Services, for their cr-backend.

// HAProxy's custom resources.
var (
	HAProxyBackendGVK = schema.GroupVersionKind{Group: "ingress.v3.haproxy.org", Version: "v3", Kind: "Backend"}
	HAProxyGlobalGVK  = schema.GroupVersionKind{Group: "ingress.v3.haproxy.org", Version: "v3", Kind: "Global"}
)

const (
	// HAProxyCRBackendAnnotation names the Backend custom resource that
	// configures an Ingress's backend (the controller's cr-backend).
	HAProxyCRBackendAnnotation = "haproxy.org/cr-backend"
	// HAProxyVersionAnnotation on the controller's pods says which release
	// of the controller they run, for an image whose tag doesn't
	// (a digest, latest, a mirror's own tags): "3.4.1", or "3.4".
	HAProxyVersionAnnotation = "waf.inkwall.dev/haproxy-controller-version"
)

// haproxyPrefixes are the annotation prefixes the controller reads, and
// none: it strips them (store.CopyAnnotations).
var haproxyPrefixes = []string{"haproxy.org/", "haproxy.com/", "ingress.kubernetes.io/", ""}

// haproxyBackendAnnotations are the controller's annotations that
// configure a backend (3.4's annotations.BackendNames), which don't apply
// to one a Backend custom resource configures.
var haproxyBackendAnnotations = []string{
	"abortonclose", "timeout-check", "timeout-server", "load-balance", "check", "check-interval", "pod-maxconn",
	"send-proxy-protocol", "server-ssl", "server-crt", "server-ca", "server-proto", "check-http", "forwarded-for",
}

// The controller reads cookie-persistence from a Service only, never an
// Ingress, so it isn't among the annotations a protected Ingress loses.

// haproxyMechanism is how the operator loads the filter in a controller's
// backends.
type haproxyMechanism int

const (
	// haproxyUnknown: the operator can't tell, or doesn't wire, the
	// controller's release.
	haproxyUnknown haproxyMechanism = iota
	// haproxySnippets: backend config snippets (3.1 to 3.2).
	haproxySnippets
	// haproxyBackendCR: the controller's Backend custom resource (3.4
	// and later).
	haproxyBackendCR
)

// haproxyControllerVersion is the release of the controller a pod runs,
// MAJOR.MINOR (and PATCH, or -1): from HAProxyVersionAnnotation, else from
// the controller container's image tag. raw is what it was read from.
func haproxyControllerVersion(pod *corev1.Pod) (v [3]int, raw string, ok bool) {
	if a := strings.TrimSpace(pod.Annotations[HAProxyVersionAnnotation]); a != "" {
		v, ok = parseHAProxyVersion(a)
		return v, HAProxyVersionAnnotation + ": " + a, ok
	}
	if len(pod.Spec.Containers) == 0 {
		return v, "no container", false
	}
	c := pod.Spec.Containers[0]
	if i := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == injection.HAProxyContainer }); i >= 0 {
		c = pod.Spec.Containers[i]
	}
	image := c.Image
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	i := strings.LastIndexByte(image, ':')
	if i < 0 || strings.Contains(image[i:], "/") {
		return v, "image " + c.Image, false
	}
	v, ok = parseHAProxyVersion(image[i+1:])
	return v, "image " + c.Image, ok
}

// parseHAProxyVersion reads "3.4.1", "v3.4", "3.2.20-alpine".
func parseHAProxyVersion(s string) ([3]int, bool) {
	v := [3]int{0, 0, -1}
	s = strings.TrimPrefix(s, "v")
	if j := strings.IndexAny(s, "-+"); j >= 0 {
		s = s[:j]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return v, false
	}
	for k, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[k] = n
	}
	return v, true
}

// mechanismOf is how the operator wires a release of the controller.
func mechanismOf(v [3]int) haproxyMechanism {
	switch {
	case v[0] != 3 || v[1] < 1:
		return haproxyUnknown
	case v[1] < 4:
		return haproxySnippets
	}
	return haproxyBackendCR
}

func versionString(v [3]int) string {
	if v[2] < 0 {
		return fmt.Sprintf("%d.%d", v[0], v[1])
	}
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
}

// haproxyMechanismOf is how the operator wires the Ingresses a controller
// serves, from its pods (haproxyControllerPods): snippets while every one
// runs 3.1 to 3.2, the Backend custom resource once one runs 3.4 or later
// (a 3.2 pod of a rollout to 3.4 reads it too; the probe says where it
// doesn't). A pod whose release the operator can't tell (its tag isn't
// one, or a major release after 3) is wired with the Backend custom
// resource when its CRD is installed (backendCRD), which the controller
// reads since 3.2, and note says so; otherwise, and for a release before
// 3.1, it is haproxyUnknown, and unsupported says why.
func haproxyMechanismOf(pods []*corev1.Pod, backendCRD bool) (m haproxyMechanism, unsupported, note string) {
	m = haproxySnippets
	var old, untold []string
	for _, pod := range pods {
		v, raw, ok := haproxyControllerVersion(pod)
		switch {
		case !ok:
			untold = append(untold, fmt.Sprintf("HAProxy pod %s/%s runs a release of the controller the operator can't tell from its %s", pod.Namespace, pod.Name, raw))
		case v[0] > 3:
			untold = append(untold, fmt.Sprintf("HAProxy pod %s/%s runs the HAProxy Kubernetes Ingress Controller %s (%s), a release the operator doesn't know", pod.Namespace, pod.Name, versionString(v), raw))
		case mechanismOf(v) == haproxyUnknown:
			old = append(old, fmt.Sprintf("HAProxy pod %s/%s runs the HAProxy Kubernetes Ingress Controller %s (%s), which the operator doesn't wire", pod.Namespace, pod.Name, versionString(v), raw))
		case mechanismOf(v) == haproxyBackendCR:
			m = haproxyBackendCR
		}
	}
	slices.Sort(old)
	slices.Sort(untold)
	const how = "the operator loads the filter through backend config snippets on controller 3.1 to 3.2 and through the controller's Backend custom resources on 3.4 and later"
	const say = "for an image whose tag isn't its release, say it in the pods' " + HAProxyVersionAnnotation + " annotation (controller.podAnnotations)"
	switch {
	case len(old) > 0:
		return haproxyUnknown, strings.Join(slices.Concat(old, untold), "; ") + ": " + how + "; run one of those (the chart's controller.image.tag), or, " + say, ""
	case len(untold) > 0 && !backendCRD:
		return haproxyUnknown, strings.Join(untold, "; ") + ": " + how + ", and the controller's Backend CRD (backends.ingress.v3.haproxy.org) isn't installed; " +
			"run one of those releases (the chart's controller.image.tag), or, " + say, ""
	case len(untold) > 0:
		return haproxyBackendCR, "", strings.Join(untold, "; ") + ": it is wired through the controller's Backend custom resource, which the controller reads since 3.2 (the probe shows whether it does); " + say
	}
	return m, "", ""
}

// haproxyGroup is what the Ingresses of one controller (an IngressClass's
// spec.controller) are wired with: its pods (haproxyControllerPods), the
// mechanism they call for, and their problems and buffer.
type haproxyGroup struct {
	pods                    []*corev1.Pod
	mech                    haproxyMechanism
	versionWhy, versionNote string
	problems                []string
	buffer                  haproxyBuffer
}

// haproxyRejectedHint follows a failed probe on an Ingress wired with the
// operator's Backend custom resource: HAProxy may have rejected it, and the
// controller then builds the backend without it, so without the filter.
func haproxyRejectedHint(ing *networkingv1.Ingress) string {
	return fmt.Sprintf("the controller sets aside a Backend custom resource HAProxy rejects and builds the backend without it, so without the filter: "+
		"look for Backend %s in the controller's log (and its haproxy_rejected_custom_resource_generation metric)", haproxyBackendRef(ing))
}

// haproxyControllerPods are the running pods of the controller with the
// engine that decide how its Ingresses are wired: in a proxy namespace and
// owned by a ReplicaSet or DaemonSet (the chart's Deployment or DaemonSet),
// so a pod anyone else makes with the controller's labels counts for
// nothing.
func (h *HAProxy) haproxyControllerPods(pods []*corev1.Pod) []*corev1.Pod {
	var out []*corev1.Pod
	for _, pod := range pods {
		if !injection.HasEngine(pod) || !h.Namespaces.Has(pod.Namespace) {
			continue
		}
		owner := metav1.GetControllerOf(pod)
		if owner == nil || (owner.Kind != "ReplicaSet" && owner.Kind != "DaemonSet") || !strings.HasPrefix(owner.APIVersion, "apps/") {
			continue
		}
		out = append(out, pod)
	}
	return out
}

// haproxyPodClass is the IngressClass controller name's suffix a
// controller pod serves (haproxy.org/ingress-controller/<class>): its
// --ingress.class, "" when unset.
func haproxyPodClass(pod *corev1.Pod) string {
	for _, c := range pod.Spec.Containers {
		args := append(slices.Clone(c.Command), c.Args...)
		for i, arg := range args {
			if v, ok := strings.CutPrefix(arg, "--ingress.class="); ok {
				return v
			}
			if arg == "--ingress.class" && i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}

// podsServing are the pods of the controller that serves Ingresses of
// controller (an IngressClass's spec.controller): those whose
// --ingress.class it names, or, when none does (a controller run without
// it), all of them.
func podsServing(pods []*corev1.Pod, controller string) []*corev1.Pod {
	class, _ := strings.CutPrefix(controller, integrations.HAProxy.ControllerPrefix)
	var out []*corev1.Pod
	for _, pod := range pods {
		if haproxyPodClass(pod) == class {
			out = append(out, pod)
		}
	}
	if len(out) == 0 {
		return pods
	}
	return out
}

// haproxyBackendCRDInstalled reports whether the API server serves the
// controller's Backend kind: one it can't tell of (an error) counts as
// not, so a controller of unknown release is reported rather than wired
// with a kind that may not be served.
func haproxyBackendCRDInstalled(ctx context.Context, r client.Reader) bool {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(HAProxyBackendGVK.GroupVersion().WithKind("BackendList"))
	return r.List(ctx, list, client.Limit(1)) == nil
}

// haproxyBackendName is the operator's Backend custom resource for an
// Ingress.
func haproxyBackendName(ingress string) string { return envoyName(ingress) }

// haproxyBackendRef is an Ingress's haproxy.org/cr-backend value when the
// operator wires it.
func haproxyBackendRef(ing *networkingv1.Ingress) string {
	return ing.Namespace + "/" + haproxyBackendName(ing.Name)
}

// haproxyAnnotation is the value of one of the controller's annotations on
// an Ingress, under any of its prefixes, and its key.
func haproxyAnnotation(a map[string]string, name string) (key, value string, ok bool) {
	for _, p := range haproxyPrefixes {
		if v, found := a[p+name]; found {
			return p + name, v, true
		}
	}
	return "", "", false
}

// userCRBackend is the Backend custom resource the user's Ingress names
// itself (cr-backend, under any prefix), "" when none or the operator's.
func userCRBackend(ing *networkingv1.Ingress) string {
	for _, p := range haproxyPrefixes {
		key := p + "cr-backend"
		v, ok := ing.Annotations[key]
		if ok && (key != HAProxyCRBackendAnnotation || v != haproxyBackendRef(ing)) {
			return key + ": " + v
		}
	}
	return ""
}

// ingressServices are the Services an Ingress routes to.
func ingressServices(ing *networkingv1.Ingress) []string {
	var out []string
	if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
		out = append(out, b.Service.Name)
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil {
				out = append(out, p.Backend.Service.Name)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// serviceCRBackends are the Ingress's Services that name a Backend custom
// resource of their own (cr-backend), which the controller takes over the
// Ingress's (Service, then Ingress, then ConfigMap): "Service app
// (cr-backend: ns/name)". A Service that doesn't exist names none.
func (h *HAProxy) serviceCRBackends(ctx context.Context, ing *networkingv1.Ingress) ([]string, error) {
	var out []string
	for _, name := range ingressServices(ing) {
		var svc corev1.Service
		switch err := h.APIReader.Get(ctx, types.NamespacedName{Namespace: ing.Namespace, Name: name}, &svc); {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			return nil, fmt.Errorf("service %s: %w", name, err)
		}
		if key, v, ok := haproxyAnnotation(svc.Annotations, "cr-backend"); ok {
			out = append(out, fmt.Sprintf("Service %s (%s: %s)", name, key, v))
		}
	}
	return out, nil
}

// ignoredBackendAnnotations are the Ingress's backend annotations that
// don't apply while the operator's Backend custom resource configures its
// backend, sorted.
func ignoredBackendAnnotations(ing *networkingv1.Ingress) []string {
	var out []string
	for _, name := range append(slices.Clone(haproxyBackendAnnotations), "backend-config-snippet") {
		if key, _, ok := haproxyAnnotation(ing.Annotations, name); ok {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// HAProxyBackendSpec is the spec of the operator's Backend custom resource
// for a protected Ingress (controller 3.4 and later): the snippet's
// (HAProxySnippet) buffer option, filter and rules, as the controller's
// fields (client-native's models), and the controller's defaults section,
// which a backend from annotations inherits too.
func HAProxyBackendSpec(o HAProxySnippetOptions) map[string]any {
	c := haproxyConfigOf(o)
	spec := map[string]any{
		"from": "haproxytech",
		"filter_list": []any{map[string]any{
			"type": "spoe", "spoe_engine": c.engine, "spoe_config": injection.HAProxySPOEConf,
		}},
	}
	if c.bufferRequest {
		spec["http-buffer-request"] = "enabled"
	}
	lists := map[string]string{
		"http-request":        "http_request_rule_list",
		"http-response":       "http_response_rule_list",
		"http-after-response": "http_after_response_rule_list",
	}
	for _, r := range c.rules {
		list := lists[r.section]
		rules, _ := spec[list].([]any)
		spec[list] = append(rules, r.model())
	}
	return spec
}

// model is the rule as the Backend custom resource's fields.
func (r haproxyRule) model() map[string]any {
	m := map[string]any{"type": r.action}
	if r.cond != "" {
		m["cond"], m["cond_test"] = r.cond, r.condTest
	}
	if len(r.hdrs) > 0 {
		hdrs := make([]any, len(r.hdrs))
		for i, h := range r.hdrs {
			hdrs[i] = map[string]any{"name": h[0], "fmt": h[1]}
		}
		m["return_hdrs"] = hdrs
	}
	switch r.action {
	case "return":
		m["return_status_code"] = int64(r.status)
		if r.contentType != "" {
			m["return_content_type"] = r.contentType
		}
		if r.contentFormat != "" {
			m["return_content_format"], m["return_content"] = r.contentFormat, r.content
		}
	case "deny":
		m["deny_status"] = int64(r.status)
	case "del-header":
		m["hdr_name"] = r.header
	case "set-header":
		m["hdr_name"], m["hdr_format"] = r.header, r.format
	case "set-var":
		m["var_scope"], m["var_name"], m["var_expr"] = r.varScope, r.varName, r.expr
	case "wait-for-body":
		// The controller writes at-least whatever it is: 0 is HAProxy's
		// default, the whole body.
		m["wait_time"], m["wait_at_least"] = r.waitMillis, int64(0)
	case "send-spoe-group":
		m["spoe_engine"], m["spoe_group"] = r.spoeEngine, r.spoeGroup
	}
	return m
}

// haproxyBackend is the operator's Backend custom resource for a protected
// Ingress, owned by it.
func haproxyBackend(ing *networkingv1.Ingress, o HAProxySnippetOptions) *unstructured.Unstructured {
	b := newObject(HAProxyBackendGVK, ing.Namespace, haproxyBackendName(ing.Name))
	owned(b, ing, networkingv1.SchemeGroupVersion.WithKind("Ingress"))
	b.Object["spec"] = HAProxyBackendSpec(o)
	return b
}

// errNoBackendCRD is a wiring failure's message when the controller's
// Backend custom resource definition isn't installed.
const errNoBackendCRD = "the HAProxy Kubernetes Ingress Controller's Backend custom resource definition (backends.ingress.v3.haproxy.org, v3) isn't installed, " +
	"which the operator wires controller 3.4 and later with: install the chart's CRDs (its crdjob, or kubectl apply its crds directory)"

// annotateHAProxy wires an Ingress, with the operator's part of its
// backend snippet (snippet, controller 3.1 to 3.2) or the operator's
// Backend custom resource (crBackend, 3.4 and later), or unwires it (both
// empty) if the operator wired it before. Either way the other mechanism's
// part goes, so a controller upgraded from 3.2 to 3.4 is wired anew.
func annotateHAProxy(ctx context.Context, c client.Client, ing *networkingv1.Ingress, snippet, crBackend string) error {
	before, wired := ing.Annotations[HAProxyWiredAnnotation]
	want := snippet != "" || crBackend != ""
	if !want && !wired {
		return nil
	}
	a := maps.Clone(ing.Annotations)
	if a == nil {
		a = map[string]string{}
	}
	if next := withSnippet(a[HAProxySnippetAnnotation], snippet); next == "" {
		delete(a, HAProxySnippetAnnotation)
	} else {
		a[HAProxySnippetAnnotation] = next
	}
	switch ours := haproxyBackendRef(ing); {
	case crBackend != "":
		a[HAProxyCRBackendAnnotation] = crBackend
	case a[HAProxyCRBackendAnnotation] == ours:
		delete(a, HAProxyCRBackendAnnotation)
	}
	if want {
		if !wired {
			a[HAProxyWiredAnnotation] = a[HAProxyStandaloneAnnotation]
		}
		a[HAProxyStandaloneAnnotation] = "true"
	} else {
		if before == "" {
			delete(a, HAProxyStandaloneAnnotation)
		} else {
			a[HAProxyStandaloneAnnotation] = before
		}
		delete(a, HAProxyWiredAnnotation)
	}
	if maps.Equal(a, ing.Annotations) {
		return nil
	}
	patch := client.MergeFrom(ing.DeepCopy())
	ing.Annotations = a
	return c.Patch(ctx, ing, patch)
}

// ensureHAProxyBackend creates or updates the operator's Backend custom
// resource for an Ingress: "" once it is, else why not.
func ensureHAProxyBackend(ctx context.Context, c client.Client, b *unstructured.Unstructured) string {
	switch err := ensureObject(ctx, c, b); {
	case meta.IsNoMatchError(err):
		return errNoBackendCRD
	case err != nil:
		return fmt.Sprintf("Backend %s: %v", b.GetName(), err)
	}
	return ""
}

// pruneHAProxyBackends deletes the operator's Backend custom resources of
// the Ingresses not in keep (nil: all), and counts them.
func pruneHAProxyBackends(ctx context.Context, c client.Client, keep map[types.NamespacedName]bool) (int, error) {
	return deleteManaged(ctx, c, HAProxyBackendGVK, func(u *unstructured.Unstructured) bool {
		return keep[types.NamespacedName{Namespace: u.GetNamespace(), Name: u.GetName()}]
	})
}

// haproxyIgnoredNote says which of a wired Ingress's backend annotations
// don't apply on controller 3.4, where the operator's Backend custom
// resource configures its backend; "" when none.
func haproxyIgnoredNote(ing *networkingv1.Ingress) string {
	ignored := ignoredBackendAnnotations(ing)
	if len(ignored) == 0 {
		return ""
	}
	return fmt.Sprintf("Ingress %s: on controller 3.4 the operator's Backend custom resource %s configures its backend, and the controller applies no backend annotation to a backend "+
		"a Backend custom resource configures: %s don't apply (docs/haproxy.md, Controller releases)", ing.Name, haproxyBackendName(ing.Name), strings.Join(ignored, ", "))
}

// parseHAProxyGlobal reads tune.bufsize and tune.maxrewrite from the
// controller's Global custom resource's spec (3.4: no global config
// snippet), HAProxy's defaults when unset.
func parseHAProxyGlobal(spec map[string]any) haproxyBuffer {
	b := parseHAProxyBuffer("")
	if n, ok, _ := unstructured.NestedInt64(spec, "tune_buffer_options", "bufsize"); ok && n > 0 {
		b.bufsize, b.source = n, "from the controller's Global custom resource"
	}
	maxrewrite := int64(haproxyDefaultMaxrewrite)
	if n, ok, _ := unstructured.NestedInt64(spec, "tune_options", "maxrewrite"); ok && n >= 0 {
		maxrewrite = n
	}
	b.maxrewrite = min(maxrewrite, b.bufsize/2)
	return b
}
