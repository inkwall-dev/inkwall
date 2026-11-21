// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// The controller's release, from the pod's annotation or its image's tag,
// and how the operator wires it: snippets on 3.1 to 3.2, the Backend
// custom resource on 3.4 and later; one it can't tell, the Backend when its
// CRD is installed (noted), else nothing; nothing before 3.1.
func TestHAProxyControllerVersion(t *testing.T) {
	for _, c := range []struct {
		image, annotation string
		ok                bool
		// want without the Backend CRD, withCRD with it.
		want, withCRD haproxyMechanism
	}{
		{"haproxytech/kubernetes-ingress:3.2.20", "", true, haproxySnippets, haproxySnippets},
		{"haproxytech/kubernetes-ingress:3.1.17", "", true, haproxySnippets, haproxySnippets},
		{"haproxytech/kubernetes-ingress:v3.2", "", true, haproxySnippets, haproxySnippets},
		{"haproxytech/kubernetes-ingress:3.4.1", "", true, haproxyBackendCR, haproxyBackendCR},
		{"haproxytech/kubernetes-ingress:3.4", "", true, haproxyBackendCR, haproxyBackendCR},
		{"registry.example.com:5000/haproxy/ingress:3.5.0-rc1@sha256:abc", "", true, haproxyBackendCR, haproxyBackendCR},
		{"haproxytech/kubernetes-ingress:3.0.5", "", true, haproxyUnknown, haproxyUnknown},
		{"haproxytech/kubernetes-ingress:1.11.3", "", true, haproxyUnknown, haproxyUnknown},
		{"haproxytech/kubernetes-ingress:4.0.0", "", true, haproxyUnknown, haproxyBackendCR},
		{"haproxytech/kubernetes-ingress:latest", "", false, haproxyUnknown, haproxyBackendCR},
		{"haproxytech/kubernetes-ingress@sha256:abc", "", false, haproxyUnknown, haproxyBackendCR},
		{"registry.example.com:5000/haproxy/ingress", "", false, haproxyUnknown, haproxyBackendCR},
		// The annotation says what the tag doesn't, and wins over it.
		{"haproxytech/kubernetes-ingress@sha256:abc", "3.4.1", true, haproxyBackendCR, haproxyBackendCR},
		{"haproxytech/kubernetes-ingress:3.4.1", "3.2", true, haproxySnippets, haproxySnippets},
		{"haproxytech/kubernetes-ingress:3.4.1", "soon", false, haproxyUnknown, haproxyBackendCR},
	} {
		pod := haproxyControllerPod("hap-1")
		pod.Spec.Containers[0].Image = c.image
		if c.annotation != "" {
			pod.Annotations[HAProxyVersionAnnotation] = c.annotation
		}
		v, _, ok := haproxyControllerVersion(pod)
		if ok != c.ok {
			t.Errorf("%s %q: ok %t", c.image, c.annotation, ok)
		}
		m, why, note := haproxyMechanismOf([]*corev1.Pod{pod}, false)
		if m != c.want || (m == haproxyUnknown) != (why != "") || note != "" {
			t.Errorf("%s %q (%v), no CRD: mechanism %d %q %q, want %d", c.image, c.annotation, v, m, why, note, c.want)
		}
		m, why, note = haproxyMechanismOf([]*corev1.Pod{pod}, true)
		if m != c.withCRD || (m == haproxyUnknown) != (why != "") || (c.want == haproxyUnknown && m == haproxyBackendCR) != (note != "") {
			t.Errorf("%s %q (%v), the CRD: mechanism %d %q %q, want %d", c.image, c.annotation, v, m, why, note, c.withCRD)
		}
	}
	// A rollout from 3.2 to 3.4: the Backend, which 3.2 reads too.
	old, next := haproxyControllerPod("hap-1"), haproxyControllerPod("hap-2")
	next.Spec.Containers[0].Image = "haproxytech/kubernetes-ingress:3.4.1"
	if m, _, _ := haproxyMechanismOf([]*corev1.Pod{old, next}, false); m != haproxyBackendCR {
		t.Errorf("3.2 and 3.4: %d", m)
	}
	// One pod the operator can't tell, without the CRD: none, naming it
	// and what to do.
	next.Spec.Containers[0].Image = "haproxytech/kubernetes-ingress:latest"
	m, why, _ := haproxyMechanismOf([]*corev1.Pod{old, next}, false)
	for _, want := range []string{"haproxy-controller/hap-2", "image haproxytech/kubernetes-ingress:latest", "controller.image.tag", HAProxyVersionAnnotation, "Backend CRD"} {
		if m != haproxyUnknown || !strings.Contains(why, want) {
			t.Errorf("%d %q lacks %q", m, why, want)
		}
	}
	// With the CRD: the Backend, and the note says why.
	m, _, note := haproxyMechanismOf([]*corev1.Pod{old, next}, true)
	for _, want := range []string{"haproxy-controller/hap-2", "reads since 3.2", HAProxyVersionAnnotation} {
		if m != haproxyBackendCR || !strings.Contains(note, want) {
			t.Errorf("%d %q lacks %q", m, note, want)
		}
	}
}

// Only the controller's own pods say how it is wired: running with the
// engine, in a proxy namespace, owned by a ReplicaSet or DaemonSet. A pod
// with its labels elsewhere, or made by hand, counts for nothing.
func TestHAProxyControllerPods(t *testing.T) {
	h := &HAProxy{Namespaces: integrations.Namespaces{"haproxy-controller"}}
	ok := haproxyControllerPod("hap-1")
	elsewhere := haproxyControllerPod("hap-2")
	elsewhere.Namespace = "tenant"
	bare := haproxyControllerPod("hap-3")
	bare.OwnerReferences = nil
	job := haproxyControllerPod("hap-4")
	job.OwnerReferences[0].Kind, job.OwnerReferences[0].APIVersion = "Job", "batch/v1"
	ds := haproxyControllerPod("hap-5")
	ds.OwnerReferences[0].Kind = "DaemonSet"
	noEngine := &corev1.Pod{ObjectMeta: *ok.ObjectMeta.DeepCopy()}
	noEngine.Name = "hap-6"
	got := h.haproxyControllerPods([]*corev1.Pod{ok, elsewhere, bare, job, ds, noEngine})
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "hap-1,hap-5" {
		t.Errorf("trusted %v", names)
	}
	// Every namespace a proxy namespace: the one elsewhere counts.
	h.Namespaces = nil
	if got := h.haproxyControllerPods([]*corev1.Pod{elsewhere}); len(got) != 1 {
		t.Errorf("every namespace: %d", len(got))
	}
}

// renderModel writes a rule of the Backend custom resource back as a
// configuration line, field by field as client-native's config-parser
// (v6.4.4) orders them, so that each resource rule can be compared with
// the snippet line it stands for. It is a reading of that code, not the
// code (client-native isn't a dependency): what the controller really
// writes is checked end to end (make kind-e2e-haproxy, controller 3.4).
func renderModel(section string, m map[string]any) string {
	str := func(k string) string { s, _ := m[k].(string); return s }
	num := func(k string) int64 { n, _ := m[k].(int64); return n }
	b := section + " " + str("type")
	switch str("type") {
	case "return":
		b += fmt.Sprintf(" status %d", num("return_status_code"))
		if ct := str("return_content_type"); ct != "" {
			b += " content-type " + ct
		}
		if f := str("return_content_format"); f != "" {
			b += " " + f + " " + str("return_content")
		}
	case "deny":
		b += fmt.Sprintf(" deny_status %d", num("deny_status"))
	case "del-header":
		b += " " + str("hdr_name")
	case "set-header":
		b += " " + str("hdr_name") + " " + str("hdr_format")
	case "set-var":
		b = section + " set-var(" + str("var_scope") + "." + str("var_name") + ") " + str("var_expr")
	case "wait-for-body":
		b += " time " + haproxyDuration(num("wait_time"))
	case "send-spoe-group":
		b += " " + str("spoe_engine") + " " + str("spoe_group")
	}
	hdrs, _ := m["return_hdrs"].([]any)
	for _, h := range hdrs {
		h := h.(map[string]any)
		b += " hdr " + h["name"].(string) + " " + h["fmt"].(string)
	}
	if c := str("cond"); c != "" {
		b += " " + c + " " + str("cond_test")
	}
	return b
}

// The Backend custom resource has the snippet's buffer option, filter
// and rules, in its order, as the controller writes them; and is JSON (an
// unstructured object's content).
func TestHAProxyBackendSpec(t *testing.T) {
	for _, o := range []HAProxySnippetOptions{
		{}, {Body: true}, {FailOpen: true}, {Block: true, Body: true},
		{Block: true, Body: true, Responses: true}, {FailOpen: true, Responses: true},
	} {
		spec := HAProxyBackendSpec(o)
		// Only JSON's types (int64, not int): it panics otherwise.
		_ = runtime.DeepCopyJSONValue(spec)
		var lines []string
		if spec["http-buffer-request"] == "enabled" {
			lines = append(lines, "option http-buffer-request")
		}
		filters := spec["filter_list"].([]any)
		f := filters[0].(map[string]any)
		if len(filters) != 1 || f["type"] != "spoe" || f["spoe_config"] != injection.HAProxySPOEConf {
			t.Fatalf("%+v: filters %v", o, filters)
		}
		lines = append(lines, "filter spoe engine "+f["spoe_engine"].(string)+" config "+injection.HAProxySPOEConf)
		// The snippet's lines, by section, in the resource's lists.
		snippet := strings.Split(HAProxySnippet(o), "\n")
		snippet = snippet[1 : len(snippet)-1]
		bySection := map[string][]string{}
		for _, l := range snippet {
			s, _, _ := strings.Cut(l, " ")
			bySection[s] = append(bySection[s], l)
		}
		// The option and the filter lead the snippet.
		if got, want := strings.Join(lines, "\n"), strings.Join(snippet[:len(lines)], "\n"); got != want {
			t.Errorf("%+v: option and filter:\n got  %s\n want %s", o, got, want)
		}
		for section, list := range map[string]string{"http-request": "http_request_rule_list", "http-response": "http_response_rule_list", "http-after-response": "http_after_response_rule_list"} {
			rules, _ := spec[list].([]any)
			if len(rules) != len(bySection[section]) {
				t.Errorf("%+v: %d %s rules, the snippet %d", o, len(rules), section, len(bySection[section]))
				continue
			}
			for i, r := range rules {
				if got := renderModel(section, r.(map[string]any)); got != bySection[section][i] {
					t.Errorf("%+v: %s rule %d:\n got  %s\n want %s", o, section, i, got, bySection[section][i])
				}
			}
		}
		for _, l := range bySection["option"] {
			if l != "option http-buffer-request" || spec["http-buffer-request"] != "enabled" {
				t.Errorf("%+v: %q", o, l)
			}
		}
		if (spec["http-buffer-request"] == "enabled") != o.Body {
			t.Errorf("%+v: http-buffer-request %v", o, spec["http-buffer-request"])
		}
		// wait-for-body: the controller dereferences at-least.
		rules, _ := spec["http_response_rule_list"].([]any)
		for _, r := range rules {
			if m := r.(map[string]any); m["type"] == "wait-for-body" && m["wait_at_least"] != int64(0) {
				t.Errorf("wait-for-body without at-least: %v", m)
			}
		}
	}
}

func haproxyCRScheme() *runtime.Scheme {
	s := haproxyScheme()
	for _, gvk := range []schema.GroupVersionKind{HAProxyBackendGVK, HAProxyGlobalGVK} {
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		s.AddKnownTypeWithName(gvk.GroupVersion().WithKind(gvk.Kind+"List"), &unstructured.UnstructuredList{})
	}
	return s
}

func haproxy34Pod(name string, args ...string) *corev1.Pod {
	pod := haproxyControllerPod(name, args...)
	pod.Spec.Containers[0].Image = "haproxytech/kubernetes-ingress:3.4.1"
	return pod
}

func getBackend(ctx context.Context, c client.Client, ns, name string) (*unstructured.Unstructured, error) {
	b := &unstructured.Unstructured{}
	b.SetGroupVersionKind(HAProxyBackendGVK)
	return b, c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, b)
}

// Controller 3.4: the protected Ingress gets the operator's Backend custom
// resource, which it names in cr-backend, with its own backend; an
// Ingress wired with a snippet before (the controller upgraded from 3.2)
// loses it; the Ingress's backend annotations, which don't apply, are
// noted; an Ingress naming its own Backend can't be wired, and says so;
// unprotected, the Ingress is as it was and the Backend gone.
func TestHAProxyWireBackendCR(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}, {Kind: "Ingress", Name: "theirs"}},
	}}
	web := haproxyIngress("web", "haproxy")
	web.UID = "web-uid"
	web.Annotations = map[string]string{"haproxy.org/timeout-server": "30s", HAProxyStandaloneAnnotation: "false"}
	theirs := haproxyIngress("theirs", "haproxy")
	theirs.Annotations = map[string]string{"cr-backend": "shop/mine"}
	pod := haproxyControllerPod("hap-1")
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).WithObjects(class, policy, pod, web, theirs).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	webT := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	theirsT := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "theirs"}}
	targets := map[Target]bool{webT: true, theirsT: true}
	wire := func(targets map[Target]bool) *Result {
		t.Helper()
		res, err := h.Wire(ctx, targets, false)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	ingress := func(name string) *networkingv1.Ingress {
		var ing networkingv1.Ingress
		if err := c.Get(ctx, types.NamespacedName{Namespace: "shop", Name: name}, &ing); err != nil {
			t.Fatal(err)
		}
		return &ing
	}

	// Wired with a snippet on 3.2.
	if s := wire(targets).Targets[webT]; !s.Wired || s.Failed != "" {
		t.Fatalf("3.2: %+v", s)
	}
	if a := ingress("web").Annotations; !strings.Contains(a[HAProxySnippetAnnotation], "filter spoe") || a[HAProxyCRBackendAnnotation] != "" {
		t.Fatalf("3.2: %v", a)
	}
	// The controller upgraded to 3.4.
	if err := c.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, haproxy34Pod("hap-2")); err != nil {
		t.Fatal(err)
	}
	res := wire(targets)
	s := res.Targets[webT]
	if !s.Wired || s.Failed != "" || s.VersionUnsupported != "" || !strings.Contains(s.Unverified, "unverified") {
		t.Fatalf("3.4: %+v", s)
	}
	if !strings.Contains(s.Note, "haproxy.org/timeout-server don't apply") || strings.Contains(s.Note, "standalone") {
		t.Errorf("3.4: the ignored annotations' note %q", s.Note)
	}
	a := ingress("web").Annotations
	if a[HAProxyCRBackendAnnotation] != "shop/inkwall-waf-web" || a[HAProxyStandaloneAnnotation] != "true" || a[HAProxyWiredAnnotation] != "false" {
		t.Fatalf("3.4: annotations %v", a)
	}
	if _, ok := a[HAProxySnippetAnnotation]; ok {
		t.Errorf("3.4: the snippet stays: %v", a)
	}
	b, err := getBackend(ctx, c, "shop", "inkwall-waf-web")
	if err != nil {
		t.Fatal(err)
	}
	spec, _, _ := unstructured.NestedMap(b.Object, "spec")
	if want := HAProxyBackendSpec(HAProxySnippetOptions{Body: true, Block: true}); !covers(spec, want) {
		t.Errorf("Backend spec %v", spec)
	}
	if refs := b.GetOwnerReferences(); len(refs) != 1 || refs[0].Kind != "Ingress" || refs[0].Name != "web" || refs[0].UID != "web-uid" || !isManaged(b) {
		t.Errorf("Backend owner %v, labels %v", refs, b.GetLabels())
	}
	// Wiring again changes nothing.
	rv, ingRV := b.GetResourceVersion(), ingress("web").ResourceVersion
	wire(targets)
	if b, _ := getBackend(ctx, c, "shop", "inkwall-waf-web"); b.GetResourceVersion() != rv || ingress("web").ResourceVersion != ingRV {
		t.Error("wired again: changed")
	}
	// Another setting: the Backend follows.
	policy.Spec.Mode = wafv1alpha1.PolicyDetect
	if err := c.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	wire(targets)
	b, _ = getBackend(ctx, c, "shop", "inkwall-waf-web")
	spec, _, _ = unstructured.NestedMap(b.Object, "spec")
	if raw, _ := json.Marshal(spec); strings.Contains(string(raw), "!{ var(txn.inkwall.action) -m found }") || strings.Contains(string(raw), "3 259") {
		t.Errorf("Detect mode: %s", raw)
	}

	// Its own Backend: not wired, said why.
	if s := res.Targets[theirsT]; s.Wired || !strings.Contains(s.Failed, "names its own Backend custom resource (cr-backend: shop/mine)") {
		t.Errorf("theirs: %+v", s)
	}
	if a := ingress("theirs").Annotations; len(a) != 1 || a["cr-backend"] != "shop/mine" {
		t.Errorf("theirs changed: %v", a)
	}

	// Unprotected: as it was, the Backend gone.
	wire(map[Target]bool{})
	if a := ingress("web").Annotations; len(a) != 2 || a["haproxy.org/timeout-server"] != "30s" || a[HAProxyStandaloneAnnotation] != "false" {
		t.Errorf("unwired: %v", a)
	}
	if _, err := getBackend(ctx, c, "shop", "inkwall-waf-web"); err == nil {
		t.Error("the Backend stays")
	}

	// Unwire (helm uninstall) does the same.
	wire(targets)
	n, err := h.Unwire(ctx, c)
	if err != nil || n["Ingress (HAProxy)"] != 1 || n["Backend (HAProxy)"] != 1 {
		t.Fatalf("unwire: %v %v", n, err)
	}
	if a := ingress("web").Annotations; len(a) != 2 {
		t.Errorf("after unwire: %v", a)
	}
}

// A controller whose release the operator can't tell: without the Backend
// CRD, the protected Ingress stays as it is, and the policy is
// Programmed=False (ProxyVersionUnsupported), naming the pod and what to
// do; the pods' annotation then says it, and the Ingress is wired. With the
// CRD, it is wired with the Backend, and the note says why.
func TestHAProxyVersionUnsupported(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
	}}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	for _, withCRD := range []bool{false, true} {
		pod := haproxyControllerPod("hap-1")
		pod.Spec.Containers[0].Image = "mirror.example.com/kubernetes-ingress@sha256:0123"
		b := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).WithObjects(class, policy.DeepCopy(), pod, haproxyIngress("web", "haproxy"))
		if !withCRD {
			b = b.WithInterceptorFuncs(noBackendCRD)
		}
		c := b.Build()
		h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
		res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		s := res.Targets[web]
		var ing networkingv1.Ingress
		_ = c.Get(ctx, web.Key, &ing)
		if withCRD {
			if !s.Wired || s.VersionUnsupported != "" || !strings.Contains(s.Note, "reads since 3.2") || ing.Annotations[HAProxyCRBackendAnnotation] != "shop/inkwall-waf-web" {
				t.Errorf("with the CRD: %+v, annotations %v", s, ing.Annotations)
			}
			continue
		}
		if s.Wired || s.VersionUnsupported == "" {
			t.Fatalf("%+v", s)
		}
		if len(ing.Annotations) != 0 {
			t.Errorf("the Ingress changed: %v", ing.Annotations)
		}
		st, reason, msg := programmed(policy, &report{kinds: []schema.GroupKind{ingressKind}, results: []*Result{res}})
		for _, want := range []string{"haproxy-controller/hap-1", "mirror.example.com/kubernetes-ingress@sha256:0123", "3.1 to 3.2", "3.4 and later", HAProxyVersionAnnotation} {
			if st != metav1.ConditionFalse || reason != ReasonProxyVersionUnsupported || !strings.Contains(msg, want) {
				t.Errorf("%s %s %q lacks %q", st, reason, msg, want)
			}
		}
		// It says its release.
		pod.Annotations[HAProxyVersionAnnotation] = "3.2.20"
		if err := c.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		if res, err = h.Wire(ctx, map[Target]bool{web: true}, false); err != nil || !res.Targets[web].Wired {
			t.Fatalf("with the annotation: %+v %v", res.Targets[web], err)
		}
		_ = c.Get(ctx, web.Key, &ing)
		if !strings.Contains(ing.Annotations[HAProxySnippetAnnotation], "filter spoe") {
			t.Errorf("not wired with the snippet: %v", ing.Annotations)
		}
	}
}

// A pod anyone can make with the controller's labels, in another
// namespace or not owned by a ReplicaSet, says nothing of how the
// controller is wired: a `latest` one, or one with a forged release
// annotation, leaves a 3.2 controller wired with snippets.
func TestHAProxyForgedPod(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
	}}
	latest := haproxyControllerPod("latest")
	latest.Namespace = "tenant"
	latest.Spec.Containers[0].Image = "haproxytech/kubernetes-ingress:latest"
	forged := haproxyControllerPod("forged")
	forged.Namespace = "tenant"
	forged.Annotations[HAProxyVersionAnnotation] = "3.4.1"
	byHand := haproxyControllerPod("by-hand")
	byHand.OwnerReferences = nil
	byHand.Annotations[HAProxyVersionAnnotation] = "3.4.1"
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).
		WithObjects(class, policy, haproxyControllerPod("hap-1"), latest, forged, byHand, haproxyIngress("web", "haproxy")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector(), Namespaces: integrations.Namespaces{"haproxy-controller"}}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Targets[web]; !s.Wired || s.VersionUnsupported != "" || s.Failed != "" {
		t.Fatalf("%+v", s)
	}
	var ing networkingv1.Ingress
	_ = c.Get(ctx, web.Key, &ing)
	if !strings.Contains(ing.Annotations[HAProxySnippetAnnotation], "filter spoe") || ing.Annotations[HAProxyCRBackendAnnotation] != "" {
		t.Errorf("not the snippet: %v", ing.Annotations)
	}
}

// Two controllers, of two IngressClasses, at 3.2 and 3.4: each one's
// Ingresses are wired as its own release asks, and probed on its own pods.
func TestHAProxyTwoControllers(t *testing.T) {
	ctx := context.Background()
	legacy := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "legacy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/legacy"}}
	current := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "current"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/current"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "old"}, {Kind: "Ingress", Name: "new"}},
	}}
	old := haproxyControllerPod("hap-32", "--ingress.class=legacy")
	old.Status.PodIP = "10.0.0.32"
	next := haproxy34Pod("hap-34", "--ingress.class=current")
	next.Status.PodIP = "10.0.0.34"
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).
		WithObjects(legacy, current, policy, old, next, haproxyIngress("old", "legacy"), haproxyIngress("new", "current")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector(), Prober: &Prober{}}
	oldT := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "old"}}
	newT := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "new"}}
	res, err := h.Wire(ctx, map[Target]bool{oldT: true, newT: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range []Target{oldT, newT} {
		if s := res.Targets[tg]; !s.Wired || s.Failed != "" || s.VersionUnsupported != "" {
			t.Errorf("%s: %+v", tg.Key.Name, s)
		}
	}
	get := func(name string) map[string]string {
		var ing networkingv1.Ingress
		_ = c.Get(ctx, types.NamespacedName{Namespace: "shop", Name: name}, &ing)
		return ing.Annotations
	}
	if a := get("old"); !strings.Contains(a[HAProxySnippetAnnotation], "filter spoe") || a[HAProxyCRBackendAnnotation] != "" {
		t.Errorf("3.2's Ingress: %v", a)
	}
	if a := get("new"); a[HAProxyCRBackendAnnotation] != "shop/inkwall-waf-new" || a[HAProxySnippetAnnotation] != "" {
		t.Errorf("3.4's Ingress: %v", a)
	}
	// Each is probed on its controller's pods only.
	h.Prober.mu.Lock()
	jobs := h.Prober.jobs[integrations.HAProxy.Name]
	h.Prober.mu.Unlock()
	for _, j := range jobs {
		want := map[string]string{"old": "10.0.0.32", "new": "10.0.0.34"}[j.Route.Key.Name]
		if len(j.Pods) != 1 || j.Pods[0].IP != want {
			t.Errorf("%s probed on %+v", j.Route.Key.Name, j.Pods)
		}
	}
}

// On 3.4 an Ingress whose Service names a Backend of its own isn't wired:
// the controller would take the Service's over the operator's.
func TestHAProxyServiceCRBackend(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
	}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "app", Annotations: map[string]string{"haproxy.org/cr-backend": "shop/theirs"}}}
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).WithObjects(class, policy, svc, haproxy34Pod("hap-1"), haproxyIngress("web", "haproxy")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Targets[web]; s.Wired || !strings.Contains(s.Failed, "Service app (haproxy.org/cr-backend: shop/theirs)") {
		t.Fatalf("%+v", s)
	}
	var ing networkingv1.Ingress
	_ = c.Get(ctx, web.Key, &ing)
	if len(ing.Annotations) != 0 {
		t.Errorf("wired: %v", ing.Annotations)
	}
	if _, err := getBackend(ctx, c, "shop", "inkwall-waf-web"); err == nil {
		t.Error("a Backend")
	}
	// Removed from the Service: wired.
	svc.Annotations = nil
	if err := c.Update(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if res, err = h.Wire(ctx, map[Target]bool{web: true}, false); err != nil || !res.Targets[web].Wired {
		t.Fatalf("%+v %v", res.Targets[web], err)
	}
}

// noBackendCRD makes a fake client answer as an API server without the
// controller's Backend CRD.
var noBackendCRD = interceptor.Funcs{
	Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if u, ok := obj.(*unstructured.Unstructured); ok && u.GroupVersionKind() == HAProxyBackendGVK {
			return &meta.NoKindMatchError{GroupKind: HAProxyBackendGVK.GroupKind(), SearchedVersions: []string{"v3"}}
		}
		return c.Get(ctx, key, obj, opts...)
	},
	List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if u, ok := list.(*unstructured.UnstructuredList); ok && u.GroupVersionKind().Group == HAProxyBackendGVK.Group {
			return &meta.NoKindMatchError{GroupKind: HAProxyBackendGVK.GroupKind()}
		}
		return c.List(ctx, list, opts...)
	},
}

// Without the controller's Backend CRD, a 3.4 controller's Ingress isn't
// wired, and the status says to install it.
func TestHAProxyBackendCRDMissing(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
	}}
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).WithObjects(class, policy, haproxy34Pod("hap-1"), haproxyIngress("web", "haproxy")).
		WithInterceptorFuncs(noBackendCRD).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if s := res.Targets[web]; s.Wired || !strings.Contains(s.Failed, "backends.ingress.v3.haproxy.org") {
		t.Fatalf("%+v", s)
	}
}

// On 3.4 HAProxy's buffer is the Global custom resource's the controller
// ConfigMap names (cr-global): its note says to raise it there.
func TestHAProxyGlobalBuffer(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}, Body: &wafv1alpha1.BodySpec{MaxBytes: new(int64(100000))},
	}}
	// A snippet 3.4 ignores.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: "hap"}, Data: map[string]string{"global-config-snippet": "tune.bufsize 128k\n"}}
	global := &unstructured.Unstructured{}
	global.SetGroupVersionKind(HAProxyGlobalGVK)
	global.SetNamespace("haproxy-controller")
	global.SetName("tuned")
	global.Object["spec"] = map[string]any{"tune_buffer_options": map[string]any{"bufsize": int64(131072)}, "tune_options": map[string]any{"maxrewrite": int64(2048)}}
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).
		WithObjects(class, policy, cm, global, haproxy34Pod("hap-1", "--configmap=haproxy-controller/hap"), haproxyIngress("web", "haproxy")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	note := func() string {
		res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		return res.Targets[web].Note
	}
	if n := note(); !strings.Contains(n, "tune.bufsize 16384, HAProxy's default") || !strings.Contains(n, "tune_buffer_options.bufsize in the Global custom resource") {
		t.Errorf("note %q", n)
	}
	cm.Data["cr-global"] = "tuned"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if n := note(); n != "" {
		t.Errorf("with a 128k buffer: %q", n)
	}
	if b := h.globalBuffer(ctx, "haproxy-controller", "haproxy-controller/tuned"); b.bufsize != 131072 || b.maxrewrite != 2048 || !strings.Contains(b.source, "Global") {
		t.Errorf("%+v", b)
	}
	if b := h.globalBuffer(ctx, "haproxy-controller", "elsewhere/none"); b.bufsize != haproxyDefaultBufsize {
		t.Errorf("a missing Global: %+v", b)
	}
}

// A failed probe on an Ingress wired with the operator's Backend says that
// HAProxy may have rejected it, and where to look: the controller then
// builds the backend without it, so without the filter.
func TestHAProxyBackendRejected(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
	}}
	c := fake.NewClientBuilder().WithScheme(haproxyCRScheme()).WithObjects(class, policy, haproxy34Pod("hap-1"), haproxyIngress("web", "haproxy")).Build()
	key := bytes.Repeat([]byte{3}, haproxyprobe.KeySize)
	prober := &Prober{
		Key: func(context.Context) ([]byte, error) { return key, nil },
		// The app answers: the filter isn't there.
		Do: func(context.Context, ProbePod, ProbeTarget, *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector(), Prober: prober}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	wire := func() TargetState {
		t.Helper()
		res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		return res.Targets[web]
	}
	if s := wire(); strings.Contains(s.Unverified, "sets aside") {
		t.Errorf("before a probe: %q", s.Unverified)
	}
	prober.Run(ctx)
	s := wire()
	for _, want := range []string{"HTTP 404", "Backend shop/inkwall-waf-web in the controller's log", "haproxy_rejected_custom_resource_generation"} {
		if !strings.Contains(s.Unverified, want) {
			t.Errorf("%q lacks %q", s.Unverified, want)
		}
	}
}
