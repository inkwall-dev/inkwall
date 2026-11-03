// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

func TestHAProxySnippet(t *testing.T) {
	closed := HAProxySnippet(false, true)
	for _, want := range []string{
		"option http-buffer-request",
		"filter spoe engine inkwall config " + injection.HAProxySPOEConf,
		"http-request return status 299 hdr x-inkwall-probe",
		"http-request deny deny_status 503 if !{ var(txn.inkwall.action) -m found }",
		"http-request deny deny_status 403",
	} {
		if !strings.Contains(closed, want) {
			t.Errorf("snippet lacks %q:\n%s", want, closed)
		}
	}
	// The probe's answer comes first, before any denial.
	if strings.Index(closed, "status 299") > strings.Index(closed, "deny_status") {
		t.Error("the probe's rule is after a denial")
	}
	open := HAProxySnippet(true, false)
	if strings.Contains(open, "if !{ var(txn.inkwall.action) -m found }") || strings.Contains(open, "http-buffer-request") {
		t.Errorf("failing open, without bodies:\n%s", open)
	}
}

// The user's own snippet lines stay, after the operator's; wiring twice
// changes nothing; unwiring restores the user's annotations.
func TestHAProxyAnnotate(t *testing.T) {
	ctx := context.Background()
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", Annotations: map[string]string{
		HAProxySnippetAnnotation: "http-request set-header X-Mine 1", HAProxyStandaloneAnnotation: "false",
	}}}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(ing).Build()
	ours := HAProxySnippet(false, true)
	if err := annotateHAProxy(ctx, c, ing, ours); err != nil {
		t.Fatal(err)
	}
	a := ing.Annotations
	if a[HAProxyStandaloneAnnotation] != "true" || !strings.HasPrefix(a[HAProxySnippetAnnotation], ours+"\n") ||
		!strings.HasSuffix(a[HAProxySnippetAnnotation], "http-request set-header X-Mine 1") || a[HAProxyWiredAnnotation] != "false" {
		t.Fatalf("annotations %v", a)
	}
	rv := ing.ResourceVersion
	if err := annotateHAProxy(ctx, c, ing, ours); err != nil || ing.ResourceVersion != rv {
		t.Fatalf("wired again: %v, resourceVersion %s -> %s", err, rv, ing.ResourceVersion)
	}
	// Another mode: the operator's part is replaced, the user's kept.
	if err := annotateHAProxy(ctx, c, ing, HAProxySnippet(true, false)); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(ing.Annotations[HAProxySnippetAnnotation], haproxySnippetBegin); n != 1 {
		t.Fatalf("%d operator parts", n)
	}
	if err := annotateHAProxy(ctx, c, ing, ""); err != nil {
		t.Fatal(err)
	}
	if a := ing.Annotations; a[HAProxySnippetAnnotation] != "http-request set-header X-Mine 1" || a[HAProxyStandaloneAnnotation] != "false" {
		t.Fatalf("unwired: %v", a)
	}
	if _, ok := ing.Annotations[HAProxyWiredAnnotation]; ok {
		t.Fatal("still marked wired")
	}
}

func haproxyScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	return s
}

func haproxyControllerPod(name string, args ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: name, UID: types.UID(name),
			Labels: map[string]string{"app.kubernetes.io/name": "kubernetes-ingress"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: injection.HAProxyContainer, Args: args,
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.0.1"},
	}
	injection.Inject(pod, injection.Sidecar{Image: "engine", SocketDir: integrations.HAProxySocketDir})
	injection.InjectHAProxy(pod)
	return pod
}

func haproxyIngress(name, class string) *networkingv1.Ingress {
	prefix := networkingv1.PathTypePrefix
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name},
		Spec: networkingv1.IngressSpec{IngressClassName: &class, Rules: []networkingv1.IngressRule{{
			Host: name + ".example.com",
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/api", PathType: &prefix,
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "app", Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
}

// Wire: a protected Ingress of the controller's class is wired and stays
// Unverified until the probe answers on every pod; another class's isn't
// HAProxy's; a pod that ignores backend snippets fails it.
func TestHAProxyWire(t *testing.T) {
	ctx := context.Background()
	classes := []client.Object{
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: integrations.HAProxy.Controller}},
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "traefik"}, Spec: networkingv1.IngressClassSpec{Controller: integrations.Traefik.Controller}},
	}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}, {Kind: "Ingress", Name: "other"}},
	}}
	pod := haproxyControllerPod("hap-1")
	c := fake.NewClientBuilder().WithScheme(haproxyScheme()).
		WithObjects(append(classes, policy, pod, haproxyIngress("web", "haproxy"), haproxyIngress("other", "traefik"))...).Build()
	key := bytes.Repeat([]byte{3}, haproxyprobe.KeySize)
	engineUp := false
	prober := &HAProxyProber{
		Key: func(context.Context) ([]byte, error) { return key, nil },
		Do: func(_ context.Context, p ProbePod, target ProbeTarget, req *http.Request) (*http.Response, error) {
			if p.IP != "10.0.0.1" || p.HTTPPort != 8080 || target.Host != "web.example.com" || !strings.HasPrefix(req.URL.Path, "/api/.well-known/inkwall-probe/") {
				t.Errorf("probe to %+v %+v %s", p, target, req.URL)
			}
			if !engineUp {
				return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			answer, ok := haproxyprobe.Check(key, req.URL.RequestURI(), req.Host, req.Header.Get(haproxyprobe.Header))
			if !ok {
				t.Error("the probe's MAC doesn't check")
			}
			h := http.Header{}
			h.Set(haproxyprobe.Header, answer)
			return &http.Response{StatusCode: haproxyprobe.Status, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector(), Prober: prober}
	web, other := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "other"}}
	targets := map[Target]bool{web: true, other: true}

	wire := func() *Result {
		t.Helper()
		res, err := h.Wire(ctx, targets, false)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := wire()
	if s := res.Targets[web]; !s.Wired || s.Failed != "" || !strings.Contains(s.Unverified, "unverified") {
		t.Fatalf("web before a probe: %+v", s)
	}
	if s := res.Targets[other]; s.Unsupported == "" || s.Wired {
		t.Fatalf("another class's Ingress: %+v", s)
	}
	var ing networkingv1.Ingress
	_ = c.Get(ctx, web.Key, &ing)
	if !strings.Contains(ing.Annotations[HAProxySnippetAnnotation], "filter spoe") || ing.Annotations[HAProxyStandaloneAnnotation] != "true" {
		t.Fatalf("annotations %v", ing.Annotations)
	}

	// The probe reaches the app: evidence that the route isn't protected.
	prober.Run(ctx)
	if s := wire().Targets[web]; !strings.Contains(s.Unverified, "HTTP 404") || !strings.Contains(s.Unverified, "haproxy-controller/hap-1") {
		t.Fatalf("after a failed probe: %+v", s)
	}
	// The engine answers: proven.
	engineUp = true
	prober.results = map[string]probeResult{}
	prober.Run(ctx)
	if s := wire().Targets[web]; s.Unverified != "" || !s.Wired {
		t.Fatalf("after the engine answered: %+v", s)
	}

	// A pod that ignores backend snippets: failed, whatever the probe.
	_ = c.Delete(ctx, pod)
	if err := c.Create(ctx, haproxyControllerPod("hap-2", "--disable-config-snippets=backend")); err != nil {
		t.Fatal(err)
	}
	if s := wire().Targets[web]; !strings.Contains(s.Failed, "--disable-config-snippets=backend") {
		t.Fatalf("snippets disabled: %+v", s)
	}

	// Unprotected: unwired.
	if _, err := h.Wire(ctx, map[Target]bool{}, false); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(ctx, web.Key, &ing)
	if _, ok := ing.Annotations[HAProxySnippetAnnotation]; ok {
		t.Fatalf("still wired: %v", ing.Annotations)
	}
}

func integrationsSelector() labels.Selector {
	return labels.SelectorFromSet(integrations.HAProxy.PodSelector)
}

// Programmed: an unverified HAProxy route is Programmed=False
// (Unverified), after the sidecar checks; a proven one is True. Traefik's
// "not served" for the same Ingress doesn't count.
func TestHAProxyProgrammed(t *testing.T) {
	tg := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"},
		Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}}}
	pod := *haproxyControllerPod("hap-1")
	rep := func(s TargetState, pods ...corev1.Pod) *report {
		return &report{kinds: []schema.GroupKind{ingressKind}, results: []*Result{
			{Proxy: "Traefik", Targets: map[Target]TargetState{tg: {Unsupported: "served by HAProxy"}}},
			{Proxy: "HAProxy", Targets: map[Target]TargetState{tg: s}, Pods: pods},
		}}
	}
	if st, reason, msg := programmed(p, rep(TargetState{Wired: true, Unverified: "Ingress web is wired; the filter is unverified"}, pod)); st != metav1.ConditionFalse || reason != ReasonUnverified || !strings.Contains(msg, "unverified") {
		t.Errorf("unverified: %s %s %s", st, reason, msg)
	}
	if st, reason, msg := programmed(p, rep(TargetState{Wired: true}, pod)); st != metav1.ConditionTrue || msg != "1 Ingress(es) wired to the engine in HAProxy" {
		t.Errorf("proven: %s %s %s", st, reason, msg)
	}
	// A pod without the engine: its traffic isn't inspected, whatever the
	// probe says of the others.
	bare := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: "hap-0"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	if _, reason, _ := programmed(p, rep(TargetState{Wired: true}, pod, bare)); reason != ReasonPendingRestart {
		t.Errorf("a pod without the engine: %s", reason)
	}
}
