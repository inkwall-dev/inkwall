// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"slices"
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
	closed := HAProxySnippet(HAProxySnippetOptions{Body: true})
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
	open := HAProxySnippet(HAProxySnippetOptions{FailOpen: true})
	if strings.Contains(open, "if !{ var(txn.inkwall.action) -m found }") || strings.Contains(open, "http-buffer-request") {
		t.Errorf("failing open, without bodies:\n%s", open)
	}
	for _, s := range []string{closed, open} {
		if strings.Contains(s, "http-response") || strings.Contains(s, "inkwall-responses") {
			t.Errorf("responses not inspected, yet response rules:\n%s", s)
		}
	}
	// Responses: the agent's scope that tells the engine they come, the
	// request's Accept-Encoding removed, the body waited for, the
	// response sent, and the rules that replace it.
	resp := HAProxySnippet(HAProxySnippetOptions{Body: true, Responses: true})
	for _, want := range []string{
		"filter spoe engine inkwall-responses config " + injection.HAProxySPOEConf,
		"http-request del-header accept-encoding",
		"http-response wait-for-body time 2s",
		"http-response send-spoe-group inkwall-responses inkwall-response",
		`http-response return status 502 content-type text/plain lf-string "Bad Gateway. Request ID: %[var(txn.inkwall.request_id)]"`,
		"{ var(txn.inkwall.response_failure) -m str closed }",
		"if { var(txn.inkwall.response_status) -m int 503 }",
		"http-response return status 403",
	} {
		if !strings.Contains(resp, want) {
			t.Errorf("responses snippet lacks %q:\n%s", want, resp)
		}
	}
	if strings.Contains(resp, "engine inkwall config") {
		t.Errorf("both scopes:\n%s", resp)
	}
	// The response is sent before the rules that act on its verdict.
	if strings.Index(resp, "send-spoe-group") > strings.Index(resp, "http-response return") {
		t.Error("a response rule before the response is sent")
	}
	// Detect mode: nothing on SPOE's error.
	for _, s := range []string{closed, open, resp} {
		if strings.Contains(s, "var(txn.inkwall.error)") {
			t.Errorf("detect mode, yet a rule on SPOE's error:\n%s", s)
		}
	}
}

// In Block mode, a request or a response HAProxy can't fit in one SPOE frame
// (txn.inkwall.error 3) is handled as oversized, whatever the failure mode:
// 413 for a request, 502 for a response, before the fail-closed rules.
func TestHAProxySnippetFrameTooBig(t *testing.T) {
	const (
		request  = `http-request deny deny_status 413 if { var(txn.inkwall.error) -m int 3 259 }`
		response = `http-response return status 502 content-type text/plain lf-string "Bad Gateway. Request ID: %[var(txn.inkwall.request_id)]" hdr x-request-id "%[var(txn.inkwall.request_id)]" if { var(txn.inkwall.responses) -m found } { var(txn.inkwall.error) -m int 3 259 }`
	)
	for _, o := range []HAProxySnippetOptions{
		{Block: true, Body: true},
		{Block: true, Body: true, FailOpen: true},
		{Block: true, Body: true, Responses: true},
		{Block: true, Body: true, FailOpen: true, Responses: true},
	} {
		s := HAProxySnippet(o)
		i := strings.Index(s, request)
		if i < 0 {
			t.Errorf("%+v: no 413 rule:\n%s", o, s)
			continue
		}
		if i < strings.Index(s, "status 299") {
			t.Errorf("%+v: the 413 rule is before the probe's answer", o)
		}
		if j := strings.Index(s, "deny_status 503 if !{"); j >= 0 && j < i {
			t.Errorf("%+v: the 413 rule is after the fail-closed rule", o)
		}
		if j := strings.Index(s, "http-request deny deny_status"); j < i {
			t.Errorf("%+v: the 413 rule is after another denial", o)
		}
		r := strings.Index(s, response)
		switch {
		case !o.Responses && r >= 0:
			t.Errorf("%+v: a response rule without responses", o)
		case o.Responses && r < 0:
			t.Errorf("%+v: no 502 rule for the response:\n%s", o, s)
		case o.Responses && r > strings.Index(s, "http-response return"):
			t.Errorf("%+v: the 502 rule is after another response rule", o)
		}
	}
}

// A route is in Block mode when one of its policies is.
func TestHAProxySettingsBlock(t *testing.T) {
	ing := types.NamespacedName{Namespace: "shop", Name: "web"}
	policy := func(name string, mode wafv1alpha1.PolicyMode) wafv1alpha1.WAFPolicy {
		return wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}, Spec: wafv1alpha1.WAFPolicySpec{
			Mode: mode, TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}}}
	}
	if s := haproxySettingsOf([]wafv1alpha1.WAFPolicy{policy("a", wafv1alpha1.PolicyDetect)}, ing); s.block {
		t.Error("Detect: block")
	}
	if s := haproxySettingsOf([]wafv1alpha1.WAFPolicy{policy("a", wafv1alpha1.PolicyDetect), policy("b", wafv1alpha1.PolicyBlock)}, ing); !s.block {
		t.Error("Detect and Block: not block")
	}
}

// A policy that inspects responses gets the response rules on its
// Ingress, and the result says HAProxy sends responses, only when every
// running controller pod's engine keeps requests for them
// (--response-messages): otherwise neither, and why, naming the pods.
func TestHAProxyWireResponses(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy-edge"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
		Responses: &wafv1alpha1.ResponsesSpec{Inspect: true},
	}}
	plain := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "q"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "other"}},
	}}
	ready := haproxyControllerPod("hap-1")
	c := fake.NewClientBuilder().WithScheme(haproxyScheme()).
		WithObjects(class, policy, plain, ready, haproxyIngress("web", "haproxy"), haproxyIngress("other", "haproxy")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	web, other := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "other"}}
	targets := map[Target]bool{web: true, other: true}
	snippet := func(tg Target) string {
		var ing networkingv1.Ingress
		_ = c.Get(ctx, tg.Key, &ing)
		return ing.Annotations[HAProxySnippetAnnotation]
	}

	res, err := h.Wire(ctx, targets, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Responses || res.ResponsesWhy != "" {
		t.Errorf("every pod ready: Responses %v, %q", res.Responses, res.ResponsesWhy)
	}
	if !strings.Contains(snippet(web), "-m found } { var(txn.inkwall.error) -m int 3 259 }") || !strings.Contains(snippet(other), "deny_status 413 if { var(txn.inkwall.error) -m int 3 259 }") {
		t.Errorf("Block mode, no rule for a message over one frame:\n%s\n%s", snippet(web), snippet(other))
	}
	if !strings.Contains(snippet(web), "send-spoe-group") {
		t.Errorf("web's snippet lacks the response rules:\n%s", snippet(web))
	}
	if s := snippet(other); strings.Contains(s, "http-response") || !strings.Contains(s, "engine inkwall config") {
		t.Errorf("other's policy doesn't inspect responses:\n%s", s)
	}

	// A pod whose engine was injected without the flag (before 0.6.0, or a
	// pinned older engine): no response rules anywhere, and why.
	old := haproxyControllerPod("hap-0")
	old.Spec.InitContainers[0].Args = slices.DeleteFunc(old.Spec.InitContainers[0].Args, func(a string) bool { return a == injection.ResponseMessagesFlag })
	if err := c.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	res, err = h.Wire(ctx, targets, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Responses || !strings.Contains(res.ResponsesWhy, "haproxy-controller/hap-0") || !strings.Contains(res.ResponsesWhy, "restart") {
		t.Errorf("a pod not ready: Responses %v, %q", res.Responses, res.ResponsesWhy)
	}
	if s := snippet(web); strings.Contains(s, "http-response") || !strings.Contains(s, "engine inkwall config") {
		t.Errorf("response rules with a pod not ready:\n%s", s)
	}
}

// The user's own snippet lines stay, after the operator's; wiring twice
// changes nothing; unwiring restores the user's annotations.
func TestHAProxyAnnotate(t *testing.T) {
	ctx := context.Background()
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", Annotations: map[string]string{
		HAProxySnippetAnnotation: "http-request set-header X-Mine 1\n", HAProxyStandaloneAnnotation: "false",
	}}}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(ing).Build()
	ours := HAProxySnippet(HAProxySnippetOptions{Body: true})
	if err := annotateHAProxy(ctx, c, ing, ours); err != nil {
		t.Fatal(err)
	}
	a := ing.Annotations
	if a[HAProxyStandaloneAnnotation] != "true" || !strings.HasPrefix(a[HAProxySnippetAnnotation], ours+"\n") ||
		!strings.HasSuffix(a[HAProxySnippetAnnotation], "http-request set-header X-Mine 1\n") || a[HAProxyWiredAnnotation] != "false" {
		t.Fatalf("annotations %v", a)
	}
	rv := ing.ResourceVersion
	if err := annotateHAProxy(ctx, c, ing, ours); err != nil || ing.ResourceVersion != rv {
		t.Fatalf("wired again: %v, resourceVersion %s -> %s", err, rv, ing.ResourceVersion)
	}
	// Another mode: the operator's part is replaced, the user's kept.
	if err := annotateHAProxy(ctx, c, ing, HAProxySnippet(HAProxySnippetOptions{FailOpen: true})); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(ing.Annotations[HAProxySnippetAnnotation], haproxySnippetBegin); n != 1 {
		t.Fatalf("%d operator parts", n)
	}
	if err := annotateHAProxy(ctx, c, ing, ""); err != nil {
		t.Fatal(err)
	}
	// Exactly as it was, its final newline (a YAML block's) included.
	if a := ing.Annotations; a[HAProxySnippetAnnotation] != "http-request set-header X-Mine 1\n" || a[HAProxyStandaloneAnnotation] != "false" {
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
	injection.Inject(pod, injection.Sidecar{Image: "engine", SocketDir: integrations.HAProxySocketDir, ResponseMessages: true})
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
		&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy-edge"}},
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
	prober := &Prober{
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
	// Responses: ResponsesNotInspected with the integration's why, until
	// HAProxy sends them; then Programmed.
	resp := p.DeepCopy()
	resp.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true}
	r := rep(TargetState{Wired: true}, pod)
	r.results[1].ResponsesWhy = "HAProxy pod haproxy-controller/hap-0 runs an engine without --response-messages: restart it"
	if st, reason, msg := programmed(resp, r); st != metav1.ConditionFalse || reason != ReasonResponsesNotInspected ||
		!strings.Contains(msg, "restart it") || strings.Contains(msg, "Envoy Gateway") {
		t.Errorf("responses not yet sent: %s %s %s", st, reason, msg)
	}
	r.results[1].Responses, r.results[1].ResponsesWhy = true, ""
	if st, reason, msg := programmed(resp, r); st != metav1.ConditionTrue {
		t.Errorf("responses sent: %s %s %s", st, reason, msg)
	}
	// Streams, event by event (#323): HAProxy doesn't send a streamed
	// body, so the policy doesn't claim its events are inspected.
	streams := resp.DeepCopy()
	streams.Spec.Responses.Streams = wafv1alpha1.StreamsInspect
	if st, reason, msg := programmed(streams, r); st != metav1.ConditionFalse || reason != ReasonResponsesNotInspected ||
		!strings.Contains(msg, "HAProxy doesn't send streamed responses' bodies") || !strings.Contains(msg, "streams: Skip") {
		t.Errorf("streams through HAProxy: %s %s %s", st, reason, msg)
	}
	streams.Spec.Responses.Streams = wafv1alpha1.StreamsSkip
	if st, reason, msg := programmed(streams, r); st != metav1.ConditionTrue {
		t.Errorf("streams skipped through HAProxy: %s %s %s", st, reason, msg)
	}
	// A pod without the engine: its traffic isn't inspected, whatever the
	// probe says of the others.
	bare := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: "hap-0"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	if _, reason, _ := programmed(p, rep(TargetState{Wired: true}, pod, bare)); reason != ReasonPendingRestart {
		t.Errorf("a pod without the engine: %s", reason)
	}
}

// tune.bufsize and tune.maxrewrite from the controller ConfigMap's
// global-config-snippet, with HAProxy's size units; HAProxy's defaults
// when unset.
func TestHAProxyBuffer(t *testing.T) {
	for _, c := range []struct {
		snippet             string
		bufsize, maxrewrite int64
	}{
		{"", 16384, 1024},
		{"maxconn 1000\n", 16384, 1024},
		{"tune.bufsize 65536\n", 65536, 1024},
		{"  tune.bufsize   128k  # bodies\n", 128 << 10, 1024},
		{"tune.bufsize 1m\ntune.maxrewrite 4096\n", 1 << 20, 4096},
		{"tune.bufsize 1G", 1 << 30, 1024},
		// maxrewrite is at most half the buffer, as HAProxy caps it.
		{"tune.bufsize 1024", 1024, 512},
		// The last one wins, as in HAProxy; an unreadable one is ignored.
		{"tune.bufsize 32768\ntune.bufsize 49152", 49152, 1024},
		{"tune.bufsize lots", 16384, 1024},
		{"# tune.bufsize 99999", 16384, 1024},
	} {
		b := parseHAProxyBuffer(c.snippet)
		if b.bufsize != c.bufsize || b.maxrewrite != c.maxrewrite {
			t.Errorf("%q: bufsize %d maxrewrite %d, want %d %d", c.snippet, b.bufsize, b.maxrewrite, c.bufsize, c.maxrewrite)
		}
	}
	if got := parseHAProxyBuffer("").visible(); got != 16384-1024 {
		t.Errorf("visible %d", got)
	}
}

// A policy inspecting more of a body than HAProxy's buffer lets the engine
// see gets a note, from the ConfigMap the controller names, which says on
// Programmed without changing it.
func TestHAProxyBufferNote(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}, Body: &wafv1alpha1.BodySpec{MaxBytes: new(int64(100000))},
	}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: "hap"}, Data: map[string]string{}}
	c := fake.NewClientBuilder().WithScheme(haproxyScheme()).
		WithObjects(class, policy, cm, haproxyControllerPod("hap-1", "--configmap=haproxy-controller/hap"), haproxyIngress("web", "haproxy")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	note := func() string {
		res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		return res.Targets[web].Note
	}
	if n := note(); !strings.Contains(n, "tune.bufsize 16384") || !strings.Contains(n, "about 15360 bytes") || !strings.Contains(n, "body.maxBytes (100000)") {
		t.Errorf("note %q", n)
	}
	cm.Data["global-config-snippet"] = "tune.bufsize 128k\n"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if n := note(); n != "" {
		t.Errorf("with a 128k buffer: %q", n)
	}

	// On Programmed, True stays True with the note.
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"},
		Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}}}}
	pod := *haproxyControllerPod("hap-1")
	rep := &report{kinds: []schema.GroupKind{ingressKind}, results: []*Result{
		{Proxy: "HAProxy", Targets: map[Target]TargetState{web: {Wired: true, Note: "the buffer note"}}, Pods: []corev1.Pod{pod}},
	}}
	if st, reason, msg := programmed(p, rep); st != metav1.ConditionTrue || reason != ReasonProgrammed || !strings.HasSuffix(msg, "; the buffer note") {
		t.Errorf("%s %s %s", st, reason, msg)
	}
}

// A policy that inspects responses, with responses.maxBytes over what
// HAProxy's buffer lets the engine see of a response, gets a note naming
// both, as for request bodies; once the buffer is raised, none.
func TestHAProxyResponseBufferNote(t *testing.T) {
	ctx := context.Background()
	class := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "haproxy"}, Spec: networkingv1.IngressClassSpec{Controller: "haproxy.org/ingress-controller/haproxy"}}
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "web"}},
		Body:       &wafv1alpha1.BodySpec{MaxBytes: new(int64(8192))},
		Responses:  &wafv1alpha1.ResponsesSpec{Inspect: true, MaxBytes: new(int64(100000))},
	}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "haproxy-controller", Name: "hap"}, Data: map[string]string{}}
	c := fake.NewClientBuilder().WithScheme(haproxyScheme()).
		WithObjects(class, policy, cm, haproxyControllerPod("hap-1", "--configmap=haproxy-controller/hap"), haproxyIngress("web", "haproxy")).Build()
	h := &HAProxy{Client: c, APIReader: c, Pods: integrationsSelector()}
	web := Target{Kind: ingressKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	note := func() string {
		res, err := h.Wire(ctx, map[Target]bool{web: true}, false)
		if err != nil {
			t.Fatal(err)
		}
		return res.Targets[web].Note
	}
	n := note()
	for _, want := range []string{"tune.bufsize 16384", "about 15360 bytes of a response", "responses.maxBytes (100000)", "responses.onOversize"} {
		if !strings.Contains(n, want) {
			t.Errorf("note lacks %q: %q", want, n)
		}
	}
	// body.maxBytes (8192) fits the buffer: the note is about responses only.
	if strings.Contains(n, "body.maxBytes") {
		t.Errorf("note names body.maxBytes: %q", n)
	}
	// Both over the buffer: one note naming both.
	policy.Spec.Body.MaxBytes = new(int64(50000))
	if err := c.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if n := note(); !strings.Contains(n, "body.maxBytes (50000)") || !strings.Contains(n, "responses.maxBytes (100000)") || strings.Count(n, "tune.bufsize 16384") != 1 {
		t.Errorf("both: %q", n)
	}
	cm.Data["global-config-snippet"] = "tune.bufsize 128k\n"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if n := note(); n != "" {
		t.Errorf("with a 128k buffer: %q", n)
	}
}
