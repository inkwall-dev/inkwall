// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// envoyTestPod is a running Envoy pod of Gateway edge/<gw>, in Envoy
// Gateway's namespace, with the engine and the Envoy container's ports.
func envoyTestPod(name, gw, ip string, ports ...int32) corev1.Pod {
	envoy := corev1.Container{Name: envoyContainer}
	for _, p := range ports {
		envoy.Ports = append(envoy.Ports, corev1.ContainerPort{ContainerPort: p})
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "envoy-gateway-system", Name: name, UID: types.UID("uid-" + name),
			Labels: map[string]string{owningGatewayName: gw, owningGatewayNamespace: "edge"}},
		Spec:   corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}, Containers: []corev1.Container{envoy}},
		Status: corev1.PodStatus{PodIP: ip, Phase: corev1.PodRunning},
	}
}

// An Envoy Gateway HTTPRoute's probe (#604), as Istio's: per Gateway, a
// target per protected rule and HTTP or HTTPS listener the route attaches
// to, from the rule's first match the probe can make, with a host the
// route serves, over TLS for an HTTPS listener, on each running Envoy pod
// of the Gateway. Unlike Istio's, the port is the Envoy container's: Envoy
// Gateway shifts a privileged listener port by 10000, unless its pods
// serve the listener's own. Header and query match values aren't sent over
// TLS (#507, #511), and a listener that asks for a client certificate
// can't be probed.
func TestEnvoyRouteProbe(t *testing.T) {
	edge := types.NamespacedName{Namespace: "edge", Name: "edge"}
	internal := types.NamespacedName{Namespace: "edge", Name: "internal"}
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "edge", Generation: 3}, Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: ptr.To(gatewayv1.Hostname("*.example.com"))},
			{Name: "alt", Port: 8080, Protocol: gatewayv1.HTTPProtocolType, Hostname: ptr.To(gatewayv1.Hostname("other.example.org"))},
			{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
		},
	}}
	// A second Gateway whose EnvoyProxy keeps the listener ports
	// (useListenerPortAsContainerPort), on a port above 1024 too.
	gw2 := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "internal"}, Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "high", Port: 8443, Protocol: gatewayv1.HTTPSProtocolType},
		},
	}}
	deleted := envoyTestPod("edge-old", "edge", "10.0.0.6", 10080, 10443)
	deleted.Status.Phase = corev1.PodSucceeded
	st := &envoyState{
		gateways: map[types.NamespacedName]*gatewayv1.Gateway{edge: gw, internal: gw2},
		pods: []corev1.Pod{
			envoyTestPod("edge-1", "edge", "10.0.0.7", 10080, 10443, 19001),
			envoyTestPod("edge-2", "edge", "10.0.0.8", 10080, 10443, 19001),
			deleted,
			envoyTestPod("internal-1", "internal", "10.0.1.7", 80, 8443),
		},
	}
	exact, prefix, regex := gatewayv1.PathMatchExact, gatewayv1.PathMatchPathPrefix, gatewayv1.PathMatchRegularExpression
	headerExact := gatewayv1.HeaderMatchExact
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", Generation: 2}, Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{
			{Name: "edge", Namespace: ptr.To(gatewayv1.Namespace("edge"))},
			{Name: "internal", Namespace: ptr.To(gatewayv1.Namespace("edge"))},
		}},
		Hostnames: []gatewayv1.Hostname{"*.example.com"},
		Rules: []gatewayv1.HTTPRouteRule{
			{Name: ptr.To(gatewayv1.SectionName("api")), Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &regex, Value: ptr.To("/v[0-9]+")}},
				{Path: &gatewayv1.HTTPPathMatch{Type: &prefix, Value: ptr.To("/api")}, Method: ptr.To(gatewayv1.HTTPMethodPost)},
			}},
			{Name: ptr.To(gatewayv1.SectionName("health")), Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: ptr.To("/healthz")}}}},
		},
	}}
	r := &envoyRoute{route: route, gateways: []types.NamespacedName{edge, internal}, sections: []string{""}}

	jobs, why := st.envoyRouteProbes(r, nil)
	if why != "" || len(jobs) != 2 {
		t.Fatalf("jobs %+v, why %q", jobs, why)
	}
	j := jobs[0]
	if j.Route.String() != "HTTPRoute web" || j.Proxy != "Envoy Gateway" || j.Fingerprint != "edge/edge/2/3" {
		t.Errorf("job %+v", j)
	}
	if len(j.Pods) != 2 || j.Pods[0].Name != "envoy-gateway-system/edge-1" || j.Pods[0].IP != "10.0.0.7" || j.Pods[1].UID != "uid-edge-2" {
		t.Errorf("Gateway edge's pods: %+v, want its two running ones", j.Pods)
	}
	// The alt listener serves another host: none of the route's.
	if len(j.Targets) != 4 {
		t.Errorf("%d targets, want 2 rules × 2 listeners serving the route's host: %+v", len(j.Targets), j.Targets)
	}
	got := map[string]ProbeTarget{}
	for _, tg := range j.Targets {
		if tg.Host != "inkwall-probe.example.com" || tg.TLS != (tg.Port == 10443) || tg.Port != 10080 && tg.Port != 10443 {
			t.Errorf("target %+v: want the concrete host, the Envoy container's port 10080, or 10443 over TLS", tg)
		}
		got[tg.Path] = tg
	}
	if api := got["/api"]; !api.Prefix || api.Method != "POST" {
		t.Errorf("api rule's target %+v", api)
	}
	if h := got["/healthz"]; h.Prefix {
		t.Errorf("health rule's target %+v", h)
	}
	j2 := jobs[1]
	if len(j2.Pods) != 1 || j2.Pods[0].IP != "10.0.1.7" || len(j2.Targets) != 4 {
		t.Fatalf("Gateway internal's job %+v", j2)
	}
	for _, tg := range j2.Targets {
		if tg.Port != 80 && tg.Port != 8443 || tg.TLS != (tg.Port == 8443) {
			t.Errorf("Gateway internal's target %+v: want the listener's own ports, its pods serving them", tg)
		}
	}

	// A protected rule alone: its targets only.
	jobs, why = st.envoyRouteProbes(&envoyRoute{route: route, gateways: []types.NamespacedName{edge}, sections: []string{"health"}}, nil)
	if why != "" || len(jobs) != 1 || len(jobs[0].Targets) != 2 || jobs[0].Targets[0].Path != "/healthz" {
		t.Errorf("rule health: jobs %+v, why %q", jobs, why)
	}

	// No running Envoy pod: a job without pods, which the Prober reports
	// as unverified.
	jobs, why = st.envoyRouteProbes(&envoyRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gone"}, edge}, sections: []string{""}}, nil)
	if why != "" || len(jobs) != 1 {
		t.Fatalf("an unknown Gateway: jobs %+v, why %q", jobs, why)
	}
	st.pods = st.pods[3:]
	jobs, why = st.envoyRouteProbes(&envoyRoute{route: route, gateways: []types.NamespacedName{edge}, sections: []string{""}}, nil)
	if why != "" || len(jobs) != 1 || len(jobs[0].Pods) != 0 || len(jobs[0].Targets) != 4 {
		t.Fatalf("no Envoy pod: jobs %+v, why %q", jobs, why)
	}
	for _, tg := range jobs[0].Targets {
		if tg.Port != 10080 && tg.Port != 10443 {
			t.Errorf("no pod to tell: target %+v, want Envoy Gateway's shifted port", tg)
		}
	}
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	p := &Prober{Key: func(context.Context) ([]byte, error) { return key, nil }}
	p.Run(context.Background())
	if u := p.Unverified(jobs[0]); !strings.Contains(u, "no Envoy Gateway pod with the engine runs") {
		t.Errorf("no Envoy pod: %q", u)
	}

	// Header and query matches: sent over plain HTTP only (#507, #511).
	route.Spec.Rules[0].Matches[1].Headers = []gatewayv1.HTTPHeaderMatch{{Type: &headerExact, Name: "X-Api-Key", Value: "k"}}
	route.Spec.Rules[0].Matches[1].QueryParams = []gatewayv1.HTTPQueryParamMatch{{Name: "v", Value: "2"}}
	if _, why := st.envoyRouteProbes(&envoyRoute{route: route, gateways: []types.NamespacedName{edge}, sections: []string{"api"}}, nil); !strings.Contains(why, "rule api") ||
		!strings.Contains(why, "doesn't send values that may be secrets") || !strings.Contains(why, "over HTTPS on port 443") {
		t.Errorf("header match over TLS: why %q", why)
	}
	plain := gw.DeepCopy()
	plain.Spec.Listeners = plain.Spec.Listeners[:1]
	st.gateways[edge] = plain
	jobs, why = st.envoyRouteProbes(&envoyRoute{route: route, gateways: []types.NamespacedName{edge}, sections: []string{"api"}}, nil)
	if why != "" || len(jobs) != 1 || len(jobs[0].Targets) != 1 {
		t.Fatalf("header match over HTTP: jobs %+v, why %q", jobs, why)
	}
	if tg := jobs[0].Targets[0]; tg.Headers["X-Api-Key"] != "k" || tg.Query != "v=2" || tg.TLS {
		t.Errorf("header match over HTTP: target %+v", tg)
	}
	st.gateways[edge] = gw
	route.Spec.Rules[0].Matches[1].Headers, route.Spec.Rules[0].Matches[1].QueryParams = nil, nil

	// Only regular expressions: not probeable.
	route.Spec.Rules[1].Matches = []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &regex, Value: ptr.To("/h.*")}}}
	if _, why := st.envoyRouteProbes(&envoyRoute{route: route, gateways: []types.NamespacedName{edge}, sections: []string{"health"}}, nil); !strings.Contains(why, "rule health") ||
		!strings.Contains(why, "regular expression") {
		t.Errorf("regular expressions: why %q", why)
	}
	route.Spec.Rules[1].Matches = nil

	// Mutual TLS: a user's ClientTrafficPolicy asking the clients of the
	// Gateway, or of the HTTPS listener, for a certificate; not when it is
	// optional, or on another listener, or the operator's.
	ctp := func(name string, ref map[string]any, validation map[string]any, managed bool) unstructured.Unstructured {
		u := newObject(ClientTrafficPolicyGVK, "edge", name)
		if !managed {
			u.SetLabels(nil)
		}
		u.Object["spec"] = map[string]any{"targetRefs": []any{ref}, "tls": map[string]any{"clientValidation": validation}}
		return *u
	}
	gwRef := map[string]any{"group": gatewayv1.GroupName, "kind": "Gateway", "name": "edge"}
	section := func(s string) map[string]any {
		return map[string]any{"group": gatewayv1.GroupName, "kind": "Gateway", "name": "edge", "sectionName": s}
	}
	certs := map[string]any{"caCertificateRefs": []any{map[string]any{"name": "ca"}}}
	for _, tc := range []struct {
		name       string
		policy     unstructured.Unstructured
		probeable  bool
		reasonPart string
	}{
		{"on the Gateway", ctp("mtls", gwRef, certs, false), false, "ClientTrafficPolicy mtls's tls.clientValidation"},
		{"on the HTTPS listener", ctp("mtls", section("https"), certs, false), false, "ClientTrafficPolicy mtls"},
		{"on another listener", ctp("mtls", section("http"), certs, false), true, ""},
		{"optional", ctp("mtls", gwRef, map[string]any{"optional": true, "caCertificateRefs": certs["caCertificateRefs"]}, false), true, ""},
		{"the operator's", ctp("mtls", gwRef, certs, true), true, ""},
		{"on another Gateway", ctp("mtls", map[string]any{"kind": "Gateway", "name": "elsewhere"}, certs, false), true, ""},
	} {
		_, why := st.envoyRouteProbes(r, []unstructured.Unstructured{tc.policy})
		if tc.probeable != (why == "") || !tc.probeable && (!strings.Contains(why, tc.reasonPart) || !strings.Contains(why, "mutual TLS") || !strings.Contains(why, "Gateway edge/edge")) {
			t.Errorf("%s: why %q", tc.name, why)
		}
	}
	// The Gateway API's own frontend validation, as for Istio.
	mtls := gw.DeepCopy()
	mtls.Spec.TLS = &gatewayv1.GatewayTLSConfig{Frontend: &gatewayv1.FrontendTLSConfig{Default: gatewayv1.TLSConfig{
		Validation: &gatewayv1.FrontendTLSValidation{CACertificateRefs: []gatewayv1.ObjectReference{{Name: "ca"}}}}}}
	st.gateways[edge] = mtls
	if _, why := st.envoyRouteProbes(r, nil); !strings.Contains(why, "spec.tls.frontend") {
		t.Errorf("frontend validation: why %q", why)
	}
	mtls.Spec.TLS.Frontend.Default.Validation.Mode = gatewayv1.AllowInsecureFallback
	if _, why := st.envoyRouteProbes(r, nil); why != "" {
		t.Errorf("frontend validation with an insecure fallback: why %q", why)
	}
	mtls.Spec.TLS.Frontend.Default.Validation.Mode = ""
	mtls.Spec.TLS.Frontend.PerPort = []gatewayv1.TLSPortConfig{{Port: 443}}
	if _, why := st.envoyRouteProbes(r, nil); why != "" {
		t.Errorf("no validation on the HTTPS listener's port: why %q", why)
	}
}

// The Envoy container's port for a listener: Envoy Gateway's shift of a
// privileged port, unless the pods serve the port itself.
func TestEnvoyListenerPort(t *testing.T) {
	pod := func(ports ...int32) *corev1.Pod { p := envoyTestPod("p", "gw", "10.0.0.1", ports...); return &p }
	for _, tc := range []struct {
		name string
		pods []*corev1.Pod
		port int32
		want int32
	}{
		{"no pod", nil, 80, 10080},
		{"shifted", []*corev1.Pod{pod(10080)}, 80, 10080},
		{"the listener's own (useListenerPortAsContainerPort)", []*corev1.Pod{pod(80)}, 80, 80},
		{"both: Envoy Gateway's default", []*corev1.Pod{pod(80, 10080)}, 80, 10080},
		{"neither", []*corev1.Pod{pod(19001)}, 443, 10443},
		{"not privileged", []*corev1.Pod{pod(10080)}, 8080, 8080},
	} {
		if got := envoyListenerPort(tc.pods, gatewayv1.Listener{Port: tc.port}); got != tc.want {
			t.Errorf("%s: port %d, want %d", tc.name, got, tc.want)
		}
	}
}

// Envoy Gateway's routes are proven by the probe (#604), as Istio's: once
// Envoy Gateway accepted the operator's policies, the route is Unverified
// until the probe has reached the engine through every Envoy pod of its
// Gateways, on the Envoy container's port; an answer from past the filter
// (a user's EnvoyPatchPolicy took it off) keeps it Unverified, and the
// policy isn't Programmed; a policy with responses.inspect waits for the
// probe's response leg too. Without a Prober, Envoy Gateway's acceptance
// is the evidence, as before.
func TestEnvoyGatewayProbeStatus(t *testing.T) {
	ctx := context.Background()
	s := scheme()
	_ = gatewayv1.Install(s)
	gc := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"controllerName": integrations.EnvoyGateway.GatewayController}}}
	gc.SetGroupVersionKind(GatewayClassGVK)
	gc.SetName("eg")
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw"}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "eg",
		Listeners:        []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}},
	}}
	hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "app"}, Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw", Namespace: ptr.To(gatewayv1.Namespace("edge"))}}},
		Hostnames:       []gatewayv1.Hostname{"shop.example.com"},
		Rules:           []gatewayv1.HTTPRouteRule{{Name: ptr.To(gatewayv1.SectionName("web"))}},
	}, Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: []gatewayv1.RouteParentStatus{{
		ParentRef:      gatewayv1.ParentReference{Name: "gw", Namespace: ptr.To(gatewayv1.Namespace("edge"))},
		ControllerName: gatewayv1.GatewayController(integrations.EnvoyGateway.GatewayController),
		Conditions:     []metav1.Condition{{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue, Reason: "Accepted"}},
	}}}}}
	pod := envoyTestPod("gw-1", "gw", "10.0.0.7", 10080)
	policy := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}, Spec: wafv1alpha1.WAFPolicySpec{
		TargetRefs: []wafv1alpha1.TargetRef{{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: "app"}},
		Mode:       wafv1alpha1.PolicyBlock,
	}}
	c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(envoyMapper()).WithObjects(gc, gw, hr, &pod, policy).WithStatusSubresource(hr).Build()

	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	var mu sync.Mutex
	// engine: the engine answers (the filter is on the route); legs counts
	// the probes by leg.
	engine := true
	legs := map[bool]int{}
	do := func(_ context.Context, pp ProbePod, target ProbeTarget, req *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if pp.IP != "10.0.0.7" || target.Port != 10080 || target.TLS || req.Host != "shop.example.com" {
			t.Errorf("probe to %+v %+v, host %s: want the Envoy pod's port 10080", pp, target, req.Host)
		}
		header := req.Header.Get(haproxyprobe.Header)
		uri := req.URL.RequestURI()
		response := haproxyprobe.IsResponseURI(uri)
		legs[response]++
		if !engine {
			return probeAnswer(http.StatusNotFound, ""), nil
		}
		if response {
			a, _, _ := haproxyprobe.ResponseLeg(key, uri, req.Host, header)
			return probeAnswer(http.StatusOK, a), nil
		}
		a, _ := haproxyprobe.Check(key, uri, req.Host, header)
		return probeAnswer(http.StatusOK, a), nil
	}
	p := &Prober{Key: func(context.Context) ([]byte, error) { return key, nil }, Do: do}
	// The Prober runs all along: it has the bundle's key before the route
	// is accepted.
	p.Run(ctx)
	in := &EnvoyGateway{Client: c, APIReader: c, Pods: labels.Everything(), Sidecar: injection.Sidecar{Image: "inkwall-engine:test"}, Prober: p}
	tg := Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "shop", Name: "app"}}
	tgRule := Target{Kind: httpRouteKind, Key: tg.Key, Section: "web"}
	wire := func() TargetState {
		t.Helper()
		res, err := in.Wire(ctx, map[Target]bool{tg: true, tgRule: true}, false)
		if err != nil {
			t.Fatalf("wire: %v", err)
		}
		if res.Targets[tg] != res.Targets[tgRule] {
			t.Errorf("the route and its rule: %+v, %+v", res.Targets[tg], res.Targets[tgRule])
		}
		return res.Targets[tg]
	}
	status := func(st TargetState) (metav1.ConditionStatus, string, string) {
		res := &Result{Proxy: "Envoy Gateway", Rolling: true, Responses: true, Streams: true, Pods: []corev1.Pod{pod}, Targets: map[Target]TargetState{tg: st}}
		return programmed(policy, &report{kinds: []schema.GroupKind{httpRouteKind}, results: []*Result{res}})
	}

	if st := wire(); !st.Wired || !strings.Contains(st.Pending, "waiting for Envoy Gateway to accept EnvoyExtensionPolicy") || st.Unverified != "" {
		t.Fatalf("before Envoy Gateway accepts the policy: %+v", st)
	}
	if n := len(p.jobs[integrations.EnvoyGateway.Name]); n != 0 {
		t.Errorf("probing a route Envoy Gateway hasn't accepted the policy of: %d jobs", n)
	}
	accept := func(gvk schema.GroupVersionKind, ns, name string) {
		t.Helper()
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvk)
		if err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, u); err != nil {
			t.Fatal(err)
		}
		u.Object["status"] = map[string]any{"ancestors": []any{map[string]any{"conditions": []any{map[string]any{"type": "Accepted", "status": "True"}}}}}
		if err := c.Update(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	accept(EnvoyExtensionPolicyGVK, "shop", envoyName("app"))
	accept(ClientTrafficPolicyGVK, "edge", envoyName("gw"))

	st := wire()
	if st.Pending != "" || st.NotProbeable != "" || !strings.Contains(st.Unverified, "HTTPRoute app is wired; the filter is unverified until the operator's probe has reached it on every Envoy Gateway pod") {
		t.Fatalf("accepted, not probed yet: %+v", st)
	}
	if got, reason, _ := status(st); got != metav1.ConditionFalse || reason != ReasonUnverified {
		t.Errorf("accepted, not probed yet: %s %s", got, reason)
	}
	jobs := p.jobs[integrations.EnvoyGateway.Name]
	if len(jobs) != 1 || jobs[0].Proxy != "Envoy Gateway" || jobs[0].Receipt || jobs[0].Responses {
		t.Fatalf("the Prober's Envoy Gateway jobs: %+v, want one for the route, its rule's target once", jobs)
	}
	p.Run(ctx)
	st = wire()
	if st.Unverified != "" || st.NotProbeable != "" || st.Responses != (ResponsesProof{}) {
		t.Fatalf("proven: %+v", st)
	}
	if got, reason, msg := status(st); got != metav1.ConditionTrue || msg != "1 HTTPRoute(s) wired to the engine in Envoy Gateway" {
		t.Errorf("proven: %s %s %q", got, reason, msg)
	}
	if legs[false] != 1 || legs[true] != 0 {
		t.Errorf("probes sent by leg: %v, want the request leg only", legs)
	}

	// The filter taken off the route: the app answers.
	mu.Lock()
	engine = false
	mu.Unlock()
	in.Prober = &Prober{Key: p.Key, Do: do}
	in.Prober.Run(ctx)
	wire()
	in.Prober.Run(ctx)
	st = wire()
	if !strings.Contains(st.Unverified, "the probe shows that Envoy Gateway doesn't run the filter for it") || !strings.Contains(st.Unverified, "envoy-gateway-system/gw-1") {
		t.Errorf("the filter off: %+v", st)
	}
	if got, reason, _ := status(st); got != metav1.ConditionFalse || reason != ReasonUnverified {
		t.Errorf("the filter off: %s %s", got, reason)
	}

	// Responses: the response leg too, from both Envoy's answers.
	mu.Lock()
	engine = true
	legs = map[bool]int{}
	mu.Unlock()
	policy.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true}
	if err := c.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	in.Prober = &Prober{Key: p.Key, Do: do}
	in.Prober.Run(ctx)
	st = wire()
	if !strings.Contains(st.Responses.Unverified, "HTTPRoute app's responses are unverified") {
		t.Fatalf("responses, not probed yet: %+v", st)
	}
	if got, reason, _ := status(st); got != metav1.ConditionFalse || reason != ReasonUnverified {
		t.Errorf("responses, not probed yet: %s %s", got, reason)
	}
	in.Prober.Run(ctx)
	st = wire()
	if st.Unverified != "" || st.Responses != (ResponsesProof{}) {
		t.Errorf("responses proven: %+v", st)
	}
	if legs[false] != 1 || legs[true] != 1 {
		t.Errorf("probes sent by leg: %v, want both", legs)
	}
	if got, _, msg := status(st); got != metav1.ConditionTrue {
		t.Errorf("responses proven: %s %q", got, msg)
	}

	// Without a Prober, Programmed rests on Envoy Gateway's acceptance.
	in.Prober = nil
	if st := wire(); st.Unverified != "" || st.Pending != "" || st.Failed != "" || !st.Wired {
		t.Errorf("without a Prober: %+v", st)
	}
}
