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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/inkwall-dev/inkwall/pkg/haproxyprobe"
)

// An Istio HTTPRoute's probe (#372): per Gateway, a target per protected
// rule and listener the route attaches to, from the rule's first match the
// probe can make (exact or prefix path, exact headers and query
// parameters, the method), on the listener's port, with a host the route
// serves (a wildcard's made concrete), over TLS for an HTTPS listener; on
// each running pod of the Gateway. A rule whose matches the probe can't
// make (regular expressions) makes the route not probeable.
func TestIstioRouteProbe(t *testing.T) {
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw"}, Spec: gatewayv1.GatewaySpec{
		Listeners: []gatewayv1.Listener{
			{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			{Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType, Hostname: ptr.To(gatewayv1.Hostname("*.example.com"))},
			{Name: "tcp", Port: 9000, Protocol: gatewayv1.TCPProtocolType},
		},
	}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw-1", UID: "u1", Labels: map[string]string{istioGatewayLabel: "gw"}},
		Status: corev1.PodStatus{PodIP: "10.0.0.7", Phase: corev1.PodRunning}}
	st := &envoyState{gateways: map[types.NamespacedName]*gatewayv1.Gateway{{Namespace: "edge", Name: "gw"}: gw}, pods: []corev1.Pod{pod}}
	exact, prefix, regex := gatewayv1.PathMatchExact, gatewayv1.PathMatchPathPrefix, gatewayv1.PathMatchRegularExpression
	headerExact, headerRegex := gatewayv1.HeaderMatchExact, gatewayv1.HeaderMatchRegularExpression
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw", Namespace: ptr.To(gatewayv1.Namespace("edge"))}}},
		Hostnames:       []gatewayv1.Hostname{"*.example.com"},
		Rules: []gatewayv1.HTTPRouteRule{
			{Name: ptr.To(gatewayv1.SectionName("api")), Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &regex, Value: ptr.To("/v[0-9]+")}},
				{Path: &gatewayv1.HTTPPathMatch{Type: &prefix, Value: ptr.To("/api")}, Method: ptr.To(gatewayv1.HTTPMethodPost),
					Headers:     []gatewayv1.HTTPHeaderMatch{{Type: &headerExact, Name: "X-Tenant", Value: "a"}},
					QueryParams: []gatewayv1.HTTPQueryParamMatch{{Name: "v", Value: "2"}}},
			}},
			{Name: ptr.To(gatewayv1.SectionName("health")), Matches: []gatewayv1.HTTPRouteMatch{
				{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: ptr.To("/healthz")}}}},
		},
	}}
	jobs, why := st.istioRouteProbes(&istioRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gw"}}, sections: []string{""}})
	if why != "" || len(jobs) != 1 {
		t.Fatalf("jobs %+v, why %q", jobs, why)
	}
	j := jobs[0]
	if j.Route.String() != "HTTPRoute web" || j.Proxy != "Istio" || len(j.Pods) != 1 || j.Pods[0].IP != "10.0.0.7" {
		t.Errorf("job %+v", j)
	}
	got := map[string]ProbeTarget{}
	for _, tg := range j.Targets {
		got[tg.Path] = tg
	}
	if len(j.Targets) != 4 {
		t.Errorf("%d targets, want 2 rules × 2 HTTP listeners: %+v", len(j.Targets), j.Targets)
	}
	for _, tg := range j.Targets {
		if tg.Host != "inkwall-probe.example.com" || (tg.Port == 443) != tg.TLS || (tg.Port != 80 && tg.Port != 443) {
			t.Errorf("target %+v: want the concrete host, port 80 or 443 over TLS", tg)
		}
	}
	if api := got["/api"]; !api.Prefix || api.Method != "POST" || api.Headers["X-Tenant"] != "a" || api.Query != "v=2" {
		t.Errorf("api rule's target %+v", api)
	}
	if h := got["/healthz"]; h.Prefix {
		t.Errorf("health rule's target %+v", h)
	}

	// Only regular expressions: not probeable.
	route.Spec.Rules[1].Matches = []gatewayv1.HTTPRouteMatch{{Headers: []gatewayv1.HTTPHeaderMatch{{Type: &headerRegex, Name: "X-A", Value: ".*"}}}}
	if _, why := st.istioRouteProbes(&istioRoute{route: route, gateways: []types.NamespacedName{{Namespace: "edge", Name: "gw"}}, sections: []string{"health"}}); !strings.Contains(why, "rule health") || !strings.Contains(why, "regular expression") {
		t.Errorf("why %q", why)
	}
}

// A VirtualService's probe: per Gateway server whose hosts it serves, on
// the server's port, over TLS for a SIMPLE TLS server; a mutual TLS server
// can't be probed.
func TestIstioVSProbe(t *testing.T) {
	gwObj := newObject(IstioGatewayGVK, "istio-ingress", "edge")
	gwObj.Object["spec"] = map[string]any{"selector": map[string]any{"istio": "ingressgateway"}, "servers": []any{
		map[string]any{"port": map[string]any{"number": int64(80), "protocol": "HTTP"}, "hosts": []any{"*"}},
		map[string]any{"port": map[string]any{"number": int64(443), "protocol": "HTTPS"}, "hosts": []any{"*/shop.example.com"}, "tls": map[string]any{"mode": "SIMPLE"}},
	}}
	vs := testVS(t, "shop", "web", `
hosts: [shop.example.com]
gateways: [istio-ingress/edge]
http:
- name: api
  match: [{uri: {regex: "/v[0-9]+"}}, {uri: {prefix: /api/}, headers: {x-tenant: {exact: a}}}]
- name: web
`)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "istio-ingress", Name: "igw-1", UID: "u1"}, Status: corev1.PodStatus{PodIP: "10.0.0.9"}}
	st := &istioIngressState{gateways: map[types.NamespacedName]*unstructured.Unstructured{{Namespace: "istio-ingress", Name: "edge"}: gwObj}}
	r := &istioVSRoute{vs: vs, gateways: []types.NamespacedName{{Namespace: "istio-ingress", Name: "edge"}}, pods: map[string][]*corev1.Pod{"istio-ingress": {pod}}}
	jobs, why := st.vsProbes(r)
	if why != "" || len(jobs) != 1 || len(jobs[0].Targets) != 4 || jobs[0].Route.String() != "VirtualService web" {
		t.Fatalf("jobs %+v, why %q", jobs, why)
	}
	for _, tg := range jobs[0].Targets {
		if tg.Host != "shop.example.com" || (tg.Port == 443) != tg.TLS {
			t.Errorf("target %+v", tg)
		}
		if tg.Path == "/api/" && (!tg.Prefix || tg.Headers["x-tenant"] != "a") {
			t.Errorf("api target %+v", tg)
		}
	}
	// A mutual TLS server can't be probed.
	servers, _, _ := unstructured.NestedSlice(gwObj.Object, "spec", "servers")
	servers[1].(map[string]any)["tls"] = map[string]any{"mode": "MUTUAL"}
	_ = unstructured.SetNestedSlice(gwObj.Object, servers, "spec", "servers")
	if _, why := st.vsProbes(r); !strings.Contains(why, "mutual TLS") {
		t.Errorf("why %q", why)
	}
}

// A wired Istio route is proven once the engine answered the probe on
// every target through every pod (Envoy's local reply: 200 and the MAC);
// an answer from past the filter (the app's) leaves it Unverified; a
// detect-mode route stays Unverified, as Envoy discards the answer; a
// route the probe can't make is NotProbeable.
func TestProveRoute(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{5}, haproxyprobe.KeySize)
	engine := true
	p := &Prober{
		Key: func(context.Context) ([]byte, error) { return key, nil },
		Do: func(_ context.Context, pod ProbePod, target ProbeTarget, req *http.Request) (*http.Response, error) {
			if target.Port == 0 || req.Header.Get("X-Tenant") != "a" {
				t.Errorf("probe %+v %v", target, req.Header)
			}
			h := http.Header{}
			if engine {
				answer, _ := haproxyprobe.Check(key, req.URL.RequestURI(), req.Host, req.Header.Get(haproxyprobe.Header))
				h.Set(haproxyprobe.Header, answer)
			}
			return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}
	job := ProbeJob{Route: ProbeRoute{Kind: "HTTPRoute", Key: types.NamespacedName{Namespace: "shop", Name: "web"}}, Proxy: "Istio",
		Pods:    []ProbePod{{Name: "edge/gw-1", UID: "u1", IP: "10.0.0.7"}},
		Targets: []ProbeTarget{{Host: "shop.example.com", Path: "/api", Prefix: true, Port: 80, Headers: map[string]string{"X-Tenant": "a"}}}}
	jobs := func() ([]ProbeJob, string) { return []ProbeJob{job}, "" }
	p.Set("istio", []ProbeJob{job})
	if _, np, u := proveRoute(p, "HTTPRoute web", false, jobs); np != "" || !strings.Contains(u, "unverified until") {
		t.Errorf("before a probe: %q %q", np, u)
	}
	p.Run(ctx)
	if _, np, u := proveRoute(p, "HTTPRoute web", false, jobs); np != "" || u != "" {
		t.Errorf("proven: %q %q", np, u)
	}
	engine = false
	p2 := &Prober{Key: p.Key, Do: p.Do}
	p2.Set("istio", []ProbeJob{job})
	p2.Run(ctx)
	if _, _, u := proveRoute(p2, "HTTPRoute web", false, jobs); !strings.Contains(u, "doesn't run the filter") {
		t.Errorf("the app answered: %q", u)
	}
	if _, _, u := proveRoute(p, "HTTPRoute web", true, jobs); !strings.Contains(u, "Detect mode") {
		t.Errorf("detect: %q", u)
	}
	if _, np, _ := proveRoute(p, "HTTPRoute web", false, func() ([]ProbeJob, string) { return nil, "a regular expression" }); np == "" {
		t.Error("not probeable: nothing said")
	}
}
