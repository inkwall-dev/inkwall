// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

func testVS(t *testing.T, ns, name, spec string) *unstructured.Unstructured {
	t.Helper()
	var s map[string]any
	if err := yaml.Unmarshal([]byte(spec), &s); err != nil {
		t.Fatal(err)
	}
	vs := newObject(IstioVirtualServiceGVK, ns, name)
	vs.SetLabels(nil)
	vs.Object["spec"] = s
	return vs
}

// Istio names a VirtualService's Envoy routes after its http routes, and
// their named matches; an unnamed http route can't be selected.
func TestVSEnvoyRoutes(t *testing.T) {
	vs := testVS(t, "shop", "web", `
http:
- name: api
  match: [{name: v1, uri: {prefix: /v1/}}, {uri: {prefix: /api/}}]
- name: web
`)
	got, err := vsEnvoyRoutes(vs)
	if err != nil || strings.Join(got, " ") != "api api.v1 web" {
		t.Errorf("%v %v", got, err)
	}
	_, err = vsEnvoyRoutes(testVS(t, "shop", "web", "http: [{name: a}, {route: [{destination: {host: b}}]}]"))
	if err == nil || !strings.Contains(err.Error(), "spec.http[1] of VirtualService web has no name") {
		t.Errorf("unnamed: %v", err)
	}
}

// The EnvoyFilter of a namespace's gateway pods: the integration's labels as
// workloadSelector, a disabled filter per VirtualService enabled on its
// routes, the integration label, and the VirtualServices it wires.
func TestIstioIngressEnvoyFilter(t *testing.T) {
	in := &IstioIngress{PodLabels: map[string]string{"istio": "ingressgateway"}}
	vs := testVS(t, "shop", "web", "http: [{name: api}]")
	f := in.envoyFilter("istio-ingress", []*istioVSRoute{{vs: vs, envoyRoutes: []string{"api"},
		routeSettings: routeSettings{body: true, maxBody: 64 << 10, timeout: time.Second}}})
	if f.GetNamespace() != "istio-ingress" || f.GetName() != istioIngressFilter || !isManaged(f) || !isIstioIngress(f) ||
		f.GetAnnotations()[istioIngressRoutes] != "shop/web" || len(f.GetOwnerReferences()) != 0 {
		t.Fatalf("metadata %v", f.Object["metadata"])
	}
	spec := jsonOf(f.Object["spec"])
	for _, want := range []string{
		`"workloadSelector":{"labels":{"istio":"ingressgateway"}}`,
		`"name":"inkwall.ext_proc.vs.shop.web"`, `"disabled":true`, `"route":{"name":"api"}`,
		`"request_body_mode":"BUFFERED_PARTIAL"`, `"status_on_error":{"code":"ServiceUnavailable"}`,
		`"per_connection_buffer_limit_bytes":10485760`,
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("no %s in %s", want, spec)
		}
	}
}

// Each Istio integration deletes only its own EnvoyFilters.
func TestIstioUnwireSeparate(t *testing.T) {
	ctx := context.Background()
	m := envoyMapper().(*meta.DefaultRESTMapper)
	m.Add(EnvoyFilterGVK, meta.RESTScopeNamespace)
	ingress := (&IstioIngress{PodLabels: map[string]string{"istio": "ingressgateway"}}).envoyFilter("edge",
		[]*istioVSRoute{{vs: testVS(t, "shop", "web", "http: [{name: api}]"), envoyRoutes: []string{"api"}}})
	gw := newObject(EnvoyFilterGVK, "edge", "inkwall-waf-gw")
	s := scheme()
	_ = gatewayv1.Install(s)
	c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(m).WithObjects(ingress, gw).Build()

	in := &IstioIngress{Client: c, APIReader: c}
	tg := Target{Kind: virtualServiceKind, Key: types.NamespacedName{Namespace: "shop", Name: "web"}}
	if ok, err := in.Wired(ctx, tg); err != nil || !ok {
		t.Errorf("Wired: %v %v", ok, err)
	}
	if n, err := in.Unwire(ctx, c); err != nil || n["EnvoyFilter"] != 1 {
		t.Fatalf("istio-ingress unwired %v %v", n, err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Errorf("the Gateway API wiring's EnvoyFilter: %v", err)
	}
	if ok, _ := in.Wired(ctx, tg); ok {
		t.Error("still wired")
	}
	again := ingress.DeepCopy()
	again.SetResourceVersion("")
	if err := c.Create(ctx, again); err != nil {
		t.Fatal(err)
	}
	if n, err := (&Istio{Client: c, APIReader: c}).Unwire(ctx, c); err != nil || n["EnvoyFilter"] != 1 {
		t.Fatalf("istio unwired %v %v", n, err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ingress), &unstructured.Unstructured{Object: map[string]any{"apiVersion": EnvoyFilterGVK.GroupVersion().String(), "kind": "EnvoyFilter"}}); err != nil {
		t.Errorf("the istio-ingress EnvoyFilter: %v", err)
	}
}

// A VirtualService's settings come from the policies on that
// VirtualService, not on an HTTPRoute of the same name.
func TestSettingsOfVirtualService(t *testing.T) {
	block := wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "vs"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Group: "networking.istio.io", Kind: "VirtualService", Name: "web"}},
	}}
	k := types.NamespacedName{Namespace: "shop", Name: "web"}
	if s := settingsOf([]wafv1alpha1.WAFPolicy{block}, virtualServiceKind, k); s.detect || s.failOpen || !s.body {
		t.Errorf("VirtualService: %+v", s)
	}
	if s := settingsOf([]wafv1alpha1.WAFPolicy{block}, httpRouteKind, k); !s.detect {
		t.Errorf("an HTTPRoute of the same name: %+v", s)
	}
}
