// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

// The EnvoyFilters of a namespace's gateway pods: a base one with the
// engine's cluster and the listeners' buffer limit, and shards with a
// disabled filter per VirtualService enabled on its routes, each with the
// integration's labels as workloadSelector, the integration label, and the
// VirtualServices it wires.
func TestIstioIngressEnvoyFilter(t *testing.T) {
	in := &IstioIngress{PodLabels: map[string]string{"istio": "ingressgateway"}}
	vs := testVS(t, "shop", "web", "http: [{name: api}]")
	fs := in.filtersOf("istio-ingress", []*istioVSRoute{{vs: vs, envoyRoutes: []string{"api"},
		routeSettings: routeSettings{body: true, maxBody: 64 << 10, timeout: time.Second}}})
	if len(fs) != 2 {
		t.Fatalf("%d EnvoyFilters, want the base one and a shard", len(fs))
	}
	base, shard := fs[0], fs[1]
	for _, f := range fs {
		if f.GetNamespace() != "istio-ingress" || !isManaged(f) || !isIstioIngress(f) || len(f.GetOwnerReferences()) != 0 {
			t.Fatalf("metadata %v", f.Object["metadata"])
		}
	}
	if base.GetName() != istioIngressFilter || base.GetAnnotations()[istioIngressRoutes] != "" {
		t.Errorf("base: %v", base.Object["metadata"])
	}
	if shard.GetName() != shardName(types.NamespacedName{Namespace: "shop", Name: "web"}) || shard.GetAnnotations()[istioIngressRoutes] != "shop/web" {
		t.Errorf("shard: %v", shard.Object["metadata"])
	}
	for f, wants := range map[*unstructured.Unstructured][]string{
		base: {`"workloadSelector":{"labels":{"istio":"ingressgateway"}}`, `"applyTo":"CLUSTER"`, `"per_connection_buffer_limit_bytes":10485760`},
		shard: {`"workloadSelector":{"labels":{"istio":"ingressgateway"}}`,
			`"name":"inkwall.ext_proc.vs.shop.web"`, `"disabled":true`, `"route":{"name":"api"}`,
			`"request_body_mode":"BUFFERED_PARTIAL"`, `"status_on_error":{"code":"ServiceUnavailable"}`},
	} {
		spec := jsonOf(f.Object["spec"])
		for _, want := range wants {
			if !strings.Contains(spec, want) {
				t.Errorf("%s: no %s in %s", f.GetName(), want, spec)
			}
		}
	}
	if strings.Contains(jsonOf(shard.Object["spec"]), `"applyTo":"CLUSTER"`) {
		t.Error("a shard adds the cluster too: Envoy would get it twice")
	}
}

// Thousands of VirtualServices on one namespace's gateway pods are spread
// over shards that each stay well under etcd's 1.5 MiB limit (#424): one
// EnvoyFilter for them all passed it at about 1,200. Each VirtualService
// is in exactly one shard, always the same, and the cluster in the base.
func TestIstioIngressShards(t *testing.T) {
	in := &IstioIngress{PodLabels: map[string]string{"istio": "ingressgateway"}}
	const n = 5000
	var rs []*istioVSRoute
	for i := range n {
		vs := testVS(t, fmt.Sprintf("team-%d", i%50), fmt.Sprintf("app-%d", i), fmt.Sprintf("http: [{name: r-%d}]", i))
		rs = append(rs, &istioVSRoute{vs: vs, envoyRoutes: []string{fmt.Sprintf("r-%d", i)},
			routeSettings: routeSettings{body: true, maxBody: 64 << 10, timeout: time.Second}})
	}
	fs := in.filtersOf("istio-ingress", rs)
	seen := map[string]string{}
	clusters := 0
	for _, f := range fs {
		raw, err := json.Marshal(f.Object)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 512<<10 {
			t.Errorf("%s is %d KiB, want at most 512", f.GetName(), len(raw)>>10)
		}
		clusters += strings.Count(string(raw), `"applyTo":"CLUSTER"`)
		for _, k := range strings.Split(f.GetAnnotations()[istioIngressRoutes], ",") {
			if k == "" {
				continue
			}
			if other, dup := seen[k]; dup {
				t.Errorf("%s in %s and %s", k, other, f.GetName())
			}
			seen[k] = f.GetName()
		}
	}
	if len(seen) != n || clusters != 1 {
		t.Errorf("%d VirtualServices in the shards, want %d; %d clusters, want 1", len(seen), n, clusters)
	}
	// The same shard in a smaller set: a VirtualService doesn't move.
	for _, f := range in.filtersOf("istio-ingress", rs[:10]) {
		for _, k := range strings.Split(f.GetAnnotations()[istioIngressRoutes], ",") {
			if k != "" && seen[k] != f.GetName() {
				t.Errorf("%s moved from %s to %s", k, seen[k], f.GetName())
			}
		}
	}
}

// Each Istio integration deletes only its own EnvoyFilters.
func TestIstioUnwireSeparate(t *testing.T) {
	ctx := context.Background()
	m := envoyMapper().(*meta.DefaultRESTMapper)
	m.Add(EnvoyFilterGVK, meta.RESTScopeNamespace)
	ingress := (&IstioIngress{PodLabels: map[string]string{"istio": "ingressgateway"}}).filtersOf("edge",
		[]*istioVSRoute{{vs: testVS(t, "shop", "web", "http: [{name: api}]"), envoyRoutes: []string{"api"}}})[1]
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

// Wire writes the base EnvoyFilter and a shard per bucket of protected
// VirtualServices, deletes a shard once its VirtualServices are no longer
// protected, and replaces a single EnvoyFilter of an operator before the
// shards (#424): its VirtualServices move to the shards, the base keeps
// the cluster.
func TestIstioIngressWireShards(t *testing.T) {
	ctx := context.Background()
	m := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range []schema.GroupVersionKind{IstioVirtualServiceGVK, IstioGatewayGVK, EnvoyFilterGVK} {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	sel := map[string]string{"istio": "ingressgateway"}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "istio-ingress", Name: "gw-1", Labels: sel, UID: "gw-1"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "inkwall-engine"}},
			Containers: []corev1.Container{{Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.31.3",
				VolumeMounts: []corev1.VolumeMount{{Name: "inkwall-socket", MountPath: "/var/run/inkwall"}}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	gw := newObject(IstioGatewayGVK, "shop", "edge")
	gw.SetLabels(nil)
	gw.Object["spec"] = map[string]any{"selector": map[string]any{"istio": "ingressgateway"}}
	in := &IstioIngress{PodLabels: sel, Pods: labels.SelectorFromSet(sel)}
	// An operator before the shards wired web-0 in one EnvoyFilter.
	old := in.filtersOf("istio-ingress", nil)[0]
	old.SetAnnotations(map[string]string{istioIngressRoutes: "shop/web-0"})
	objs := []client.Object{pod, gw, old}
	targets := map[Target]bool{}
	for i := range 40 {
		vs := testVS(t, "shop", fmt.Sprintf("web-%d", i), fmt.Sprintf("{gateways: [edge], http: [{name: r-%d}]}", i))
		objs = append(objs, vs)
		targets[Target{Kind: virtualServiceKind, Key: types.NamespacedName{Namespace: "shop", Name: vs.GetName()}}] = true
	}
	c := fake.NewClientBuilder().WithScheme(scheme()).WithRESTMapper(m).WithObjects(objs...).Build()
	in.Client, in.APIReader = c, c
	filters := func() map[string]string {
		t.Helper()
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(EnvoyFilterGVK.GroupVersion().WithKind("EnvoyFilterList"))
		if err := c.List(ctx, list, client.InNamespace("istio-ingress")); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range list.Items {
			out[f.GetName()] = f.GetAnnotations()[istioIngressRoutes]
		}
		return out
	}
	wire := func(targets map[Target]bool) {
		t.Helper()
		res, err := in.Wire(ctx, targets, false)
		if err != nil {
			t.Fatal(err)
		}
		for tg := range targets {
			if s := res.Targets[tg]; !s.Wired || s.Failed != "" {
				t.Fatalf("%s: %+v", tg.Key, s)
			}
		}
	}
	wire(targets)
	got := filters()
	if got[istioIngressFilter] != "" || len(got) < 3 {
		t.Fatalf("EnvoyFilters %v, want the base without VirtualServices and shards", got)
	}
	for tg := range targets {
		if !slices.Contains(strings.Split(got[shardName(tg.Key)], ","), tg.Key.String()) {
			t.Errorf("%s isn't in its shard %s", tg.Key, shardName(tg.Key))
		}
	}
	if ok, err := in.Wired(ctx, Target{Kind: virtualServiceKind, Key: types.NamespacedName{Namespace: "shop", Name: "web-7"}}); !ok || err != nil {
		t.Errorf("Wired web-7: %v %v", ok, err)
	}

	// Only web-0 left: its shard and the base remain.
	one := Target{Kind: virtualServiceKind, Key: types.NamespacedName{Namespace: "shop", Name: "web-0"}}
	wire(map[Target]bool{one: true})
	if got := filters(); len(got) != 2 || got[shardName(one.Key)] != "shop/web-0" {
		t.Errorf("EnvoyFilters %v, want the base and web-0's shard", got)
	}
	// None: none.
	wire(map[Target]bool{})
	if got := filters(); len(got) != 0 {
		t.Errorf("EnvoyFilters %v, want none", got)
	}
}
