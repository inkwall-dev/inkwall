// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"fmt"
	"os"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

var env *testenv.Env

func TestMain(m *testing.M) {
	var (
		stop func()
		err  error
	)
	env, stop, err = testenv.Start(testenv.Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "envtest:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

// traefikKinds are what Traefik's wiring takes today.
var traefikKinds = map[string][]schema.GroupKind{"traefik": {ingressKind, {Group: "traefik.io", Kind: "IngressRoute"}}}

func TestProxies(t *testing.T) {
	const (
		traefik        = "traefik.io/ingress-controller"
		traefikGateway = "traefik.io/gateway-controller"
		nginx          = "k8s.io/ingress-nginx"
	)
	for _, tc := range []struct {
		name             string
		ingress, gateway []Class
		kinds            map[string][]schema.GroupKind
		want             []wafv1alpha1.ProxyStatus
	}{
		{name: "none"},
		{
			name:    "Traefik, ingress-nginx, Traefik's Gateway",
			ingress: []Class{{"traefik", traefik}, {"nginx", nginx}, {"internal", traefik}},
			gateway: []Class{{"traefik", traefikGateway}},
			kinds:   traefikKinds,
			want: []wafv1alpha1.ProxyStatus{
				{ControllerName: nginx, IngressClasses: []string{"nginx"}, Support: wafv1alpha1.SupportUnsupported,
					Message: "Inkwall has no integration for this controller: its routes can't be protected"},
				{ControllerName: traefikGateway, Integration: "traefik", GatewayClasses: []string{"traefik"}, Support: wafv1alpha1.SupportUnsupported,
					Message: "Inkwall doesn't wire traefik's HTTPRoutes (GatewayClasses) yet"},
				{ControllerName: traefik, Integration: "traefik", IngressClasses: []string{"internal", "traefik"}, Support: wafv1alpha1.SupportFull},
			},
		},
		{
			// Once an integration wires HTTPRoutes (#125), its GatewayClasses are.
			name:    "HTTPRoutes wired",
			gateway: []Class{{"traefik", traefikGateway}},
			kinds:   map[string][]schema.GroupKind{"traefik": {httpRouteKind}},
			want: []wafv1alpha1.ProxyStatus{
				{ControllerName: traefikGateway, Integration: "traefik", GatewayClasses: []string{"traefik"}, Support: wafv1alpha1.SupportFull},
			},
		},
		{
			// One controller for both kinds of class, one of them wired.
			name:    "partial",
			ingress: []Class{{"traefik", traefik}},
			gateway: []Class{{"odd", traefik}},
			kinds:   traefikKinds,
			want: []wafv1alpha1.ProxyStatus{
				{ControllerName: traefik, Integration: "traefik", IngressClasses: []string{"traefik"}, GatewayClasses: []string{"odd"},
					Support: wafv1alpha1.SupportPartial, Message: "Inkwall doesn't wire traefik's HTTPRoutes (GatewayClasses) yet"},
			},
		},
	} {
		if got := Proxies(tc.ingress, tc.gateway, tc.kinds); !apiequality.Semantic.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

// TestReconcile records the classes in the InkwallConfig, once it exists.
func TestReconcile(t *testing.T) {
	testenv.Skip(t, env)
	ctx := context.Background()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = wafv1alpha1.AddToScheme(s)
	c, err := client.New(env.Config, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	// Envoy Gateway's wiring takes HTTPRoutes (#127).
	kinds := map[string][]schema.GroupKind{"traefik": traefikKinds["traefik"], "envoy-gateway": {httpRouteKind}}
	r := &Reconciler{Client: c, Kinds: kinds}
	reconcileOnce := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, reconcile.Request{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, ic := range []*networkingv1.IngressClass{
		{ObjectMeta: metav1.ObjectMeta{Name: "traefik"}, Spec: networkingv1.IngressClassSpec{Controller: "traefik.io/ingress-controller"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}, Spec: networkingv1.IngressClassSpec{Controller: "k8s.io/ingress-nginx"}},
	} {
		if err := c.Create(ctx, ic); err != nil {
			t.Fatal(err)
		}
	}
	gc := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"controllerName": "gateway.envoyproxy.io/gatewayclass-controller"}}}
	gc.SetGroupVersionKind(GatewayClassGVK)
	gc.SetName("eg")
	if err := c.Create(ctx, gc); err != nil {
		t.Fatal(err)
	}

	// No InkwallConfig: nothing to write to.
	reconcileOnce()

	cfg := &wafv1alpha1.InkwallConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	if err := c.Create(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	reconcileOnce()
	if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), cfg); err != nil {
		t.Fatal(err)
	}
	support := map[string]wafv1alpha1.Support{}
	for _, p := range cfg.Status.Proxies {
		support[p.ControllerName] = p.Support
	}
	want := map[string]wafv1alpha1.Support{
		"traefik.io/ingress-controller":                 wafv1alpha1.SupportFull,
		"k8s.io/ingress-nginx":                          wafv1alpha1.SupportUnsupported,
		"gateway.envoyproxy.io/gatewayclass-controller": wafv1alpha1.SupportFull,
	}
	if !apiequality.Semantic.DeepEqual(support, want) {
		t.Errorf("proxies %+v, want %v", cfg.Status.Proxies, want)
	}

	// Unchanged: not written again.
	rv := cfg.ResourceVersion
	reconcileOnce()
	if err := c.Get(ctx, client.ObjectKeyFromObject(cfg), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ResourceVersion != rv {
		t.Error("an unchanged status was written again")
	}
}

// A disabled integration's proxy is Unsupported, and says why; the others
// are as they were.
func TestDisable(t *testing.T) {
	proxies := Proxies(
		[]Class{{Name: "traefik", Controller: "traefik.io/ingress-controller"}},
		[]Class{{Name: "eg", Controller: "gateway.envoyproxy.io/gatewayclass-controller"}},
		map[string][]schema.GroupKind{"traefik": {ingressKind}, "envoy-gateway": {httpRouteKind}},
	)
	got := Disable(proxies, map[string]string{"envoy-gateway": "the envoy-gateway integration is disabled"})
	want := []wafv1alpha1.ProxyStatus{
		{ControllerName: "gateway.envoyproxy.io/gatewayclass-controller", Integration: "envoy-gateway", GatewayClasses: []string{"eg"},
			Support: wafv1alpha1.SupportUnsupported, Message: "the envoy-gateway integration is disabled"},
		{ControllerName: "traefik.io/ingress-controller", Integration: "traefik", IngressClasses: []string{"traefik"}, Support: wafv1alpha1.SupportFull},
	}
	if !apiequality.Semantic.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}
