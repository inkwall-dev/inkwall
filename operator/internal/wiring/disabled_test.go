// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// A disabled integration reports the targets its proxy serves, and only
// reads the routes and classes: anything else, such as its proxy's own
// objects, fails the test.
func TestDisabled(t *testing.T) {
	ctx := context.Background()
	s := scheme()
	_ = gatewayv1.Install(s)
	// A mapper that finds a kind's version, as the API server's does.
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{IngressRouteGVK.GroupVersion(), GatewayGVK.GroupVersion(), networkingv1.SchemeGroupVersion})
	for _, gvk := range []schema.GroupVersionKind{IngressRouteGVK, GatewayGVK, HTTPRouteGVK,
		networkingv1.SchemeGroupVersion.WithKind("Ingress"), networkingv1.SchemeGroupVersion.WithKind("IngressClass")} {
		mapper.Add(gvk, meta.RESTScopeNamespace)
	}
	mapper.Add(GatewayClassGVK, meta.RESTScopeRoot)

	class := func(name, controller string) *networkingv1.IngressClass {
		return &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: networkingv1.IngressClassSpec{Controller: controller}}
	}
	ingress := func(name, class string) *networkingv1.Ingress {
		return &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}, Spec: networkingv1.IngressSpec{IngressClassName: ptr.To(class)}}
	}
	gatewayClass := func(name, controller string) *unstructured.Unstructured {
		gc := newObject(GatewayClassGVK, "", name)
		gc.Object["spec"] = map[string]any{"controllerName": controller}
		return gc
	}
	gateway := func(name, class string) *gatewayv1.Gateway {
		return &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: name}, Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName(class)}}
	}
	route := func(name string, gateways ...string) *gatewayv1.HTTPRoute {
		hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}}
		for _, gw := range gateways {
			hr.Spec.ParentRefs = append(hr.Spec.ParentRefs, gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gw), Namespace: ptr.To(gatewayv1.Namespace("edge"))})
		}
		return hr
	}
	c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(mapper).WithObjects(
		class("traefik", integrations.Traefik.Controller), class("nginx", "k8s.io/ingress-nginx"),
		ingress("web", "traefik"), ingress("other", "nginx"), ingressRoute("shop", "ir"),
		gatewayClass("eg", integrations.EnvoyGateway.GatewayController), gatewayClass("other", "example.com/gateway"),
		gateway("eg", "eg"), gateway("other", "other"),
		route("envoy", "other", "eg"), route("elsewhere", "other"), route("orphan", "missing"),
	).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if gvk, _ := c.GroupVersionKindFor(obj); gvk.Group == "gateway.envoyproxy.io" || gvk.Kind == "Middleware" {
				t.Errorf("read %s %s", gvk.Kind, key)
			}
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if gvk, _ := c.GroupVersionKindFor(list); gvk.Group == "gateway.envoyproxy.io" || gvk.Kind == "MiddlewareList" {
				t.Errorf("listed %s", gvk.Kind)
			}
			return c.List(ctx, list, opts...)
		},
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			t.Error("created an object")
			return nil
		},
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			t.Error("updated an object")
			return nil
		},
		Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
			t.Error("patched an object")
			return nil
		},
	}).Build()

	target := func(kind schema.GroupKind, name string) Target {
		return Target{Kind: kind, Key: types.NamespacedName{Namespace: "shop", Name: name}}
	}
	for _, tc := range []struct {
		in      Integration
		targets []Target
		served  []Target
	}{{
		in: &Traefik{Client: c, APIReader: c},
		targets: []Target{
			target(ingressKind, "web"), target(ingressKind, "other"), target(ingressKind, "missing"),
			target(routeKind, "ir"), target(routeKind, "missing"),
		},
		served: []Target{target(ingressKind, "web"), target(routeKind, "ir")},
	}, {
		in: &EnvoyGateway{Client: c, APIReader: c},
		targets: []Target{
			target(httpRouteKind, "envoy"), target(httpRouteKind, "elsewhere"), target(httpRouteKind, "orphan"), target(httpRouteKind, "missing"),
		},
		served: []Target{target(httpRouteKind, "envoy")},
	}} {
		t.Run(tc.in.Name(), func(t *testing.T) {
			d := Disable(tc.in, "the "+tc.in.Name()+" integration is disabled", c, Config{})
			targets := map[Target]bool{}
			for _, tg := range tc.targets {
				targets[tg] = true
			}
			res, err := d.Wire(ctx, targets, false)
			if err != nil {
				t.Fatal(err)
			}
			if res.Disabled != "the "+tc.in.Name()+" integration is disabled" || len(res.Targets) != len(tc.served) {
				t.Errorf("result %+v, want %v served", res, tc.served)
			}
			for _, tg := range tc.served {
				if s, ok := res.Targets[tg]; !ok || s != (TargetState{}) {
					t.Errorf("%v: %+v, %v; want served, not wired", tg, s, ok)
				}
				if wired, err := d.Wired(ctx, tg); wired || err != nil {
					t.Errorf("%v wired: %v, %v", tg, wired, err)
				}
			}
		})
	}
}

// A target served by a disabled integration is IntegrationDisabled, even
// when another integration of its kind says it doesn't serve it; the other
// targets are unaffected.
func TestProgrammedIntegrationDisabled(t *testing.T) {
	route := func(name string) Target {
		return Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "shop", Name: name}}
	}
	withEngine := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "e"},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}}}
	other := &Result{Proxy: "Other", Pods: []corev1.Pod{withEngine}, Targets: map[Target]TargetState{
		route("envoy"): {Unsupported: "HTTPRoute envoy is served by Gateways of other controllers"},
		route("web"):   {Wired: true},
	}}
	envoy := &Result{Proxy: "envoy-gateway", Disabled: "the envoy-gateway integration is disabled", Targets: map[Target]TargetState{
		route("envoy"): {},
	}}
	rep := &report{kinds: []schema.GroupKind{httpRouteKind, httpRouteKind}, results: []*Result{other, envoy}}
	pol := func(names ...string) *wafv1alpha1.WAFPolicy {
		p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"}}
		for _, n := range names {
			p.Spec.TargetRefs = append(p.Spec.TargetRefs, wafv1alpha1.TargetRef{Group: gatewayv1.GroupName, Kind: "HTTPRoute", Name: n})
		}
		return p
	}
	if st, reason, msg := programmed(pol("web", "envoy"), rep); st != metav1.ConditionFalse || reason != ReasonIntegrationDisabled ||
		!strings.Contains(msg, "envoy-gateway integration is disabled") {
		t.Errorf("served by the disabled integration: %s %s %q", st, reason, msg)
	}
	if st, reason, _ := programmed(pol("web"), rep); st != metav1.ConditionTrue {
		t.Errorf("served by the other: %s %s", st, reason)
	}
}
