// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// routeStatus is a parent status of an HTTPRoute for Gateway platform/prod.
func routeStatus(controller string, accepted metav1.ConditionStatus) gatewayv1.RouteParentStatus {
	return gatewayv1.RouteParentStatus{
		ParentRef:      gatewayv1.ParentReference{Name: "prod", Namespace: new(gatewayv1.Namespace("platform"))},
		ControllerName: gatewayv1.GatewayController(controller),
		Conditions: []metav1.Condition{{Type: string(gatewayv1.RouteConditionAccepted), Status: accepted,
			Reason: "NotAllowedByListeners", Message: "no listener allows the route's namespace"}},
	}
}

// The operator changes a Gateway (its EnvoyProxy, its parametersRef, the
// ConfigMap of Istio's) for a protected HTTPRoute only once that Gateway
// accepts the route, as the route's status says, from the Gateway's
// controller: a parentRef alone doesn't make it serve the route. Until
// then the route is not Programmed, and says why.
func TestWiresOnlyGatewaysThatAcceptTheRoute(t *testing.T) {
	for _, proxy := range []struct {
		name, class, controller string
		new                     func(client.Client) Integration
		// injected reports whether the Gateway got the engine.
		injected func(t *testing.T, c client.Client, gw *gatewayv1.Gateway) bool
	}{{
		name: "Envoy Gateway", class: "eg", controller: integrations.EnvoyGateway.GatewayController,
		new: func(c client.Client) Integration {
			return &EnvoyGateway{Client: c, APIReader: c, Pods: labels.Everything(), Sidecar: injection.Sidecar{Image: "inkwall-engine:test"}}
		},
		injected: func(t *testing.T, c client.Client, gw *gatewayv1.Gateway) bool {
			ep := &unstructured.Unstructured{}
			ep.SetGroupVersionKind(EnvoyProxyGVK)
			err := c.Get(context.Background(), types.NamespacedName{Namespace: "platform", Name: envoyName("prod")}, ep)
			if err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
			return gw.Spec.Infrastructure != nil || err == nil
		},
	}, {
		name: "Istio", class: "istio", controller: integrations.Istio.GatewayController,
		new: func(c client.Client) Integration {
			return &Istio{Client: c, APIReader: c, Pods: labels.Everything(), Sidecar: injection.Sidecar{Image: "inkwall-engine:test"}}
		},
		injected: func(t *testing.T, c client.Client, gw *gatewayv1.Gateway) bool {
			err := c.Get(context.Background(), types.NamespacedName{Namespace: "platform", Name: envoyName("prod")}, &corev1.ConfigMap{})
			if err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
			return gw.Spec.Infrastructure != nil || err == nil
		},
	}} {
		for _, tc := range []struct {
			name   string
			status []gatewayv1.RouteParentStatus
			wired  bool
			reason string
		}{
			{name: "no status", reason: "waiting for " + proxy.name + " to accept HTTPRoute decoy on Gateway platform/prod"},
			{name: "not accepted", status: []gatewayv1.RouteParentStatus{routeStatus(proxy.controller, metav1.ConditionFalse)},
				reason: "Gateway platform/prod doesn't accept HTTPRoute decoy (no listener allows the route's namespace)"},
			{name: "accepted by another controller", status: []gatewayv1.RouteParentStatus{routeStatus("example.com/other", metav1.ConditionTrue)},
				reason: "waiting for " + proxy.name},
			{name: "accepted", status: []gatewayv1.RouteParentStatus{routeStatus(proxy.controller, metav1.ConditionTrue)}, wired: true},
		} {
			t.Run(proxy.name+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				s := scheme()
				_ = gatewayv1.Install(s)
				m := envoyMapper().(*meta.DefaultRESTMapper)
				m.Add(EnvoyFilterGVK, meta.RESTScopeNamespace)

				gc := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"controllerName": proxy.controller}}}
				gc.SetGroupVersionKind(GatewayClassGVK)
				gc.SetName(proxy.class)
				same := gatewayv1.NamespacesFromSame
				prod := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "platform", Name: "prod"}, Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(proxy.class),
					Listeners: []gatewayv1.Listener{{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType,
						AllowedRoutes: &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{From: &same}}}},
				}}
				hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "decoy"}, Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "prod", Namespace: new(gatewayv1.Namespace("platform"))}}},
				}, Status: gatewayv1.HTTPRouteStatus{RouteStatus: gatewayv1.RouteStatus{Parents: tc.status}}}
				c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(m).WithObjects(gc, prod, hr).WithStatusSubresource(hr).Build()

				tg := Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "tenant", Name: "decoy"}}
				res, err := proxy.new(c).Wire(ctx, map[Target]bool{tg: true}, false)
				if err != nil {
					t.Logf("wire: %v", err)
				}
				var got gatewayv1.Gateway
				if err := c.Get(ctx, types.NamespacedName{Namespace: "platform", Name: "prod"}, &got); err != nil {
					t.Fatal(err)
				}
				if injected := proxy.injected(t, c, &got); injected != tc.wired {
					t.Errorf("Gateway platform/prod injected: %v, want %v (infrastructure %+v)", injected, tc.wired, got.Spec.Infrastructure)
				}
				st := res.Targets[tg]
				if tc.wired {
					return
				}
				if st.Wired || st.Unsupported != "" || !strings.Contains(st.Pending, tc.reason) {
					t.Errorf("target %+v, want Pending with %q", st, tc.reason)
				}
			})
		}
	}
}
