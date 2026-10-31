// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// testEnvoyGateway follows a policy on HTTPRoutes that Envoy Gateway
// serves: nothing is wired without Envoy Gateway's CRDs; once installed,
// the engine goes into the Gateways' EnvoyProxy (the user's, keeping their
// fields, or one the operator makes), the routes get an
// EnvoyExtensionPolicy once every Envoy pod has the engine, and
// unprotecting puts everything back as it was. Runs after testHTTPRoutes,
// which installs the Gateway API's CRDs.
func testEnvoyGateway(ctx context.Context, t *testing.T, c client.Client) {
	const ns, edge = "eg-apps", "eg-edge"
	for _, n := range []string{ns, edge} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err != nil {
			t.Fatal(err)
		}
	}
	programmed := func(name string, st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &got); err != nil {
				return err.Error()
			}
			cnd := meta.FindStatusCondition(got.Status.Conditions, wafv1alpha1.ConditionProgrammed)
			if cnd == nil {
				return "no Programmed"
			}
			if cnd.Status != st || cnd.Reason != reason || !strings.Contains(cnd.Message, msg) {
				return string(cnd.Status) + " " + cnd.Reason + ": " + cnd.Message
			}
			return ""
		}
	}
	get := func(gvk schema.GroupVersionKind, namespace, name string) (*unstructured.Unstructured, error) {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvk)
		return u, c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, u)
	}
	gone := func(gvk schema.GroupVersionKind, namespace, name string) func() string {
		return func() string {
			if _, err := get(gvk, namespace, name); !apierrors.IsNotFound(err) {
				return fmt.Sprintf("%s %s/%s: %v", gvk.Kind, namespace, name, err)
			}
			return ""
		}
	}
	// specJSON is an object's spec, for comparing.
	specJSON := func(u *unstructured.Unstructured) string {
		raw, _ := json.Marshal(u.Object["spec"])
		return string(raw)
	}

	// Envoy Gateway's class, a Gateway naming the user's EnvoyProxy, one
	// naming none, and a route on each.
	class := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "eg"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: "gateway.envoyproxy.io/gatewayclass-controller"}}
	listeners := []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80}}
	custom := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "custom"}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "eg", Listeners: listeners,
		Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: "gateway.envoyproxy.io", Kind: "EnvoyProxy", Name: "custom"}},
	}}
	plain := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "plain"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "eg", Listeners: listeners}}
	route := func(name, gw string, rules ...string) *gatewayv1.HTTPRoute {
		hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw), Namespace: new(gatewayv1.Namespace(edge))}}},
			Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(name + ".example.com")},
		}}
		for _, r := range rules {
			hr.Spec.Rules = append(hr.Spec.Rules, gatewayv1.HTTPRouteRule{Name: new(gatewayv1.SectionName(r))})
		}
		return hr
	}
	app, api := route("app", "custom", "web"), route("api", "plain", "admin", "public")
	for _, o := range []client.Object{class, custom, plain, app, api} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "eg"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock,
		TargetRefs: []wafv1alpha1.TargetRef{
			{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"},
			{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "api", SectionName: "admin"},
		},
	}}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// No Envoy Gateway CRDs: nothing wired, said so.
	eventually(t, "WiringFailed without the CRDs", programmed("eg", metav1.ConditionFalse, wiring.ReasonWiringFailed, "Envoy Gateway's CRDs"))

	// Installed, with the user's EnvoyProxy: it gets the engine, their
	// fields kept.
	if err := testenv.InstallEnvoyGateway(env); err != nil {
		t.Fatal(err)
	}
	theirs := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"provider": map[string]any{
		"type": "Kubernetes", "kubernetes": map[string]any{"envoyDeployment": map[string]any{
			"replicas": int64(2),
			"pod":      map[string]any{"volumes": []any{map[string]any{"name": "user-vol", "emptyDir": map[string]any{}}}},
		}},
	}}}}
	theirs.SetGroupVersionKind(wiring.EnvoyProxyGVK)
	theirs.SetNamespace(edge)
	theirs.SetName("custom")
	if err := c.Create(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	before := specJSON(theirs)
	eventually(t, "the user's EnvoyProxy has the engine", func() string {
		ep, err := get(wiring.EnvoyProxyGVK, edge, "custom")
		if err != nil {
			return err.Error()
		}
		inits, _, _ := unstructured.NestedSlice(ep.Object, "spec", "provider", "kubernetes", "envoyDeployment", "initContainers")
		vols, _, _ := unstructured.NestedSlice(ep.Object, "spec", "provider", "kubernetes", "envoyDeployment", "pod", "volumes")
		mounts, _, _ := unstructured.NestedSlice(ep.Object, "spec", "provider", "kubernetes", "envoyDeployment", "container", "volumeMounts")
		replicas, _, _ := unstructured.NestedInt64(ep.Object, "spec", "provider", "kubernetes", "envoyDeployment", "replicas")
		if len(inits) != 1 || inits[0].(map[string]any)["name"] != injection.ContainerName || len(vols) != 5 || vols[0].(map[string]any)["name"] != "user-vol" ||
			len(mounts) != 1 || replicas != 2 {
			return specJSON(ep)
		}
		return ""
	})
	// The other Gateway names the operator's EnvoyProxy.
	ours := "inkwall-waf-plain"
	eventually(t, "the operator's EnvoyProxy for Gateway plain", func() string {
		var gw gatewayv1.Gateway
		if err := c.Get(ctx, client.ObjectKeyFromObject(plain), &gw); err != nil {
			return err.Error()
		}
		if i := gw.Spec.Infrastructure; i == nil || i.ParametersRef == nil || i.ParametersRef.Name != ours {
			return fmt.Sprintf("infrastructure %+v", i)
		}
		if _, err := get(wiring.EnvoyProxyGVK, edge, ours); err != nil {
			return err.Error()
		}
		return ""
	})
	// No Envoy pod yet: the routes aren't wired.
	eventually(t, "SidecarMissing without Envoy pods", programmed("eg", metav1.ConditionFalse, wiring.ReasonSidecarMissing, "no Envoy Gateway pod"))
	if _, err := get(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app"); !apierrors.IsNotFound(err) {
		t.Fatalf("wired before the pods have the engine: %v", err)
	}

	// Envoy pods, one from before the engine (Envoy Gateway is replacing
	// it): still not wired.
	envoyPod := func(gw, name string, engine bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "eg-system", Name: name, Labels: map[string]string{
			"app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway", "app.kubernetes.io/component": "proxy",
			"gateway.envoyproxy.io/owning-gateway-name": gw, "gateway.envoyproxy.io/owning-gateway-namespace": edge,
		}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "envoy", Image: "envoy"}}}}
		if engine {
			p.Spec.InitContainers = []corev1.Container{{Name: injection.ContainerName, Image: "inkwall-engine:test"}}
		}
		return p
	}
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "eg-system"}}); err != nil {
		t.Fatal(err)
	}
	old := envoyPod("custom", "envoy-custom-old", false)
	for _, p := range []*corev1.Pod{old, envoyPod("custom", "envoy-custom-new", true), envoyPod("plain", "envoy-plain", true)} {
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "PendingRestart while Envoy Gateway replaces a pod", programmed("eg", metav1.ConditionFalse, wiring.ReasonPendingRestart, "eg-system/envoy-custom-old"))
	// The Gateway whose pods all have it is wired.
	eventually(t, "Gateway plain's route wired, one rule", func() string {
		p, err := get(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-api")
		if err != nil {
			return err.Error()
		}
		if s := specJSON(p); !strings.Contains(s, `"sectionName":"admin"`) || strings.Contains(s, "public") || !strings.Contains(s, `"body":"BufferedPartial"`) {
			return s
		}
		return ""
	})
	if _, err := get(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app"); !apierrors.IsNotFound(err) {
		t.Fatalf("Gateway custom's route wired while a pod lacks the engine: %v", err)
	}
	if err := c.Delete(ctx, old); err != nil {
		t.Fatal(err)
	}
	// Wired, in force once Envoy Gateway accepts the policies.
	eventually(t, "Pending until Envoy Gateway accepts them", programmed("eg", metav1.ConditionFalse, wiring.ReasonPending, "waiting for Envoy Gateway to accept"))
	accept := func(gvk schema.GroupVersionKind, namespace, name, status, msg string) {
		t.Helper()
		u, err := get(gvk, namespace, name)
		if err != nil {
			t.Fatal(err)
		}
		update(ctx, t, c, u, func(u *unstructured.Unstructured) {
			_ = unstructured.SetNestedSlice(u.Object, []any{map[string]any{"conditions": []any{map[string]any{
				"type": "Accepted", "status": status, "reason": "Test", "message": msg,
			}}}}, "status", "ancestors")
		})
	}
	accept(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app", "True", "")
	accept(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-api", "True", "")
	accept(wiring.ClientTrafficPolicyGVK, edge, "inkwall-waf-custom", "True", "")
	eventually(t, "Pending on the other buffer limit", programmed("eg", metav1.ConditionFalse, wiring.ReasonPending, "ClientTrafficPolicy inkwall-waf-plain"))
	accept(wiring.ClientTrafficPolicyGVK, edge, "inkwall-waf-plain", "True", "")
	eventually(t, "Programmed", programmed("eg", metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s) wired to the engine in Envoy Gateway"))
	for _, o := range []struct {
		gvk             schema.GroupVersionKind
		namespace, name string
	}{
		{wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app"},
		{wiring.BackendGVK, ns, wiring.EnvoyBackend},
		{wiring.ClientTrafficPolicyGVK, edge, "inkwall-waf-custom"},
		{wiring.ClientTrafficPolicyGVK, edge, "inkwall-waf-plain"},
	} {
		if _, err := get(o.gvk, o.namespace, o.name); err != nil {
			t.Errorf("%s %s/%s: %v", o.gvk.Kind, o.namespace, o.name, err)
		}
	}
	// The trust ConfigMap is in the Envoy pods' namespace.
	eventually(t, "the trust ConfigMap for the Envoy pods", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: "eg-system", Name: injection.TrustConfigMap}, &cm); err != nil {
			return err.Error()
		}
		return ""
	})

	// Envoy Gateway refuses a policy: reported.
	accept(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app", "False", "Backend is disabled")
	eventually(t, "WiringFailed when Envoy Gateway refuses it", programmed("eg", metav1.ConditionFalse, wiring.ReasonWiringFailed, "Backend is disabled"))
	accept(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app", "True", "")
	eventually(t, "Programmed again", programmed("eg", metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s)"))

	// Detect mode: Envoy doesn't wait for the engine, nor buffers the body.
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyDetect })
	eventually(t, "detect mode: shadowMode, a streamed body", func() string {
		p, err := get(wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app")
		if err != nil {
			return err.Error()
		}
		if s := specJSON(p); !strings.Contains(s, `"shadowMode":true`) || !strings.Contains(s, `"body":"Streamed"`) {
			return s
		}
		return ""
	})
	eventually(t, "no buffer limit in detect mode", gone(wiring.ClientTrafficPolicyGVK, edge, "inkwall-waf-plain"))
	eventually(t, "Programmed in detect mode", programmed("eg", metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s)"))

	// Unprotected: everything goes, the user's objects as they were.
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	for _, o := range []struct {
		gvk             schema.GroupVersionKind
		namespace, name string
	}{
		{wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-app"},
		{wiring.EnvoyExtensionPolicyGVK, ns, "inkwall-waf-api"},
		{wiring.BackendGVK, ns, wiring.EnvoyBackend},
		{wiring.ClientTrafficPolicyGVK, edge, "inkwall-waf-custom"},
		{wiring.EnvoyProxyGVK, edge, ours},
	} {
		eventually(t, o.gvk.Kind+" "+o.name+" deleted", gone(o.gvk, o.namespace, o.name))
	}
	eventually(t, "the user's EnvoyProxy as it was", func() string {
		ep, err := get(wiring.EnvoyProxyGVK, edge, "custom")
		if err != nil {
			return err.Error()
		}
		if s := specJSON(ep); s != before || len(ep.GetAnnotations()) > 0 {
			return s
		}
		return ""
	})
	eventually(t, "Gateway plain as it was", func() string {
		var gw gatewayv1.Gateway
		if err := c.Get(ctx, client.ObjectKeyFromObject(plain), &gw); err != nil {
			return err.Error()
		}
		if gw.Spec.Infrastructure != nil || len(gw.Annotations) > 0 {
			return fmt.Sprintf("%+v %v", gw.Spec.Infrastructure, gw.Annotations)
		}
		return ""
	})
	eventually(t, "the policy released", func() string {
		if err := c.Get(ctx, client.ObjectKeyFromObject(pol), &wafv1alpha1.WAFPolicy{}); !apierrors.IsNotFound(err) {
			return fmt.Sprint(err)
		}
		return ""
	})
	for _, o := range []client.Object{app, api, custom, plain, class} {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace("eg-system")); err != nil {
		t.Fatal(err)
	}
}
