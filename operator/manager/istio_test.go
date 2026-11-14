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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// testIstio follows a policy on HTTPRoutes that Istio's Gateways serve:
// nothing is wired without Istio's EnvoyFilter CRD; once installed, the
// engine goes into the Gateways' deployment overlay (the user's ConfigMap,
// keeping their fields, or one the operator makes and names), each Gateway
// gets an EnvoyFilter for its protected routes once every pod of it has
// the engine, the policy is Programmed once Istio accepts the routes, and
// unprotecting puts everything back as it was. Runs after
// testHTTPRoutes, which installs the Gateway API's CRDs.
func testIstio(ctx context.Context, t *testing.T, c client.Client) {
	// edge is a proxy namespace: Istio runs a Gateway's pods in its
	// namespace.
	const ns, edge = "istio-apps", "istio-edge"
	for _, n := range []string{ns, edge} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err != nil {
			t.Fatal(err)
		}
	}
	programmed := func(st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "istio"}, &got); err != nil {
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
	filter := func(gw string) (string, error) {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(wiring.EnvoyFilterGVK)
		if err := c.Get(ctx, types.NamespacedName{Namespace: edge, Name: "inkwall-waf-" + gw}, u); err != nil {
			return "", err
		}
		raw, _ := json.Marshal(u.Object["spec"])
		return string(raw), nil
	}
	filterHas := func(gw string, want []string, not ...string) func() string {
		return func() string {
			s, err := filter(gw)
			if err != nil {
				return err.Error()
			}
			for _, w := range want {
				if !strings.Contains(s, w) {
					return "no " + w + " in " + s
				}
			}
			for _, n := range not {
				if strings.Contains(s, n) {
					return n + " in " + s
				}
			}
			return ""
		}
	}
	noFilter := func(gw string) func() string {
		return func() string {
			if _, err := filter(gw); !apierrors.IsNotFound(err) {
				return fmt.Sprintf("EnvoyFilter of %s: %v", gw, err)
			}
			return ""
		}
	}

	// Istio's class, a Gateway naming the user's ConfigMap, one naming
	// none, and a route on each.
	class := &gatewayv1.GatewayClass{ObjectMeta: metav1.ObjectMeta{Name: "istio"}, Spec: gatewayv1.GatewayClassSpec{ControllerName: "istio.io/gateway-controller"}}
	listeners := []gatewayv1.Listener{{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80}}
	const userOverlay = "# the user's\nspec:\n  replicas: 2\n"
	params := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "custom-params"}, Data: map[string]string{"deployment": userOverlay}}
	custom := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "custom"}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "istio", Listeners: listeners,
		Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: "", Kind: "ConfigMap", Name: "custom-params"}},
	}}
	plain := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: "plain"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "istio", Listeners: listeners}}
	route := func(name, gw string, rules ...string) *gatewayv1.HTTPRoute {
		hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw), Namespace: new(gatewayv1.Namespace(edge))}}},
			Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(name + ".example.com")},
		}}
		for _, r := range rules {
			rule := gatewayv1.HTTPRouteRule{}
			if r != "" {
				rule.Name = new(gatewayv1.SectionName(r))
			}
			hr.Spec.Rules = append(hr.Spec.Rules, rule)
		}
		return hr
	}
	app, api := route("app", "custom", ""), route("api", "plain", "admin", "public")
	for _, o := range []client.Object{class, params, custom, plain, app, api} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "istio"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode: wafv1alpha1.PolicyBlock,
		TargetRefs: []wafv1alpha1.TargetRef{
			{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"},
			{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "api", SectionName: "admin"},
		},
	}}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}

	// No EnvoyFilter CRD: nothing wired, said so.
	eventually(t, "WiringFailed without the CRD", programmed(metav1.ConditionFalse, wiring.ReasonWiringFailed, "Istio's EnvoyFilter CRD"))
	var cm corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKeyFromObject(params), &cm); err != nil || cm.Data["deployment"] != userOverlay {
		t.Fatalf("the user's ConfigMap changed without the CRD: %v %v", err, cm.Data)
	}

	// Installed: the user's ConfigMap gets the engine, their fields kept;
	// the other Gateway names the operator's.
	if err := testenv.InstallIstio(env); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the user's ConfigMap has the engine", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, client.ObjectKeyFromObject(params), &cm); err != nil {
			return err.Error()
		}
		if d := cm.Data["deployment"]; !strings.Contains(d, "replicas: 2") || !strings.Contains(d, "name: inkwall-engine") || !strings.Contains(d, "name: istio-proxy") {
			return d
		}
		return ""
	})
	eventually(t, "Gateway plain names the operator's ConfigMap", func() string {
		var gw gatewayv1.Gateway
		if err := c.Get(ctx, client.ObjectKeyFromObject(plain), &gw); err != nil {
			return err.Error()
		}
		if i := gw.Spec.Infrastructure; i == nil || i.ParametersRef == nil || i.ParametersRef.Name != "inkwall-waf-plain" || i.ParametersRef.Kind != "ConfigMap" {
			return fmt.Sprintf("infrastructure %+v", i)
		}
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: edge, Name: "inkwall-waf-plain"}, &cm); err != nil {
			return err.Error()
		}
		if !strings.Contains(cm.Data["deployment"], "inkwall-engine") || len(cm.OwnerReferences) != 1 || cm.OwnerReferences[0].Name != "plain" {
			return fmt.Sprintf("%v %v", cm.Data, cm.OwnerReferences)
		}
		return ""
	})
	eventually(t, "SidecarMissing without Istio pods", programmed(metav1.ConditionFalse, wiring.ReasonSidecarMissing, "no Istio pod"))
	if _, err := filter("custom"); !apierrors.IsNotFound(err) {
		t.Fatalf("wired before the pods have the engine: %v", err)
	}

	// The Gateways' pods, one from before the engine (Istio is replacing
	// it): still not wired there.
	istioPod := func(gw, name string, engine bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: edge, Name: name, Labels: map[string]string{
			"gateway.istio.io/managed": "istio.io-gateway-controller", "gateway.networking.k8s.io/gateway-name": gw,
		}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.31.3"}}}}
		if engine {
			p.Spec.InitContainers = []corev1.Container{{Name: injection.ContainerName, Image: "inkwall-engine:test"}}
		}
		return p
	}
	old := istioPod("custom", "custom-old", false)
	for i, p := range []*corev1.Pod{old, istioPod("custom", "custom-new", true), istioPod("plain", "plain-a", true)} {
		if err := c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		// An address, for the operator's probe (#372; the test's prober
		// answers as the engine would).
		p.Status.PodIP = fmt.Sprintf("10.0.0.%d", 21+i)
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "PendingRestart while Istio replaces a pod", programmed(metav1.ConditionFalse, wiring.ReasonPendingRestart, "istio-edge/custom-old"))
	// The Gateway whose pods all have it is wired: its protected rule only.
	eventually(t, "Gateway plain's EnvoyFilter, one rule", filterHas("plain",
		[]string{`"name":"inkwall.ext_proc.istio-apps.api"`, `"route":{"name":"admin"}`, `"request_body_mode":"BUFFERED_PARTIAL"`, `"per_connection_buffer_limit_bytes":10485760`},
		"public"))
	if _, err := filter("custom"); !apierrors.IsNotFound(err) {
		t.Fatalf("Gateway custom wired while a pod lacks the engine: %v", err)
	}
	if err := c.Delete(ctx, old); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Gateway custom's EnvoyFilter, the whole route", filterHas("custom", []string{`"route":{"name":"istio-apps.app.0"}`}))

	// Wired, in force once Istio accepts the routes on their Gateways.
	eventually(t, "Pending until Istio accepts the routes", programmed(metav1.ConditionFalse, wiring.ReasonPending, "waiting for Istio to accept HTTPRoute"))
	accept := func(hr *gatewayv1.HTTPRoute, gw string, status metav1.ConditionStatus) {
		t.Helper()
		update(ctx, t, c, hr, func(hr *gatewayv1.HTTPRoute) {
			hr.Status.Parents = []gatewayv1.RouteParentStatus{{
				ParentRef:      gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gw), Namespace: new(gatewayv1.Namespace(edge))},
				ControllerName: "istio.io/gateway-controller",
				Conditions: []metav1.Condition{{Type: "Accepted", Status: status, Reason: "Accepted", Message: "Route was valid",
					LastTransitionTime: metav1.Now(), ObservedGeneration: hr.Generation}},
			}}
		})
	}
	accept(app, "custom", metav1.ConditionTrue)
	eventually(t, "Pending on the other route", programmed(metav1.ConditionFalse, wiring.ReasonPending, "HTTPRoute api on Gateway istio-edge/plain"))
	accept(api, "plain", metav1.ConditionTrue)
	eventually(t, "Programmed", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s) wired to the engine in Istio"))
	eventually(t, "the trust ConfigMap for the Gateways' pods", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Namespace: edge, Name: injection.TrustConfigMap}, &cm); err != nil {
			return err.Error()
		}
		return ""
	})

	// Another route of the Gateway with a rule of a protected rule's name:
	// Istio names Envoy's routes after the rule, so it would be wired too.
	twin := route("twin", "plain", "admin")
	if err := c.Create(ctx, twin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "WiringFailed on a shared rule name", programmed(metav1.ConditionFalse, wiring.ReasonWiringFailed, "rule admin of HTTPRoute api has the name of a rule of HTTPRoute istio-apps/twin"))
	eventually(t, "and not wired", noFilter("plain"))
	if err := c.Delete(ctx, twin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Programmed once renamed", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s)"))

	// A Gateway outside the proxy namespaces: its pods get no engine, the
	// route isn't wired there, nor Programmed, but stays wired on its
	// other Gateway.
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "istio-elsewhere"}}); err != nil {
		t.Fatal(err)
	}
	elsewhere := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "istio-elsewhere", Name: "far"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "istio", Listeners: listeners}}
	if err := c.Create(ctx, elsewhere); err != nil {
		t.Fatal(err)
	}
	farPod := istioPod("far", "far-a", true)
	farPod.Namespace = "istio-elsewhere"
	if err := c.Create(ctx, farPod); err != nil {
		t.Fatal(err)
	}
	update(ctx, t, c, app, func(hr *gatewayv1.HTTPRoute) {
		hr.Spec.ParentRefs = append(hr.Spec.ParentRefs, gatewayv1.ParentReference{Name: "far", Namespace: new(gatewayv1.Namespace("istio-elsewhere"))})
	})
	eventually(t, "Pending on a Gateway outside the proxy namespaces", programmed(metav1.ConditionFalse, wiring.ReasonPending, "Gateway istio-elsewhere/far has no running Istio pod"))
	// Still inspected on the Gateway that has the engine.
	if s, err := filter("custom"); err != nil || !strings.Contains(s, "inkwall.ext_proc.istio-apps.app") {
		t.Fatalf("the route left its ready Gateway: %v %s", err, s)
	}
	update(ctx, t, c, app, func(hr *gatewayv1.HTTPRoute) { hr.Spec.ParentRefs = hr.Spec.ParentRefs[:1] })
	for _, o := range []client.Object{farPod, elsewhere} {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "the far Gateway left as it was", func() string {
		var gw gatewayv1.Gateway
		if err := c.Get(ctx, client.ObjectKeyFromObject(elsewhere), &gw); err != nil && !apierrors.IsNotFound(err) {
			return err.Error()
		}
		return ""
	})
	eventually(t, "Programmed again", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s)"))

	// Responses (#595): the probe's response leg proves they reach the
	// engine, answered in its response phase on every pod. An engine that
	// answers it at the request phase doesn't keep the route's responses:
	// ResponsesNotInspected, naming the pod.
	t.Cleanup(func() { earlyPods.Delete(edge + "/plain-a") })
	earlyPods.Store(edge+"/plain-a", true)
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Responses = &wafv1alpha1.ResponsesSpec{Inspect: true} })
	eventually(t, "responses: the filter sends them", filterHas("custom", []string{`"response_header_mode":"SEND"`}))
	eventually(t, "responses not reaching an engine: ResponsesNotInspected", programmed(metav1.ConditionFalse, wiring.ReasonResponsesNotInspected,
		"don't reach the engine on Istio: pod "+edge+"/plain-a"))
	earlyPods.Delete(edge + "/plain-a")
	eventually(t, "Programmed once the response leg is answered", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s)"))

	// Detect mode: Envoy doesn't wait for the engine, nor holds the body.
	// Envoy discards the engine's answer to the probe in observability
	// mode: the route is proven by the receipts the Gateways' engines
	// report (#475), through the operator's distribution server and its
	// engine report; its responses by the receipts of the response leg
	// (#595), which an engine that doesn't keep them never reports.
	stopEngines := observeProbes(ctx, t, c, edge+"/custom-new", edge+"/plain-a")
	earlyPods.Store(edge+"/plain-a", true)
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyDetect })
	eventually(t, "detect mode: observability_mode, a streamed body, no buffer limit", filterHas("custom",
		[]string{`"observability_mode":true`, `"request_body_mode":"STREAMED"`, `"failure_mode_allow":true`}, "per_connection_buffer_limit_bytes", "BUFFERED_PARTIAL"))
	eventually(t, "detect mode: no receipt of the response, ResponsesNotInspected", programmed(metav1.ConditionFalse, wiring.ReasonResponsesNotInspected,
		"no receipt of the probe's response"))
	earlyPods.Delete(edge + "/plain-a")
	eventually(t, "Programmed in detect mode by the engines' probe receipts", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "2 HTTPRoute(s)"))
	stopEngines()

	// Unprotected: everything goes, the user's objects as they were.
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	for _, gw := range []string{"custom", "plain"} {
		eventually(t, "EnvoyFilter of "+gw+" deleted", noFilter(gw))
	}
	eventually(t, "the user's ConfigMap as it was", func() string {
		var cm corev1.ConfigMap
		if err := c.Get(ctx, client.ObjectKeyFromObject(params), &cm); err != nil {
			return err.Error()
		}
		if cm.Data["deployment"] != userOverlay || len(cm.Labels) > 0 || len(cm.Annotations) > 0 {
			return fmt.Sprintf("%q %v %v", cm.Data["deployment"], cm.Labels, cm.Annotations)
		}
		return ""
	})
	eventually(t, "the operator's ConfigMap deleted", func() string {
		if err := c.Get(ctx, types.NamespacedName{Namespace: edge, Name: "inkwall-waf-plain"}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
			return fmt.Sprint(err)
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
	for _, o := range []client.Object{app, api, custom, plain, class, params} {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(edge)); err != nil {
		t.Fatal(err)
	}
}
