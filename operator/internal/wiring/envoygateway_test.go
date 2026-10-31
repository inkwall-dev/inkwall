// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// userEnvoyProxy is an EnvoyProxy with the user's own init container,
// volume and mount.
func userEnvoyProxy(ns, name string) *unstructured.Unstructured {
	ep := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"logging": map[string]any{"level": map[string]any{"default": "warn"}},
		"provider": map[string]any{"type": "Kubernetes", "kubernetes": map[string]any{"envoyDeployment": map[string]any{
			"replicas":       int64(2),
			"initContainers": []any{map[string]any{"name": "user-init", "image": "busybox"}},
			"pod":            map[string]any{"volumes": []any{map[string]any{"name": "user-vol", "emptyDir": map[string]any{}}}},
			"container":      map[string]any{"volumeMounts": []any{map[string]any{"name": "user-vol", "mountPath": "/user"}}},
		}}},
	}}}
	ep.SetGroupVersionKind(EnvoyProxyGVK)
	ep.SetNamespace(ns)
	ep.SetName(name)
	return ep
}

func names(ep *unstructured.Unstructured, path ...string) string {
	items, _, _ := unstructured.NestedSlice(ep.Object, path...)
	var out []string
	for _, it := range items {
		out = append(out, it.(map[string]any)["name"].(string))
	}
	return strings.Join(out, ",")
}

// The engine goes first among the init containers, its volumes and mount
// after the user's; as the API server returns it, nothing changes; removed,
// the EnvoyProxy is as it was.
func TestWithSidecar(t *testing.T) {
	s := injection.Sidecar{Image: "inkwall-engine:test", OperatorAddr: "inkwall-operator.inkwall-system.svc:9445", BundleSecret: "inkwall-system/inkwall-bundle",
		Args: []string{"ext-proc", "--listen=unix:" + envoySocket}}
	for _, tc := range []struct {
		name string
		ep   *unstructured.Unstructured
	}{
		{"the user's fields", userEnvoyProxy("shop", "custom")},
		{"no provider", func() *unstructured.Unstructured {
			ep := userEnvoyProxy("shop", "bare")
			unstructured.RemoveNestedField(ep.Object, "spec", "provider")
			return ep
		}()},
	} {
		orig := tc.ep.DeepCopy()
		ep := tc.ep
		if changed, err := withSidecar(ep, s, true); err != nil || !changed {
			t.Fatalf("%s: add: %v %v", tc.name, changed, err)
		}
		inits := names(ep, initPath...)
		if !strings.HasPrefix(inits, "inkwall-engine") {
			t.Errorf("%s: init containers %s", tc.name, inits)
		}
		if got := names(ep, mountsPath...); !strings.HasSuffix(got, "inkwall-socket") {
			t.Errorf("%s: mounts %s", tc.name, got)
		}
		if got := names(ep, volumesPath...); !strings.HasSuffix(got, "inkwall-secrets,inkwall-cache,inkwall-tmp,inkwall-socket") {
			t.Errorf("%s: volumes %s", tc.name, got)
		}
		engine, _, _ := unstructured.NestedSlice(ep.Object, initPath...)
		args := engine[0].(map[string]any)["args"].([]any)
		if args[0] != "ext-proc" || args[1] != "--listen=unix:/var/run/inkwall-socket/extproc.sock" {
			t.Errorf("%s: args %v", tc.name, args)
		}
		if engine[0].(map[string]any)["restartPolicy"] != "Always" {
			t.Errorf("%s: not a native sidecar", tc.name)
		}

		// As the API server stores it: JSON numbers, defaults.
		raw, _ := json.Marshal(ep.Object)
		back := &unstructured.Unstructured{}
		if err := back.UnmarshalJSON(raw); err != nil {
			t.Fatal(err)
		}
		// The API server defaults a port's protocol.
		stored, _, _ := unstructured.NestedSlice(back.Object, initPath...)
		stored[0].(map[string]any)["ports"].([]any)[0].(map[string]any)["protocol"] = "TCP"
		_ = unstructured.SetNestedSlice(back.Object, stored, initPath...)
		if changed, err := withSidecar(back, s, true); err != nil || changed {
			t.Errorf("%s: again: %v %v", tc.name, changed, err)
		}
		// A new engine image changes it.
		s2 := s
		s2.Image = "inkwall-engine:new"
		if changed, _ := withSidecar(back.DeepCopy(), s2, true); !changed {
			t.Errorf("%s: a new image didn't change it", tc.name)
		}

		if changed, err := withSidecar(back, injection.Sidecar{}, false); err != nil || !changed {
			t.Fatalf("%s: remove: %v %v", tc.name, changed, err)
		}
		raw, _ = json.Marshal(orig.Object)
		want := &unstructured.Unstructured{}
		_ = want.UnmarshalJSON(raw)
		if !apiequality.Semantic.DeepEqual(back.Object, want.Object) {
			t.Errorf("%s: removed:\n%v\nwant\n%v", tc.name, back.Object, want.Object)
		}
	}
	// Not the operator's: nothing to remove.
	if changed, _ := withSidecar(userEnvoyProxy("shop", "custom"), injection.Sidecar{}, false); changed {
		t.Error("an EnvoyProxy the operator didn't change was changed")
	}
}

func TestExtensionPolicy(t *testing.T) {
	hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "app", UID: "u1"}}
	p := extensionPolicy(&envoyRoute{route: hr, sections: []string{""}, body: true, timeout: 250 * time.Millisecond})
	if p.GetName() != "inkwall-waf-app" || p.GetNamespace() != "shop" || p.GetOwnerReferences()[0].UID != "u1" || !isManaged(p) {
		t.Errorf("metadata %v", p.Object["metadata"])
	}
	spec := p.Object["spec"].(map[string]any)
	ref := spec["targetRefs"].([]any)[0].(map[string]any)
	if ref["kind"] != "HTTPRoute" || ref["name"] != "app" || ref["sectionName"] != nil {
		t.Errorf("targetRefs %v", spec["targetRefs"])
	}
	ep := spec["extProc"].([]any)[0].(map[string]any)
	if ep["messageTimeout"] != "350ms" || ep["failOpen"] != false ||
		ep["processingMode"].(map[string]any)["request"].(map[string]any)["body"] != "BufferedPartial" ||
		ep["processingMode"].(map[string]any)["response"] != nil {
		t.Errorf("extProc %v", ep)
	}
	be := ep["backendRefs"].([]any)[0].(map[string]any)
	if be["kind"] != "Backend" || be["name"] != EnvoyBackend {
		t.Errorf("backendRefs %v", be)
	}

	// Two rules, no body, failing open.
	p = extensionPolicy(&envoyRoute{route: hr, sections: []string{"admin", "login"}, timeout: time.Second, failOpen: true})
	spec = p.Object["spec"].(map[string]any)
	refs := spec["targetRefs"].([]any)
	if len(refs) != 2 || refs[0].(map[string]any)["sectionName"] != "admin" || refs[1].(map[string]any)["sectionName"] != "login" {
		t.Errorf("targetRefs %v", refs)
	}
	ep = spec["extProc"].([]any)[0].(map[string]any)
	if ep["messageTimeout"] != "1.1s" || ep["failOpen"] != true || len(ep["processingMode"].(map[string]any)["request"].(map[string]any)) != 0 {
		t.Errorf("extProc %v", ep)
	}

	b := backend("shop")
	if path, _, _ := unstructured.NestedSlice(b.Object, "spec", "endpoints"); path[0].(map[string]any)["unix"].(map[string]any)["path"] != "/var/run/inkwall-socket/extproc.sock" {
		t.Errorf("Backend %v", b.Object)
	}
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "gw"}}
	if limit, _, _ := unstructured.NestedString(bufferLimit(gw).Object, "spec", "connection", "bufferLimit"); limit != "10Mi" {
		t.Errorf("bufferLimit %q", limit)
	}
}

func TestRouteSettings(t *testing.T) {
	route := types.NamespacedName{Namespace: "shop", Name: "app"}
	pol := func(name string, spec wafv1alpha1.WAFPolicySpec) wafv1alpha1.WAFPolicy {
		spec.TargetRefs = append(spec.TargetRefs, wafv1alpha1.TargetRef{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"})
		return wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: name}, Spec: spec}
	}
	noBody := &wafv1alpha1.BodySpec{Inspect: ptr.To(false)}
	for _, tc := range []struct {
		name     string
		policies []wafv1alpha1.WAFPolicy
		body     bool
		timeout  time.Duration
		failOpen bool
	}{
		{"detect", []wafv1alpha1.WAFPolicy{pol("a", wafv1alpha1.WAFPolicySpec{})}, true, 250 * time.Millisecond, true},
		{"block", []wafv1alpha1.WAFPolicy{pol("a", wafv1alpha1.WAFPolicySpec{Mode: wafv1alpha1.PolicyBlock})}, true, 250 * time.Millisecond, false},
		{"block, failing open, no body", []wafv1alpha1.WAFPolicy{pol("a", wafv1alpha1.WAFPolicySpec{Mode: wafv1alpha1.PolicyBlock, FailureMode: wafv1alpha1.FailOpen, Body: noBody})},
			false, 250 * time.Millisecond, true},
		{"two rules' policies", []wafv1alpha1.WAFPolicy{
			pol("a", wafv1alpha1.WAFPolicySpec{Body: noBody, Timeout: &metav1.Duration{Duration: 800 * time.Millisecond}}),
			pol("b", wafv1alpha1.WAFPolicySpec{FailureMode: wafv1alpha1.FailClosed}),
		}, true, 800 * time.Millisecond, false},
		{"another route's", []wafv1alpha1.WAFPolicy{{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "x"},
			Spec: wafv1alpha1.WAFPolicySpec{Mode: wafv1alpha1.PolicyBlock, TargetRefs: []wafv1alpha1.TargetRef{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "other"}}}}},
			false, 250 * time.Millisecond, true},
	} {
		body, timeout, failOpen := routeSettings(tc.policies, route)
		if body != tc.body || timeout != tc.timeout || failOpen != tc.failOpen {
			t.Errorf("%s: %v %v %v", tc.name, body, timeout, failOpen)
		}
	}
}

func TestEnvoyName(t *testing.T) {
	if n := envoyName("app"); n != "inkwall-waf-app" {
		t.Error(n)
	}
	long := strings.Repeat("a", 253)
	n := envoyName(long)
	if len(n) != 253 || n == envoyName(long[:252]+"b") || !strings.HasPrefix(n, "inkwall-waf-aaa") {
		t.Errorf("%d %s", len(n), n)
	}
}

func jsonOf(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// envoyMapper knows Envoy Gateway's kinds, as an API server with its CRDs.
func envoyMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range []schema.GroupVersionKind{EnvoyProxyGVK, EnvoyExtensionPolicyGVK, BackendGVK, ClientTrafficPolicyGVK, GatewayGVK, HTTPRouteGVK} {
		m.Add(gvk, meta.RESTScopeNamespace)
	}
	m.Add(GatewayClassGVK, meta.RESTScopeRoot)
	return m
}

// Unwired: the operator's objects go, the user's EnvoyProxy loses the
// engine, a Gateway that names the operator's EnvoyProxy names none again;
// the user's own policies stay.
func TestEnvoyUnwire(t *testing.T) {
	ctx := context.Background()
	s := scheme()
	_ = gatewayv1.Install(s)
	sc := injection.Sidecar{Image: "inkwall-engine:test", Args: []string{"ext-proc"}}

	theirs := userEnvoyProxy("edge", "custom")
	before := theirs.DeepCopy()
	if _, err := withSidecar(theirs, sc, true); err != nil {
		t.Fatal(err)
	}
	userGW := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "custom"}, Spec: gatewayv1.GatewaySpec{
		GatewayClassName: "eg", Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: "gateway.envoyproxy.io", Kind: "EnvoyProxy", Name: "custom"}},
	}}
	// A Gateway that had no EnvoyProxy, and one with infrastructure labels.
	ours := newObject(EnvoyProxyGVK, "edge", envoyName("plain"))
	ours.Object["spec"] = map[string]any{}
	if _, err := withSidecar(ours, sc, true); err != nil {
		t.Fatal(err)
	}
	ref := &gatewayv1.LocalParametersReference{Group: "gateway.envoyproxy.io", Kind: "EnvoyProxy", Name: envoyName("plain")}
	plain := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "plain", Annotations: map[string]string{sidecarMark: envoyName("plain")}},
		Spec: gatewayv1.GatewaySpec{GatewayClassName: "eg", Infrastructure: &gatewayv1.GatewayInfrastructure{ParametersRef: ref}}}
	oursLabelled := newObject(EnvoyProxyGVK, "edge", envoyName("labelled"))
	oursLabelled.Object["spec"] = map[string]any{}
	refL := *ref
	refL.Name = envoyName("labelled")
	labelled := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "labelled", Annotations: map[string]string{sidecarMark: envoyName("labelled")}},
		Spec: gatewayv1.GatewaySpec{GatewayClassName: "eg", Infrastructure: &gatewayv1.GatewayInfrastructure{
			Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{"team": "edge"}, ParametersRef: &refL}}}

	hr := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "app"}}
	eep := extensionPolicy(&envoyRoute{route: hr, sections: []string{""}, body: true})
	userEEP := newObject(EnvoyExtensionPolicyGVK, "shop", "lua")
	userEEP.SetLabels(nil)
	be := backend("shop")
	ctp := bufferLimit(plain)

	c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(envoyMapper()).
		WithObjects(theirs, userGW, ours, plain, oursLabelled, labelled, eep, userEEP, be, ctp).Build()
	n, err := (&EnvoyGateway{Client: c, APIReader: c}).Unwire(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if n["EnvoyExtensionPolicy"] != 1 || n["Backend"] != 1 || n["ClientTrafficPolicy"] != 1 || n["EnvoyProxy"] != 3 || n["Gateway"] != 2 {
		t.Errorf("counts %v", n)
	}
	for _, o := range []*unstructured.Unstructured{eep, be, ctp, ours, oursLabelled} {
		got := &unstructured.Unstructured{}
		got.SetGroupVersionKind(o.GroupVersionKind())
		if err := c.Get(ctx, client.ObjectKeyFromObject(o), got); !apierrors.IsNotFound(err) {
			t.Errorf("%s %s not deleted: %v", o.GetKind(), o.GetName(), err)
		}
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(EnvoyProxyGVK)
	if err := c.Get(ctx, client.ObjectKeyFromObject(userEEP), userEEP); err != nil {
		t.Errorf("the user's EnvoyExtensionPolicy: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(theirs), got); err != nil {
		t.Fatal(err)
	}
	if a, b := jsonOf(got.Object["spec"]), jsonOf(before.Object["spec"]); a != b || got.GetAnnotations()[sidecarMark] != "" {
		t.Errorf("the user's EnvoyProxy:\n%s\nwant\n%s", a, b)
	}
	var gw gatewayv1.Gateway
	if err := c.Get(ctx, client.ObjectKeyFromObject(plain), &gw); err != nil || gw.Spec.Infrastructure != nil || gw.Annotations[sidecarMark] != "" {
		t.Errorf("Gateway plain: %v %+v %v", err, gw.Spec.Infrastructure, gw.Annotations)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(labelled), &gw); err != nil || gw.Spec.Infrastructure == nil ||
		gw.Spec.Infrastructure.ParametersRef != nil || gw.Spec.Infrastructure.Labels["team"] != "edge" {
		t.Errorf("Gateway labelled: %v %+v", err, gw.Spec.Infrastructure)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(userGW), &gw); err != nil || gw.Spec.Infrastructure.ParametersRef.Name != "custom" {
		t.Errorf("Gateway custom: %v %+v", err, gw.Spec.Infrastructure)
	}
}

// Rolling: a proxy pod without the engine is being replaced.
func TestProgrammedRolling(t *testing.T) {
	route := Target{Kind: httpRouteKind, Key: types.NamespacedName{Namespace: "shop", Name: "app"}}
	withEngine := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "envoy-gateway-system", Name: "new"},
		Spec: corev1.PodSpec{InitContainers: []corev1.Container{{Name: injection.ContainerName}}}}
	old := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "envoy-gateway-system", Name: "old"}}
	p := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "p"},
		Spec: wafv1alpha1.WAFPolicySpec{TargetRefs: []wafv1alpha1.TargetRef{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute", Name: "app"}}}}
	rep := func(pods ...corev1.Pod) *report {
		return &report{kinds: []schema.GroupKind{httpRouteKind}, results: []*Result{{Proxy: "Envoy Gateway", Rolling: true, Pods: pods,
			Targets: map[Target]TargetState{route: {Wired: true}}}}}
	}
	if st, _, msg := programmed(p, rep(withEngine)); st != metav1.ConditionTrue || msg != "1 HTTPRoute(s) wired to the engine in Envoy Gateway" {
		t.Errorf("%s %q", st, msg)
	}
	if _, reason, msg := programmed(p, rep(withEngine, old)); reason != ReasonPendingRestart || !strings.Contains(msg, "Envoy Gateway is replacing its pods") ||
		!strings.Contains(msg, "envoy-gateway-system/old") {
		t.Errorf("%s %q", reason, msg)
	}
	pending := rep(withEngine)
	pending.results[0].Targets[route] = TargetState{Wired: true, Pending: "waiting for Envoy Gateway to accept ClientTrafficPolicy inkwall-waf-gw"}
	if st, reason, msg := programmed(p, pending); st != metav1.ConditionFalse || reason != ReasonPending || !strings.Contains(msg, "inkwall-waf-gw") {
		t.Errorf("pending: %s %s %q", st, reason, msg)
	}
	if _, reason, msg := programmed(p, rep()); reason != ReasonSidecarMissing || !strings.Contains(msg, "no Envoy Gateway pod of the routes' Gateways") {
		t.Errorf("%s %q", reason, msg)
	}
}

// A Gateway that keeps the engine keeps the operator's EnvoyProxy, even
// before the cache shows the parametersRef just set to it.
func TestRemoveSidecarsKeeps(t *testing.T) {
	ctx := context.Background()
	s := scheme()
	_ = gatewayv1.Install(s)
	ours := newObject(EnvoyProxyGVK, "edge", envoyName("plain"))
	ours.Object["spec"] = map[string]any{}
	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Namespace: "edge", Name: "plain"}, Spec: gatewayv1.GatewaySpec{GatewayClassName: "eg"}}
	c := fake.NewClientBuilder().WithScheme(s).WithRESTMapper(envoyMapper()).WithObjects(ours, gw).Build()
	if _, err := removeSidecars(ctx, c, map[types.NamespacedName]bool{{Namespace: "edge", Name: "plain"}: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(ours), ours); err != nil {
		t.Errorf("the operator's EnvoyProxy was deleted: %v", err)
	}
}
