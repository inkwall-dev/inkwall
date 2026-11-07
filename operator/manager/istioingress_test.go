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
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/operator/internal/wiring"
	"github.com/inkwall-dev/inkwall/operator/test/testenv"
)

// testIstioIngress follows a policy on a VirtualService bound to an Istio
// Gateway that selects Istio's ingress gateway pods: the Pod webhook
// injects the engine into the pods and mounts its socket in istio-proxy;
// the namespace of the pods gets an EnvoyFilter for the protected
// VirtualService once every pod its Gateway selects has the engine; pods
// the webhook can't inject, shared and missing http route names are
// refused; unprotecting removes the EnvoyFilter. Runs after testIstio,
// which installs Istio's CRDs.
func testIstioIngress(ctx context.Context, t *testing.T, c client.Client) {
	// gw is a proxy namespace; far isn't.
	const apps, gw, far = "vs-apps", "istio-gw", "istio-far"
	for _, n := range []string{apps, gw, far} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := testenv.InstallIstio(env); err != nil {
		t.Fatal(err)
	}
	object := func(gvkKind, ns, name, spec string) *unstructured.Unstructured {
		t.Helper()
		var s map[string]any
		if err := yaml.Unmarshal([]byte(spec), &s); err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{Object: map[string]any{"spec": s}}
		u.SetAPIVersion("networking.istio.io/v1")
		u.SetKind(gvkKind)
		u.SetNamespace(ns)
		u.SetName(name)
		return u
	}
	programmed := func(st metav1.ConditionStatus, reason, msg string) func() string {
		return func() string {
			var got wafv1alpha1.WAFPolicy
			if err := c.Get(ctx, client.ObjectKey{Namespace: apps, Name: "vs"}, &got); err != nil {
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
	// filter is the specs of the gateway pods' EnvoyFilters: the base one,
	// which must exist, and its shards (#424).
	filter := func() (string, error) {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(wiring.EnvoyFilterGVK)
		if err := c.Get(ctx, types.NamespacedName{Namespace: gw, Name: "inkwall-istio-ingress"}, u); err != nil {
			return "", err
		}
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(wiring.EnvoyFilterGVK.GroupVersion().WithKind("EnvoyFilterList"))
		if err := c.List(ctx, list, client.InNamespace(gw)); err != nil {
			return "", err
		}
		var specs []string
		for _, f := range list.Items {
			if strings.HasPrefix(f.GetName(), "inkwall-istio-ingress") {
				raw, _ := json.Marshal(f.Object["spec"])
				specs = append(specs, string(raw))
			}
		}
		return strings.Join(specs, "\n"), nil
	}
	filterHas := func(want []string, not ...string) func() string {
		return func() string {
			s, err := filter()
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
	noFilter := func() string {
		if _, err := filter(); !apierrors.IsNotFound(err) {
			return fmt.Sprintf("EnvoyFilter: %v", err)
		}
		return ""
	}

	edge := object("Gateway", gw, "edge", "selector: {istio: ingressgateway}\nservers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: ['*']}]")
	web := object("VirtualService", apps, "web", `
hosts: [shop.example.com]
gateways: [istio-gw/edge]
http:
- name: vs-api
  match: [{uri: {prefix: /api/}}]
  route: [{destination: {host: api}}]
- name: vs-web
  route: [{destination: {host: web}}]
`)
	open := object("VirtualService", apps, "open", "hosts: [open.example.com]\ngateways: [istio-gw/edge]\nhttp: [{name: vs-open, route: [{destination: {host: web}}]}]")
	pol := &wafv1alpha1.WAFPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: apps, Name: "vs"}, Spec: wafv1alpha1.WAFPolicySpec{
		Mode:       wafv1alpha1.PolicyBlock,
		TargetRefs: []wafv1alpha1.TargetRef{{Group: "networking.istio.io", Kind: "VirtualService", Name: "web"}},
	}}
	for _, o := range []client.Object{edge, web, open, pol} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "SidecarMissing without gateway pods", programmed(metav1.ConditionFalse, wiring.ReasonSidecarMissing, "no Istio ingress gateway pod"))

	// The gateway pod: the webhook injects the engine and mounts its
	// socket in istio-proxy.
	gwPod := func(ns, name string, extra map[string]string) *corev1.Pod {
		l := map[string]string{"istio": "ingressgateway", "app": "istio-ingressgateway"}
		for k, v := range extra {
			l[k] = v
		}
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: l},
			Spec: corev1.PodSpec{ServiceAccountName: "istio-ingressgateway", Containers: []corev1.Container{{Name: "istio-proxy", Image: "docker.io/istio/proxyv2:1.31.3"}}}}
	}
	pod := gwPod(gw, "gw-a", nil)
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	if !injection.HasEngine(pod) || !injection.HasSocket(pod, "istio-proxy") {
		t.Fatalf("the gateway pod wasn't injected: %+v %+v", pod.Spec.InitContainers, pod.Spec.Containers)
	}
	eventually(t, "the EnvoyFilter, the protected VirtualService's routes only", filterHas(
		[]string{`"workloadSelector":{"labels":{"istio":"ingressgateway"}}`, `"name":"inkwall.ext_proc.vs.vs-apps.web"`,
			`"route":{"name":"vs-api"}`, `"route":{"name":"vs-web"}`, `"request_body_mode":"BUFFERED_PARTIAL"`},
		"vs-open"))
	eventually(t, "Programmed", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "1 VirtualService(s) wired to the engine in Istio ingress gateway"))

	// A pod opted out of injection: the route isn't wired there.
	optOut := gwPod(gw, "gw-out", map[string]string{injection.InjectLabel: "false"})
	if err := c.Create(ctx, optOut); err != nil {
		t.Fatal(err)
	}
	eventually(t, "not Programmed with a pod without the engine", func() string {
		if programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, "")() == "" {
			return "still Programmed"
		}
		return ""
	})
	eventually(t, "and unwired", noFilter)
	if err := c.Delete(ctx, optOut); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Programmed again", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, ""))

	// A pod the Gateway selects outside the proxy namespaces would serve
	// the route uninspected.
	farPod := gwPod(far, "gw-far", nil)
	if err := c.Create(ctx, farPod); err != nil {
		t.Fatal(err)
	}
	eventually(t, "WiringFailed with a pod outside the proxy namespaces", programmed(metav1.ConditionFalse, wiring.ReasonWiringFailed, "istio-far/gw-far"))
	if err := c.Delete(ctx, farPod); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Programmed without it", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, ""))

	// Another VirtualService on the same pods with a protected route's name.
	twin := object("VirtualService", apps, "twin", "hosts: [twin.example.com]\ngateways: [istio-gw/edge]\nhttp: [{name: vs-api, route: [{destination: {host: web}}]}]")
	if err := c.Create(ctx, twin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "WiringFailed on a shared route name", programmed(metav1.ConditionFalse, wiring.ReasonWiringFailed, "http route vs-api of VirtualService web has the name of one of VirtualService vs-apps/twin"))
	eventually(t, "and not wired", noFilter)
	if err := c.Delete(ctx, twin); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Programmed once renamed", programmed(metav1.ConditionTrue, wiring.ReasonProgrammed, ""))

	// Detect mode: Envoy doesn't wait for the engine.
	update(ctx, t, c, pol, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyDetect })
	eventually(t, "detect mode", filterHas([]string{`"observability_mode":true`, `"request_body_mode":"STREAMED"`}, "per_connection_buffer_limit_bytes"))

	// Unprotected: the EnvoyFilter goes.
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventually(t, "EnvoyFilter deleted", noFilter)
	eventually(t, "the policy released", func() string {
		if err := c.Get(ctx, client.ObjectKeyFromObject(pol), &wafv1alpha1.WAFPolicy{}); !apierrors.IsNotFound(err) {
			return fmt.Sprint(err)
		}
		return ""
	})
	for _, o := range []client.Object{web, open, edge} {
		if err := c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.DeleteAllOf(ctx, &corev1.Pod{}, client.InNamespace(gw)); err != nil {
		t.Fatal(err)
	}
}
