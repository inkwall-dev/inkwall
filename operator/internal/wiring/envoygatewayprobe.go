// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// The operator's probe through Envoy Gateway (#604), as through Istio
// (istioprobe.go): Envoy Gateway accepting the operator's
// EnvoyExtensionPolicy shows that it translated the policy, not that Envoy
// runs the filter on the route's traffic (a user's EnvoyPatchPolicy may
// take it off, a translation bug drop it). So a wired route is Programmed
// only once a probe through every Envoy pod of its Gateways, on every
// listener the route is attached to, has reached the engine, and, for a
// policy with responses.inspect, the probe's response leg too (#595).

// Envoy Gateway's names in its Envoy pods, and how it maps a listener's
// port to the Envoy container's.
const (
	// envoyContainer is the Envoy container of an Envoy Gateway pod.
	envoyContainer = "envoy"
	// envoyPortShift is what Envoy Gateway adds to a privileged listener
	// port (below envoyPrivilegedPorts) for the Envoy container, which
	// then needs no capability to bind it, unless the EnvoyProxy sets
	// useListenerPortAsContainerPort.
	envoyPortShift       = 10000
	envoyPrivilegedPorts = 1024
)

// envoyRouteProbes are the probes of a protected HTTPRoute, one job per
// Envoy Gateway Gateway; why says why the route can't be probed, if it
// can't. trafficPolicies are the cluster's ClientTrafficPolicies: one of
// the user's that asks a listener's clients for a certificate makes the
// route not probeable there.
func (st *envoyState) envoyRouteProbes(r *envoyRoute, trafficPolicies []unstructured.Unstructured) ([]ProbeJob, string) {
	return st.httpRouteProbes(r.route, r.sections, r.gateways, gatewayProbes{
		proxy: "Envoy Gateway",
		pods:  st.podsOf,
		port:  envoyListenerPort,
		clientCert: func(gw types.NamespacedName, l gatewayv1.Listener) string {
			return clientValidation(trafficPolicies, gw, l)
		},
	})
}

// envoyListenerPort is the port the Envoy pods of a Gateway serve a
// listener on: Envoy Gateway shifts a privileged port by envoyPortShift,
// unless the EnvoyProxy keeps it (useListenerPortAsContainerPort). The
// Envoy container's ports say which: the listener's own when it lists
// only that one, the shifted one otherwise.
func envoyListenerPort(pods []*corev1.Pod, l gatewayv1.Listener) int32 {
	if l.Port >= envoyPrivilegedPorts {
		return l.Port
	}
	shifted := l.Port + envoyPortShift
	for _, p := range pods {
		for _, c := range p.Spec.Containers {
			if c.Name != envoyContainer {
				continue
			}
			has := func(port int32) bool {
				return slices.ContainsFunc(c.Ports, func(cp corev1.ContainerPort) bool { return cp.ContainerPort == port })
			}
			if has(l.Port) && !has(shifted) {
				return l.Port
			}
			return shifted
		}
	}
	return shifted
}

// clientValidation says which of the user's ClientTrafficPolicies has
// Envoy ask the clients of a Gateway's listener for a certificate
// (tls.clientValidation, not optional), on the Gateway or that listener,
// or "".
func clientValidation(policies []unstructured.Unstructured, gw types.NamespacedName, l gatewayv1.Listener) string {
	for i := range policies {
		p := &policies[i]
		if isManaged(p) || p.GetNamespace() != gw.Namespace {
			continue
		}
		v, ok, _ := unstructured.NestedMap(p.Object, "spec", "tls", "clientValidation")
		if !ok {
			continue
		}
		if optional, _, _ := unstructured.NestedBool(v, "optional"); optional {
			continue
		}
		refs, _, _ := unstructured.NestedSlice(p.Object, "spec", "targetRefs")
		if one, ok, _ := unstructured.NestedMap(p.Object, "spec", "targetRef"); ok {
			refs = append(refs, one)
		}
		if slices.ContainsFunc(refs, func(x any) bool {
			ref, _ := x.(map[string]any)
			group, _ := ref["group"].(string)
			section, _ := ref["sectionName"].(string)
			return ref["kind"] == "Gateway" && ref["name"] == gw.Name && (group == "" || group == gatewayv1.GroupName) &&
				(section == "" || section == string(l.Name))
		}) {
			return "ClientTrafficPolicy " + p.GetName() + "'s tls.clientValidation"
		}
	}
	return ""
}
