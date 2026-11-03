// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package integrations knows the proxies Inkwall wires into (0004 §4.2):
// how to recognise each one's IngressClass or GatewayClass and pods, and
// which engine adapter its pods use: Traefik, Envoy Gateway, Istio and
// the HAProxy Kubernetes Ingress Controller.
package integrations

import (
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Integration is one proxy.
type Integration struct {
	// Name, e.g. "traefik".
	Name string
	// Controller is the IngressClass spec.controller of the proxy, if it
	// serves Ingresses.
	Controller string
	// GatewayController is its GatewayClass spec.controllerName, if it
	// implements the Gateway API.
	GatewayController string
	// PodSelector matches the proxy's data-plane pods by default (the
	// labels its official Helm chart sets); InkwallConfig can override it
	// (Selectors).
	PodSelector labels.Set
	// Adapter is the engine command and its flags for this proxy.
	Adapter []string
}

// Traefik is the Traefik integration: the engine answers its ForwardAuth
// middleware.
var Traefik = Integration{
	Name:              "traefik",
	Controller:        "traefik.io/ingress-controller",
	GatewayController: "traefik.io/gateway-controller",
	PodSelector:       labels.Set{"app.kubernetes.io/name": "traefik"},
	Adapter:           []string{"forward-auth"},
}

// Traefik's kinds (traefik.io/v1alpha1) the operator reads and writes, and
// inkwallctl reads.
var (
	TraefikMiddlewareGVK   = schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "Middleware"}
	TraefikIngressRouteGVK = schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRoute"}
)

// EnvoySocketDir holds the engine's Unix socket in Envoy Gateway's and
// Istio's pods.
const EnvoySocketDir = "/var/run/inkwall-socket"

// EnvoyGateway is the Envoy Gateway integration: the engine, in the Envoy
// pods through the Gateway's EnvoyProxy, answers the ext_proc filter of
// each protected HTTPRoute on a Unix socket.
var EnvoyGateway = Integration{
	Name:              "envoy-gateway",
	GatewayController: "gateway.envoyproxy.io/gatewayclass-controller",
	PodSelector:       labels.Set{"app.kubernetes.io/name": "envoy", "app.kubernetes.io/managed-by": "envoy-gateway"},
	Adapter:           []string{"ext-proc", "--listen=unix:" + EnvoySocketDir + "/extproc.sock"},
}

// Istio is the Istio integration (its Gateway API implementation): the
// engine, in the Gateway's pods through the ConfigMap its parametersRef
// names, answers the ext_proc filter an EnvoyFilter adds for each protected
// HTTPRoute, on a Unix socket.
var Istio = Integration{
	Name:              "istio",
	GatewayController: "istio.io/gateway-controller",
	PodSelector:       labels.Set{"gateway.istio.io/managed": "istio.io-gateway-controller"},
	Adapter:           []string{"ext-proc", "--listen=unix:" + EnvoySocketDir + "/extproc.sock"},
}

// HAProxySocketDir holds the engine's Unix socket in the HAProxy
// Kubernetes Ingress Controller's pods.
const HAProxySocketDir = "/var/run/inkwall-socket"

// HAProxy is the HAProxy Kubernetes Ingress Controller integration: the
// engine, injected into the controller's pods with the SPOE agent's
// configuration, answers the SPOE filter each protected Ingress's backend
// loads (0002 §6.4), on a Unix socket.
var HAProxy = Integration{
	Name:        "haproxy",
	Controller:  "haproxy.org/ingress-controller/haproxy",
	PodSelector: labels.Set{"app.kubernetes.io/name": "kubernetes-ingress"},
	Adapter:     []string{"spoe", "--listen=unix:" + HAProxySocketDir + "/spoe.sock"},
}

// All are the known integrations.
var All = []Integration{Traefik, EnvoyGateway, Istio, HAProxy}

// ForController returns the integration of an IngressClass or GatewayClass
// controller, or nil when Inkwall doesn't know it.
func ForController(controller string) *Integration {
	for i := range All {
		if controller != "" && (All[i].Controller == controller || All[i].GatewayController == controller) {
			return &All[i]
		}
	}
	return nil
}

func byName(name string) *Integration {
	for i := range All {
		if All[i].Name == name {
			return &All[i]
		}
	}
	return nil
}
