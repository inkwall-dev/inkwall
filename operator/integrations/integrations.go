// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package integrations knows the proxies Inkwall wires into (0004 §4.2):
// how to recognise each one's IngressClass or GatewayClass and pods, and
// which engine adapter its pods use: Traefik, Envoy Gateway, Istio and
// the HAProxy Kubernetes Ingress Controller.
package integrations

import (
	"strings"

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
	// ControllerPrefix, when set, starts the IngressClass spec.controller
	// of the proxy instead, followed by a name of the user's.
	ControllerPrefix string
	// GatewayController is its GatewayClass spec.controllerName, if it
	// implements the Gateway API.
	GatewayController string
	// PodSelector matches the proxy's data-plane pods by default (the
	// labels its official Helm chart sets); InkwallConfig can override it
	// (Selectors).
	PodSelector labels.Set
	// Adapter is the engine command and its flags for this proxy.
	Adapter []string
	// SocketContainer, for a proxy the Pod webhook injects that calls the
	// engine on a Unix socket, is the proxy's container: it mounts the
	// socket's directory (EnvoySocketDir).
	SocketContainer string
	// PodAnnotations are set on the pods the Pod webhook injects, for the
	// proxy's own injector.
	PodAnnotations map[string]string
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

// Istio's own API (networking.istio.io/v1) the operator reads, and
// inkwallctl reads: VirtualServices are targets of the istio-ingress
// integration, bound to Istio's Gateways (not the Gateway API's).
var (
	IstioVirtualServiceGVK = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1", Kind: "VirtualService"}
	IstioGatewayGVK        = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1", Kind: "Gateway"}
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
//
// Its IngressClasses' controller is haproxy.org/ingress-controller/
// followed by its --ingress.class (haproxy by default).
var HAProxy = Integration{
	Name:             "haproxy",
	ControllerPrefix: "haproxy.org/ingress-controller/",
	PodSelector:      labels.Set{"app.kubernetes.io/name": "kubernetes-ingress"},
	Adapter:          []string{"spoe", "--listen=unix:" + HAProxySocketDir + "/spoe.sock"},
}

// IstioIngress is the integration of Istio's ingress gateways, the ones its
// istio/gateway Helm chart deploys, which Istio's own Gateways select and
// VirtualServices bind to: the engine, injected into their pods by the Pod
// webhook, answers the ext_proc filter an EnvoyFilter adds for each
// protected VirtualService, on a Unix socket the istio-proxy container
// mounts. It has no class: Istio's Gateways select pods by label.
var IstioIngress = Integration{
	Name:            "istio-ingress",
	PodSelector:     labels.Set{"istio": "ingressgateway"},
	Adapter:         []string{"ext-proc", "--listen=unix:" + EnvoySocketDir + "/extproc.sock"},
	SocketContainer: "istio-proxy",
	// Istio's injector would point the engine's probes at its agent in
	// istio-proxy, which starts after the engine (a native sidecar): the
	// engine's startup probe could never pass.
	PodAnnotations: map[string]string{"sidecar.istio.io/rewriteAppHTTPProbers": "false"},
}

// All are the known integrations.
var All = []Integration{Traefik, EnvoyGateway, Istio, HAProxy, IstioIngress}

// ForController returns the integration of an IngressClass or GatewayClass
// controller, or nil when Inkwall doesn't know it.
func ForController(controller string) *Integration {
	for i := range All {
		if All[i].ServesIngresses(controller) || controller != "" && All[i].GatewayController == controller {
			return &All[i]
		}
	}
	return nil
}

// ServesIngresses reports whether an IngressClass spec.controller is the
// integration's.
func (i *Integration) ServesIngresses(controller string) bool {
	if i.ControllerPrefix != "" {
		name, ok := strings.CutPrefix(controller, i.ControllerPrefix)
		return ok && name != ""
	}
	return controller != "" && controller == i.Controller
}

func byName(name string) *Integration {
	for i := range All {
		if All[i].Name == name {
			return &All[i]
		}
	}
	return nil
}
