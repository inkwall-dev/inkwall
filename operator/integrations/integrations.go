// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package integrations knows the proxies Inkwall wires into (0004 §4.2):
// how to recognise each one's IngressClass or GatewayClass and pods, and
// which engine adapter its pods use: Traefik and Envoy Gateway.
package integrations

import (
	"k8s.io/apimachinery/pkg/labels"
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

// EnvoySocketDir holds the engine's Unix socket in Envoy Gateway's pods.
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

// All are the known integrations.
var All = []Integration{Traefik, EnvoyGateway}

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
