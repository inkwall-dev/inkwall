// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package integrations knows the proxies Inkwall wires into (0004 §4.2):
// how to recognise each one's IngressClass and pods, and which engine
// adapter its pods use. Traefik is the first.
package integrations

import (
	"k8s.io/apimachinery/pkg/labels"
)

// Integration is one proxy.
type Integration struct {
	// Name, e.g. "traefik".
	Name string
	// Controller is the IngressClass spec.controller of the proxy.
	Controller string
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
	Name:        "traefik",
	Controller:  "traefik.io/ingress-controller",
	PodSelector: labels.Set{"app.kubernetes.io/name": "traefik"},
	Adapter:     []string{"forward-auth"},
}

// All are the known integrations.
var All = []Integration{Traefik}

// ForController returns the integration of an IngressClass controller, or
// nil when Inkwall doesn't know it.
func ForController(controller string) *Integration {
	for i := range All {
		if All[i].Controller == controller {
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
