// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Selectors are the pod selectors in effect, by integration: each one's
// default, or InkwallConfig.spec.integrations[].selector. The operator
// reads them when it starts, since its cache of proxy pods is built from
// them. A nil *Selectors is the defaults.
type Selectors struct {
	byName map[string]*metav1.LabelSelector
}

// Defaults are the integrations' own selectors.
func Defaults() *Selectors {
	s := &Selectors{byName: map[string]*metav1.LabelSelector{}}
	for _, i := range All {
		s.byName[i.Name] = &metav1.LabelSelector{MatchLabels: maps.Clone(map[string]string(i.PodSelector))}
	}
	return s
}

// FromConfig applies the overrides of an InkwallConfig's integrations. It
// returns the controllers it ignored, which Inkwall doesn't integrate yet.
func FromConfig(specs []wafv1alpha1.IntegrationSpec) (*Selectors, []string, error) {
	s := Defaults()
	var ignored []string
	for _, spec := range specs {
		if spec.Selector == nil {
			continue
		}
		if byName(spec.Controller) == nil {
			ignored = append(ignored, spec.Controller)
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(spec.Selector)
		if err != nil {
			return nil, nil, fmt.Errorf("integration %s: selector: %w", spec.Controller, err)
		}
		// An empty selector would inject the engine into every pod.
		if sel.Empty() {
			return nil, nil, fmt.Errorf("integration %s: the selector selects every pod", spec.Controller)
		}
		s.byName[spec.Controller] = spec.Selector.DeepCopy()
	}
	return s, ignored, nil
}

func (s *Selectors) get(name string) *metav1.LabelSelector {
	if s == nil {
		s = Defaults()
	}
	return s.byName[name]
}

// LabelSelector returns an integration's selector, for the Pod webhook's
// objectSelector.
func (s *Selectors) LabelSelector(name string) *metav1.LabelSelector {
	return s.get(name).DeepCopy()
}

// Selector returns an integration's selector.
func (s *Selectors) Selector(name string) labels.Selector {
	sel, err := metav1.LabelSelectorAsSelector(s.get(name))
	if err != nil {
		// FromConfig checked it.
		return labels.Nothing()
	}
	return sel
}

// PodSelector matches the pods of every integration, for the operator's
// cache and the controllers' lists. A label selector can't express a union
// of selectors with different keys; with Traefik the only integration, it
// is Traefik's.
func (s *Selectors) PodSelector() labels.Selector {
	return s.Selector(Traefik.Name)
}

// ForPod returns the integration whose pods carry podLabels, or nil.
func (s *Selectors) ForPod(podLabels map[string]string) *Integration {
	for i := range All {
		if s.Selector(All[i].Name).Matches(labels.Set(podLabels)) {
			return &All[i]
		}
	}
	return nil
}

// Equal reports whether s and o select the same pods.
func (s *Selectors) Equal(o *Selectors) bool {
	if s == nil {
		s = Defaults()
	}
	if o == nil {
		o = Defaults()
	}
	return apiequality.Semantic.DeepEqual(s.byName, o.byName)
}

// String lists the selectors, for logs.
func (s *Selectors) String() string {
	if s == nil {
		s = Defaults()
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(s.byName)) {
		out = append(out, name+"="+s.Selector(name).String())
	}
	return strings.Join(out, " ")
}
