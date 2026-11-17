// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
)

// errNoRule is a sectionName that names no rule of the HTTPRoute.
var errNoRule = errors.New("no such rule")

// httpRouteMatches expands an HTTPRoute into route matches: its hostnames ×
// its rules' matches, or only the matches of the rule named section when it
// isn't empty. No hostnames match any host, a wildcard hostname matches
// subdomains at any depth, and a rule without matches is PathPrefix /. A
// match the engine can't express (a regular expression path, headers, query
// parameters) is an error naming the rule.
func httpRouteMatches(hr *gatewayv1.HTTPRoute, section string) ([]*bundlev1.RouteMatch, error) {
	hosts := []string{""}
	if len(hr.Spec.Hostnames) > 0 {
		hosts = hosts[:0]
		for _, h := range hr.Spec.Hostnames {
			hosts = append(hosts, strings.ToLower(string(h)))
		}
	}
	var out []*bundlev1.RouteMatch
	seen := map[string]bool{}
	found := false
	for i, rule := range hr.Spec.Rules {
		name := ""
		if rule.Name != nil {
			name = string(*rule.Name)
		}
		if section != "" && name != section {
			continue
		}
		found = true
		matches := rule.Matches
		if len(matches) == 0 {
			matches = []gatewayv1.HTTPRouteMatch{{}}
		}
		for j, m := range matches {
			pm, methods, err := httpRouteMatch(m)
			if err != nil {
				where := fmt.Sprintf("spec.rules[%d].matches[%d]", i, j)
				if name != "" {
					where += fmt.Sprintf(" (rule %s)", name)
				}
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			for _, host := range hosts {
				rm := &bundlev1.RouteMatch{Host: host, Path: pm, Methods: methods,
					WildcardAnyDepth: strings.HasPrefix(host, "*.")}
				// Matches that differ only in what the engine doesn't match
				// on are one route to the engine.
				if k := routeKey(rm); !seen[k] {
					seen[k] = true
					out = append(out, rm)
				}
			}
		}
	}
	if section != "" && !found {
		return nil, errNoRule
	}
	return out, nil
}

// httpRouteMatch reads one HTTPRoute match: an Exact or PathPrefix path
// (PathPrefix / when there is none) and a method.
func httpRouteMatch(m gatewayv1.HTTPRouteMatch) (*bundlev1.PathMatch, []string, error) {
	switch {
	case len(m.Headers) > 0:
		return nil, nil, errors.New("headers matches are not supported: only paths (Exact, PathPrefix) and methods can be protected")
	case len(m.QueryParams) > 0:
		return nil, nil, errors.New("queryParams matches are not supported: only paths (Exact, PathPrefix) and methods can be protected")
	}
	typ, value := gatewayv1.PathMatchPathPrefix, "/"
	if p := m.Path; p != nil {
		if p.Type != nil {
			typ = *p.Type
		}
		if p.Value != nil {
			value = *p.Value
		}
	}
	if !strings.HasPrefix(value, "/") {
		return nil, nil, fmt.Errorf("path %q is not absolute", value)
	}
	// The engine compares clean paths, as it cleans request paths.
	pm := &bundlev1.PathMatch{Value: path.Clean(value)}
	switch typ {
	case gatewayv1.PathMatchExact:
		pm.Type = bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT
	case gatewayv1.PathMatchPathPrefix:
		pm.Type = bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX
	default:
		return nil, nil, fmt.Errorf("%s paths are not supported: only Exact and PathPrefix", typ)
	}
	var methods []string
	if m.Method != nil {
		methods = []string{strings.ToUpper(string(*m.Method))}
	}
	return pm, methods, nil
}

// gatewayControllers are the GatewayClass controllers of the integrations.
var gatewayControllers = func() map[string]bool {
	out := map[string]bool{}
	for _, i := range integrations.All {
		if i.GatewayController != "" {
			out[i.GatewayController] = true
		}
	}
	return out
}()

// AttachedGateways returns the Gateways ("namespace/name") that accepted an
// HTTPRoute, as their status says: a parent of its parentRefs whose
// controller is an integration's, with Accepted True. A route no such
// Gateway accepted carries no traffic through a proxy the engine is in.
func AttachedGateways(hr *gatewayv1.HTTPRoute) []string {
	ref := func(p gatewayv1.ParentReference) (types.NamespacedName, bool) {
		if p.Group != nil && *p.Group != gatewayv1.GroupName || p.Kind != nil && *p.Kind != "Gateway" {
			return types.NamespacedName{}, false
		}
		ns := hr.Namespace
		if p.Namespace != nil {
			ns = string(*p.Namespace)
		}
		return types.NamespacedName{Namespace: ns, Name: string(p.Name)}, true
	}
	var out []string
	for _, st := range hr.Status.Parents {
		if !gatewayControllers[string(st.ControllerName)] ||
			!meta.IsStatusConditionTrue(st.Conditions, string(gatewayv1.RouteConditionAccepted)) {
			continue
		}
		gw, ok := ref(st.ParentRef)
		if !ok {
			continue
		}
		// A status left from a parentRef the spec no longer names doesn't
		// count.
		inSpec := slices.ContainsFunc(hr.Spec.ParentRefs, func(p gatewayv1.ParentReference) bool {
			k, ok := ref(p)
			return ok && k == gw
		})
		if inSpec {
			out = append(out, gw.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
