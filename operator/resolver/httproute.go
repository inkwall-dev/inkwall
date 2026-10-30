// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"errors"
	"fmt"
	"path"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// errNoRule is a sectionName that names no rule of the HTTPRoute.
var errNoRule = errors.New("no such rule")

// httpRouteMatches expands an HTTPRoute into route matches: its hostnames ×
// its rules' matches, or only the matches of the rule named section when it
// isn't empty. No hostnames match any host, and a rule without matches is
// PathPrefix /. A match the engine can't express (a regular expression
// path, headers, query parameters) is an error naming the rule.
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
				rm := &bundlev1.RouteMatch{Host: host, Path: pm, Methods: methods}
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
