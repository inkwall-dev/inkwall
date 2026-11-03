// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// virtualServiceMatches expands an Istio VirtualService into route matches:
// its hosts × its http routes' matches. "*" is any host, a wildcard host
// matches subdomains at any depth (as Envoy's domains do), and an http route
// without matches, or a match without a uri, is every path. What the engine
// can't match on is an error naming where, as for an HTTPRoute: a regex uri,
// headers and the other match conditions, a delegate, or a short host name
// (a mesh service, not a host a gateway serves). A prefix uri is matched by
// whole path segments: longer paths in its last segment get the host's most
// general policy (pkg/policy).
func virtualServiceMatches(vs *unstructured.Unstructured) ([]*bundlev1.RouteMatch, error) {
	hostList, _, err := unstructured.NestedStringSlice(vs.Object, "spec", "hosts")
	if err != nil {
		return nil, fmt.Errorf("spec.hosts: %w", err)
	}
	if len(hostList) == 0 {
		return nil, errors.New("spec.hosts: no hosts")
	}
	var hosts []string
	for _, h := range hostList {
		h = strings.ToLower(h)
		switch {
		case h == "*":
			h = ""
		case !strings.Contains(h, "."):
			return nil, fmt.Errorf("spec.hosts: host %q is a short name, a mesh service: only a gateway's hosts (with a domain) can be protected", h)
		}
		hosts = append(hosts, h)
	}
	routes, ok, err := unstructured.NestedSlice(vs.Object, "spec", "http")
	if err != nil {
		return nil, fmt.Errorf("spec.http: %w", err)
	}
	if !ok || len(routes) == 0 {
		return nil, errors.New("spec.http: no http routes: only HTTP traffic can be protected")
	}
	var out []*bundlev1.RouteMatch
	seen := map[string]bool{}
	for i, r := range routes {
		route, _ := r.(map[string]any)
		where := fmt.Sprintf("spec.http[%d]", i)
		if _, ok := route["delegate"]; ok {
			return nil, fmt.Errorf("%s: delegate routes are not supported", where)
		}
		name, _ := route["name"].(string)
		matches, _ := route["match"].([]any)
		if len(matches) == 0 {
			matches = []any{map[string]any{}}
		}
		for j, m := range matches {
			match, _ := m.(map[string]any)
			pm, methods, err := virtualServiceMatch(match)
			if err != nil {
				at := fmt.Sprintf("%s.match[%d]", where, j)
				if name != "" {
					at += fmt.Sprintf(" (route %s)", name)
				}
				return nil, fmt.Errorf("%s: %w", at, err)
			}
			for _, host := range hosts {
				rm := &bundlev1.RouteMatch{Host: host, Path: pm, Methods: methods, WildcardAnyDepth: strings.HasPrefix(host, "*.")}
				if k := routeKey(rm); !seen[k] {
					seen[k] = true
					out = append(out, rm)
				}
			}
		}
	}
	return out, nil
}

// vsMatchKeys are the fields of an HTTPMatchRequest the engine's routes
// cover; statPrefix and name don't change what matches.
var vsMatchKeys = []string{"name", "uri", "method", "statPrefix"}

// virtualServiceMatch reads one HTTPMatchRequest: an exact or prefix uri
// (prefix / when there is none), and an exact method.
func virtualServiceMatch(m map[string]any) (*bundlev1.PathMatch, []string, error) {
	var other []string
	for k := range m {
		if !slices.Contains(vsMatchKeys, k) {
			other = append(other, k)
		}
	}
	if len(other) > 0 {
		slices.Sort(other)
		return nil, nil, fmt.Errorf("%s matches are not supported: only uris (exact, prefix) and exact methods can be protected", strings.Join(other, ", "))
	}
	pm := &bundlev1.PathMatch{Type: bundlev1.PathMatchType_PATH_MATCH_TYPE_PREFIX, Value: "/"}
	if uri, ok := m["uri"].(map[string]any); ok {
		exact, isExact := uri["exact"].(string)
		prefix, isPrefix := uri["prefix"].(string)
		value := exact
		switch {
		case isExact:
			pm.Type = bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT
		case isPrefix:
			// Istio's prefix is a string prefix, the engine's whole path
			// segments: /apiv2, which Istio's /api also routes here, matches
			// none of the engine's routes, and gets the host's most general
			// policy, as any path of a protected host the routes miss.
			value = prefix
		case uri["regex"] != nil:
			return nil, nil, errors.New("regex uris are not supported: only exact and prefix uris")
		default:
			return nil, nil, errors.New("only exact and prefix uris are supported")
		}
		if !strings.HasPrefix(value, "/") {
			return nil, nil, fmt.Errorf("uri %q is not absolute", value)
		}
		// The engine compares clean paths, as it cleans request paths.
		pm.Value = path.Clean(value)
	}
	var methods []string
	if method, ok := m["method"].(map[string]any); ok {
		exact, isExact := method["exact"].(string)
		if !isExact || len(method) != 1 {
			return nil, nil, errors.New("only an exact method is supported")
		}
		methods = []string{strings.ToUpper(exact)}
	}
	return pm, methods, nil
}
