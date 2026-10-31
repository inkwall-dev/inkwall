// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"cmp"
	"net"
	"net/url"
	"path"
	"slices"
	"strings"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// route is one RouteMatch of a policy.
type route struct {
	host     string // lower case; "" any host; "*.example.com" a wildcard
	wildcard bool
	anyDepth bool // the wildcard covers any depth (Gateway API), not one label
	exact    bool // exact path; otherwise an element-wise prefix
	path     string
	methods  []string
	policy   *Policy
}

// rank orders routes from most to least specific: host (exact, wildcard,
// any), then exact path over prefix, then longer path, then routes that
// name methods over those that don't, then an HTTPRoute's wildcard over an
// Ingress's, as the HTTPRoute is the more specific target.
func compareRoutes(a, b *route) int {
	hostRank := func(r *route) int {
		switch {
		case r.host == "":
			return 0
		case r.wildcard:
			return 1
		}
		return 2
	}
	if c := cmp.Compare(hostRank(b), hostRank(a)); c != 0 {
		return c
	}
	if a.exact != b.exact {
		if a.exact {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(len(b.path), len(a.path)); c != 0 {
		return c
	}
	if c := cmp.Compare(min(len(b.methods), 1), min(len(a.methods), 1)); c != 0 {
		return c
	}
	if a.anyDepth != b.anyDepth {
		if a.anyDepth {
			return -1
		}
		return 1
	}
	// Deterministic among equals: the operator rejects true ties.
	return cmp.Compare(a.policy.ID, b.policy.ID)
}

func newRoute(m *bundlev1.RouteMatch, p *Policy) route {
	r := route{host: strings.ToLower(m.GetHost()), policy: p, methods: m.GetMethods()}
	r.wildcard = strings.HasPrefix(r.host, "*.")
	r.anyDepth = r.wildcard && m.GetWildcardAnyDepth()
	r.exact = m.GetPath().GetType() == bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT
	r.path = m.GetPath().GetValue()
	if r.path == "" {
		r.path = "/"
	}
	if !r.exact {
		// Element-wise: a trailing slash makes no difference.
		r.path = strings.TrimSuffix(r.path, "/")
	}
	return r
}

// matcher finds the policy for a request.
type matcher struct {
	byHost   map[string][]*route // exact hosts
	wildcard map[string][]*route // "*.example.com" under "example.com"
	anyDepth map[string][]*route // the wildcards of any depth, again
	anyHost  []*route
}

func newMatcher(routes []route) *matcher {
	m := &matcher{byHost: map[string][]*route{}, wildcard: map[string][]*route{}, anyDepth: map[string][]*route{}}
	for i := range routes {
		r := &routes[i]
		switch {
		case r.host == "":
			m.anyHost = append(m.anyHost, r)
		case r.wildcard:
			m.wildcard[r.host[2:]] = append(m.wildcard[r.host[2:]], r)
			if r.anyDepth {
				m.anyDepth[r.host[2:]] = append(m.anyDepth[r.host[2:]], r)
			}
		default:
			m.byHost[r.host] = append(m.byHost[r.host], r)
		}
	}
	for _, rs := range m.byHost {
		slices.SortFunc(rs, compareRoutes)
	}
	for _, rs := range m.wildcard {
		slices.SortFunc(rs, compareRoutes)
	}
	for _, rs := range m.anyDepth {
		slices.SortFunc(rs, compareRoutes)
	}
	slices.SortFunc(m.anyHost, compareRoutes)
	return m
}

// lookup returns the policy for a request, or nil when no policy covers its
// host. A request to a covered host whose path matches none of the host's
// routes gets the host's most general policy: in front of a proxy that only
// sends requests from protected routes, a path that fails to match is one
// the proxy normalizes differently, and must not go uninspected.
func (m *matcher) lookup(host, rawURI, method string) *Policy {
	host = normalizeHost(host)
	p := normalizePath(rawURI)
	var candidates [][]*route
	if rs, ok := m.byHost[host]; ok {
		candidates = append(candidates, rs)
	}
	if _, parent, ok := strings.Cut(host, "."); ok {
		if rs, ok := m.wildcard[parent]; ok {
			candidates = append(candidates, rs)
		}
		// Wildcards of any depth, from the closest parent domain out.
		for len(m.anyDepth) > 0 {
			if _, parent, ok = strings.Cut(parent, "."); !ok {
				break
			}
			if rs, ok := m.anyDepth[parent]; ok {
				candidates = append(candidates, rs)
			}
		}
	}
	if len(m.anyHost) > 0 {
		candidates = append(candidates, m.anyHost)
	}
	for _, rs := range candidates {
		for _, r := range rs {
			if r.matches(p, method) {
				return r.policy
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	// The most general route of the most specific host.
	rs := candidates[0]
	return rs[len(rs)-1].policy
}

func (r *route) matches(p, method string) bool {
	if len(r.methods) > 0 && !slices.Contains(r.methods, method) {
		return false
	}
	if r.exact {
		return p == r.path
	}
	if r.path == "" { // "/"
		return true
	}
	return p == r.path || strings.HasPrefix(p, r.path+"/")
}

// normalizeHost lower-cases a host and drops its port and trailing dot.
func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	return strings.Trim(h, "[]")
}

// normalizePath returns the decoded, cleaned path of a request target, as
// proxies route on it.
func normalizePath(rawURI string) string {
	p, _, _ := strings.Cut(rawURI, "?")
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}
