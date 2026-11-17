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
	"github.com/inkwall-dev/inkwall/pkg/router"
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
// host: the policy of its decoded, cleaned path (policies returns them
// all).
func (m *matcher) lookup(host, rawURI, method string) *Policy {
	var buf [4]*Policy
	if ps := m.policies(host, rawURI, method, buf[:0]); len(ps) > 0 {
		return ps[0]
	}
	return nil
}

// policies appends to buf the policies of a request, none when no policy
// covers its host. Proxies route on different forms of a path: as received
// (HAProxy), with dot segments removed and %2F kept (Envoy, Istio's
// default), with slashes merged too (Envoy Gateway), or decoded and cleaned
// (Traefik). Each form a proxy may route on selects a policy, and a request
// whose forms select different policies gets each of them, so that it is
// never inspected by a weaker policy than the one of the route the proxy
// chose. The policy of the decoded, cleaned path comes first. A request to
// a covered host whose path matches none of the host's routes gets the
// host's most general policy: in front of a proxy that only sends requests
// from protected routes, a path that fails to match is one the proxy
// normalizes differently, and must not go uninspected.
func (m *matcher) policies(host, rawURI, method string, buf []*Policy) []*Policy {
	host = normalizeHost(host)
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
	if len(candidates) == 0 {
		return buf
	}
	var forms [maxPathForms]string
	for _, p := range pathForms(rawURI, forms[:0]) {
		if pol := match(candidates, p, method); !slices.Contains(buf, pol) {
			buf = append(buf, pol)
		}
	}
	return buf
}

// match returns the policy of the first route of candidates that matches
// p and method, or the most general route of the most specific host.
func match(candidates [][]*route, p, method string) *Policy {
	for _, rs := range candidates {
		for _, r := range rs {
			if r.matches(p, method) {
				return r.policy
			}
		}
	}
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
// Traefik routes on it.
func normalizePath(rawURI string) string {
	p := targetPath(rawURI)
	if u, err := url.PathUnescape(p); err == nil {
		p = u
	}
	return path.Clean(p)
}

// targetPath returns the path of a request target, from "/".
func targetPath(rawURI string) string {
	p, _, _ := strings.Cut(rawURI, "?")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// maxPathForms bounds the forms pathForms returns: three decodings, four
// normalizations of each.
const maxPathForms = 12

// pathForms appends to buf the distinct forms of a request target's path a
// proxy may route on, normalizePath's first. The path is decoded not at
// all, of the unreserved characters only (RFC 3986 §6.2.2.2, as Envoy
// does), or entirely (%2F included); then kept as is, its dot segments
// removed (RFC 3986 §5.2.4, "//" kept), its dot segments removed then its
// slashes merged, or cleaned (path.Clean: slashes merged first). A plain
// path, which none of these change, has one form, or two with a trailing
// slash path.Clean drops.
func pathForms(rawURI string, buf []string) []string {
	add := func(p string) {
		if !slices.Contains(buf, p) {
			buf = append(buf, p)
		}
	}
	add(normalizePath(rawURI))
	p := targetPath(rawURI)
	if _, ok := router.UnambiguousPath(p); ok {
		add(p)
		return buf
	}
	for _, d := range [...]string{p, decodeUnreserved(p), decodeAll(p)} {
		add(d)
		r := removeDotSegments(d)
		add(r)
		add(mergeSlashes(r))
		add(path.Clean(d))
	}
	return buf
}

// decodeAll decodes every percent-encoded byte of p, or returns p when it
// holds an invalid escape.
func decodeAll(p string) string {
	if u, err := url.PathUnescape(p); err == nil {
		return u
	}
	return p
}

// decodeUnreserved decodes the percent-encoded unreserved characters of p
// (ALPHA, DIGIT, "-", ".", "_", "~") and keeps the other escapes.
func decodeUnreserved(p string) string {
	if !strings.Contains(p, "%") {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) {
			if c, ok := unhex(p[i+1], p[i+2]); ok && unreserved(c) {
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

func unhex(h, l byte) (byte, bool) {
	v := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	hv, ok1 := v(h)
	lv, ok2 := v(l)
	return hv<<4 | lv, ok1 && ok2
}

func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0
}

// removeDotSegments removes the "." and ".." segments of p, which starts
// with "/", as RFC 3986 §5.2.4 does: an empty segment ("//") is a segment,
// so "/a//../b" is "/a/b".
func removeDotSegments(p string) string {
	if !strings.Contains(p, "/.") {
		return p
	}
	segs := strings.Split(p[1:], "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		last := i == len(segs)-1
		switch s {
		case ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
			continue
		}
		if last {
			out = append(out, "")
		}
	}
	return "/" + strings.Join(out, "/")
}

// mergeSlashes replaces each run of slashes in p with one.
func mergeSlashes(p string) string {
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}
