// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package resolver

import (
	"cmp"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	networkingv1 "k8s.io/api/networking/v1"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
)

// Routes of policies in different namespaces can overlap: one request
// matches both. The engine gets one route table for every proxy, so it
// can only follow the proxy's routing when both routes are routed by the
// same Gateway, or the same IngressClass: there, the more specific route
// wins in the proxy as in the engine. Otherwise (routes of two proxies, an
// IngressRoute or a VirtualService, or two routes the engine can't rank)
// the overlap goes to the stricter policy, or, when neither is stricter, to
// the older one; the other policy's route the engine would pick there is
// left out. Both policies' status says so (ReasonRouteOverlap).

// A route's domains name what routes it: routes of one domain are routed by
// one proxy, which picks the most specific route, as the engine does.
// Targets that aren't known to share a proxy have domains of their own.

func ingressDomain(ing *networkingv1.Ingress) string {
	class := ing.Annotations["kubernetes.io/ingress.class"]
	if ing.Spec.IngressClassName != nil {
		class = *ing.Spec.IngressClassName
	}
	return "IngressClass/" + class
}

func gatewayDomain(gw string) string { return "Gateway/" + gw }

func objectDomain(kind, namespace, name string) string { return kind + "/" + namespace + "/" + name }

// sameDomain reports whether two routes share a domain.
func sameDomain(a, b map[string]bool) bool {
	for d := range a {
		if b[d] {
			return true
		}
	}
	return false
}

// dominates reports whether policy a is stricter than b: they differ only
// in their mode and skipped paths, a blocks when b does, and skips no path
// b doesn't skip.
func dominates(a, b *bundlev1.Policy) bool {
	strip := func(p *bundlev1.Policy) *bundlev1.Policy {
		p = proto.Clone(p).(*bundlev1.Policy)
		p.Id, p.Routes, p.Mode, p.SkipPaths, p.SkipBodyPaths = "", nil, bundlev1.Mode_MODE_UNSPECIFIED, nil, nil
		return p
	}
	if !proto.Equal(strip(a), strip(b)) {
		return false
	}
	blocks := func(p *bundlev1.Policy) bool { return p.GetMode() == bundlev1.Mode_MODE_BLOCK }
	subset := func(x, y []string) bool {
		for _, s := range x {
			if !slices.Contains(y, s) {
				return false
			}
		}
		return true
	}
	if blocks(b) && !blocks(a) || !subset(a.GetSkipPaths(), b.GetSkipPaths()) || !subset(a.GetSkipBodyPaths(), b.GetSkipBodyPaths()) {
		return false
	}
	return blocks(a) != blocks(b) || !subset(b.GetSkipPaths(), a.GetSkipPaths()) || !subset(b.GetSkipBodyPaths(), a.GetSkipBodyPaths())
}

// matchPath is a route's path as the engine compares it.
func matchPath(m *bundlev1.RouteMatch) (exact bool, p string) {
	exact = m.GetPath().GetType() == bundlev1.PathMatchType_PATH_MATCH_TYPE_EXACT
	p = cmp.Or(m.GetPath().GetValue(), "/")
	if !exact {
		p = strings.TrimSuffix(p, "/")
	}
	return exact, p
}

// compareSpecificity orders two routes as the engine tries them: < 0 when
// a is tried first, 0 when the engine can't tell them apart (it would pick
// by policy ID).
func compareSpecificity(a, b *bundlev1.RouteMatch) int {
	hostRank := func(m *bundlev1.RouteMatch) int {
		switch h := m.GetHost(); {
		case h == "":
			return 0
		case strings.HasPrefix(h, "*."):
			return 1
		}
		return 2
	}
	if c := cmp.Compare(hostRank(b), hostRank(a)); c != 0 {
		return c
	}
	ea, pa := matchPath(a)
	eb, pb := matchPath(b)
	if ea != eb {
		if ea {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(len(pb), len(pa)); c != 0 {
		return c
	}
	if c := cmp.Compare(min(len(b.GetMethods()), 1), min(len(a.GetMethods()), 1)); c != 0 {
		return c
	}
	da, db := a.GetWildcardAnyDepth() && hostRank(a) == 1, b.GetWildcardAnyDepth() && hostRank(b) == 1
	if da != db {
		if da {
			return -1
		}
		return 1
	}
	return 0
}

// hostsOverlap reports whether some host matches both routes' hosts. It
// errs towards an overlap.
func hostsOverlap(a, b *bundlev1.RouteMatch) bool {
	ha, hb := a.GetHost(), b.GetHost()
	if ha == "" || hb == "" || ha == hb {
		return true
	}
	// covers reports whether wildcard w matches h or, for a wildcard h,
	// some of the hosts it matches.
	covers := func(w *bundlev1.RouteMatch, h string) bool {
		suffix, ok := strings.CutPrefix(w.GetHost(), "*")
		if !ok {
			return false
		}
		return strings.HasSuffix(strings.TrimPrefix(h, "*"), suffix)
	}
	return covers(a, hb) || covers(b, ha)
}

// pathsOverlap reports whether some path matches both routes' paths.
func pathsOverlap(a, b *bundlev1.RouteMatch) bool {
	under := func(p, prefix string) bool { return prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/") }
	ea, pa := matchPath(a)
	eb, pb := matchPath(b)
	switch {
	case ea && eb:
		return pa == pb
	case ea:
		return under(pa, pb)
	case eb:
		return under(pb, pa)
	}
	return under(pa, pb) || under(pb, pa)
}

func methodsOverlap(a, b *bundlev1.RouteMatch) bool {
	if len(a.GetMethods()) == 0 || len(b.GetMethods()) == 0 {
		return true
	}
	for _, m := range a.GetMethods() {
		if slices.Contains(b.GetMethods(), m) {
			return true
		}
	}
	return false
}

func routesOverlap(a, b *bundlev1.RouteMatch) bool {
	return hostsOverlap(a, b) && pathsOverlap(a, b) && methodsOverlap(a, b)
}

// overlapPairs calls f for each pair of routes whose hosts may overlap
// (indexes into routes, i < j), without comparing every route to every
// other: routes are grouped by the domain their host is under.
func overlapPairs(routes []*bundlev1.RouteMatch, f func(i, j int)) {
	// Each route under its host's registrable-ish suffixes: an exact host
	// and a wildcard meet under the wildcard's suffix.
	byName := map[string][]int{}
	var anyHost []int
	for i, m := range routes {
		h := strings.TrimPrefix(m.GetHost(), "*.")
		if m.GetHost() == "" {
			anyHost = append(anyHost, i)
			continue
		}
		byName[h] = append(byName[h], i)
	}
	seen := map[[2]int]bool{}
	pair := func(i, j int) {
		if i == j {
			return
		}
		if i > j {
			i, j = j, i
		}
		if !seen[[2]int{i, j}] {
			seen[[2]int{i, j}] = true
			f(i, j)
		}
	}
	for i, m := range routes {
		if m.GetHost() == "" {
			for _, j := range anyHost {
				pair(i, j)
			}
			continue
		}
		for _, j := range anyHost {
			pair(i, j)
		}
		// The host and its parent domains: a wildcard's suffix is one.
		for h := strings.TrimPrefix(m.GetHost(), "*."); h != ""; {
			for _, j := range byName[h] {
				pair(i, j)
			}
			_, parent, ok := strings.Cut(h, ".")
			if !ok {
				break
			}
			h = parent
		}
	}
}
