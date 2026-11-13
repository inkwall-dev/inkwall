// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// The operator's probe through Istio (#372): the EnvoyFilter's patches
// match Envoy's routes by the names Istio gives them, which Istio accepts
// whether they match or not. So a wired route is Programmed only once a
// probe through every pod, on every listener (server) the route is served
// on, has reached the engine (pkg/haproxyprobe; the ext_proc adapter
// answers it, 0006 §2). These build the probes; the Prober sends them.

// probeHost is the concrete host the probe asks for: a wildcard's made
// concrete with a label of the probe's own, "*" and "" any host.
func probeHost(h string) string {
	switch {
	case h == "" || h == "*":
		return anyHost
	case strings.HasPrefix(h, "*."):
		return "inkwall-probe" + h[1:]
	}
	return h
}

// hostMatches reports whether a route's host is one a listener (server)
// host serves: equal, or under its wildcard, or any.
func hostMatches(listener, host string) bool {
	switch {
	case listener == "" || listener == "*" || host == "*" || listener == host:
		return true
	case strings.HasPrefix(listener, "*."):
		return strings.HasSuffix(strings.TrimPrefix(host, "*"), listener[1:])
	case strings.HasPrefix(host, "*."):
		return strings.HasSuffix(listener, host[1:])
	}
	return false
}

// routeHost is the host a route's probe asks for on a listener: the first
// of the route's hosts the listener serves, or the listener's own when the
// route has none; ok is false when the listener serves none of them.
func routeHost(listener string, hosts []string) (string, bool) {
	if len(hosts) == 0 {
		return probeHost(listener), true
	}
	for _, h := range hosts {
		if hostMatches(listener, h) {
			if h == "*" || strings.HasPrefix(h, "*.") {
				if listener != "" && listener != "*" && !strings.HasPrefix(listener, "*.") {
					return listener, true
				}
			}
			return probeHost(h), true
		}
	}
	return "", false
}

// httpRouteMatchTarget is the probe of an HTTPRoute match, or why it can't
// be made.
func httpRouteMatchTarget(m gatewayv1.HTTPRouteMatch) (ProbeTarget, string) {
	t := ProbeTarget{Path: "/", Prefix: true}
	if p := m.Path; p != nil {
		switch {
		case p.Type != nil && *p.Type == gatewayv1.PathMatchRegularExpression:
			return t, "a regular expression path"
		case p.Value != nil:
			t.Path = *p.Value
			t.Prefix = p.Type == nil || *p.Type == gatewayv1.PathMatchPathPrefix
		}
	}
	for _, h := range m.Headers {
		if h.Type != nil && *h.Type == gatewayv1.HeaderMatchRegularExpression {
			return t, "a regular expression header match"
		}
		if t.Headers == nil {
			t.Headers = map[string]string{}
		}
		t.Headers[string(h.Name)] = h.Value
	}
	q := url.Values{}
	for _, p := range m.QueryParams {
		if p.Type != nil && *p.Type == gatewayv1.QueryParamMatchRegularExpression {
			return t, "a regular expression query parameter match"
		}
		q.Set(string(p.Name), p.Value)
	}
	t.Query = q.Encode()
	if m.Method != nil {
		t.Method = string(*m.Method)
	}
	return t, ""
}

// istioRouteProbes are the probes of a protected HTTPRoute, one job per
// Istio Gateway; why says why the route can't be probed, if it can't.
func (st *envoyState) istioRouteProbes(r *istioRoute) ([]ProbeJob, string) {
	hr := r.route
	name := "HTTPRoute " + hr.Name
	sel := rules{}
	for _, s := range r.sections {
		sel = sel.with(s)
	}
	// A target per protected rule, from its first match the probe can make.
	var ruleTargets []ProbeTarget
	var ruleLabels []string
	for i, rule := range hr.Spec.Rules {
		ruleName := ""
		if rule.Name != nil {
			ruleName = string(*rule.Name)
		}
		if !sel.has(ruleName) {
			continue
		}
		label := ruleName
		if label == "" {
			label = fmt.Sprint(i)
		}
		matches := rule.Matches
		if len(matches) == 0 {
			matches = []gatewayv1.HTTPRouteMatch{{}}
		}
		var t ProbeTarget
		why := ""
		for _, m := range matches {
			if t, why = httpRouteMatchTarget(m); why == "" {
				break
			}
		}
		if why != "" {
			return nil, fmt.Sprintf("%s can't be probed: rule %s has only matches the probe can't make (%s)", name, label, why)
		}
		ruleTargets = append(ruleTargets, t)
		ruleLabels = append(ruleLabels, label)
	}
	var hosts []string
	for _, h := range hr.Spec.Hostnames {
		hosts = append(hosts, string(h))
	}
	var jobs []ProbeJob
	for _, gwKey := range r.gateways {
		gw := st.gateways[gwKey]
		if gw == nil {
			continue
		}
		job := ProbeJob{Route: ProbeRoute{Kind: "HTTPRoute", Key: key(hr)}, Proxy: "Istio",
			Fingerprint: fmt.Sprintf("%s/%d/%d", gwKey, hr.Generation, gw.Generation)}
		for _, l := range attachedListeners(hr, gw) {
			if l.Protocol != gatewayv1.HTTPProtocolType && l.Protocol != gatewayv1.HTTPSProtocolType {
				continue
			}
			listenerHost := ""
			if l.Hostname != nil {
				listenerHost = string(*l.Hostname)
			}
			host, ok := routeHost(listenerHost, hosts)
			if !ok {
				continue
			}
			for k, t := range ruleTargets {
				t.Host, t.Port, t.TLS = host, l.Port, l.Protocol == gatewayv1.HTTPSProtocolType
				if t.TLS && sendsValues(t) {
					return nil, fmt.Sprintf("%s can't be probed: rule %s %s, and Gateway %s serves it over HTTPS on port %d", name, ruleLabels[k], overTLS, gwKey, l.Port)
				}
				job.Targets = append(job.Targets, t)
			}
		}
		if len(job.Targets) == 0 {
			return nil, fmt.Sprintf("%s can't be probed: it is on no HTTP or HTTPS listener of Gateway %s", name, gwKey)
		}
		for _, p := range istioPodsOf(st, gwKey) {
			job.Pods = append(job.Pods, ProbePod{Name: p.Namespace + "/" + p.Name, UID: p.UID, IP: p.Status.PodIP})
		}
		jobs = append(jobs, job)
	}
	return jobs, ""
}

// attachedListeners are the listeners of a Gateway an HTTPRoute's
// parentRefs attach it to: the one its sectionName names, those on its
// port, or all.
func attachedListeners(hr *gatewayv1.HTTPRoute, gw *gatewayv1.Gateway) []gatewayv1.Listener {
	var out []gatewayv1.Listener
	for _, p := range hr.Spec.ParentRefs {
		ns := hr.Namespace
		if p.Namespace != nil {
			ns = string(*p.Namespace)
		}
		if string(p.Name) != gw.Name || ns != gw.Namespace {
			continue
		}
		for _, l := range gw.Spec.Listeners {
			if p.SectionName != nil && *p.SectionName != l.Name || p.Port != nil && *p.Port != l.Port {
				continue
			}
			if !slices.ContainsFunc(out, func(o gatewayv1.Listener) bool { return o.Name == l.Name }) {
				out = append(out, l)
			}
		}
	}
	return out
}

// vsMatchTarget is the probe of a VirtualService's http match, or why it
// can't be made.
func vsMatchTarget(m map[string]any) (ProbeTarget, string) {
	t := ProbeTarget{Path: "/", Prefix: true}
	if uri, ok := m["uri"].(map[string]any); ok {
		switch {
		case uri["exact"] != nil:
			t.Path, t.Prefix = fmt.Sprint(uri["exact"]), false
		case uri["prefix"] != nil:
			t.Path = fmt.Sprint(uri["prefix"])
		default:
			return t, "a regular expression uri"
		}
	}
	if hs, ok := m["headers"].(map[string]any); ok {
		for name, v := range hs {
			sm, _ := v.(map[string]any)
			switch {
			case sm["exact"] != nil:
				t.Headers = setHeader(t.Headers, name, fmt.Sprint(sm["exact"]))
			case sm["prefix"] != nil:
				t.Headers = setHeader(t.Headers, name, fmt.Sprint(sm["prefix"]))
			default:
				return t, "a regular expression header match"
			}
		}
	}
	q := url.Values{}
	if qs, ok := m["queryParams"].(map[string]any); ok {
		for name, v := range qs {
			sm, _ := v.(map[string]any)
			switch {
			case sm["exact"] != nil:
				q.Set(name, fmt.Sprint(sm["exact"]))
			case sm["prefix"] != nil:
				q.Set(name, fmt.Sprint(sm["prefix"]))
			default:
				return t, "a regular expression query parameter match"
			}
		}
	}
	t.Query = q.Encode()
	if method, ok := m["method"].(map[string]any); ok {
		if method["exact"] == nil {
			return t, "a method match other than exact"
		}
		t.Method = fmt.Sprint(method["exact"])
	}
	return t, ""
}

func setHeader(h map[string]string, k, v string) map[string]string {
	if h == nil {
		h = map[string]string{}
	}
	h[k] = v
	return h
}

// vsProbes are the probes of a protected VirtualService, one job per
// Istio Gateway; why says why it can't be probed, if it can't.
func (st *istioIngressState) vsProbes(r *istioVSRoute) ([]ProbeJob, string) {
	name := "VirtualService " + r.vs.GetName()
	var targets []ProbeTarget
	var labels []string
	routes, _, _ := unstructured.NestedSlice(r.vs.Object, "spec", "http")
	for i, rt := range routes {
		route, _ := rt.(map[string]any)
		label, _ := route["name"].(string)
		if label == "" {
			label = fmt.Sprint(i)
		}
		matches, _ := route["match"].([]any)
		if len(matches) == 0 {
			matches = []any{map[string]any{}}
		}
		var t ProbeTarget
		why := ""
		for _, m := range matches {
			mm, _ := m.(map[string]any)
			if t, why = vsMatchTarget(mm); why == "" {
				break
			}
		}
		if why != "" {
			return nil, fmt.Sprintf("%s can't be probed: http route %s has only matches the probe can't make (%s)", name, label, why)
		}
		targets = append(targets, t)
		labels = append(labels, label)
	}
	hosts, _, _ := unstructured.NestedStringSlice(r.vs.Object, "spec", "hosts")
	var jobs []ProbeJob
	for _, gwKey := range r.gateways {
		gw := st.gateways[gwKey]
		if gw == nil {
			continue
		}
		job := ProbeJob{Route: ProbeRoute{Kind: "VirtualService", Key: key(r.vs)}, Proxy: "Istio ingress gateway",
			Fingerprint: fmt.Sprintf("%s/%d/%d", gwKey, r.vs.GetGeneration(), gw.GetGeneration())}
		servers, _, _ := unstructured.NestedSlice(gw.Object, "spec", "servers")
		for _, sv := range servers {
			server, _ := sv.(map[string]any)
			port, _, _ := unstructured.NestedInt64(server, "port", "number")
			protocol, _, _ := unstructured.NestedString(server, "port", "protocol")
			mode, _, _ := unstructured.NestedString(server, "tls", "mode")
			serverHosts, _, _ := unstructured.NestedStringSlice(server, "hosts")
			host, ok := "", false
			for _, sh := range serverHosts {
				if _, h, cut := strings.Cut(sh, "/"); cut {
					sh = h
				}
				if host, ok = routeHost(sh, hosts); ok {
					break
				}
			}
			if !ok {
				continue
			}
			tls := false
			switch strings.ToUpper(protocol) {
			case "HTTP", "HTTP2", "GRPC":
			case "HTTPS":
				if m := strings.ToUpper(mode); m != "" && m != "SIMPLE" {
					return nil, fmt.Sprintf("%s can't be probed: Gateway %s serves it on port %d with %s (mutual TLS or passthrough), where the probe has no client certificate", name, gwKey, port, m)
				}
				tls = true
			default:
				continue
			}
			for k, t := range targets {
				t.Host, t.Port, t.TLS = host, int32(port), tls // #nosec G115 -- a port
				if t.TLS && sendsValues(t) {
					return nil, fmt.Sprintf("%s can't be probed: http route %s %s, and Gateway %s serves it over TLS on port %d", name, labels[k], overTLS, gwKey, port)
				}
				job.Targets = append(job.Targets, t)
			}
		}
		if len(job.Targets) == 0 {
			return nil, fmt.Sprintf("%s can't be probed: no HTTP or HTTPS server of Gateway %s serves its hosts", name, gwKey)
		}
		if s := selectorOf(gw); s != nil {
			for _, pods := range r.pods {
				for _, p := range pods {
					if gatewaySelects(s, p) {
						job.Pods = append(job.Pods, ProbePod{Name: p.Namespace + "/" + p.Name, UID: p.UID, IP: p.Status.PodIP})
					}
				}
			}
		}
		jobs = append(jobs, job)
	}
	return jobs, ""
}

func gatewaySelects(s labels.Selector, p *corev1.Pod) bool { return s.Matches(labels.Set(p.Labels)) }

// proveRoute probes a wired Istio route: its jobs, and why it isn't
// proven yet (unverified) or can't be (notProbeable). In detect mode
// (ext_proc's observability mode) Envoy discards the engine's answer and
// forwards the probe to the app: the route is proven by the receipt the
// probed pod's engine reports instead (#475), which shows that the engine
// sees the route's traffic there, all a Detect-mode route does with it.
// The probe then reaches the app, so it is sent only as a GET or HEAD.
func proveRoute(p *Prober, name string, detect bool, jobsOf func() ([]ProbeJob, string)) (jobs []ProbeJob, notProbeable, unverified string) {
	jobs, why := jobsOf()
	if why != "" {
		return nil, why, ""
	}
	if detect {
		for i := range jobs {
			for _, t := range jobs[i].Targets {
				if t.Method != "" && t.Method != http.MethodGet && t.Method != http.MethodHead {
					return nil, fmt.Sprintf("%s can't be probed in Detect mode: a rule of it matches only %s requests, and in Detect mode Envoy forwards the probe to the app, so the probe sends only GET and HEAD requests", name, t.Method), ""
				}
			}
			jobs[i].Receipt = true
		}
	}
	if p == nil {
		return nil, "", name + " is wired, but the operator doesn't probe Istio: the filter is unverified"
	}
	for _, j := range jobs {
		if u := p.Unverified(j); u != "" {
			return jobs, "", u
		}
	}
	return jobs, "", ""
}

// userFiltersKey identifies the users' EnvoyFilters as they are now (each
// one's namespace, name and resourceVersion), for the Istio routes' probe
// fingerprints: a user's EnvoyFilter can take Inkwall's filter off a
// listener (or put it back), which the routes' own generations don't show,
// so any change re-probes them at once. The operator's own are left out:
// they change with the wiring. "" without the CRD.
func userFiltersKey(ctx context.Context, c client.Reader) (string, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(EnvoyFilterGVK.GroupVersion().WithKind("EnvoyFilterList"))
	switch err := c.List(ctx, list); {
	case meta.IsNoMatchError(err):
		return "", nil
	case err != nil:
		return "", err
	}
	var ids []string
	for i := range list.Items {
		f := &list.Items[i]
		if !isManaged(f) {
			ids = append(ids, f.GetNamespace()+"/"+f.GetName()+"@"+f.GetResourceVersion())
		}
	}
	slices.Sort(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return hex.EncodeToString(sum[:8]), nil
}

// withFilters adds the users' EnvoyFilters key to the jobs' fingerprints.
func withFilters(jobs []ProbeJob, filters string) []ProbeJob {
	for i := range jobs {
		jobs[i].Fingerprint += "/" + filters
	}
	return jobs
}

// overTLS says why a target with header or query match values isn't
// probed over TLS.
const overTLS = "matches on header or query values, which the probe sends only over plain HTTP: over TLS it doesn't verify the gateway's certificate, so it doesn't send values that may be secrets"

// sendsValues reports whether a target carries match values from the
// route (headers, query parameters), which may be secrets.
func sendsValues(t ProbeTarget) bool {
	return len(t.Headers) > 0 || t.Query != ""
}
