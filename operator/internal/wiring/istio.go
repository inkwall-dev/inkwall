// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// Istio's wiring (0004 §4.4), for the Gateways of its Gateway API
// implementation. Istio runs each Gateway's Envoy in a Deployment it
// renders in the Gateway's namespace, overlaid with the ConfigMap the
// Gateway's parametersRef names: the engine joins those pods as a native
// sidecar through that ConfigMap's deployment overlay (the user's, or one
// the operator makes and names), and answers ext_proc on a Unix socket the
// istio-proxy container mounts too. Each Gateway serving a protected
// HTTPRoute, once every pod of it has the engine, gets an EnvoyFilter for
// its pods: a cluster for the engine's socket, a disabled ext_proc filter
// per protected route, with that route's settings, enabled on the Envoy
// routes of its protected rules, and, when a body is inspected, Envoy's
// buffer limit raised. Unprotected routes get nothing.
//
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch;update;patch,roleName=inkwall-operator-istio
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;gatewayclasses,verbs=get;list;watch,roleName=inkwall-operator-istio
// +kubebuilder:rbac:groups=networking.istio.io,resources=envoyfilters,verbs=get;list;watch;create;update;patch;delete,roleName=inkwall-operator-istio
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;create;update;patch;delete,roleName=inkwall-operator-istio
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=inkwallconfigs,verbs=get;list;watch,roleName=inkwall-operator-istio

// EnvoyFilterGVK is Istio's EnvoyFilter, read and written unstructured: the
// operator doesn't depend on Istio's Go module.
var EnvoyFilterGVK = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1alpha3", Kind: "EnvoyFilter"}

// Names of the Istio wiring.
const (
	// istioGatewayLabel names the Gateway of the pods Istio runs for it.
	istioGatewayLabel = "gateway.networking.k8s.io/gateway-name"
	// istioProxy is the Envoy container of a Gateway's pods.
	istioProxy = "istio-proxy"
	// istioCluster is the engine's socket, in the EnvoyFilter.
	istioCluster = "inkwall-engine"
	// istioFilterPrefix starts the name of a route's ext_proc filter.
	istioFilterPrefix = "inkwall.ext_proc."
	// istioOverlay is the ConfigMap key Istio overlays its Deployment
	// with (a strategic merge patch, in YAML).
	istioOverlay = "deployment"
	// istioSidecarLabel marks a ConfigMap the operator put the engine into,
	// the user's or its own, so unwiring finds them.
	istioSidecarLabel = "waf.inkwall.dev/sidecar"
	// istioOriginal holds a user's ConfigMap's overlay before the engine
	// went in: it is put back as it was, when nothing else changed.
	istioOriginal = "waf.inkwall.dev/original-deployment"
	// istioMark on a Gateway names the operator's ConfigMap its
	// parametersRef names, which the operator set (Envoy Gateway's mark,
	// sidecarMark, names an EnvoyProxy).
	istioMark = "waf.inkwall.dev/configmap"
	// istioRoutes on the operator's EnvoyFilter lists the routes it wires,
	// namespace/name, comma-separated.
	istioRoutes = "waf.inkwall.dev/routes"
	// istioMinMinor is the oldest Istio (1.x) the operator wires: its Envoy
	// (1.36) sends ext_proc's protocol_config (1.33), which the engine
	// reads the body mode from, and knows status_on_error (1.36). An older
	// Envoy would reject the filter, and keep serving without it.
	istioMinMinor = 28
)

// Istio is the wiring of Istio: the HTTPRoutes of its Gateways.
type Istio struct {
	Client client.Client
	// APIReader reads the operator's objects, and ConfigMaps, uncached.
	APIReader client.Reader
	// Pods selects the pods Istio runs for Gateways.
	Pods labels.Selector
	// Sidecar is the engine put into the Gateways' pods, before the
	// InkwallConfig's engine settings.
	Sidecar injection.Sidecar
	// Watches of kinds whose CRD may be missing; nil: only read at each
	// reconcile.
	HTTPRoutes, Gateways, GatewayClasses, EnvoyFilters *crdwatch.Kind
}

// Name implements Integration.
func (*Istio) Name() string { return integrations.Istio.Name }

// Kinds implements Integration.
func (*Istio) Kinds() []schema.GroupKind { return []schema.GroupKind{httpRouteKind} }

// Watch implements Integration.
func (i *Istio) Watch(c controller.Controller, cache cache.Cache, h handler.EventHandler) error {
	for _, obj := range []client.Object{&corev1.Pod{}, &wafv1alpha1.InkwallConfig{}} {
		if err := c.Watch(source.Kind(cache, obj, h)); err != nil {
			return err
		}
	}
	addWatches(c, h, i.HTTPRoutes, i.Gateways, i.GatewayClasses, i.EnvoyFilters)
	return nil
}

// istioRoute is a protected HTTPRoute that Istio serves.
type istioRoute struct {
	route    *gatewayv1.HTTPRoute
	gateways []types.NamespacedName
	others   []string
	// sections are the rules protected, or [""] for the whole route.
	sections []string
	routeSettings
}

// envoyRoutes are the names Istio gives the Envoy routes of the protected
// rules: a rule's name, or namespace.route.index for a rule without one.
func (r *istioRoute) envoyRoutes() []string {
	sel := rules{}
	for _, s := range r.sections {
		sel = sel.with(s)
	}
	var out []string
	for i, rule := range r.route.Spec.Rules {
		name := ""
		if rule.Name != nil {
			name = string(*rule.Name)
		}
		if !sel.has(name) {
			continue
		}
		if name == "" {
			name = r.route.Namespace + "." + r.route.Name + "." + strconv.Itoa(i)
		}
		out = append(out, name)
	}
	return out
}

// istioFilterName is the name of a route's ext_proc filter in Envoy.
func istioFilterName(route types.NamespacedName) string {
	return istioFilterPrefix + route.Namespace + "." + route.Name
}

// Wire implements Integration: it puts the engine into the pods of the
// Gateways serving protected HTTPRoutes, gives those Gateways an
// EnvoyFilter for the routes once their pods have it, and removes the rest.
func (i *Istio) Wire(ctx context.Context, targets map[Target]bool, off bool) (*Result, error) {
	st, err := i.read(ctx)
	if err != nil {
		return nil, err
	}
	res := i.result()

	var policies wafv1alpha1.WAFPolicyList
	if err := i.Client.List(ctx, &policies); err != nil {
		return nil, err
	}
	routes := map[types.NamespacedName]*istioRoute{}
	for tg := range targets {
		hr := st.routes[tg.Key]
		if tg.Kind != httpRouteKind || hr == nil || !rules(nil).with(tg.Section).any(hr) {
			continue
		}
		gws, others := st.parents(hr)
		if len(gws) == 0 {
			// Reported by the integration of its Gateways, or as unsupported
			// by every integration.
			why := "no Gateway"
			if len(others) > 0 {
				why = "Gateways of other controllers (GatewayClass " + strings.Join(others, ", GatewayClass ") + ")"
			}
			res.Targets[tg] = TargetState{Unsupported: fmt.Sprintf("HTTPRoute %s is served by %s, which Inkwall doesn't wire yet", tg.Key.Name, why)}
			continue
		}
		r := routes[tg.Key]
		if r == nil {
			r = &istioRoute{route: hr, gateways: gws, others: st.unwired(others)}
			routes[tg.Key] = r
		}
		r.sections = append(r.sections, tg.Section)
	}
	for k, r := range routes {
		r.sections = slices.Compact(slices.Sorted(slices.Values(r.sections)))
		if r.sections[0] == "" {
			r.sections = r.sections[:1]
		}
		r.routeSettings = settingsOf(policies.Items, httpRouteKind, k)
	}

	on := !off && st.egCRDs
	inject := map[types.NamespacedName]bool{}
	if on {
		for _, r := range routes {
			for _, gw := range r.gateways {
				inject[gw] = true
			}
		}
	}
	ready := map[types.NamespacedName]bool{}
	old := map[types.NamespacedName]string{}
	for gw := range inject {
		pods := istioPodsOf(st, gw)
		ready[gw] = len(pods) > 0 && !slices.ContainsFunc(pods, func(p *corev1.Pod) bool { return !injection.HasEngine(p) })
		for _, p := range pods {
			res.Pods = append(res.Pods, *p)
			if v := tooOld(p); v != "" {
				old[gw] = v
			}
		}
	}

	var errs []error
	failed := map[types.NamespacedName]string{}
	wanted := map[types.NamespacedName]bool{}
	filters := map[types.NamespacedName]bool{}
	if st.egCRDs {
		sidecar, err := i.sidecar(ctx)
		if err != nil {
			return nil, err
		}
		// 1. The engine into the Gateways' pods.
		for gw := range inject {
			if err := i.inject(ctx, st.gateways[gw], sidecar); err != nil {
				errs = append(errs, fmt.Errorf("inject the engine into Gateway %s: %w", gw, err))
				if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
					continue
				}
				log.FromContext(ctx).Error(err, "engine not injected", "gateway", gw)
				for k, r := range routes {
					if slices.Contains(r.gateways, gw) {
						failed[k] = fmt.Sprintf("Gateway %s: %v", gw.Name, err)
					}
				}
			}
		}
		// 2. Each route on each of its Gateways that is ready, unless Istio
		// is too old there or the route's Envoy routes' names aren't its
		// alone: a Gateway's filter doesn't wait for the route's other
		// Gateways, though the route is wired only once it is on all.
		byGateway := map[types.NamespacedName][]*istioRoute{}
		for k, r := range routes {
			wanted[k] = true
			for _, gw := range r.gateways {
				if !ready[gw] {
					wanted[k] = false
					continue
				}
				why := ""
				if old[gw] != "" {
					why = fmt.Sprintf("Gateway %s runs Istio %s: Inkwall wires Istio 1.%d or later", gw.Name, old[gw], istioMinMinor)
				} else {
					why = st.sharedRuleName(r, gw)
				}
				if why != "" {
					if failed[k] == "" {
						failed[k] = why
					}
					continue
				}
				byGateway[gw] = append(byGateway[gw], r)
			}
		}
		// 3. An EnvoyFilter per Gateway with such routes.
		for gw, rs := range byGateway {
			slices.SortFunc(rs, func(a, b *istioRoute) int {
				return strings.Compare(a.route.Namespace+"/"+a.route.Name, b.route.Namespace+"/"+b.route.Name)
			})
			filters[gw] = true
			if err := i.ensure(ctx, envoyFilter(st.gateways[gw], rs)); err != nil {
				errs = append(errs, fmt.Errorf("ensure the EnvoyFilter of Gateway %s: %w", gw, err))
				for _, r := range rs {
					if failed[key(r.route)] == "" {
						failed[key(r.route)] = fmt.Sprintf("Gateway %s: %v", gw.Name, err)
					}
				}
			}
		}
		// 4. The rest goes, in reverse: a route stops calling the engine
		// before its Gateway's pods lose it.
		if _, err := deleteManaged(ctx, i.Client, EnvoyFilterGVK, func(u *unstructured.Unstructured) bool {
			return isIstioIngress(u) || filters[types.NamespacedName{Namespace: u.GetNamespace(), Name: targetGateway(u)}]
		}); err != nil {
			errs = append(errs, err)
		} else if _, err := removeIstioSidecars(ctx, i.Client, i.APIReader, inject); err != nil {
			errs = append(errs, err)
		}
	}

	for tg := range targets {
		r := routes[tg.Key]
		if _, ok := res.Targets[tg]; ok || tg.Kind != httpRouteKind || r == nil || !rules(nil).with(tg.Section).any(r.route) {
			continue
		}
		s := TargetState{Wired: wanted[tg.Key] && failed[tg.Key] == ""}
		if len(r.others) > 0 {
			s.Partly = fmt.Sprintf("HTTPRoute %s is also attached to Gateways of %s, which Inkwall doesn't wire yet: its traffic there is not inspected",
				tg.Key.Name, strings.Join(r.others, ", "))
		}
		switch {
		case !st.egCRDs:
			s.Failed = "Istio's EnvoyFilter CRD is not installed"
		case failed[tg.Key] != "":
			s.Failed = failed[tg.Key]
		case !wanted[tg.Key] && on:
			var why []string
			for _, gw := range r.gateways {
				switch {
				case ready[gw]:
				case len(istioPodsOf(st, gw)) == 0:
					why = append(why, fmt.Sprintf("Gateway %s has no running Istio pod", gw))
				default:
					why = append(why, fmt.Sprintf("Gateway %s has Istio pods without the engine", gw))
				}
			}
			s.Pending = fmt.Sprintf("HTTPRoute %s is wired once every Istio pod of its Gateways has the engine: %s", tg.Key.Name, strings.Join(why, "; "))
		case s.Wired:
			// Istio reports nothing on an EnvoyFilter: in force once Istio
			// serves the route on each of its Gateways.
			s.Pending = istioAccepted(r.route, r.gateways)
		}
		res.Targets[tg] = s
	}
	return res, errors.Join(errs...)
}

func key(o client.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: o.GetNamespace(), Name: o.GetName()}
}

// read lists what the wiring reads, from the cache. It reuses Envoy
// Gateway's state: classes are Istio's (with no EnvoyProxy), and egCRDs
// says Istio's EnvoyFilter CRD is installed.
func (i *Istio) read(ctx context.Context) (*envoyState, error) {
	st := &envoyState{
		routes: map[types.NamespacedName]*gatewayv1.HTTPRoute{}, gateways: map[types.NamespacedName]*gatewayv1.Gateway{},
		classes: map[string]*types.NamespacedName{}, controllers: map[string]string{},
	}
	mapper := i.Client.RESTMapper()
	installed := map[schema.GroupVersionKind]bool{}
	for _, gvk := range []schema.GroupVersionKind{HTTPRouteGVK, GatewayGVK, GatewayClassGVK, EnvoyFilterGVK} {
		ok, err := crdwatch.Installed(mapper, gvk)
		if err != nil {
			return nil, err
		}
		installed[gvk] = ok
	}
	st.egCRDs = installed[EnvoyFilterGVK]
	var (
		routes   gatewayv1.HTTPRouteList
		gateways gatewayv1.GatewayList
		pods     corev1.PodList
	)
	classes := &unstructured.UnstructuredList{}
	classes.SetGroupVersionKind(GatewayClassGVK.GroupVersion().WithKind("GatewayClassList"))
	for gvk, l := range map[schema.GroupVersionKind]client.ObjectList{HTTPRouteGVK: &routes, GatewayGVK: &gateways, GatewayClassGVK: classes} {
		if !installed[gvk] {
			continue
		}
		if err := i.Client.List(ctx, l); err != nil {
			return nil, err
		}
	}
	if err := i.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: i.Pods}); err != nil {
		return nil, err
	}
	for j := range routes.Items {
		hr := &routes.Items[j]
		st.routes[key(hr)] = hr
	}
	for j := range gateways.Items {
		gw := &gateways.Items[j]
		st.gateways[key(gw)] = gw
	}
	for _, gc := range classes.Items {
		c, _, _ := unstructured.NestedString(gc.Object, "spec", "controllerName")
		if st.controllers[gc.GetName()] = c; c == integrations.Istio.GatewayController {
			st.classes[gc.GetName()] = nil
		}
	}
	st.pods = pods.Items
	return st, nil
}

// istioPodsOf returns the running pods Istio runs for a Gateway.
func istioPodsOf(st *envoyState, gw types.NamespacedName) []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range running(st.pods) {
		if p.Namespace == gw.Namespace && p.Labels[istioGatewayLabel] == gw.Name {
			out = append(out, p)
		}
	}
	return out
}

var istioVersion = regexp.MustCompile(`:1\.(\d+)\.`)

// tooOld returns the version of a pod's Istio when it is older than the
// operator wires, read from its istio-proxy image tag; "" when it isn't,
// or the tag says nothing (a custom build).
func tooOld(p *corev1.Pod) string {
	for _, c := range p.Spec.Containers {
		if c.Name != istioProxy {
			continue
		}
		m := istioVersion.FindStringSubmatch(c.Image)
		if m == nil {
			return ""
		}
		if minor, err := strconv.Atoi(m[1]); err == nil && minor < istioMinMinor {
			return "1." + m[1]
		}
	}
	return ""
}

// sharedRuleName says why a route can't be wired on a Gateway: Istio names
// an Envoy route after its HTTPRoute rule's name alone (or
// namespace.route.index for an unnamed rule), so a protected rule's name
// that another HTTPRoute of the Gateway also gives an Envoy route would
// select that route's traffic too.
func (st *envoyState) sharedRuleName(r *istioRoute, gw types.NamespacedName) string {
	ours := map[string]bool{}
	for _, n := range r.envoyRoutes() {
		ours[n] = true
	}
	for _, k := range slices.SortedFunc(maps.Keys(st.routes), func(a, b types.NamespacedName) int { return strings.Compare(a.String(), b.String()) }) {
		hr := st.routes[k]
		if k == key(r.route) {
			continue
		}
		if gws, _ := st.parents(hr); !slices.Contains(gws, gw) {
			continue
		}
		// Its Envoy routes' names: its rules' names, or those Istio gives
		// the unnamed ones.
		theirs := &istioRoute{route: hr, sections: []string{""}}
		for _, n := range theirs.envoyRoutes() {
			if ours[n] {
				return fmt.Sprintf("rule %s of HTTPRoute %s has the name of a rule of HTTPRoute %s on Gateway %s, and Istio names Envoy's routes after their rule: rename one of them",
					n, r.route.Name, k, gw.Name)
			}
		}
	}
	return ""
}

// istioAccepted says what a wired route waits for: Istio accepting it on
// each of its Gateways (its parent status), or "".
func istioAccepted(hr *gatewayv1.HTTPRoute, gateways []types.NamespacedName) string {
	var waiting []string
	for _, gw := range gateways {
		accepted := false
		for _, p := range hr.Status.Parents {
			ns := hr.Namespace
			if p.ParentRef.Namespace != nil {
				ns = string(*p.ParentRef.Namespace)
			}
			if string(p.ControllerName) != integrations.Istio.GatewayController || string(p.ParentRef.Name) != gw.Name || ns != gw.Namespace {
				continue
			}
			accepted = meta.IsStatusConditionTrue(p.Conditions, string(gatewayv1.RouteConditionAccepted))
		}
		if !accepted {
			waiting = append(waiting, gw.String())
		}
	}
	if len(waiting) == 0 {
		return ""
	}
	return fmt.Sprintf("waiting for Istio to accept HTTPRoute %s on Gateway %s", hr.Name, strings.Join(waiting, ", "))
}

// envoyFilter is the operator's EnvoyFilter for a Gateway's pods (0006 §2),
// with its protected routes: the engine's socket as a cluster, and per
// route an ext_proc filter, disabled for the Gateway's other routes, with
// that route's settings, as Envoy Gateway's integration sets them: the
// request headers with the client's protocol, and the body when a policy
// inspects it, held by Envoy (BUFFERED_PARTIAL, up to its buffer limit,
// raised to the largest body a policy inspects) for the engine's verdict;
// the response is not sent. Envoy waits for the engine a little longer than
// its deadline; failure_mode_allow when every policy fails open. In detect
// mode Envoy doesn't wait (observability_mode) and streams the body.
func envoyFilter(gw *gatewayv1.Gateway, routes []*istioRoute) *unstructured.Unstructured {
	f := newObject(EnvoyFilterGVK, gw.Namespace, envoyName(gw.Name))
	owned(f, gw, GatewayGVK)
	var names []string
	var fr []istioFilterRoute
	for _, r := range routes {
		names = append(names, key(r.route).String())
		fr = append(fr, istioFilterRoute{filter: istioFilterName(key(r.route)), envoyRoutes: r.envoyRoutes(), routeSettings: r.routeSettings})
	}
	f.Object["spec"] = map[string]any{
		"workloadSelector": map[string]any{"labels": map[string]any{istioGatewayLabel: gw.Name}},
		"configPatches":    istioPatches(fr),
	}
	f.SetAnnotations(map[string]string{istioRoutes: strings.Join(names, ",")})
	return f
}

// istioFilterRoute is a protected route in an EnvoyFilter: its ext_proc
// filter's name, the names of its Envoy routes, its policies' settings.
type istioFilterRoute struct {
	filter      string
	envoyRoutes []string
	routeSettings
}

// istioPatches are an EnvoyFilter's patches for its routes (0006 §2), for
// Gateway API's Gateways and Istio's ingress gateways alike: the engine's
// socket as a cluster, and per route an ext_proc filter, disabled for the
// gateway's other routes, with that route's settings (istioExtProc), and,
// when a body is held, Envoy's buffer limit raised to the largest body a
// policy inspects.
func istioPatches(routes []istioFilterRoute) []any {
	patches, buffered := istioRoutePatches(routes)
	base := istioBasePatches(buffered)
	// The cluster, the routes' patches, then the listener's: the order the
	// Gateway API wiring has always written.
	return slices.Concat(base[:1], patches, base[1:])
}

// istioBasePatches are the patches a workload needs once, whatever its
// routes: the engine's cluster and, when a route buffers request bodies,
// the listeners' buffer limit.
func istioBasePatches(buffered bool) []any {
	patches := []any{map[string]any{
		"applyTo": "CLUSTER",
		"match":   map[string]any{"context": "GATEWAY"},
		"patch": map[string]any{"operation": "ADD", "value": map[string]any{
			"name":            istioCluster,
			"type":            "STATIC",
			"connect_timeout": "1s",
			"typed_extension_protocol_options": map[string]any{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type":                "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"explicit_http_config": map[string]any{"http2_protocol_options": map[string]any{}},
			}},
			"load_assignment": map[string]any{"cluster_name": istioCluster, "endpoints": []any{map[string]any{"lb_endpoints": []any{map[string]any{
				"endpoint": map[string]any{"address": map[string]any{"pipe": map[string]any{"path": envoySocket}}},
			}}}}},
		}},
	}}
	if buffered {
		patches = append(patches, map[string]any{
			"applyTo": "LISTENER",
			"match":   map[string]any{"context": "GATEWAY"},
			"patch":   map[string]any{"operation": "MERGE", "value": map[string]any{"per_connection_buffer_limit_bytes": int64(envoyBufferLimit)}},
		})
	}
	return patches
}

// istioRoutePatches are the routes' own patches: a disabled ext_proc filter
// per route, enabled on its Envoy routes; buffered tells whether one
// buffers request bodies.
func istioRoutePatches(routes []istioFilterRoute) (patches []any, buffered bool) {
	for _, r := range routes {
		extProc, mode := istioExtProc(r.routeSettings)
		patches = append(patches, map[string]any{
			"applyTo": "HTTP_FILTER",
			"match": map[string]any{"context": "GATEWAY", "listener": map[string]any{"filterChain": map[string]any{"filter": map[string]any{
				"name": "envoy.filters.network.http_connection_manager", "subFilter": map[string]any{"name": "envoy.filters.http.router"},
			}}}},
			"patch": map[string]any{"operation": "INSERT_BEFORE", "value": map[string]any{
				"name": r.filter, "disabled": true, "typed_config": extProc,
			}},
		})
		// Enabled on the protected rules' routes.
		perRoute := map[string]any{
			"@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig",
			"config": map[string]any{
				"@type":     "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute",
				"overrides": map[string]any{"processing_mode": mode},
			},
		}
		for _, rn := range r.envoyRoutes {
			patches = append(patches, map[string]any{
				"applyTo": "HTTP_ROUTE",
				"match":   map[string]any{"context": "GATEWAY", "routeConfiguration": map[string]any{"vhost": map[string]any{"route": map[string]any{"name": rn}}}},
				"patch": map[string]any{"operation": "MERGE", "value": map[string]any{
					"typed_per_filter_config": map[string]any{r.filter: perRoute},
				}},
			})
		}
		buffered = buffered || r.buffered()
	}
	return patches, buffered
}

// istioExtProc is a route's ext_proc filter config, from its policies'
// settings, and the processing mode its routes enable it with: every
// per-policy setting of the Istio wiring is here (Envoy Gateway's are in
// extensionPolicy). The response's headers and body only when a policy
// inspects responses (#374), held likewise (streamed in detect mode), and
// the engine may tell Envoy not to send a body it doesn't read
// (allow_mode_override); otherwise SKIP, which adds nothing to a response.
func istioExtProc(r routeSettings) (config, mode map[string]any) {
	mode = map[string]any{"request_header_mode": "SEND", "response_header_mode": "SKIP"}
	switch {
	case r.body && r.detect:
		mode["request_body_mode"] = "STREAMED"
	case r.body:
		mode["request_body_mode"] = "BUFFERED_PARTIAL"
	}
	if r.responses {
		mode["response_header_mode"] = "SEND"
		mode["response_body_mode"] = "BUFFERED_PARTIAL"
		if r.detect {
			mode["response_body_mode"] = "STREAMED"
		}
	}
	config = map[string]any{
		"@type":              "type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor",
		"grpc_service":       map[string]any{"envoy_grpc": map[string]any{"cluster_name": istioCluster}},
		"processing_mode":    mode,
		"request_attributes": []any{"request.protocol"},
		"message_timeout":    fmt.Sprintf("%.3fs", (r.timeout + messageMargin).Seconds()),
		"failure_mode_allow": r.failOpen,
		// 503, as the engine answers a request it can't inspect; Envoy's
		// default is 500.
		"status_on_error": map[string]any{"code": "ServiceUnavailable"},
	}
	if r.detect {
		config["observability_mode"] = true
	}
	if r.responses {
		config["allow_mode_override"] = true
	}
	return config, mode
}

// isIstioIngress tells an EnvoyFilter of the istio-ingress integration's,
// which the Gateway API wiring leaves alone.
func isIstioIngress(u *unstructured.Unstructured) bool {
	return u.GetLabels()[istioIntegrationLabel] == integrations.IstioIngress.Name
}

// targetGateway is the Gateway an operator's EnvoyFilter is for.
func targetGateway(u *unstructured.Unstructured) string {
	name, _, _ := unstructured.NestedString(u.Object, "spec", "workloadSelector", "labels", istioGatewayLabel)
	return name
}

// ensure creates the operator's EnvoyFilter, or sets its spec, annotations
// and owner. One of the same name it didn't create is left alone, and
// reported.
func (i *Istio) ensure(ctx context.Context, want *unstructured.Unstructured) error {
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(want.GroupVersionKind())
	hash := hashOf(want.Object["spec"])
	annotations := want.GetAnnotations()
	annotations[hashAnnotation] = hash
	switch err := i.Client.Get(ctx, client.ObjectKeyFromObject(want), cur); {
	case apierrors.IsNotFound(err):
		want.SetAnnotations(annotations)
		return i.Client.Create(ctx, want)
	case err != nil:
		return err
	}
	if !isManaged(cur) {
		return fmt.Errorf("%s %s/%s exists and wasn't created by Inkwall; rename or delete it", want.GetKind(), want.GetNamespace(), want.GetName())
	}
	if maps.Equal(cur.GetAnnotations(), annotations) && covers(cur.Object["spec"], want.Object["spec"]) &&
		reflect.DeepEqual(cur.GetOwnerReferences(), want.GetOwnerReferences()) {
		return nil
	}
	cur.Object["spec"] = want.Object["spec"]
	cur.SetOwnerReferences(want.GetOwnerReferences())
	cur.SetAnnotations(annotations)
	return i.Client.Update(ctx, cur)
}

// sidecar is the engine for the Gateways' pods, with the InkwallConfig's
// settings.
func (i *Istio) sidecar(ctx context.Context) (injection.Sidecar, error) {
	s := i.Sidecar
	s.Args = integrations.Istio.Adapter
	s.SocketDir = integrations.EnvoySocketDir
	var cfg wafv1alpha1.InkwallConfig
	switch err := i.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); {
	case apierrors.IsNotFound(err):
		return s, nil
	case err != nil:
		return s, err
	}
	return s.Configured(cfg.Spec.Engine), nil
}

// configMapOf returns the ConfigMap a Gateway's parametersRef names, if
// any.
func configMapOf(gw *gatewayv1.Gateway) string {
	if i := gw.Spec.Infrastructure; i != nil && i.ParametersRef != nil && i.ParametersRef.Group == "" && i.ParametersRef.Kind == "ConfigMap" {
		return i.ParametersRef.Name
	}
	return ""
}

// inject puts the engine into a Gateway's pods: into the deployment overlay
// of the ConfigMap it names, or of one the operator makes and names in its
// parametersRef. Istio renders the Gateway's Deployment again when that
// ConfigMap changes, which rolls its pods.
func (i *Istio) inject(ctx context.Context, gw *gatewayv1.Gateway, s injection.Sidecar) error {
	name, theirs := configMapOf(gw), true
	if name == "" || name == gw.Annotations[istioMark] {
		name, theirs = envoyName(gw.Name), false
	}
	cm := &corev1.ConfigMap{}
	err := i.APIReader.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, cm)
	switch {
	case apierrors.IsNotFound(err) && theirs:
		return fmt.Errorf("its ConfigMap %s doesn't exist", name)
	case apierrors.IsNotFound(err):
		cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Namespace: gw.Namespace, Name: name, Labels: managedLabels(),
			OwnerReferences: []metav1.OwnerReference{{APIVersion: GatewayGVK.GroupVersion().String(), Kind: GatewayGVK.Kind, Name: gw.Name, UID: gw.UID}},
		}}
		cm.Labels[istioSidecarLabel] = "true"
		if _, err := withIstioSidecar(cm, s, true); err != nil {
			return err
		}
		if err := i.Client.Create(ctx, cm); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		changed, err := withIstioSidecar(cm, s, true)
		if err != nil || !changed {
			return err
		}
		if err := i.Client.Update(ctx, cm); err != nil {
			return err
		}
	}
	if configMapOf(gw) != "" {
		return nil
	}
	patch := client.MergeFrom(gw.DeepCopy())
	if gw.Spec.Infrastructure == nil {
		gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{}
	}
	gw.Spec.Infrastructure.ParametersRef = &gatewayv1.LocalParametersReference{Group: "", Kind: "ConfigMap", Name: name}
	if gw.Annotations == nil {
		gw.Annotations = map[string]string{}
	}
	gw.Annotations[istioMark] = name
	return i.Client.Patch(ctx, gw, patch)
}

// Paths in a Deployment overlay.
var (
	istioInitPath       = []string{"spec", "template", "spec", "initContainers"}
	istioVolumesPath    = []string{"spec", "template", "spec", "volumes"}
	istioContainersPath = []string{"spec", "template", "spec", "containers"}
)

// withIstioSidecar adds the engine to a ConfigMap's deployment overlay
// (want), or removes what the operator added: the engine first among the
// init containers, its volumes, and the socket's mount in the istio-proxy
// container. The user's entries stay, in order; a user's overlay is put
// back as it was when nothing else changed. It reports whether cm changed.
func withIstioSidecar(cm *corev1.ConfigMap, s injection.Sidecar, want bool) (bool, error) {
	marked := cm.Labels[istioSidecarLabel] == "true"
	if !want && !marked {
		return false, nil
	}
	raw := cm.Data[istioOverlay]
	overlay := map[string]any{}
	if strings.TrimSpace(raw) != "" {
		if err := yaml.Unmarshal([]byte(raw), &overlay); err != nil {
			return false, fmt.Errorf("ConfigMap %s/%s: its %s overlay: %w", cm.Namespace, cm.Name, istioOverlay, err)
		}
		if overlay == nil {
			overlay = map[string]any{}
		}
	}
	before, err := normalize(overlay)
	if err != nil {
		return false, err
	}
	lists, err := sidecarEntries(s)
	if err != nil {
		return false, err
	}
	// The same entries as in an EnvoyProxy, at the Deployment's paths.
	inits, volumes, mounts := lists[0], lists[1], lists[2]
	inits.path, volumes.path = istioInitPath, istioVolumesPath
	for _, l := range []sidecarList{inits, volumes} {
		cur, _, err := unstructured.NestedSlice(overlay, l.path...)
		if err != nil {
			return false, fmt.Errorf("ConfigMap %s/%s: %w", cm.Namespace, cm.Name, err)
		}
		next := slices.DeleteFunc(slices.Clone(cur), func(x any) bool {
			m, _ := x.(map[string]any)
			name, _ := m["name"].(string)
			return slices.Contains(l.names, name)
		})
		if want {
			if l.first {
				next = append(slices.Clone(l.items), next...)
			} else {
				next = append(next, l.items...)
			}
		}
		if len(next) == 0 {
			unstructured.RemoveNestedField(overlay, l.path...)
			continue
		}
		if err := unstructured.SetNestedSlice(overlay, next, l.path...); err != nil {
			return false, err
		}
	}
	// The socket's mount in istio-proxy: the container's entry merges into
	// Istio's by name.
	containers, _, err := unstructured.NestedSlice(overlay, istioContainersPath...)
	if err != nil {
		return false, fmt.Errorf("ConfigMap %s/%s: %w", cm.Namespace, cm.Name, err)
	}
	found := false
	for j, x := range containers {
		c, _ := x.(map[string]any)
		if c["name"] != istioProxy {
			continue
		}
		found = true
		cur, _ := c["volumeMounts"].([]any)
		next := slices.DeleteFunc(slices.Clone(cur), func(x any) bool {
			m, _ := x.(map[string]any)
			return m["name"] == injection.SocketVolume
		})
		if want {
			next = append(next, mounts.items...)
		}
		if len(next) == 0 {
			delete(c, "volumeMounts")
		} else {
			c["volumeMounts"] = next
		}
		containers[j] = c
	}
	if want && !found {
		containers = append(containers, map[string]any{"name": istioProxy, "volumeMounts": slices.Clone(mounts.items)})
	}
	containers = slices.DeleteFunc(containers, func(x any) bool {
		c, _ := x.(map[string]any)
		return c["name"] == istioProxy && len(c) == 1
	})
	if len(containers) == 0 {
		unstructured.RemoveNestedField(overlay, istioContainersPath...)
	} else if err := unstructured.SetNestedSlice(overlay, containers, istioContainersPath...); err != nil {
		return false, err
	}
	pruneEmpty(overlay, istioInitPath[:len(istioInitPath)-1])
	if spec, ok := overlay["spec"].(map[string]any); ok && len(spec) == 0 {
		delete(overlay, "spec")
	}

	after, err := normalize(overlay)
	if err != nil {
		return false, err
	}
	if want && marked && reflect.DeepEqual(before, after) {
		return false, nil
	}
	if cm.Annotations == nil {
		cm.Annotations = map[string]string{}
	}
	if want {
		if !marked && !isManaged(cm) {
			// The user's overlay, to put back.
			cm.Annotations[istioOriginal] = raw
		}
		if cm.Labels == nil {
			cm.Labels = map[string]string{}
		}
		cm.Labels[istioSidecarLabel] = "true"
		out, err := yaml.Marshal(after)
		if err != nil {
			return false, err
		}
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data[istioOverlay] = string(out)
		return true, nil
	}
	// Removed: the user's overlay as it was, when nothing else changed.
	original, saved := cm.Annotations[istioOriginal]
	orig := map[string]any{}
	if saved && strings.TrimSpace(original) != "" {
		_ = yaml.Unmarshal([]byte(original), &orig)
	}
	origNorm, _ := normalize(orig)
	switch {
	case saved && reflect.DeepEqual(origNorm, after):
		if original == "" {
			delete(cm.Data, istioOverlay)
		} else {
			cm.Data[istioOverlay] = original
		}
	case len(after.(map[string]any)) == 0:
		delete(cm.Data, istioOverlay)
	default:
		out, err := yaml.Marshal(after)
		if err != nil {
			return false, err
		}
		cm.Data[istioOverlay] = string(out)
	}
	delete(cm.Annotations, istioOriginal)
	if len(cm.Annotations) == 0 {
		cm.Annotations = nil
	}
	delete(cm.Labels, istioSidecarLabel)
	if len(cm.Labels) == 0 {
		cm.Labels = nil
	}
	return true, nil
}

// normalize is v as JSON decodes it: numbers as float64.
func normalize(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	return out, json.Unmarshal(raw, &out)
}

// removeIstioSidecars takes the engine out of the pods of the Gateways
// keep doesn't name (nil: all): the operator's entries leave the users'
// ConfigMaps, and a Gateway that names the operator's ConfigMap names none
// again, before that ConfigMap is deleted. It counts the ConfigMaps and
// Gateways it changed. reader lists ConfigMaps, which the cache doesn't
// hold.
func removeIstioSidecars(ctx context.Context, c client.Client, reader client.Reader, keep map[types.NamespacedName]bool) (map[string]int, error) {
	n := map[string]int{}
	used := map[types.NamespacedName]bool{}
	var gateways gatewayv1.GatewayList
	if ok, _ := crdwatch.Installed(c.RESTMapper(), GatewayGVK); ok {
		if err := c.List(ctx, &gateways); err != nil {
			return n, err
		}
	}
	var errs []error
	for j := range gateways.Items {
		gw := &gateways.Items[j]
		k := key(gw)
		if keep[k] {
			for _, name := range []string{configMapOf(gw), envoyName(gw.Name)} {
				used[types.NamespacedName{Namespace: gw.Namespace, Name: name}] = true
			}
			continue
		}
		mark := gw.Annotations[istioMark]
		if mark == "" {
			continue
		}
		patch := client.MergeFrom(gw.DeepCopy())
		if configMapOf(gw) == mark {
			if i := gw.Spec.Infrastructure; len(i.Labels) == 0 && len(i.Annotations) == 0 {
				gw.Spec.Infrastructure = nil
			} else {
				gw.Spec.Infrastructure.ParametersRef = nil
			}
		}
		delete(gw.Annotations, istioMark)
		if err := c.Patch(ctx, gw, patch); client.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("restore Gateway %s: %w", k, err))
			used[types.NamespacedName{Namespace: gw.Namespace, Name: mark}] = true
			continue
		}
		n["Gateway"]++
	}
	var cms corev1.ConfigMapList
	if err := reader.List(ctx, &cms, client.MatchingLabels{istioSidecarLabel: "true"}); err != nil {
		return n, errors.Join(append(errs, err)...)
	}
	for j := range cms.Items {
		cm := &cms.Items[j]
		k := key(cm)
		if used[k] {
			continue
		}
		var err error
		if isManaged(cm) {
			err = c.Delete(ctx, cm)
		} else if _, err = withIstioSidecar(cm, injection.Sidecar{}, false); err == nil {
			err = c.Update(ctx, cm)
		}
		if client.IgnoreNotFound(err) != nil {
			errs = append(errs, fmt.Errorf("restore ConfigMap %s: %w", k, err))
			continue
		}
		n["ConfigMap"]++
	}
	return n, errors.Join(errs...)
}

// Wired implements Integration: an EnvoyFilter of the operator's wires the
// route.
func (i *Istio) Wired(ctx context.Context, tg Target) (bool, error) {
	if tg.Kind != httpRouteKind {
		return false, nil
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(EnvoyFilterGVK.GroupVersion().WithKind("EnvoyFilterList"))
	switch err := i.APIReader.List(ctx, list, client.MatchingLabels(managedLabels())); {
	case meta.IsNoMatchError(err):
		return false, nil
	case err != nil:
		return false, err
	}
	for _, f := range list.Items {
		if slices.Contains(strings.Split(f.GetAnnotations()[istioRoutes], ","), tg.Key.String()) {
			return true, nil
		}
	}
	return false, nil
}

// Unwire implements Integration: the routes stop calling the engine, then
// the engine leaves the Gateways' pods (Istio rolls them), and the users'
// Gateways and ConfigMaps are as they were.
func (i *Istio) Unwire(ctx context.Context, c client.Client) (map[string]int, error) {
	n := map[string]int{}
	count, err := deleteManaged(ctx, c, EnvoyFilterGVK, isIstioIngress)
	if count > 0 {
		n[EnvoyFilterGVK.Kind] = count
	}
	if err != nil {
		return n, err
	}
	reader := i.APIReader
	if reader == nil {
		reader = c
	}
	counts, err := removeIstioSidecars(ctx, c, reader, nil)
	maps.Copy(n, counts)
	return n, err
}

// result is an empty Result of the Istio Gateway API wiring: its pods are
// rolled by Istio, and its filter sends responses to the engine (#374).
func (*Istio) result() *Result {
	return &Result{Proxy: "Istio", Targets: map[Target]TargetState{}, Rolling: true, Responses: true}
}
