// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// The wiring of Istio's ingress gateways (0004 §4.4), for VirtualServices
// bound to Istio's own Gateways (networking.istio.io), which select the
// gateway pods by label. The Pod webhook injects the engine into those
// pods (integrations.IstioIngress) and mounts its socket in istio-proxy;
// the pods are the user's Deployment, restarted to get it. Each proxy
// namespace whose gateway pods serve protected VirtualServices, once every
// running pod a protected VirtualService's Gateways select has the engine,
// gets an EnvoyFilter for those pods: a cluster for the engine's socket, a
// disabled ext_proc filter per protected VirtualService, with its settings,
// enabled on the Envoy routes Istio names after its http routes, and, when
// a body is inspected, Envoy's buffer limit raised. Unprotected routes get
// nothing.
//
// +kubebuilder:rbac:groups=networking.istio.io,resources=envoyfilters,verbs=get;list;watch;create;update;patch;delete,roleName=inkwall-operator-istio-ingress
// +kubebuilder:rbac:groups=networking.istio.io,resources=virtualservices;gateways,verbs=get;list;watch,roleName=inkwall-operator-istio-ingress

// IstioVirtualServiceGVK and IstioGatewayGVK are Istio's, read
// unstructured.
var (
	IstioVirtualServiceGVK = integrations.IstioVirtualServiceGVK
	IstioGatewayGVK        = integrations.IstioGatewayGVK

	virtualServiceKind = IstioVirtualServiceGVK.GroupKind()
)

// Names of the Istio ingress wiring.
const (
	// istioIngressFilter is the operator's EnvoyFilter in a namespace of
	// gateway pods. Not inkwall-waf-<name>, which an Istio Gateway API
	// Gateway's EnvoyFilter could be.
	istioIngressFilter = "inkwall-istio-ingress"
	// istioIntegrationLabel tells the EnvoyFilters of the two Istio
	// integrations apart.
	istioIntegrationLabel = "waf.inkwall.dev/integration"
	// istioIngressRoutes on the operator's EnvoyFilter lists the
	// VirtualServices it wires, namespace/name, comma-separated.
	istioIngressRoutes = "waf.inkwall.dev/virtualservices"
	// istioVSFilterPrefix starts the name of a VirtualService's ext_proc
	// filter in Envoy.
	istioVSFilterPrefix = "inkwall.ext_proc.vs."
)

// IstioIngress is the wiring of Istio's ingress gateways: their
// VirtualServices.
type IstioIngress struct {
	Client client.Client
	// APIReader lists the pods a Gateway selects, uncached: some may not be
	// in the cache (outside the proxy namespaces, other labels).
	APIReader client.Reader
	// Pods selects the gateway pods the Pod webhook injects; PodLabels are
	// its labels, the EnvoyFilters' workloadSelector (nil: the selector
	// isn't plain labels, which an EnvoyFilter can't use).
	Pods      labels.Selector
	PodLabels map[string]string
	// Watches of kinds whose CRD may be missing; nil: only read at each
	// reconcile.
	VirtualServices, Gateways, EnvoyFilters *crdwatch.Kind
}

// Name implements Integration.
func (*IstioIngress) Name() string { return integrations.IstioIngress.Name }

// Kinds implements Integration.
func (*IstioIngress) Kinds() []schema.GroupKind { return []schema.GroupKind{virtualServiceKind} }

// Watch implements Integration.
func (i *IstioIngress) Watch(c controller.Controller, cache cache.Cache, h handler.EventHandler) error {
	if err := c.Watch(source.Kind(cache, client.Object(&corev1.Pod{}), h)); err != nil {
		return err
	}
	addWatches(c, h, i.VirtualServices, i.Gateways, i.EnvoyFilters)
	return nil
}

// VirtualServices lists Istio's VirtualServices; none when their CRD isn't
// installed.
func VirtualServices(ctx context.Context, c client.Client) ([]unstructured.Unstructured, error) {
	if installed, err := crdwatch.Installed(c.RESTMapper(), IstioVirtualServiceGVK); !installed || err != nil {
		return nil, err
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(IstioVirtualServiceGVK.GroupVersion().WithKind("VirtualServiceList"))
	if err := c.List(ctx, list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// istioIngressState is what the wiring reads.
type istioIngressState struct {
	crds     bool
	services map[types.NamespacedName]*unstructured.Unstructured
	gateways map[types.NamespacedName]*unstructured.Unstructured
	// pods are the gateway pods of the integration (the cache's).
	pods []corev1.Pod
}

// vsGateways are the Istio Gateways a VirtualService is bound to, but the
// mesh, and the names it gives that no Gateway has.
func (st *istioIngressState) vsGateways(vs *unstructured.Unstructured) (found []types.NamespacedName, missing []string, mesh bool) {
	names, _, _ := unstructured.NestedStringSlice(vs.Object, "spec", "gateways")
	if len(names) == 0 {
		return nil, nil, true
	}
	for _, n := range names {
		if n == "mesh" {
			mesh = true
			continue
		}
		k := types.NamespacedName{Namespace: vs.GetNamespace(), Name: n}
		if ns, name, ok := strings.Cut(n, "/"); ok {
			k = types.NamespacedName{Namespace: ns, Name: name}
		}
		if st.gateways[k] == nil {
			missing = append(missing, k.String())
			continue
		}
		if !slices.Contains(found, k) {
			found = append(found, k)
		}
	}
	return found, missing, mesh
}

// selector is an Istio Gateway's pod selector; nil when it has none (it
// would select every gateway, which Istio doesn't allow).
func selectorOf(gw *unstructured.Unstructured) labels.Selector {
	sel, _, _ := unstructured.NestedStringMap(gw.Object, "spec", "selector")
	if len(sel) == 0 {
		return nil
	}
	return labels.SelectorFromSet(sel)
}

// vsEnvoyRoutes are the names Istio gives the Envoy routes of a
// VirtualService's http routes: the route's name, followed by "." and the
// match's name for a named match. An http route without a name gives Envoy
// routes no name, or one only its match names, which other VirtualServices
// may share: refused.
func vsEnvoyRoutes(vs *unstructured.Unstructured) ([]string, error) {
	routes, _, _ := unstructured.NestedSlice(vs.Object, "spec", "http")
	var out []string
	for j, r := range routes {
		route, _ := r.(map[string]any)
		name, _ := route["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("spec.http[%d] of VirtualService %s has no name, and Istio names Envoy's routes after it: name every http route", j, vs.GetName())
		}
		matches, _ := route["match"].([]any)
		plain := len(matches) == 0
		for _, m := range matches {
			match, _ := m.(map[string]any)
			if mn, _ := match["name"].(string); mn != "" {
				out = append(out, name+"."+mn)
			} else {
				plain = true
			}
		}
		if plain {
			out = append(out, name)
		}
	}
	return slices.Compact(slices.Sorted(slices.Values(out))), nil
}

// istioVSRoute is a protected VirtualService its gateways serve.
type istioVSRoute struct {
	vs       *unstructured.Unstructured
	gateways []types.NamespacedName
	// pods are the running pods its Gateways select, by namespace, that
	// the integration selects (in the cache).
	pods        map[string][]*corev1.Pod
	envoyRoutes []string
	routeSettings
}

// Wire implements Integration: it gives each namespace of gateway pods
// serving protected VirtualServices an EnvoyFilter for them, once those
// pods have the engine, and removes the rest.
func (i *IstioIngress) Wire(ctx context.Context, targets map[Target]bool, off bool) (*Result, error) {
	st, err := i.read(ctx)
	if err != nil {
		return nil, err
	}
	res := i.result()
	var policies wafv1alpha1.WAFPolicyList
	if err := i.Client.List(ctx, &policies); err != nil {
		return nil, err
	}
	cached := map[types.UID]*corev1.Pod{}
	for j := range st.pods {
		cached[st.pods[j].UID] = &st.pods[j]
	}

	// The pods each Gateway selector selects, listed once per reconcile
	// however many VirtualServices its Gateways serve (#373).
	selected := map[string][]corev1.Pod{}
	routes := map[types.NamespacedName]*istioVSRoute{}
	failed := map[types.NamespacedName]string{}
	pending := map[types.NamespacedName]string{}
	partly := map[types.NamespacedName]string{}
	for tg := range targets {
		vs := st.services[tg.Key]
		if tg.Kind != virtualServiceKind || vs == nil {
			continue
		}
		gws, missing, mesh := st.vsGateways(vs)
		if len(gws) == 0 && len(missing) == 0 {
			res.Targets[tg] = TargetState{Unsupported: fmt.Sprintf("VirtualService %s is bound to no Gateway (only the mesh), which Inkwall doesn't wire", tg.Key.Name)}
			continue
		}
		r := &istioVSRoute{vs: vs, gateways: gws, pods: map[string][]*corev1.Pod{}, routeSettings: settingsOf(policies.Items, virtualServiceKind, tg.Key)}
		routes[tg.Key] = r
		if mesh {
			partly[tg.Key] = fmt.Sprintf("VirtualService %s is also bound to the mesh, whose sidecars Inkwall doesn't wire: its traffic there is not inspected", tg.Key.Name)
		}
		if r.envoyRoutes, err = vsEnvoyRoutes(vs); err != nil {
			failed[tg.Key] = err.Error()
			continue
		}
		var outside []string
		for _, gw := range gws {
			sel := selectorOf(st.gateways[gw])
			if sel == nil {
				failed[tg.Key] = fmt.Sprintf("Istio Gateway %s has no selector", gw)
				break
			}
			// Every pod the Gateway selects, also those the cache leaves
			// out: one the Pod webhook doesn't inject would serve the
			// route uninspected.
			pods, ok := selected[sel.String()]
			if !ok {
				var list corev1.PodList
				if err := i.APIReader.List(ctx, &list, client.MatchingLabelsSelector{Selector: sel}); err != nil {
					return nil, err
				}
				pods = list.Items
				selected[sel.String()] = pods
			}
			for _, p := range running(pods) {
				if c := cached[p.UID]; c != nil {
					if !slices.Contains(r.pods[p.Namespace], c) {
						r.pods[p.Namespace] = append(r.pods[p.Namespace], c)
					}
				} else {
					outside = append(outside, workloadOf(p))
				}
			}
		}
		if failed[tg.Key] != "" {
			continue
		}
		if len(outside) > 0 {
			slices.Sort(outside)
			failed[tg.Key] = fmt.Sprintf("its Gateways select pods the Pod webhook doesn't inject (outside the proxy namespaces, or without the %s integration's labels), which would serve it uninspected: %s",
				integrations.IstioIngress.Name, strings.Join(slices.Compact(outside), ", "))
			continue
		}
		switch {
		case len(gws) == 0:
			pending[tg.Key] = fmt.Sprintf("VirtualService %s is wired once its Gateway %s exists", tg.Key.Name, strings.Join(missing, ", "))
		case len(r.pods) == 0:
			pending[tg.Key] = fmt.Sprintf("VirtualService %s is wired once its Gateways select a running ingress gateway pod in the proxy namespaces", tg.Key.Name)
		}
	}

	on := !off && st.crds
	// The namespaces of gateway pods, and their routes; a route is wired in
	// a namespace once all its pods there have the engine and the socket.
	byNamespace := map[string][]*istioVSRoute{}
	ready := map[types.NamespacedName]bool{}
	var errs []error
	if on {
		if i.PodLabels == nil {
			errs = append(errs, errors.New("the istio-ingress pod selector isn't plain labels, which an EnvoyFilter's workloadSelector needs"))
		}
		seen := map[types.UID]bool{}
		for k, r := range routes {
			if failed[k] != "" || len(r.pods) == 0 {
				continue
			}
			ready[k] = true
			for ns, pods := range r.pods {
				for _, p := range pods {
					if !seen[p.UID] {
						seen[p.UID] = true
						res.Pods = append(res.Pods, *p)
					}
				}
				if slices.ContainsFunc(pods, func(p *corev1.Pod) bool {
					return !injection.HasEngine(p) || !injection.HasSocket(p, integrations.IstioIngress.SocketContainer)
				}) {
					ready[k] = false
					continue
				}
				if v := oldestIstio(pods); v != "" {
					failed[k] = fmt.Sprintf("its gateway pods run Istio %s: Inkwall wires Istio 1.%d or later", v, istioMinMinor)
					continue
				}
				if why := st.sharedVSName(r, ns, k); why != "" {
					failed[k] = why
					continue
				}
				if i.PodLabels != nil {
					byNamespace[ns] = append(byNamespace[ns], r)
				}
			}
		}
	}

	if st.crds {
		keep := map[string]bool{}
		for ns, rs := range byNamespace {
			slices.SortFunc(rs, func(a, b *istioVSRoute) int { return strings.Compare(vsKey(a), vsKey(b)) })
			keep[ns] = true
			if err := i.ensure(ctx, i.envoyFilter(ns, rs)); err != nil {
				errs = append(errs, fmt.Errorf("ensure the EnvoyFilter of namespace %s: %w", ns, err))
				for _, r := range rs {
					if k := key(r.vs); failed[k] == "" {
						failed[k] = fmt.Sprintf("namespace %s: %v", ns, err)
					}
				}
			}
		}
		if _, err := deleteManaged(ctx, i.Client, EnvoyFilterGVK, func(u *unstructured.Unstructured) bool {
			return !isIstioIngress(u) || keep[u.GetNamespace()]
		}); err != nil {
			errs = append(errs, err)
		}
	}

	for tg := range targets {
		r := routes[tg.Key]
		if _, ok := res.Targets[tg]; ok || tg.Kind != virtualServiceKind || r == nil {
			continue
		}
		s := TargetState{Wired: ready[tg.Key] && failed[tg.Key] == "", Partly: partly[tg.Key]}
		switch {
		case !st.crds:
			s.Failed = "Istio's VirtualService, Gateway and EnvoyFilter CRDs are not all installed"
		case failed[tg.Key] != "":
			s.Failed = failed[tg.Key]
		case pending[tg.Key] != "":
			s.Pending = pending[tg.Key]
		case on && !ready[tg.Key]:
			s.Pending = fmt.Sprintf("VirtualService %s is wired once every gateway pod its Gateways select has the engine", tg.Key.Name)
		case s.Wired:
			s.Pending = istioVSReconciled(r.vs)
		}
		res.Targets[tg] = s
	}
	return res, errors.Join(errs...)
}

func oldestIstio(pods []*corev1.Pod) string {
	for _, p := range pods {
		if v := tooOld(p); v != "" {
			return v
		}
	}
	return ""
}

func vsKey(r *istioVSRoute) string { return key(r.vs).String() }

// istioVSReconciled says what a wired VirtualService waits for: Istio
// reports nothing on it by default, but with status enabled
// (PILOT_ENABLE_STATUS) a Reconciled condition that isn't True.
func istioVSReconciled(vs *unstructured.Unstructured) string {
	conds, _, _ := unstructured.NestedSlice(vs.Object, "status", "conditions")
	for _, c := range conds {
		cond, _ := c.(map[string]any)
		if cond["type"] == "Reconciled" && cond["status"] != "True" {
			return fmt.Sprintf("waiting for Istio to reconcile VirtualService %s", vs.GetName())
		}
	}
	return ""
}

// sharedVSName says why a VirtualService can't be wired on a namespace's
// gateway pods: another VirtualService those pods serve names an Envoy
// route as it does, so its filter would be on for that route too.
func (st *istioIngressState) sharedVSName(r *istioVSRoute, ns string, self types.NamespacedName) string {
	ours := map[string]bool{}
	for _, n := range r.envoyRoutes {
		ours[n] = true
	}
	for _, k := range slices.SortedFunc(maps.Keys(st.services), func(a, b types.NamespacedName) int { return strings.Compare(a.String(), b.String()) }) {
		if k == self {
			continue
		}
		other := st.services[k]
		gws, _, _ := st.vsGateways(other)
		serves := false
		for _, gw := range gws {
			if sel := selectorOf(st.gateways[gw]); sel != nil && slices.ContainsFunc(st.pods, func(p corev1.Pod) bool {
				return p.Namespace == ns && sel.Matches(labels.Set(p.Labels))
			}) {
				serves = true
			}
		}
		if !serves {
			continue
		}
		names, _ := vsEnvoyRoutes(other)
		for _, n := range names {
			if ours[n] {
				return fmt.Sprintf("http route %s of VirtualService %s has the name of one of VirtualService %s, served by the same gateway pods (namespace %s), and Istio names Envoy's routes after it: rename one of them",
					n, self.Name, k, ns)
			}
		}
	}
	return ""
}

// envoyFilter is the operator's EnvoyFilter for a namespace's gateway pods,
// with the protected VirtualServices they serve.
func (i *IstioIngress) envoyFilter(ns string, routes []*istioVSRoute) *unstructured.Unstructured {
	f := newObject(EnvoyFilterGVK, ns, istioIngressFilter)
	lbl := f.GetLabels()
	lbl[istioIntegrationLabel] = integrations.IstioIngress.Name
	f.SetLabels(lbl)
	var names []string
	var fr []istioFilterRoute
	for _, r := range routes {
		k := key(r.vs)
		names = append(names, k.String())
		fr = append(fr, istioFilterRoute{filter: istioVSFilterPrefix + k.Namespace + "." + k.Name, envoyRoutes: r.envoyRoutes, routeSettings: r.routeSettings})
	}
	podLabels := map[string]any{}
	for k, v := range i.PodLabels {
		podLabels[k] = v
	}
	f.Object["spec"] = map[string]any{
		"workloadSelector": map[string]any{"labels": podLabels},
		"configPatches":    istioPatches(fr),
	}
	f.SetAnnotations(map[string]string{istioIngressRoutes: strings.Join(names, ",")})
	return f
}

// ensure creates or updates the operator's EnvoyFilter, as the Gateway API
// wiring does.
func (i *IstioIngress) ensure(ctx context.Context, want *unstructured.Unstructured) error {
	return (&Istio{Client: i.Client}).ensure(ctx, want)
}

// read lists what the wiring reads, from the cache.
func (i *IstioIngress) read(ctx context.Context) (*istioIngressState, error) {
	st := &istioIngressState{services: map[types.NamespacedName]*unstructured.Unstructured{}, gateways: map[types.NamespacedName]*unstructured.Unstructured{}}
	st.crds = true
	for _, gvk := range []schema.GroupVersionKind{IstioVirtualServiceGVK, IstioGatewayGVK, EnvoyFilterGVK} {
		ok, err := crdwatch.Installed(i.Client.RESTMapper(), gvk)
		if err != nil {
			return nil, err
		}
		st.crds = st.crds && ok
	}
	if !st.crds {
		// The VirtualServices still count: the targets exist.
		services, err := VirtualServices(ctx, i.Client)
		if err != nil {
			return nil, err
		}
		for j := range services {
			st.services[key(&services[j])] = &services[j]
		}
		return st, nil
	}
	for gvk, m := range map[schema.GroupVersionKind]map[types.NamespacedName]*unstructured.Unstructured{IstioVirtualServiceGVK: st.services, IstioGatewayGVK: st.gateways} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
		if err := i.Client.List(ctx, list); err != nil {
			return nil, err
		}
		for j := range list.Items {
			m[key(&list.Items[j])] = &list.Items[j]
		}
	}
	var pods corev1.PodList
	if err := i.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: i.Pods}); err != nil {
		return nil, err
	}
	st.pods = pods.Items
	return st, nil
}

// Wired implements Integration: an EnvoyFilter of the operator's wires the
// VirtualService.
func (i *IstioIngress) Wired(ctx context.Context, tg Target) (bool, error) {
	if tg.Kind != virtualServiceKind {
		return false, nil
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(EnvoyFilterGVK.GroupVersion().WithKind("EnvoyFilterList"))
	switch err := i.APIReader.List(ctx, list, client.MatchingLabels{istioIntegrationLabel: integrations.IstioIngress.Name}); {
	case meta.IsNoMatchError(err):
		return false, nil
	case err != nil:
		return false, err
	}
	for _, f := range list.Items {
		if isManaged(&f) && slices.Contains(strings.Split(f.GetAnnotations()[istioIngressRoutes], ","), tg.Key.String()) {
			return true, nil
		}
	}
	return false, nil
}

// Unwire implements Integration: the VirtualServices stop calling the
// engine. The gateway pods keep it until they restart, as Traefik's do.
func (i *IstioIngress) Unwire(ctx context.Context, c client.Client) (map[string]int, error) {
	n := map[string]int{}
	count, err := deleteManaged(ctx, c, EnvoyFilterGVK, func(u *unstructured.Unstructured) bool { return !isIstioIngress(u) })
	if count > 0 {
		n[EnvoyFilterGVK.Kind] = count
	}
	return n, err
}

// result is an empty Result of the Istio ingress wiring: its filter sends
// responses to the engine (#374).
func (*IstioIngress) result() *Result {
	return &Result{Proxy: "Istio ingress gateway", Targets: map[Target]TargetState{}, Responses: true}
}
