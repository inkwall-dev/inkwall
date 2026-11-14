// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package wiring sends a proxy's protected routes to the engine (0004
// §4.4), through one Integration per proxy. For Traefik: an operator-owned
// ForwardAuth Middleware in each namespace with protected routes, attached
// to protected Ingresses through Traefik's router.middlewares annotation,
// to protected IngressRoutes' routes through their middlewares, and to
// protected HTTPRoutes' rules through an ExtensionRef filter.
package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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

	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// Names of the Traefik wiring.
const (
	// MiddlewareName is the operator's Middleware in each protected
	// namespace; not "inkwall", so it can't take over one made by hand.
	MiddlewareName = "inkwall-waf"
	// MiddlewaresAnnotation lists an Ingress router's Middlewares.
	MiddlewaresAnnotation = "traefik.ingress.kubernetes.io/router.middlewares"
	// WiredAnnotation marks an Ingress, IngressRoute or HTTPRoute the
	// operator wired, with the Middleware it added (MiddlewareRef on an
	// Ingress, MiddlewareName on the others), so it removes exactly that.
	WiredAnnotation = "waf.inkwall.dev/wired"
	// legacyClassAnnotation is the class before ingressClassName.
	legacyClassAnnotation  = "kubernetes.io/ingress.class"
	defaultClassAnnotation = "ingressclass.kubernetes.io/is-default-class"

	// forwardAuthAddress is the injected engine, in Traefik's pod.
	forwardAuthAddress = "http://127.0.0.1:9001/v1/forward-auth"
	// maxAuthResponseBytes caps the engine's answer that Traefik reads: a
	// status line's worth today, with room for a block page.
	maxAuthResponseBytes = 64 << 10

	// From Traefik v3.7, MiddlewareName chains two Middlewares (#625):
	// bodyMiddlewareName bounds the request body (Buffering), then
	// authMiddlewareName asks the engine (ForwardAuth).
	bodyMiddlewareName = MiddlewareName + "-body"
	authMiddlewareName = MiddlewareName + "-auth"
	// maxBufferedBody is the largest body Traefik reads: one byte more than
	// the largest body.maxBytes, so such a body reaches the engine, which
	// handles it as oversized. Traefik answers 413 to a larger one.
	maxBufferedBody = policy.MaxBodyBytes + 1
)

// middlewareNames are the operator's Middlewares in a namespace, the one
// routes refer to first.
var middlewareNames = []string{MiddlewareName, bodyMiddlewareName, authMiddlewareName}

// MiddlewareRef is how an Ingress in namespace refers to the operator's
// Middleware there.
func MiddlewareRef(namespace string) string {
	return namespace + "-" + MiddlewareName + "@kubernetescrd"
}

// Middleware returns the operator's Middleware for namespace that routes
// refer to, as Traefik v3.7 and later get it.
func Middleware(namespace string) *unstructured.Unstructured {
	ms := ourMiddlewares(namespace, false)
	return ms[len(ms)-1]
}

// Middlewares returns the operator's Middlewares for namespace, as Traefik
// v3.7 and later get them, in the order they are written: the one routes
// refer to last.
func Middlewares(namespace string) []*unstructured.Unstructured {
	return ourMiddlewares(namespace, false)
}

// ourMiddlewares returns the operator's Middlewares for namespace, in the
// order they are written, the one routes refer to (MiddlewareName) last.
//
// Traefik's ForwardAuth allocates maxBodySize+1 bytes for every request,
// with a body or not (pkg/middlewares/auth/forward.go, v3.7): at the 10 MiB
// a policy may inspect, that added 8 ms to every request (#625). From
// Traefik v3.7, a Buffering Middleware bounds the body instead: it reads
// what comes, and answers 413 past maxBufferedBody. ForwardAuth, after it,
// then reads the whole (bounded) body, with no limit of its own. Before
// v3.7 (legacy), Buffering can't let responses through unbuffered, which
// would hold back streamed responses: ForwardAuth bounds the body itself,
// as before.
func ourMiddlewares(namespace string, legacy bool) []*unstructured.Unstructured {
	m := func(name string, spec map[string]any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
		u.SetNamespace(namespace)
		u.SetName(name)
		u.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"})
		u.Object["spec"] = spec
		return u
	}
	if legacy {
		return []*unstructured.Unstructured{m(MiddlewareName, map[string]any{"forwardAuth": forwardAuth(true)})}
	}
	return []*unstructured.Unstructured{
		m(bodyMiddlewareName, map[string]any{"buffering": map[string]any{
			"maxRequestBodyBytes": int64(maxBufferedBody),
			// In memory, as ForwardAuth held it: Traefik writes a body
			// as large as this to a file (which a read-only root file
			// system may not allow).
			"memRequestBodyBytes": int64(maxBufferedBody),
			// Responses pass as they come (Server-Sent Events,
			// downloads): only the request is held.
			"disableResponseBuffer": true,
		}}),
		m(authMiddlewareName, map[string]any{"forwardAuth": forwardAuth(false)}),
		m(MiddlewareName, map[string]any{"chain": map[string]any{"middlewares": []any{
			map[string]any{"name": bodyMiddlewareName},
			map[string]any{"name": authMiddlewareName},
		}}}),
	}
}

// forwardAuth is the ForwardAuth Middleware's spec. It sets no timeout or
// failure behaviour: Traefik has neither. When Traefik can't reach the
// engine, it answers 500 itself and doesn't forward the request, at once on
// a refused connection, after its fixed 30 s client timeout on a hung
// engine (pkg/middlewares/auth/forward.go, v3.7; traefik/traefik#9857).
// The policy's mode and failure mode apply only while the engine answers
// (0002 §7.3).
func forwardAuth(legacy bool) map[string]any {
	fa := map[string]any{
		"address": forwardAuthAddress,
		// Must be false: with true, Traefik keeps a client's own
		// X-Forwarded-Uri, and the engine would inspect that instead of
		// the real URI (0002 §6.3).
		"trustForwardHeader": false,
		// Without it, bodies reach the application uninspected.
		"forwardBody":         true,
		"authResponseHeaders": []any{"X-Request-Id"},
	}
	if legacy {
		// The largest body a policy can inspect: smaller bodies reach
		// the engine, whose policy decides; Traefik refuses larger ones
		// (401) itself. Traefik allocates it for every request.
		fa["maxBodySize"] = int64(policy.MaxBodyBytes)
		return fa
	}
	// No limit: the Buffering Middleware before it bounds the body.
	fa["maxBodySize"] = int64(-1)
	// Without it, Traefik reads any size of answer from the engine, and
	// warns about it (v3.7).
	fa["maxResponseBodySize"] = int64(maxAuthResponseBytes)
	return fa
}

// SpecMatches reports whether a Middleware's spec, as read from the API
// server, is want's.
func SpecMatches(got, want *unstructured.Unstructured) bool {
	// Through JSON, numbers compare whatever their Go type (int64 as
	// written, int64 or float64 as read).
	norm := func(u *unstructured.Unstructured) any {
		raw, err := json.Marshal(u.Object["spec"])
		if err != nil {
			return nil
		}
		var v any
		if json.Unmarshal(raw, &v) != nil {
			return nil
		}
		return v
	}
	g, w := norm(got), norm(want)
	return w != nil && reflect.DeepEqual(g, w)
}

// dropsV37Fields reports whether the API server dropped, from a Middleware
// it stored (m, as returned), a field of want that Traefik v3.7 added: its
// CRD is older.
func dropsV37Fields(m, want *unstructured.Unstructured) bool {
	for _, path := range [][]string{
		{"spec", "buffering", "disableResponseBuffer"},
		{"spec", "forwardAuth", "maxResponseBodySize"},
	} {
		_, asked, _ := unstructured.NestedFieldNoCopy(want.Object, path...)
		_, kept, _ := unstructured.NestedFieldNoCopy(m.Object, path...)
		if asked && !kept {
			return true
		}
	}
	return false
}

// oldTraefik reports whether one of Traefik's pods runs Traefik before
// v3.7, by its image's tag. An image whose version can't be told (a digest,
// latest, another name) is taken to match Traefik's CRDs.
func oldTraefik(pods []corev1.Pod) bool {
	for i := range pods {
		for _, c := range pods[i].Spec.Containers {
			repo, tag, ok := strings.Cut(c.Image[strings.LastIndex(c.Image, "/")+1:], ":")
			if !ok || repo != "traefik" {
				continue
			}
			var major, minor int
			if n, _ := fmt.Sscanf(strings.TrimPrefix(tag, "v"), "%d.%d", &major, &minor); n == 2 && (major < 3 || major == 3 && minor < 7) {
				return true
			}
		}
	}
	return false
}

// WithMiddleware returns the annotation value with ref added (first, so the
// engine sees the request before other Middlewares change it), unchanged if
// present.
func WithMiddleware(current, ref string) string {
	items := splitMiddlewares(current)
	for _, it := range items {
		if it == ref {
			return current
		}
	}
	return strings.Join(append([]string{ref}, items...), ",")
}

// WithoutMiddleware returns the annotation value without ref.
func WithoutMiddleware(current, ref string) string {
	var out []string
	for _, it := range splitMiddlewares(current) {
		if it != ref {
			out = append(out, it)
		}
	}
	return strings.Join(out, ",")
}

// WithRouteMiddleware adds the operator's Middleware to every route of an
// IngressRoute (want), first, or removes it from them. A route refers to it
// by name only: Traefik looks it up in the IngressRoute's namespace, which
// needs no allowCrossNamespace. The user's Middlewares stay, in order. It
// reports whether ir changed.
func WithRouteMiddleware(ir *unstructured.Unstructured, want bool) (bool, error) {
	routes, _, err := unstructured.NestedSlice(ir.Object, "spec", "routes")
	if err != nil {
		return false, err
	}
	ours := func(m any) bool {
		ref, _ := m.(map[string]any)
		ns, _ := ref["namespace"].(string)
		return ref["name"] == MiddlewareName && (ns == "" || ns == ir.GetNamespace())
	}
	changed := false
	for i, r := range routes {
		route, ok := r.(map[string]any)
		if !ok {
			return false, fmt.Errorf("spec.routes[%d] is not an object", i)
		}
		mws, _ := route["middlewares"].([]any)
		has := slices.ContainsFunc(mws, ours)
		switch {
		case want && !has:
			route["middlewares"] = append([]any{map[string]any{"name": MiddlewareName}}, mws...)
		case !want && has:
			if mws = slices.DeleteFunc(mws, ours); len(mws) == 0 {
				delete(route, "middlewares")
			} else {
				route["middlewares"] = mws
			}
		default:
			continue
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, unstructured.SetNestedSlice(ir.Object, routes, "spec", "routes")
}

func splitMiddlewares(s string) []string {
	var out []string
	for _, it := range strings.Split(s, ",") {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return out
}

// Controller returns the controller of the IngressClass serving ing, or ""
// when it can't be told. classes maps class names to their controllers;
// defaultClass is the class marked default, if any.
func Controller(ing *networkingv1.Ingress, classes map[string]string, defaultClass string) string {
	name := ""
	if ing.Spec.IngressClassName != nil {
		name = *ing.Spec.IngressClassName
	} else if a := ing.Annotations[legacyClassAnnotation]; a != "" {
		name = a
	} else {
		name = defaultClass
	}
	if c, ok := classes[name]; ok {
		return c
	}
	// The legacy annotation names Traefik's default class without an
	// IngressClass object.
	if name == "traefik" {
		return integrations.Traefik.Controller
	}
	return ""
}

// IsDefaultClass reports whether an IngressClass is the cluster default.
func IsDefaultClass(ic *networkingv1.IngressClass) bool {
	return ic.Annotations[defaultClassAnnotation] == "true"
}

// Traefik's wiring reads routes, classes and Traefik's pods, and writes the
// Middleware in protected namespaces and the references to it.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch,roleName=inkwall-operator-traefik
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch,roleName=inkwall-operator-traefik
// +kubebuilder:rbac:groups=traefik.io,resources=middlewares,verbs=get;list;watch;create;update;patch;delete,roleName=inkwall-operator-traefik
// +kubebuilder:rbac:groups=traefik.io,resources=ingressroutes,verbs=get;list;watch;update;patch,roleName=inkwall-operator-traefik
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;update;patch,roleName=inkwall-operator-traefik
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;gatewayclasses,verbs=get;list;watch,roleName=inkwall-operator-traefik

// Traefik is the wiring of Traefik: its Ingresses, IngressRoutes, and the
// HTTPRoutes of its Gateway API provider.
type Traefik struct {
	Client client.Client
	// APIReader reads Middlewares and targets uncached.
	APIReader client.Reader
	// Pods selects Traefik's pods (integrations.Selectors).
	Pods labels.Selector
	// Watches of IngressRoutes, HTTPRoutes, Gateways and GatewayClasses,
	// once their CRDs are installed; nil: only read at each reconcile.
	IngressRoutes, HTTPRoutes, Gateways, GatewayClasses *crdwatch.Kind

	// legacyCRD: the API server dropped a field Traefik v3.7 added from a
	// Middleware (its CRD is older), so the Middlewares of older Traefiks
	// are written from then on; otherwise every reconcile would rewrite
	// them.
	legacyCRD atomic.Bool
}

var (
	ingressKind = schema.GroupKind{Group: networkingv1.GroupName, Kind: "Ingress"}
	routeKind   = integrations.TraefikIngressRouteGVK.GroupKind()
)

// Name implements Integration.
func (*Traefik) Name() string { return integrations.Traefik.Name }

// Kinds implements Integration.
func (*Traefik) Kinds() []schema.GroupKind {
	return []schema.GroupKind{ingressKind, routeKind, httpRouteKind}
}

// Watch implements Integration.
func (t *Traefik) Watch(c controller.Controller, cache cache.Cache, h handler.EventHandler) error {
	// Ingress annotations matter (the operator's own included). The
	// manager caches only proxy pods: their sidecar decides PendingRestart.
	for _, obj := range []client.Object{&networkingv1.Ingress{}, &networkingv1.IngressClass{}, &corev1.Pod{}} {
		if err := c.Watch(source.Kind(cache, obj, h)); err != nil {
			return err
		}
	}
	// Their middlewares and filters matter (the operator's own included),
	// and which Gateways, of which classes, serve an HTTPRoute.
	for _, k := range []*crdwatch.Kind{t.IngressRoutes, t.HTTPRoutes, t.Gateways, t.GatewayClasses} {
		if k != nil {
			k.Add(c, h)
		}
	}
	return nil
}

// target is an Ingress some policy protects.
type target struct {
	ing        *networkingv1.Ingress
	controller string
}

// state is what Wire found, for its Result.
type state struct {
	ingresses map[types.NamespacedName]*networkingv1.Ingress
	// wire are the Ingress targets.
	wire map[types.NamespacedName]target
	// routes are the IngressRoutes, when routeCRD (their CRD is
	// installed); routeErr says why one couldn't be wired.
	routes   map[types.NamespacedName]*unstructured.Unstructured
	routeCRD bool
	routeErr map[types.NamespacedName]string
	// httpRoutes are the HTTPRoutes (none without their CRD), with the
	// controllers of their Gateways; httpRouteErr says why one couldn't be
	// wired.
	httpRoutes   map[types.NamespacedName]*gatewayv1.HTTPRoute
	controllers  map[types.NamespacedName][]string
	httpRouteErr map[types.NamespacedName]string
	// ingressErr says why an Ingress couldn't be wired.
	ingressErr map[types.NamespacedName]string
	// traefikCRDs: the Middleware CRD is installed.
	traefikCRDs bool
	// middlewareErr: namespace -> why its Middleware can't be used.
	middlewareErr map[string]string
	// wanted are the routes kept wired, by kind.
	wanted map[schema.GroupKind]map[types.NamespacedName]bool
	pods   []corev1.Pod
}

// IngressRoutes lists Traefik's IngressRoutes; installed is false, with
// none, when their CRD isn't.
func IngressRoutes(ctx context.Context, c client.Client) (routes []unstructured.Unstructured, installed bool, err error) {
	if installed, err = crdwatch.Installed(c.RESTMapper(), integrations.TraefikIngressRouteGVK); !installed || err != nil {
		return nil, false, err
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(integrations.TraefikIngressRouteGVK.GroupVersion().WithKind("IngressRouteList"))
	if err := c.List(ctx, list); err != nil {
		return nil, true, err
	}
	return list.Items, true, nil
}

// Wire implements Integration: it wires every protected Traefik Ingress and
// IngressRoute, and unwires the rest.
func (t *Traefik) Wire(ctx context.Context, targets map[Target]bool, off bool) (*Result, error) {
	logger := log.FromContext(ctx)
	var (
		ingresses networkingv1.IngressList
		classList networkingv1.IngressClassList
		pods      corev1.PodList
	)
	for _, l := range []client.ObjectList{&ingresses, &classList} {
		if err := t.Client.List(ctx, l); err != nil {
			return nil, err
		}
	}
	if err := t.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: t.Pods}); err != nil {
		return nil, err
	}
	classes, defaultClass := map[string]string{}, ""
	for i := range classList.Items {
		ic := &classList.Items[i]
		classes[ic.Name] = ic.Spec.Controller
		if IsDefaultClass(ic) {
			defaultClass = ic.Name
		}
	}
	byKey := map[types.NamespacedName]*networkingv1.Ingress{}
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		byKey[types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}] = ing
	}

	routes, routeCRD, err := IngressRoutes(ctx, t.Client)
	if err != nil {
		return nil, err
	}
	st := &state{
		ingresses: byKey, wire: map[types.NamespacedName]target{},
		routes: map[types.NamespacedName]*unstructured.Unstructured{}, routeCRD: routeCRD, routeErr: map[types.NamespacedName]string{},
		httpRouteErr: map[types.NamespacedName]string{},
		ingressErr:   map[types.NamespacedName]string{},
		traefikCRDs:  t.middlewaresInstalled(), middlewareErr: map[string]string{},
		wanted: map[schema.GroupKind]map[types.NamespacedName]bool{ingressKind: {}, routeKind: {}, httpRouteKind: {}},
		pods:   pods.Items,
	}
	for i := range routes {
		ir := &routes[i]
		st.routes[types.NamespacedName{Namespace: ir.GetNamespace(), Name: ir.GetName()}] = ir
	}
	if st.httpRoutes, st.controllers, err = t.httpRoutes(ctx); err != nil {
		return nil, err
	}

	// The routes go to the engine only while a Traefik pod that gets it
	// runs. With injection off, or no Traefik pod selected (the
	// InkwallConfig's selector changed, or was deleted), new proxy pods
	// would have no engine: nothing is wired.
	on := !off && len(running(pods.Items)) > 0 && st.traefikCRDs

	// The routes to wire: every Ingress target that Traefik serves, every
	// IngressRoute target, and the rules of every HTTPRoute target that
	// only Traefik's Gateways serve. Another controller can't resolve the
	// ExtensionRef to Traefik's Middleware, and must fail the rules that
	// have it (Gateway API): such a route isn't wired.
	wireRoutes := map[types.NamespacedName]bool{}
	wireRules := map[types.NamespacedName]rules{}
	for tg := range targets {
		switch tg.Kind {
		case httpRouteKind:
			if hr, ok := st.httpRoutes[tg.Key]; ok && st.traefikOnly(tg.Key) {
				if wireRules[tg.Key] = wireRules[tg.Key].with(tg.Section); !wireRules[tg.Key].any(hr) {
					delete(wireRules, tg.Key)
				}
			}
		case ingressKind:
			if ing, ok := byKey[tg.Key]; ok {
				st.wire[tg.Key] = target{ing: ing, controller: Controller(ing, classes, defaultClass)}
			}
		case routeKind:
			if _, ok := st.routes[tg.Key]; ok {
				wireRoutes[tg.Key] = true
			}
		}
	}

	needed := map[string]bool{} // namespaces whose Middleware is used
	if on {
		for _, tg := range st.wire {
			if tg.controller == integrations.Traefik.Controller {
				needed[tg.ing.Namespace] = true
			}
		}
		for k := range wireRoutes {
			needed[k.Namespace] = true
		}
		for k := range wireRules {
			needed[k.Namespace] = true
		}
		old := oldTraefik(pods.Items)
		for ns := range needed {
			if err := t.ensureMiddleware(ctx, ns, old); err != nil {
				st.middlewareErr[ns] = err.Error()
				logger.Error(err, "Middleware not wired", "namespace", ns)
			}
		}
	}

	// Ingress annotations: add the Middleware to protected Traefik
	// Ingresses, remove it from those the operator wired before. One that
	// can't be written is reported, the others are still wired, and its
	// namespace keeps the Middleware: a router referring to a missing one
	// fails.
	var errs []error
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		k := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		tg, protected := st.wire[k]
		want := protected && on && tg.controller == integrations.Traefik.Controller && st.middlewareErr[ing.Namespace] == ""
		st.wanted[ingressKind][k] = want
		if err := annotate(ctx, t.Client, ing, want); err != nil {
			errs = append(errs, fmt.Errorf("wire Ingress %s: %w", k, err))
			st.ingressErr[k] = fmt.Sprintf("Ingress %s: %v", k.Name, err)
			needed[k.Namespace] = true
		}
	}

	// IngressRoutes: the same, in each route's middlewares.
	for k, ir := range st.routes {
		want := wireRoutes[k] && on && st.middlewareErr[k.Namespace] == ""
		st.wanted[routeKind][k] = want
		switch err := wireRoute(ctx, t.Client, ir, want); {
		case apierrors.IsConflict(err):
			// Changed since the cache saw it: again, once it has.
			errs = append(errs, fmt.Errorf("wire IngressRoute %s: %w", k, err))
			needed[k.Namespace] = true
		case err != nil:
			errs = append(errs, fmt.Errorf("wire IngressRoute %s: %w", k, err))
			st.routeErr[k] = fmt.Sprintf("IngressRoute %s: %v", k.Name, err)
			logger.Error(err, "IngressRoute not wired", "ingressroute", k)
			needed[k.Namespace] = true
		}
	}

	// HTTPRoutes: the same, in their rules' filters.
	for k, hr := range st.httpRoutes {
		var sel rules
		if r, ok := wireRules[k]; ok && on && st.middlewareErr[k.Namespace] == "" {
			sel = r
		}
		st.wanted[httpRouteKind][k] = sel != nil
		switch err := t.wireHTTPRoute(ctx, hr, sel); {
		case apierrors.IsConflict(err):
			errs = append(errs, fmt.Errorf("wire HTTPRoute %s: %w", k, err))
			needed[k.Namespace] = true
		case err != nil:
			errs = append(errs, fmt.Errorf("wire HTTPRoute %s: %w", k, err))
			st.httpRouteErr[k] = fmt.Sprintf("HTTPRoute %s: %v", k.Name, err)
			logger.Error(err, "HTTPRoute not wired", "httproute", k)
			needed[k.Namespace] = true
		}
	}

	// After the routes: a router referring to a missing Middleware fails.
	if st.traefikCRDs {
		if err := t.pruneMiddlewares(ctx, needed); err != nil {
			errs = append(errs, err)
		}
	}
	return st.result(targets), errors.Join(errs...)
}

// result reports on each target.
func (st *state) result(targets map[Target]bool) *Result {
	res := &Result{Proxy: "Traefik", Targets: map[Target]TargetState{}, Pods: st.pods}
	for tg := range targets {
		k := tg.Key
		var s TargetState
		switch tg.Kind {
		case ingressKind:
			if _, ok := st.ingresses[k]; !ok {
				continue
			}
			switch c := st.wire[k].controller; {
			case c != integrations.Traefik.Controller:
				if c == "" {
					c = "no known IngressClass"
				}
				s.Unsupported = fmt.Sprintf("Ingress %s is served by %s, which Inkwall doesn't wire yet", k.Name, c)
			case !st.traefikCRDs:
				s.Failed = "Traefik's Middleware CRD is not installed"
			case st.middlewareErr[k.Namespace] != "":
				s.Failed = st.middlewareErr[k.Namespace]
			case st.ingressErr[k] != "":
				s.Failed = st.ingressErr[k]
			}
		case routeKind:
			switch {
			case !st.routeCRD:
				s.Failed = "Traefik's IngressRoute CRD is not installed"
			case st.routes[k] == nil:
				continue
			case !st.traefikCRDs:
				s.Failed = "Traefik's Middleware CRD is not installed"
			case st.middlewareErr[k.Namespace] != "":
				s.Failed = st.middlewareErr[k.Namespace]
			case st.routeErr[k] != "":
				s.Failed = st.routeErr[k]
			}
		case httpRouteKind:
			hr := st.httpRoutes[k]
			if hr == nil || !rules(nil).with(tg.Section).any(hr) {
				continue // Accepted reports it
			}
			mine, others := st.gatewayControllers(k)
			switch {
			case !mine:
				s.Unsupported = fmt.Sprintf("HTTPRoute %s is attached to no Gateway of a known GatewayClass", k.Name)
				if len(others) > 0 {
					s.Unsupported = fmt.Sprintf("HTTPRoute %s is served by %s, which Inkwall doesn't wire yet", k.Name, strings.Join(others, ", "))
				}
			case len(others) > 0:
				s.Failed = fmt.Sprintf("HTTPRoute %s is also attached to Gateways of %s, which would fail its rules with Traefik's filter (an ExtensionRef to its Middleware): "+
					"attach it to Traefik's Gateways only, or give each proxy its own HTTPRoute", k.Name, strings.Join(others, ", "))
			case !st.traefikCRDs:
				s.Failed = "Traefik's Middleware CRD is not installed"
			case st.middlewareErr[k.Namespace] != "":
				s.Failed = st.middlewareErr[k.Namespace]
			case st.httpRouteErr[k] != "":
				s.Failed = st.httpRouteErr[k]
			}
		default:
			continue
		}
		s.Wired = st.wanted[tg.Kind][k]
		res.Targets[tg] = s
	}
	return res
}

// Wired implements Integration: the target carries WiredAnnotation.
func (t *Traefik) Wired(ctx context.Context, tg Target) (bool, error) {
	var obj client.Object
	switch tg.Kind {
	case ingressKind:
		obj = &networkingv1.Ingress{}
	case routeKind:
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(integrations.TraefikIngressRouteGVK)
		obj = u
	case httpRouteKind:
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(HTTPRouteGVK)
		obj = u
	default:
		return false, nil
	}
	switch err := t.APIReader.Get(ctx, tg.Key, obj); {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return false, nil
	case err != nil:
		return false, err
	}
	return obj.GetAnnotations()[WiredAnnotation] != "", nil
}

func (t *Traefik) middlewaresInstalled() bool {
	_, err := t.Client.RESTMapper().RESTMapping(integrations.TraefikMiddlewareGVK.GroupKind(), integrations.TraefikMiddlewareGVK.Version)
	return err == nil
}

// errLegacyCRD: the API server dropped a field Traefik v3.7 added.
var errLegacyCRD = errors.New("the Traefik Middleware CRD is older than v3.7")

// ensureMiddleware creates or corrects the operator's Middlewares in
// namespace: those of Traefik v3.7 and later, or, when Traefik's pods
// (oldTraefik) or its CRD are older, the ForwardAuth alone. A Middleware of
// one of their names that the operator didn't create is left alone, and
// reported.
func (t *Traefik) ensureMiddleware(ctx context.Context, namespace string, oldTraefik bool) error {
	if !oldTraefik && !t.legacyCRD.Load() {
		err := t.ensureMiddlewares(ctx, ourMiddlewares(namespace, false))
		if !errors.Is(err, errLegacyCRD) {
			return err
		}
		if !t.legacyCRD.Swap(true) {
			log.FromContext(ctx).Info("Traefik's Middleware CRD is older than v3.7 (no buffering.disableResponseBuffer or forwardAuth.maxResponseBodySize): " +
				"ForwardAuth bounds request bodies itself, which costs Traefik milliseconds on every request, and the engine's answers are not size-capped; upgrade Traefik and its CRDs to v3.7 or later")
		}
	}
	if err := t.ensureMiddlewares(ctx, ourMiddlewares(namespace, true)); err != nil {
		return err
	}
	// The Middlewares of Traefik v3.7 that the ForwardAuth no longer
	// chains, if made before.
	for _, name := range []string{bodyMiddlewareName, authMiddlewareName} {
		if cur, err := t.ours(ctx, namespace, name); err == nil && cur != nil {
			if err := t.Client.Delete(ctx, cur); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// ensureMiddlewares creates or corrects each of want, in order, once none
// of them is someone else's. It returns errLegacyCRD, before the next one,
// when the API server drops a field of Traefik v3.7 from one.
func (t *Traefik) ensureMiddlewares(ctx context.Context, want []*unstructured.Unstructured) error {
	cur := make([]*unstructured.Unstructured, len(want))
	for i, w := range want {
		var err error
		if cur[i], err = t.ours(ctx, w.GetNamespace(), w.GetName()); err != nil {
			return err
		}
	}
	for i, w := range want {
		stored := w.DeepCopy()
		switch {
		case cur[i] == nil:
			if err := t.Client.Create(ctx, stored); err != nil {
				return err
			}
		case SpecMatches(cur[i], w):
			continue
		default:
			stored = cur[i]
			stored.Object["spec"] = w.DeepCopy().Object["spec"]
			if err := t.Client.Update(ctx, stored); err != nil {
				return err
			}
		}
		if dropsV37Fields(stored, w) {
			return errLegacyCRD
		}
	}
	return nil
}

// ours reads the Middleware name in namespace: nil if there is none, an
// error if the operator didn't create it.
func (t *Traefik) ours(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(integrations.TraefikMiddlewareGVK)
	switch err := t.APIReader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, cur); {
	case apierrors.IsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, err
	}
	if cur.GetLabels()["app.kubernetes.io/managed-by"] != "inkwall-operator" {
		return nil, fmt.Errorf("Middleware %s/%s exists and wasn't created by Inkwall; rename or delete it", namespace, name)
	}
	return cur, nil
}

// pruneMiddlewares deletes the operator's Middlewares in namespaces that no
// longer need one.
func (t *Traefik) pruneMiddlewares(ctx context.Context, needed map[string]bool) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(integrations.TraefikMiddlewareGVK.GroupVersion().WithKind("MiddlewareList"))
	if err := t.APIReader.List(ctx, list, client.MatchingLabels{"app.kubernetes.io/managed-by": "inkwall-operator"}); err != nil {
		return err
	}
	for i := range list.Items {
		m := &list.Items[i]
		if slices.Contains(middlewareNames, m.GetName()) && !needed[m.GetNamespace()] {
			if err := t.Client.Delete(ctx, m); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// annotate adds the operator's Middleware to an Ingress (want), or removes
// it if the operator added it before. Only the operator's entry changes;
// Middlewares the user listed stay, in order.
func annotate(ctx context.Context, c client.Client, ing *networkingv1.Ingress, want bool) error {
	ref := MiddlewareRef(ing.Namespace)
	cur := ing.Annotations[MiddlewaresAnnotation]
	wired := ing.Annotations[WiredAnnotation] == ref
	var next string
	switch {
	case want:
		next = WithMiddleware(cur, ref)
		if next == cur && wired {
			return nil
		}
	case wired:
		next = WithoutMiddleware(cur, ref)
	default:
		return nil
	}
	patch := client.MergeFrom(ing.DeepCopy())
	if ing.Annotations == nil {
		ing.Annotations = map[string]string{}
	}
	if want {
		ing.Annotations[MiddlewaresAnnotation] = next
		ing.Annotations[WiredAnnotation] = ref
	} else {
		if next == "" {
			delete(ing.Annotations, MiddlewaresAnnotation)
		} else {
			ing.Annotations[MiddlewaresAnnotation] = next
		}
		delete(ing.Annotations, WiredAnnotation)
	}
	return c.Patch(ctx, ing, patch)
}

// wireRoute adds the operator's Middleware to an IngressRoute's routes
// (want), or removes it if the operator added it before. Only the
// operator's entries change; Middlewares the user listed stay, in order.
func wireRoute(ctx context.Context, c client.Client, ir *unstructured.Unstructured, want bool) error {
	wired := ir.GetAnnotations()[WiredAnnotation] == MiddlewareName
	if !want && !wired {
		return nil
	}
	orig := ir.DeepCopy()
	changed, err := WithRouteMiddleware(ir, want)
	if err != nil {
		return err
	}
	if want && !changed && wired {
		return nil
	}
	annotations := ir.GetAnnotations()
	if want {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[WiredAnnotation] = MiddlewareName
	} else {
		delete(annotations, WiredAnnotation)
	}
	ir.SetAnnotations(annotations)
	// spec.routes is one list to a merge patch: the resourceVersion makes
	// sure it doesn't overwrite a change the cache hasn't seen.
	return c.Patch(ctx, ir, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
}
