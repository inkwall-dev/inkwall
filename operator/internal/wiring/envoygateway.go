// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/policy"
)

// Envoy Gateway's wiring (0004 §4.4). The engine runs in the Envoy pods of
// each Gateway that serves a protected HTTPRoute, as a native sidecar the
// Gateway's EnvoyProxy adds to them; it answers ext_proc on a Unix socket
// the Envoy container mounts too. Each protected HTTPRoute gets an
// EnvoyExtensionPolicy whose ext_proc filter calls the engine through a
// Backend in the route's namespace, once every Envoy pod of its Gateways
// has the engine; each such Gateway gets a ClientTrafficPolicy raising
// Envoy's buffer limit, so the body it holds for the engine isn't cut
// short. Unprotected routes get nothing.
//
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyproxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies;backends;clienttrafficpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=inkwallconfigs,verbs=get;list;watch

// Names of the Envoy Gateway wiring.
const (
	// EnvoyBackend is the operator's Backend, the engine's socket, in each
	// namespace with protected HTTPRoutes.
	EnvoyBackend = "inkwall-engine"
	// envoyPrefix starts the names of the operator's EnvoyExtensionPolicy
	// for a route, and of its EnvoyProxy and ClientTrafficPolicy for a
	// Gateway.
	envoyPrefix = "inkwall-waf-"
	// envoySocket is the engine's ext_proc socket in the Envoy pods.
	envoySocket = integrations.EnvoySocketDir + "/extproc.sock"
	// envoyBufferLimit is Envoy's buffer per connection, which caps the
	// body ext_proc holds for the engine: the largest body a policy
	// inspects. A body cut at it is handled as an oversized one.
	envoyBufferLimit = policy.MaxBodyBytes
	// messageMargin is how much longer than the engine's deadline Envoy
	// waits for its answer: the engine answers by its deadline, with the
	// policy's failure mode.
	messageMargin = 100 * time.Millisecond
	// sidecarMark on an EnvoyProxy or a Gateway records what the operator
	// added: the engine ("sidecar", plus ",provider" when it made
	// spec.provider), or the operator's EnvoyProxy in parametersRef (its
	// name).
	sidecarMark     = WiredAnnotation
	createdProvider = "provider"
	// hashAnnotation holds hashOf what the operator wrote: the spec of its
	// own objects, its entries in an EnvoyProxy.
	hashAnnotation = "waf.inkwall.dev/hash"
)

// Envoy Gateway's kinds, read and written unstructured: the operator
// doesn't depend on Envoy Gateway's Go module.
var (
	EnvoyProxyGVK           = schema.GroupVersionKind{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "EnvoyProxy"}
	EnvoyExtensionPolicyGVK = schema.GroupVersionKind{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "EnvoyExtensionPolicy"}
	BackendGVK              = schema.GroupVersionKind{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "Backend"}
	ClientTrafficPolicyGVK  = schema.GroupVersionKind{Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "ClientTrafficPolicy"}
	// GatewayGVK and HTTPRouteGVK are the Gateway API's, read typed.
	GatewayGVK   = schema.GroupVersionKind{Group: gatewayv1.GroupName, Version: "v1", Kind: "Gateway"}
	HTTPRouteGVK = schema.GroupVersionKind{Group: gatewayv1.GroupName, Version: "v1", Kind: "HTTPRoute"}
	// GatewayClassGVK is read unstructured, as discovery does.
	GatewayClassGVK = schema.GroupVersionKind{Group: gatewayv1.GroupName, Version: "v1", Kind: "GatewayClass"}

	httpRouteKind = HTTPRouteGVK.GroupKind()
)

// Labels the Envoy pods of a Gateway carry.
const (
	owningGatewayName      = "gateway.envoyproxy.io/owning-gateway-name"
	owningGatewayNamespace = "gateway.envoyproxy.io/owning-gateway-namespace"
)

// EnvoyGateway is the wiring of Envoy Gateway: its HTTPRoutes.
type EnvoyGateway struct {
	Client client.Client
	// APIReader reads the operator's objects uncached.
	APIReader client.Reader
	// Pods selects Envoy Gateway's Envoy pods.
	Pods labels.Selector
	// Sidecar is the engine put into the Envoy pods, before the
	// InkwallConfig's engine settings.
	Sidecar injection.Sidecar
	// Watches of kinds whose CRD may be missing; nil: only read at each
	// reconcile.
	HTTPRoutes, Gateways, GatewayClasses, EnvoyProxies, ExtensionPolicies *crdwatch.Kind
}

// Name implements Integration.
func (*EnvoyGateway) Name() string { return integrations.EnvoyGateway.Name }

// Kinds implements Integration.
func (*EnvoyGateway) Kinds() []schema.GroupKind { return []schema.GroupKind{httpRouteKind} }

// Watch implements Integration.
func (e *EnvoyGateway) Watch(c controller.Controller, cache cache.Cache, h handler.EventHandler) error {
	// Pods are watched by Traefik's wiring too, in the same cache; the
	// InkwallConfig's engine settings go into the EnvoyProxies.
	for _, obj := range []client.Object{&corev1.Pod{}, &wafv1alpha1.InkwallConfig{}} {
		if err := c.Watch(source.Kind(cache, obj, h)); err != nil {
			return err
		}
	}
	for _, k := range []*crdwatch.Kind{e.HTTPRoutes, e.Gateways, e.GatewayClasses, e.EnvoyProxies, e.ExtensionPolicies} {
		if k != nil {
			k.Add(c, h)
		}
	}
	return nil
}

// envoyRoute is a protected HTTPRoute that Envoy Gateway serves.
type envoyRoute struct {
	route *gatewayv1.HTTPRoute
	// gateways are its Envoy Gateway parents.
	gateways []types.NamespacedName
	// sections are the rules protected, or [""] for the whole route.
	sections []string
	// body, timeout and failOpen come from the policies that protect it.
	body     bool
	timeout  time.Duration
	failOpen bool
}

// envoyState is what Wire read.
type envoyState struct {
	routes   map[types.NamespacedName]*gatewayv1.HTTPRoute
	gateways map[types.NamespacedName]*gatewayv1.Gateway
	// classes are the GatewayClasses of Envoy Gateway, with their
	// EnvoyProxy (namespace/name), if any.
	classes map[string]*types.NamespacedName
	pods    []corev1.Pod
	// egCRDs: Envoy Gateway's CRDs are installed.
	egCRDs bool
}

// Wire implements Integration: it puts the engine into the Envoy pods of
// the Gateways serving protected HTTPRoutes, attaches the engine to those
// routes once the pods have it, and removes the rest.
func (e *EnvoyGateway) Wire(ctx context.Context, targets map[Target]bool, off bool) (*Result, error) {
	st, err := e.read(ctx)
	if err != nil {
		return nil, err
	}
	res := &Result{Proxy: "Envoy Gateway", Targets: map[Target]TargetState{}, Rolling: true}

	// The protected routes Envoy Gateway serves, and the others' reasons.
	var policies wafv1alpha1.WAFPolicyList
	if err := e.Client.List(ctx, &policies); err != nil {
		return nil, err
	}
	routes := map[types.NamespacedName]*envoyRoute{}
	for tg := range targets {
		hr := st.routes[tg.Key]
		if tg.Kind != httpRouteKind || hr == nil {
			continue
		}
		gws, others := st.parents(hr)
		if len(gws) == 0 {
			why := "no Gateway"
			if len(others) > 0 {
				why = "Gateways of other controllers (" + strings.Join(others, ", ") + ")"
			}
			res.Targets[tg] = TargetState{Unsupported: fmt.Sprintf("HTTPRoute %s is served by %s, which Inkwall doesn't wire yet", tg.Key.Name, why)}
			continue
		}
		r := routes[tg.Key]
		if r == nil {
			r = &envoyRoute{route: hr, gateways: gws}
			routes[tg.Key] = r
		}
		// "" is the whole route.
		r.sections = append(r.sections, tg.Section)
	}
	for k, r := range routes {
		r.sections = slices.Compact(slices.Sorted(slices.Values(r.sections)))
		if r.sections[0] == "" {
			r.sections = r.sections[:1]
		}
		r.body, r.timeout, r.failOpen = routeSettings(policies.Items, k)
	}

	// The Gateways whose pods get the engine.
	on := !off && st.egCRDs
	inject := map[types.NamespacedName]bool{}
	if on {
		for _, r := range routes {
			for _, gw := range r.gateways {
				inject[gw] = true
			}
		}
	}
	// A Gateway is ready once every running Envoy pod of it has the
	// engine: before, a pod without it would fail the routes' requests.
	ready := map[types.NamespacedName]bool{}
	for gw := range inject {
		pods := st.podsOf(gw)
		ready[gw] = len(pods) > 0 && !slices.ContainsFunc(pods, func(p *corev1.Pod) bool { return !injection.HasEngine(p) })
		for _, p := range pods {
			res.Pods = append(res.Pods, *p)
		}
	}

	var errs error
	failed := map[types.NamespacedName]string{}
	wanted := map[types.NamespacedName]bool{}
	if st.egCRDs {
		sidecar, err := e.sidecar(ctx)
		if err != nil {
			return nil, err
		}
		// 1. The engine into the Envoy pods. A Gateway whose pods have it
		// already keeps its routes wired meanwhile.
		for gw := range inject {
			switch err := e.inject(ctx, st, st.gateways[gw], sidecar); {
			case apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err):
				// Changed since the cache saw it: again, once it has.
				errs = errors.Join(errs, fmt.Errorf("inject the engine into Gateway %s: %w", gw, err))
			case err != nil:
				errs = errors.Join(errs, fmt.Errorf("inject the engine into Gateway %s: %w", gw, err))
				log.FromContext(ctx).Error(err, "engine not injected", "gateway", gw)
				for k, r := range routes {
					if slices.Contains(r.gateways, gw) {
						failed[k] = fmt.Sprintf("Gateway %s: %v", gw.Name, err)
					}
				}
			}
		}
		// 2. The routes whose Gateways are ready.
		backends := map[string]bool{}
		for k, r := range routes {
			if !slices.ContainsFunc(r.gateways, func(gw types.NamespacedName) bool { return !ready[gw] }) {
				wanted[k] = true
				backends[k.Namespace] = true
			}
		}
		noBackend := map[string]string{}
		for ns := range backends {
			if err := e.ensure(ctx, backend(ns)); err != nil {
				errs = errors.Join(errs, fmt.Errorf("ensure Backend %s/%s: %w", ns, EnvoyBackend, err))
				noBackend[ns] = err.Error()
			}
		}
		buffered := map[types.NamespacedName]bool{}
		for k := range wanted {
			r := routes[k]
			if why := noBackend[k.Namespace]; why != "" {
				failed[k] = why
				continue
			}
			if err := e.ensure(ctx, extensionPolicy(r)); err != nil {
				errs = errors.Join(errs, fmt.Errorf("ensure the EnvoyExtensionPolicy of HTTPRoute %s: %w", k, err))
				failed[k] = err.Error()
				continue
			}
			if r.body {
				for _, gw := range r.gateways {
					buffered[gw] = true
				}
			}
		}
		// 3. Envoy's buffer limit on the Gateways with routes whose body
		// is inspected.
		for gw := range buffered {
			if err := e.ensureBufferLimit(ctx, st.gateways[gw]); err != nil {
				errs = errors.Join(errs, fmt.Errorf("ensure the ClientTrafficPolicy of Gateway %s: %w", gw, err))
			}
		}
		// 4. The rest goes, in reverse: a route stops calling the engine
		// before its Gateway's pods lose it.
		if err := e.prune(ctx, wanted, buffered, inject); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	for tg := range targets {
		if _, ok := res.Targets[tg]; ok || tg.Kind != httpRouteKind || st.routes[tg.Key] == nil {
			continue
		}
		s := TargetState{Wired: wanted[tg.Key]}
		switch {
		case !st.egCRDs:
			s.Failed = "Envoy Gateway's CRDs (EnvoyProxy, EnvoyExtensionPolicy, Backend, ClientTrafficPolicy) are not installed"
		case failed[tg.Key] != "":
			s.Failed = failed[tg.Key]
		case s.Wired:
			if why, err := e.rejected(ctx, tg.Key); err != nil {
				errs = errors.Join(errs, err)
			} else if why != "" {
				s.Failed = why
			}
		}
		res.Targets[tg] = s
	}
	return res, errs
}

// read lists what the wiring reads, from the cache.
func (e *EnvoyGateway) read(ctx context.Context) (*envoyState, error) {
	st := &envoyState{
		routes: map[types.NamespacedName]*gatewayv1.HTTPRoute{}, gateways: map[types.NamespacedName]*gatewayv1.Gateway{},
		classes: map[string]*types.NamespacedName{},
	}
	// Without the HTTPRoute CRD, there is no route to wire; without the
	// Gateway or GatewayClass CRD, Envoy Gateway serves none.
	mapper := e.Client.RESTMapper()
	installed := map[schema.GroupVersionKind]bool{}
	for _, gvk := range []schema.GroupVersionKind{HTTPRouteGVK, GatewayGVK, GatewayClassGVK, EnvoyProxyGVK, EnvoyExtensionPolicyGVK, BackendGVK, ClientTrafficPolicyGVK} {
		ok, err := crdwatch.Installed(mapper, gvk)
		if err != nil {
			return nil, err
		}
		installed[gvk] = ok
	}
	st.egCRDs = installed[EnvoyProxyGVK] && installed[EnvoyExtensionPolicyGVK] && installed[BackendGVK] && installed[ClientTrafficPolicyGVK]

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
		if err := e.Client.List(ctx, l); err != nil {
			return nil, err
		}
	}
	if err := e.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: e.Pods}); err != nil {
		return nil, err
	}
	for i := range routes.Items {
		hr := &routes.Items[i]
		st.routes[types.NamespacedName{Namespace: hr.Namespace, Name: hr.Name}] = hr
	}
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		st.gateways[types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}] = gw
	}
	for _, gc := range classes.Items {
		if c, _, _ := unstructured.NestedString(gc.Object, "spec", "controllerName"); c != integrations.EnvoyGateway.GatewayController {
			continue
		}
		var proxy *types.NamespacedName
		ref, _, _ := unstructured.NestedStringMap(gc.Object, "spec", "parametersRef")
		if ref["group"] == EnvoyProxyGVK.Group && ref["kind"] == EnvoyProxyGVK.Kind {
			proxy = &types.NamespacedName{Namespace: ref["namespace"], Name: ref["name"]}
		}
		st.classes[gc.GetName()] = proxy
	}
	st.pods = pods.Items
	return st, nil
}

// parents returns a route's Envoy Gateway Gateways, and the other
// Gateways' classes.
func (st *envoyState) parents(hr *gatewayv1.HTTPRoute) (ours []types.NamespacedName, others []string) {
	for _, p := range hr.Spec.ParentRefs {
		if p.Group != nil && *p.Group != gatewayv1.GroupName || p.Kind != nil && *p.Kind != "Gateway" {
			continue
		}
		key := types.NamespacedName{Namespace: hr.Namespace, Name: string(p.Name)}
		if p.Namespace != nil {
			key.Namespace = string(*p.Namespace)
		}
		gw := st.gateways[key]
		if gw == nil {
			continue
		}
		if _, ok := st.classes[string(gw.Spec.GatewayClassName)]; ok {
			if !slices.Contains(ours, key) {
				ours = append(ours, key)
			}
		} else if c := "GatewayClass " + string(gw.Spec.GatewayClassName); !slices.Contains(others, c) {
			others = append(others, c)
		}
	}
	slices.SortFunc(ours, func(a, b types.NamespacedName) int { return cmp.Compare(a.String(), b.String()) })
	return ours, others
}

// podsOf returns the running Envoy pods of a Gateway.
func (st *envoyState) podsOf(gw types.NamespacedName) []*corev1.Pod {
	var out []*corev1.Pod
	for _, p := range running(st.pods) {
		if p.Labels[owningGatewayName] == gw.Name && p.Labels[owningGatewayNamespace] == gw.Namespace {
			out = append(out, p)
		}
	}
	return out
}

// routeSettings returns, for a route, whether a policy protecting it
// inspects bodies, the longest engine deadline, and whether every one of
// them lets requests through when the engine fails.
func routeSettings(policies []wafv1alpha1.WAFPolicy, route types.NamespacedName) (body bool, timeout time.Duration, failOpen bool) {
	timeout, failOpen = pipeline.DefaultTimeout, true
	for i := range policies {
		p := &policies[i]
		if p.Namespace != route.Namespace || p.DeletionTimestamp != nil ||
			!slices.ContainsFunc(p.Spec.TargetRefs, func(r wafv1alpha1.TargetRef) bool {
				return targetOf(p.Namespace, r).Kind == httpRouteKind && r.Name == route.Name
			}) {
			continue
		}
		if b := p.Spec.Body; b == nil || b.Inspect == nil || *b.Inspect {
			body = true
		}
		if p.Spec.Timeout != nil {
			timeout = max(timeout, p.Spec.Timeout.Duration)
		}
		mode := cmp.Or(p.Spec.FailureMode, wafv1alpha1.FailOpen)
		if p.Spec.Mode == wafv1alpha1.PolicyBlock && p.Spec.FailureMode == "" {
			mode = wafv1alpha1.FailClosed
		}
		failOpen = failOpen && mode == wafv1alpha1.FailOpen
	}
	return body, timeout, failOpen
}

// envoyName is the name of an operator object for a route or Gateway:
// envoyPrefix and its name, shortened with a hash when too long.
func envoyName(name string) string {
	const maxLen = 253
	if len(envoyPrefix)+len(name) <= maxLen {
		return envoyPrefix + name
	}
	sum := sha256.Sum256([]byte(name))
	h := hex.EncodeToString(sum[:4])
	return envoyPrefix + name[:maxLen-len(envoyPrefix)-len(h)-1] + "-" + h
}

func managedLabels() map[string]string {
	return map[string]string{"app.kubernetes.io/managed-by": "inkwall-operator"}
}

func isManaged(o client.Object) bool {
	return o.GetLabels()["app.kubernetes.io/managed-by"] == "inkwall-operator"
}

func newObject(gvk schema.GroupVersionKind, namespace, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	u.SetNamespace(namespace)
	u.SetName(name)
	u.SetLabels(managedLabels())
	return u
}

// owned makes owner the controller of u, so it goes with it.
func owned(u *unstructured.Unstructured, owner client.Object, gvk schema.GroupVersionKind) {
	u.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Name: owner.GetName(), UID: owner.GetUID(),
	}})
}

// backend is the operator's Backend in namespace: the engine's socket in
// the Envoy pod.
func backend(namespace string) *unstructured.Unstructured {
	b := newObject(BackendGVK, namespace, EnvoyBackend)
	b.Object["spec"] = map[string]any{"endpoints": []any{map[string]any{"unix": map[string]any{"path": envoySocket}}}}
	return b
}

// extensionPolicy is the operator's EnvoyExtensionPolicy for a route
// (0006 §2): the request headers, and the body when a policy inspects it,
// held by Envoy (BufferedPartial: up to its buffer limit) for the engine's
// verdict; the response is not sent. Envoy waits for the engine a little
// longer than its deadline, as the engine applies the policy's failure
// mode; failOpen covers an engine that can't be reached, as the policies
// would.
func extensionPolicy(r *envoyRoute) *unstructured.Unstructured {
	p := newObject(EnvoyExtensionPolicyGVK, r.route.Namespace, envoyName(r.route.Name))
	owned(p, r.route, HTTPRouteGVK)
	var refs []any
	for _, s := range r.sections {
		ref := map[string]any{"group": gatewayv1.GroupName, "kind": "HTTPRoute", "name": r.route.Name}
		if s != "" {
			ref["sectionName"] = s
		}
		refs = append(refs, ref)
	}
	request := map[string]any{}
	if r.body {
		request["body"] = "BufferedPartial"
	}
	p.Object["spec"] = map[string]any{
		"targetRefs": refs,
		"extProc": []any{map[string]any{
			"backendRefs":    []any{map[string]any{"group": BackendGVK.Group, "kind": BackendGVK.Kind, "name": EnvoyBackend}},
			"processingMode": map[string]any{"request": request},
			"messageTimeout": (r.timeout + messageMargin).String(),
			"failOpen":       r.failOpen,
		}},
	}
	return p
}

// bufferLimit is the operator's ClientTrafficPolicy for a Gateway.
func bufferLimit(gw *gatewayv1.Gateway) *unstructured.Unstructured {
	p := newObject(ClientTrafficPolicyGVK, gw.Namespace, envoyName(gw.Name))
	owned(p, gw, GatewayGVK)
	p.Object["spec"] = map[string]any{
		"targetRefs": []any{map[string]any{"group": gatewayv1.GroupName, "kind": "Gateway", "name": gw.Name}},
		"connection": map[string]any{"bufferLimit": fmt.Sprintf("%dMi", envoyBufferLimit>>20)},
	}
	return p
}

// ensure creates the operator's object, or sets its spec and owner. One of
// the same name it didn't create is left alone, and reported.
func (e *EnvoyGateway) ensure(ctx context.Context, want *unstructured.Unstructured) error {
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(want.GroupVersionKind())
	switch err := e.Client.Get(ctx, client.ObjectKeyFromObject(want), cur); {
	case apierrors.IsNotFound(err):
		want.SetAnnotations(map[string]string{hashAnnotation: hashOf(want.Object["spec"])})
		return e.Client.Create(ctx, want)
	case err != nil:
		return err
	}
	if !isManaged(cur) {
		return fmt.Errorf("%s %s/%s exists and wasn't created by Inkwall; rename or delete it", want.GetKind(), want.GetNamespace(), want.GetName())
	}
	hash := hashOf(want.Object["spec"])
	if cur.GetAnnotations()[hashAnnotation] == hash && covers(cur.Object["spec"], want.Object["spec"]) &&
		apiequality.Semantic.DeepEqual(cur.GetOwnerReferences(), want.GetOwnerReferences()) {
		return nil
	}
	cur.Object["spec"] = want.Object["spec"]
	cur.SetOwnerReferences(want.GetOwnerReferences())
	cur.SetAnnotations(map[string]string{hashAnnotation: hash})
	return e.Client.Update(ctx, cur)
}

// hashOf is a short hash of what the operator wrote, kept in
// hashAnnotation: a change of its own (a field it no longer sets) shows
// there, while covers ignores the API server's defaults.
func hashOf(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// covers reports whether got has every field of want, with its value: the
// fields the API server defaults don't count. Numbers compare by value, as
// JSON decodes them.
func covers(got, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range w {
			if !covers(g[k], v) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !covers(g[i], w[i]) {
				return false
			}
		}
		return true
	}
	if a, ok := number(got); ok {
		b, ok := number(want)
		return ok && a == b
	}
	return got == want
}

func number(v any) (float64, bool) {
	switch v := v.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// ensureBufferLimit gives a Gateway the operator's ClientTrafficPolicy,
// unless the user has one for it: Envoy Gateway applies one per Gateway,
// so the operator's would take its place.
func (e *EnvoyGateway) ensureBufferLimit(ctx context.Context, gw *gatewayv1.Gateway) error {
	if gw == nil {
		return nil
	}
	theirs, err := e.userTrafficPolicy(ctx, gw)
	switch {
	case err != nil:
		return err
	case theirs != "":
		log.FromContext(ctx).V(1).Info("the Gateway has a ClientTrafficPolicy: its connection.bufferLimit caps the bodies inspected", "gateway", gw.Namespace+"/"+gw.Name, "clienttrafficpolicy", theirs)
		return nil
	}
	return e.ensure(ctx, bufferLimit(gw))
}

// userTrafficPolicy names a ClientTrafficPolicy, not the operator's, that
// targets a Gateway.
func (e *EnvoyGateway) userTrafficPolicy(ctx context.Context, gw *gatewayv1.Gateway) (string, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ClientTrafficPolicyGVK.GroupVersion().WithKind("ClientTrafficPolicyList"))
	if err := e.Client.List(ctx, list, client.InNamespace(gw.Namespace)); err != nil {
		return "", err
	}
	for i := range list.Items {
		p := &list.Items[i]
		if isManaged(p) {
			continue
		}
		refs, _, _ := unstructured.NestedSlice(p.Object, "spec", "targetRefs")
		if one, ok, _ := unstructured.NestedMap(p.Object, "spec", "targetRef"); ok {
			refs = append(refs, one)
		}
		for _, r := range refs {
			if ref, _ := r.(map[string]any); ref["kind"] == "Gateway" && ref["name"] == gw.Name {
				return p.GetName(), nil
			}
		}
	}
	return "", nil
}

// rejected returns why Envoy Gateway didn't accept a route's
// EnvoyExtensionPolicy, if it says so; "" while it hasn't said.
func (e *EnvoyGateway) rejected(ctx context.Context, route types.NamespacedName) (string, error) {
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(EnvoyExtensionPolicyGVK)
	if err := e.Client.Get(ctx, types.NamespacedName{Namespace: route.Namespace, Name: envoyName(route.Name)}, p); err != nil {
		return "", client.IgnoreNotFound(err)
	}
	ancestors, _, _ := unstructured.NestedSlice(p.Object, "status", "ancestors")
	for _, a := range ancestors {
		conds, _, _ := unstructured.NestedSlice(a.(map[string]any), "conditions")
		for _, c := range conds {
			c, _ := c.(map[string]any)
			if c["type"] == "Accepted" && c["status"] == "False" {
				return fmt.Sprintf("Envoy Gateway didn't accept EnvoyExtensionPolicy %s (%v): %v", p.GetName(), c["reason"], c["message"]), nil
			}
		}
	}
	return "", nil
}

// sidecar is the engine for the Envoy pods, with the InkwallConfig's
// settings.
func (e *EnvoyGateway) sidecar(ctx context.Context) (injection.Sidecar, error) {
	s := e.Sidecar
	s.Args = integrations.EnvoyGateway.Adapter
	s.SocketDir = integrations.EnvoySocketDir
	var cfg wafv1alpha1.InkwallConfig
	switch err := e.Client.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); {
	case apierrors.IsNotFound(err):
		return s, nil
	case err != nil:
		return s, err
	}
	return s.Configured(cfg.Spec.Engine), nil
}

// envoyProxyOf returns the EnvoyProxy a Gateway names, if any.
func envoyProxyOf(gw *gatewayv1.Gateway) string {
	if i := gw.Spec.Infrastructure; i != nil && i.ParametersRef != nil &&
		string(i.ParametersRef.Group) == EnvoyProxyGVK.Group && string(i.ParametersRef.Kind) == EnvoyProxyGVK.Kind {
		return i.ParametersRef.Name
	}
	return ""
}

// inject puts the engine into a Gateway's Envoy pods: into the EnvoyProxy
// it names, or into one the operator makes and names in its parametersRef.
// Envoy Gateway rolls the Envoy Deployment when its EnvoyProxy changes.
func (e *EnvoyGateway) inject(ctx context.Context, st *envoyState, gw *gatewayv1.Gateway, s injection.Sidecar) error {
	name, theirs := envoyProxyOf(gw), true
	if name == "" || name == gw.Annotations[sidecarMark] {
		name, theirs = envoyName(gw.Name), false
	}
	ep := &unstructured.Unstructured{}
	ep.SetGroupVersionKind(EnvoyProxyGVK)
	err := e.Client.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, ep)
	switch {
	case apierrors.IsNotFound(err) && theirs:
		return fmt.Errorf("its EnvoyProxy %s doesn't exist", name)
	case apierrors.IsNotFound(err):
		// The operator's own, merged into the GatewayClass's, if any.
		ep = newObject(EnvoyProxyGVK, gw.Namespace, name)
		owned(ep, gw, GatewayGVK)
		ep.Object["spec"] = map[string]any{}
		if st.classes[string(gw.Spec.GatewayClassName)] != nil {
			ep.Object["spec"] = map[string]any{"mergeType": "StrategicMerge"}
		}
		if _, err := withSidecar(ep, s, true); err != nil {
			return err
		}
		if err := e.Client.Create(ctx, ep); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		orig := ep.DeepCopy()
		changed, err := withSidecar(ep, s, true)
		if err != nil || !changed {
			return err
		}
		// spec.provider holds lists: the resourceVersion makes sure the
		// patch doesn't drop a change the cache hasn't seen.
		if err := e.Client.Patch(ctx, ep, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
	}
	if envoyProxyOf(gw) != "" {
		return nil
	}
	// The Gateway names the operator's EnvoyProxy.
	patch := client.MergeFrom(gw.DeepCopy())
	if gw.Spec.Infrastructure == nil {
		gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{}
	}
	gw.Spec.Infrastructure.ParametersRef = &gatewayv1.LocalParametersReference{Group: gatewayv1.Group(EnvoyProxyGVK.Group), Kind: gatewayv1.Kind(EnvoyProxyGVK.Kind), Name: name}
	if gw.Annotations == nil {
		gw.Annotations = map[string]string{}
	}
	gw.Annotations[sidecarMark] = name
	return e.Client.Patch(ctx, gw, patch)
}

// Paths in an EnvoyProxy.
var (
	deploymentPath = []string{"spec", "provider", "kubernetes", "envoyDeployment"}
	initPath       = append(slices.Clone(deploymentPath), "initContainers")
	volumesPath    = append(slices.Clone(deploymentPath), "pod", "volumes")
	mountsPath     = append(slices.Clone(deploymentPath), "container", "volumeMounts")
)

// withSidecar adds the engine to an EnvoyProxy (want), or removes what the
// operator added: the engine container first among the init containers, its
// volumes, and the socket's mount in the Envoy container. The user's
// entries stay, in order. It reports whether ep changed.
func withSidecar(ep *unstructured.Unstructured, s injection.Sidecar, want bool) (bool, error) {
	mark := ep.GetAnnotations()[sidecarMark]
	if !want && mark == "" {
		return false, nil
	}
	orig := ep.DeepCopy()
	if want {
		if _, ok, _ := unstructured.NestedMap(ep.Object, "spec", "provider"); !ok {
			mark = "sidecar," + createdProvider
			if err := unstructured.SetNestedField(ep.Object, "Kubernetes", "spec", "provider", "type"); err != nil {
				return false, err
			}
		} else if mark == "" {
			mark = "sidecar"
		}
	}
	lists, err := sidecarEntries(s)
	if err != nil {
		return false, err
	}
	same := ep.GetAnnotations()[hashAnnotation] == hashOf(lists)
	for _, l := range lists {
		cur, _, err := unstructured.NestedSlice(ep.Object, l.path...)
		if err != nil {
			return false, err
		}
		ours := func(x any) bool {
			name, _ := x.(map[string]any)["name"].(string)
			return slices.Contains(l.names, name)
		}
		next := slices.DeleteFunc(slices.Clone(cur), ours)
		if want {
			if l.first {
				next = append(slices.Clone(l.items), next...)
			} else {
				next = append(next, l.items...)
			}
			if same && covers(cur, next) {
				continue
			}
		}
		if len(next) == 0 {
			unstructured.RemoveNestedField(ep.Object, l.path...)
			pruneEmpty(ep.Object, l.path[:len(l.path)-1])
			continue
		}
		if err := unstructured.SetNestedSlice(ep.Object, next, l.path...); err != nil {
			return false, err
		}
	}
	annotations := ep.GetAnnotations()
	if want {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[sidecarMark] = mark
		annotations[hashAnnotation] = hashOf(lists)
	} else {
		if strings.HasSuffix(mark, ","+createdProvider) {
			if p, _, _ := unstructured.NestedMap(ep.Object, "spec", "provider"); len(p) == 1 && p["type"] == "Kubernetes" {
				unstructured.RemoveNestedField(ep.Object, "spec", "provider")
			}
		}
		delete(annotations, sidecarMark)
		delete(annotations, hashAnnotation)
		if len(annotations) == 0 {
			annotations = nil
		}
	}
	ep.SetAnnotations(annotations)
	return !apiequality.Semantic.DeepEqual(orig.Object, ep.Object), nil
}

// sidecarList is the operator's entries in one list of an EnvoyProxy.
type sidecarList struct {
	path  []string
	names []string
	items []any
	// first: before the user's entries (the engine starts before their
	// init containers), else after.
	first bool
}

// sidecarEntries are what the operator adds to an EnvoyProxy: the engine
// as an init container, its volumes, and the socket's mount in the Envoy
// container.
func sidecarEntries(s injection.Sidecar) ([]sidecarList, error) {
	s.SocketDir = integrations.EnvoySocketDir
	engine, volumes := injection.Engine(s)
	mount := corev1.VolumeMount{Name: injection.SocketVolume, MountPath: integrations.EnvoySocketDir}
	lists := []sidecarList{
		{path: initPath, names: []string{injection.ContainerName}, first: true},
		{path: volumesPath},
		{path: mountsPath, names: []string{injection.SocketVolume}},
	}
	objs := [][]any{{&engine}, nil, {&mount}}
	for i := range volumes {
		lists[1].names = append(lists[1].names, volumes[i].Name)
		objs[1] = append(objs[1], &volumes[i])
	}
	for i := range lists {
		for _, o := range objs[i] {
			u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
			if err != nil {
				return nil, err
			}
			lists[i].items = append(lists[i].items, u)
		}
	}
	return lists, nil
}

// pruneEmpty removes the empty maps along path, deepest first.
func pruneEmpty(obj map[string]any, path []string) {
	for i := len(path); i > 1; i-- {
		m, ok, _ := unstructured.NestedMap(obj, path[:i]...)
		if !ok || len(m) > 0 {
			return
		}
		unstructured.RemoveNestedField(obj, path[:i]...)
	}
}

// prune deletes the operator's EnvoyExtensionPolicies and Backends no
// longer wanted, its ClientTrafficPolicies on Gateways without such
// routes, and the engine from the Envoy pods of Gateways that no longer
// need it.
func (e *EnvoyGateway) prune(ctx context.Context, routes, buffered, gateways map[types.NamespacedName]bool) error {
	namespaces := map[string]bool{}
	for k := range routes {
		namespaces[k.Namespace] = true
	}
	var errs error
	for _, del := range []struct {
		gvk  schema.GroupVersionKind
		keep func(*unstructured.Unstructured) bool
	}{
		{EnvoyExtensionPolicyGVK, func(u *unstructured.Unstructured) bool {
			return routes[types.NamespacedName{Namespace: u.GetNamespace(), Name: targetName(u)}]
		}},
		{BackendGVK, func(u *unstructured.Unstructured) bool { return namespaces[u.GetNamespace()] }},
		{ClientTrafficPolicyGVK, func(u *unstructured.Unstructured) bool {
			return buffered[types.NamespacedName{Namespace: u.GetNamespace(), Name: targetName(u)}]
		}},
	} {
		if _, err := deleteManaged(ctx, e.Client, del.gvk, del.keep); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		// The engine stays while a route may still call it.
		return errs
	}
	_, err := removeSidecars(ctx, e.Client, gateways)
	return err
}

// targetName is the route or Gateway an operator's policy targets.
func targetName(u *unstructured.Unstructured) string {
	refs, _, _ := unstructured.NestedSlice(u.Object, "spec", "targetRefs")
	if len(refs) == 0 {
		return ""
	}
	ref, _ := refs[0].(map[string]any)
	name, _ := ref["name"].(string)
	return name
}

// deleteManaged deletes the operator's objects of a kind that keep doesn't
// want (nil: all), and counts them. A missing CRD is none.
func deleteManaged(ctx context.Context, c client.Client, gvk schema.GroupVersionKind, keep func(*unstructured.Unstructured) bool) (int, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
	switch err := c.List(ctx, list, client.MatchingLabels(managedLabels())); {
	case meta.IsNoMatchError(err):
		return 0, nil
	case err != nil:
		return 0, err
	}
	n := 0
	var errs error
	for i := range list.Items {
		u := &list.Items[i]
		if keep != nil && keep(u) {
			continue
		}
		if err := c.Delete(ctx, u); client.IgnoreNotFound(err) != nil {
			errs = errors.Join(errs, fmt.Errorf("delete %s %s/%s: %w", gvk.Kind, u.GetNamespace(), u.GetName(), err))
			continue
		}
		n++
	}
	return n, errs
}

// removeSidecars takes the engine out of the Envoy pods of the Gateways
// keep doesn't name (nil: all): the operator's entries leave the users'
// EnvoyProxies, and a Gateway that names the operator's EnvoyProxy names
// none again, before that EnvoyProxy is deleted. It counts the
// EnvoyProxies and Gateways it changed.
func removeSidecars(ctx context.Context, c client.Client, keep map[types.NamespacedName]bool) (map[string]int, error) {
	n := map[string]int{}
	if ok, err := crdwatch.Installed(c.RESTMapper(), EnvoyProxyGVK); !ok || err != nil {
		return n, err
	}
	// The EnvoyProxies the Gateways to keep use.
	used := map[types.NamespacedName]bool{}
	var gateways gatewayv1.GatewayList
	if ok, _ := crdwatch.Installed(c.RESTMapper(), GatewayGVK); ok {
		if err := c.List(ctx, &gateways); err != nil {
			return n, err
		}
	}
	var errs error
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
		if keep[key] {
			// The cache may not show yet the parametersRef just set.
			for _, name := range []string{envoyProxyOf(gw), envoyName(gw.Name)} {
				used[types.NamespacedName{Namespace: gw.Namespace, Name: name}] = true
			}
			continue
		}
		mark := gw.Annotations[sidecarMark]
		if mark == "" {
			continue
		}
		patch := client.MergeFrom(gw.DeepCopy())
		if envoyProxyOf(gw) == mark {
			if i := gw.Spec.Infrastructure; len(i.Labels) == 0 && len(i.Annotations) == 0 {
				gw.Spec.Infrastructure = nil
			} else {
				gw.Spec.Infrastructure.ParametersRef = nil
			}
		}
		delete(gw.Annotations, sidecarMark)
		if err := c.Patch(ctx, gw, patch); client.IgnoreNotFound(err) != nil {
			errs = errors.Join(errs, fmt.Errorf("restore Gateway %s: %w", key, err))
			// Its EnvoyProxy stays while it names it.
			used[types.NamespacedName{Namespace: gw.Namespace, Name: mark}] = true
			continue
		}
		n["Gateway"]++
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(EnvoyProxyGVK.GroupVersion().WithKind("EnvoyProxyList"))
	if err := c.List(ctx, list); err != nil {
		return n, errors.Join(errs, err)
	}
	for i := range list.Items {
		ep := &list.Items[i]
		key := types.NamespacedName{Namespace: ep.GetNamespace(), Name: ep.GetName()}
		if used[key] || !isManaged(ep) && ep.GetAnnotations()[sidecarMark] == "" {
			continue
		}
		var err error
		if isManaged(ep) {
			// No Gateway names it any more.
			err = c.Delete(ctx, ep)
		} else {
			orig := ep.DeepCopy()
			if _, err = withSidecar(ep, injection.Sidecar{}, false); err == nil {
				err = c.Patch(ctx, ep, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
			}
		}
		if client.IgnoreNotFound(err) != nil {
			errs = errors.Join(errs, fmt.Errorf("restore EnvoyProxy %s: %w", key, err))
			continue
		}
		n["EnvoyProxy"]++
	}
	return n, errs
}

// Wired implements Integration: the route has the operator's
// EnvoyExtensionPolicy.
func (e *EnvoyGateway) Wired(ctx context.Context, tg Target) (bool, error) {
	if tg.Kind != httpRouteKind {
		return false, nil
	}
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(EnvoyExtensionPolicyGVK)
	switch err := e.APIReader.Get(ctx, types.NamespacedName{Namespace: tg.Key.Namespace, Name: envoyName(tg.Key.Name)}, p); {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return false, nil
	case err != nil:
		return false, err
	}
	return isManaged(p), nil
}

// Unwire implements Integration: the routes stop calling the engine, then
// the engine leaves the Envoy pods (Envoy Gateway rolls them), and the
// users' Gateways and EnvoyProxies are as they were.
func (e *EnvoyGateway) Unwire(ctx context.Context, c client.Client) (map[string]int, error) {
	n := map[string]int{}
	for _, gvk := range []schema.GroupVersionKind{EnvoyExtensionPolicyGVK, BackendGVK, ClientTrafficPolicyGVK} {
		count, err := deleteManaged(ctx, c, gvk, nil)
		if count > 0 {
			n[gvk.Kind] = count
		}
		if err != nil {
			return n, err
		}
	}
	counts, err := removeSidecars(ctx, c, nil)
	maps.Copy(n, counts)
	return n, err
}
