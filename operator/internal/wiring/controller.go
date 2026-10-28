// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/crdwatch"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// The wiring controller reads routes and proxy pods, writes the Traefik
// Middleware in protected namespaces, adds it to protected Ingresses and
// IngressRoutes, and reports Programmed.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=traefik.io,resources=middlewares,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=traefik.io,resources=ingressroutes,verbs=get;list;watch;update;patch

// Reasons of the Programmed condition.
const (
	ReasonProgrammed            = "Programmed"
	ReasonControllerUnsupported = "ControllerUnsupported"
	ReasonWiringFailed          = "WiringFailed"
	ReasonPendingRestart        = "PendingRestart"
	ReasonSidecarMissing        = "SidecarMissing"
	ReasonNoTargets             = "NoTargets"
)

const (
	debounce = time.Second
	// resync also notices Traefik's CRDs being installed later.
	resync = time.Minute
)

var clusterRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "wiring"}}

// Reconciler wires protected routes. It runs on the leader.
type Reconciler struct {
	Client client.Client
	// APIReader reads Middlewares uncached.
	APIReader client.Reader
	// PodWebhook is the MutatingWebhookConfiguration that injects the
	// engine: a proxy pod created after it without the engine was missed
	// by the webhook (SidecarMissing), one created before it predates
	// Inkwall (PendingRestart).
	PodWebhook string
	// TraefikPods selects Traefik's pods (integrations.Selectors).
	TraefikPods labels.Selector
	// IngressRoutes watches Traefik's IngressRoutes once their CRD is
	// installed; nil: they are only read at each reconcile.
	IngressRoutes *crdwatch.Kind
}

// SetupWithManager registers the controller.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	enqueue := handler.Funcs{
		CreateFunc: func(_ context.Context, _ event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, debounce)
		},
		UpdateFunc: func(_ context.Context, _ event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, debounce)
		},
		DeleteFunc: func(_ context.Context, _ event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.AddAfter(clusterRequest, debounce)
		},
		GenericFunc: func(_ context.Context, _ event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			q.Add(clusterRequest)
		},
	}
	start := make(chan event.GenericEvent, 1)
	start <- event.GenericEvent{Object: &corev1.Pod{}}
	c, err := ctrl.NewControllerManagedBy(mgr).
		Named("wiring").
		Watches(&wafv1alpha1.WAFPolicy{}, enqueue, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Ingress annotations matter (the operator's own included).
		Watches(&networkingv1.Ingress{}, enqueue).
		Watches(&networkingv1.IngressClass{}, enqueue).
		// The manager caches only proxy pods: their sidecar decides
		// PendingRestart.
		Watches(&corev1.Pod{}, enqueue).
		WatchesRawSource(source.Channel(start, enqueue)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Build(r)
	if err != nil {
		return err
	}
	if r.IngressRoutes != nil {
		// Their middlewares matter (the operator's own included).
		r.IngressRoutes.Add(c, enqueue)
	}
	return nil
}

// target is an Ingress some policy protects.
type target struct {
	ing        *networkingv1.Ingress
	controller string
}

// state is what a reconcile found, for Programmed.
type state struct {
	ingresses map[types.NamespacedName]*networkingv1.Ingress
	// wire are the Ingress targets.
	wire map[types.NamespacedName]target
	// routes are the IngressRoutes, when routeCRD (their CRD is
	// installed); routeErr says why one couldn't be wired.
	routes   map[types.NamespacedName]*unstructured.Unstructured
	routeCRD bool
	routeErr map[types.NamespacedName]string
	// traefikCRDs: the Middleware CRD is installed.
	traefikCRDs bool
	// middlewareErr: namespace -> why its Middleware can't be used.
	middlewareErr  map[string]string
	pods           []corev1.Pod
	injectingSince time.Time
}

// IngressRoutes lists Traefik's IngressRoutes; installed is false, with
// none, when their CRD isn't.
func IngressRoutes(ctx context.Context, c client.Client) (routes []unstructured.Unstructured, installed bool, err error) {
	if installed, err = crdwatch.Installed(c.RESTMapper(), IngressRouteGVK); !installed || err != nil {
		return nil, false, err
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(IngressRouteGVK.GroupVersion().WithKind("IngressRouteList"))
	if err := c.List(ctx, list); err != nil {
		return nil, true, err
	}
	return list.Items, true, nil
}

// Reconcile wires every protected Traefik Ingress and IngressRoute, unwires
// the rest, and reports Programmed.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	var (
		policies  wafv1alpha1.WAFPolicyList
		ingresses networkingv1.IngressList
		classList networkingv1.IngressClassList
		pods      corev1.PodList
	)
	for _, l := range []client.ObjectList{&policies, &ingresses, &classList} {
		if err := r.Client.List(ctx, l); err != nil {
			return reconcile.Result{}, err
		}
	}
	if err := r.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: r.TraefikPods}); err != nil {
		return reconcile.Result{}, err
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

	routes, routeCRD, err := IngressRoutes(ctx, r.Client)
	if err != nil {
		return reconcile.Result{}, err
	}
	st := &state{
		ingresses: byKey, wire: map[types.NamespacedName]target{},
		routes: map[types.NamespacedName]*unstructured.Unstructured{}, routeCRD: routeCRD, routeErr: map[types.NamespacedName]string{},
		traefikCRDs: r.middlewaresInstalled(), middlewareErr: map[string]string{},
	}
	for i := range routes {
		ir := &routes[i]
		st.routes[types.NamespacedName{Namespace: ir.GetNamespace(), Name: ir.GetName()}] = ir
	}

	// The routes to wire: every Ingress target of a policy that Traefik
	// serves, and every IngressRoute target. A policy that isn't accepted
	// yet is wired too: until its rules are in a bundle, the engine lets its
	// routes through (no-policy).
	wireRoutes := map[types.NamespacedName]bool{}
	for _, p := range policies.Items {
		for _, t := range p.Spec.TargetRefs {
			k := types.NamespacedName{Namespace: p.Namespace, Name: t.Name}
			switch t.Kind {
			case "Ingress":
				if ing, ok := byKey[k]; ok {
					st.wire[k] = target{ing: ing, controller: Controller(ing, classes, defaultClass)}
				}
			case "IngressRoute":
				if _, ok := st.routes[k]; ok {
					wireRoutes[k] = true
				}
			}
		}
	}

	needed := map[string]bool{} // namespaces whose Middleware is used
	if st.traefikCRDs {
		for _, t := range st.wire {
			if t.controller == integrations.Traefik.Controller {
				needed[t.ing.Namespace] = true
			}
		}
		for k := range wireRoutes {
			needed[k.Namespace] = true
		}
		for ns := range needed {
			if err := r.ensureMiddleware(ctx, ns); err != nil {
				st.middlewareErr[ns] = err.Error()
				logger.Error(err, "Middleware not wired", "namespace", ns)
			}
		}
	}

	// Ingress annotations: add the Middleware to protected Traefik
	// Ingresses, remove it from those the operator wired before.
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		k := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		t, protected := st.wire[k]
		want := protected && st.traefikCRDs && t.controller == integrations.Traefik.Controller && st.middlewareErr[ing.Namespace] == ""
		if err := r.annotate(ctx, ing, want); err != nil {
			return reconcile.Result{}, fmt.Errorf("wire ingress %s: %w", k, err)
		}
	}

	// IngressRoutes: the same, in each route's middlewares. One that can't
	// be written is reported, the others are still wired.
	var conflicts error
	for k, ir := range st.routes {
		want := wireRoutes[k] && st.traefikCRDs && st.middlewareErr[k.Namespace] == ""
		switch err := r.wireRoute(ctx, ir, want); {
		case apierrors.IsConflict(err):
			// Changed since the cache saw it: again, once it has.
			conflicts = errors.Join(conflicts, fmt.Errorf("wire IngressRoute %s: %w", k, err))
		case err != nil:
			st.routeErr[k] = fmt.Sprintf("IngressRoute %s: %v", k.Name, err)
			logger.Error(err, "IngressRoute not wired", "ingressroute", k)
		}
	}

	// After the routes: a router referring to a missing Middleware fails.
	if st.traefikCRDs {
		if err := r.pruneMiddlewares(ctx, needed); err != nil {
			return reconcile.Result{}, err
		}
	}

	st.pods, st.injectingSince = pods.Items, r.injectingSince(ctx)
	if err := r.report(ctx, policies.Items, st); err != nil {
		return reconcile.Result{}, err
	}
	if conflicts != nil || len(st.routeErr) > 0 {
		return reconcile.Result{}, errors.Join(conflicts, errors.New("IngressRoutes not wired"))
	}
	return reconcile.Result{RequeueAfter: resync}, nil
}

// injectingSince is when the Pod webhook was installed; zero if unknown.
func (r *Reconciler) injectingSince(ctx context.Context) time.Time {
	if r.PodWebhook == "" {
		return time.Time{}
	}
	var cfg admissionregistrationv1.MutatingWebhookConfiguration
	if err := r.Client.Get(ctx, types.NamespacedName{Name: r.PodWebhook}, &cfg); err != nil {
		return time.Time{}
	}
	return cfg.CreationTimestamp.Time
}

func (r *Reconciler) middlewaresInstalled() bool {
	_, err := r.Client.RESTMapper().RESTMapping(MiddlewareGVK.GroupKind(), MiddlewareGVK.Version)
	return err == nil
}

// ensureMiddleware creates or corrects the operator's Middleware. One with
// the same name the operator didn't create is left alone, and reported.
func (r *Reconciler) ensureMiddleware(ctx context.Context, namespace string) error {
	want := Middleware(namespace)
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(MiddlewareGVK)
	err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(want), cur)
	switch {
	case apierrors.IsNotFound(err):
		return r.Client.Create(ctx, want)
	case err != nil:
		return err
	}
	if cur.GetLabels()["app.kubernetes.io/managed-by"] != "inkwall-operator" {
		return fmt.Errorf("Middleware %s/%s exists and wasn't created by Inkwall; rename or delete it", namespace, MiddlewareName)
	}
	if ForwardAuthMatches(cur) {
		return nil
	}
	cur.Object["spec"] = want.Object["spec"]
	return r.Client.Update(ctx, cur)
}

// pruneMiddlewares deletes the operator's Middlewares in namespaces that no
// longer need one.
func (r *Reconciler) pruneMiddlewares(ctx context.Context, needed map[string]bool) error {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(MiddlewareGVK.GroupVersion().WithKind("MiddlewareList"))
	if err := r.APIReader.List(ctx, list, client.MatchingLabels{"app.kubernetes.io/managed-by": "inkwall-operator"}); err != nil {
		return err
	}
	for i := range list.Items {
		m := &list.Items[i]
		if m.GetName() == MiddlewareName && !needed[m.GetNamespace()] {
			if err := r.Client.Delete(ctx, m); client.IgnoreNotFound(err) != nil {
				return err
			}
		}
	}
	return nil
}

// annotate adds the operator's Middleware to an Ingress (want), or removes
// it if the operator added it before. Only the operator's entry changes;
// Middlewares the user listed stay, in order.
func (r *Reconciler) annotate(ctx context.Context, ing *networkingv1.Ingress, want bool) error {
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
	return r.Client.Patch(ctx, ing, patch)
}

// wireRoute adds the operator's Middleware to an IngressRoute's routes
// (want), or removes it if the operator added it before. Only the
// operator's entries change; Middlewares the user listed stay, in order.
func (r *Reconciler) wireRoute(ctx context.Context, ir *unstructured.Unstructured, want bool) error {
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
	return r.Client.Patch(ctx, ir, client.MergeFromWithOptions(orig, client.MergeFromWithOptimisticLock{}))
}

// programmed computes a policy's Programmed condition.
func programmed(p *wafv1alpha1.WAFPolicy, st *state) (metav1.ConditionStatus, string, string) {
	var unsupported, failed []string
	ingresses, routes := 0, 0
	for _, t := range p.Spec.TargetRefs {
		k := types.NamespacedName{Namespace: p.Namespace, Name: t.Name}
		switch t.Kind {
		case "Ingress":
			if _, ok := st.ingresses[k]; !ok {
				continue // reported by Accepted
			}
			tg := st.wire[k]
			switch {
			case tg.controller != integrations.Traefik.Controller:
				c := tg.controller
				if c == "" {
					c = "no known IngressClass"
				}
				unsupported = append(unsupported, fmt.Sprintf("Ingress %s is served by %s, which Inkwall doesn't wire yet", t.Name, c))
			case !st.traefikCRDs:
				failed = append(failed, "Traefik's Middleware CRD is not installed")
			case st.middlewareErr[p.Namespace] != "":
				failed = append(failed, st.middlewareErr[p.Namespace])
			default:
				ingresses++
			}
		case "IngressRoute":
			if !st.routeCRD {
				failed = append(failed, "Traefik's IngressRoute CRD is not installed")
				continue
			}
			if _, ok := st.routes[k]; !ok {
				continue // reported by Accepted
			}
			switch {
			case !st.traefikCRDs:
				failed = append(failed, "Traefik's Middleware CRD is not installed")
			case st.middlewareErr[p.Namespace] != "":
				failed = append(failed, st.middlewareErr[p.Namespace])
			case st.routeErr[k] != "":
				failed = append(failed, st.routeErr[k])
			default:
				routes++
			}
		default:
			unsupported = append(unsupported, fmt.Sprintf("%s %s (only Ingress and IngressRoute targets are wired so far)", t.Kind, t.Name))
		}
	}
	slices.Sort(failed)
	switch {
	case len(failed) > 0:
		return metav1.ConditionFalse, ReasonWiringFailed, strings.Join(slices.Compact(failed), "; ")
	case len(unsupported) > 0:
		return metav1.ConditionFalse, ReasonControllerUnsupported, strings.Join(unsupported, "; ")
	case ingresses+routes == 0:
		return metav1.ConditionFalse, ReasonNoTargets, "none of the policy's targets exists"
	}
	var wired []string
	if ingresses > 0 {
		wired = append(wired, fmt.Sprintf("%d Ingress(es)", ingresses))
	}
	if routes > 0 {
		wired = append(wired, fmt.Sprintf("%d IngressRoute(s)", routes))
	}

	// The routes go to Traefik's pods, whose sidecar must be there.
	var missed, optedOut, before []string
	running := 0
	for _, pod := range st.pods {
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		running++
		name := pod.Namespace + "/" + pod.Name
		switch {
		case injection.HasEngine(&pod):
		case injection.OptedOut(&pod):
			optedOut = append(optedOut, name)
		case !st.injectingSince.IsZero() && pod.CreationTimestamp.After(st.injectingSince):
			missed = append(missed, name)
		default:
			before = append(before, name)
		}
	}
	for _, l := range [][]string{missed, optedOut, before} {
		slices.Sort(l)
	}
	switch {
	case running == 0:
		return metav1.ConditionFalse, ReasonSidecarMissing, "no Traefik pod is running"
	case len(missed) > 0 || len(optedOut) > 0:
		var why []string
		if len(missed) > 0 {
			why = append(why, "created while the operator was unavailable (the injection webhook fails open in detect mode), restart them once it is back: "+strings.Join(missed, ", "))
		}
		if len(optedOut) > 0 {
			why = append(why, "opted out with "+injection.InjectAnnotation+": \"false\": "+strings.Join(optedOut, ", "))
		}
		return metav1.ConditionFalse, ReasonSidecarMissing, "Traefik pods run without the engine, their traffic is not inspected; " + strings.Join(why, "; ")
	case len(before) > 0:
		return metav1.ConditionFalse, ReasonPendingRestart, fmt.Sprintf(
			"Traefik pods started before Inkwall run without the engine; restart them (kubectl rollout restart) to inject it: %s",
			strings.Join(before, ", "))
	}
	return metav1.ConditionTrue, ReasonProgrammed, strings.Join(wired, " and ") + " wired to the engine in Traefik"
}

func (r *Reconciler) report(ctx context.Context, policies []wafv1alpha1.WAFPolicy, s *state) error {
	for i := range policies {
		p := &policies[i]
		st, reason, msg := programmed(p, s)
		first := true
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if !first {
				if err := r.Client.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil {
					return err
				}
			}
			first = false
			if !meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
				Type: wafv1alpha1.ConditionProgrammed, Status: st, Reason: reason, Message: msg, ObservedGeneration: p.Generation,
			}) {
				return nil
			}
			return r.Client.Status().Update(ctx, p)
		})
		if client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}
