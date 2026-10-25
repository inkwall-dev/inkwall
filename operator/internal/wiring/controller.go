// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package wiring

import (
	"context"
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
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// The wiring controller reads routes and proxy pods, writes the Traefik
// Middleware in protected namespaces, adds it to protected Ingresses, and
// reports Programmed.
//
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingressclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=traefik.io,resources=middlewares,verbs=get;list;watch;create;update;patch;delete

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
	return ctrl.NewControllerManagedBy(mgr).
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
		Complete(r)
}

// target is an Ingress some policy protects.
type target struct {
	ing        *networkingv1.Ingress
	controller string
}

// Reconcile wires every protected Traefik Ingress, unwires the rest, and
// reports Programmed.
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
	if err := r.Client.List(ctx, &pods, client.MatchingLabels(integrations.Traefik.PodSelector)); err != nil {
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

	// The Ingresses to wire: every Ingress target of a policy that Traefik
	// serves. A policy that isn't accepted yet is wired too: until its rules
	// are in a bundle, the engine lets its routes through (no-policy).
	wire := map[types.NamespacedName]target{}
	for _, p := range policies.Items {
		for _, t := range p.Spec.TargetRefs {
			if t.Kind != "Ingress" {
				continue
			}
			k := types.NamespacedName{Namespace: p.Namespace, Name: t.Name}
			if ing, ok := byKey[k]; ok {
				wire[k] = target{ing: ing, controller: Controller(ing, classes, defaultClass)}
			}
		}
	}

	traefikCRDs := r.middlewaresInstalled()
	// Namespace -> why its Middleware can't be used ("" when it can).
	middlewareErr := map[string]string{}
	if traefikCRDs {
		needed := map[string]bool{}
		for _, t := range wire {
			if t.controller == integrations.Traefik.Controller {
				needed[t.ing.Namespace] = true
			}
		}
		for ns := range needed {
			if err := r.ensureMiddleware(ctx, ns); err != nil {
				middlewareErr[ns] = err.Error()
				logger.Error(err, "Middleware not wired", "namespace", ns)
			}
		}
		if err := r.pruneMiddlewares(ctx, needed); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Ingress annotations: add the Middleware to protected Traefik
	// Ingresses, remove it from those the operator wired before.
	for i := range ingresses.Items {
		ing := &ingresses.Items[i]
		k := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		t, protected := wire[k]
		want := protected && traefikCRDs && t.controller == integrations.Traefik.Controller && middlewareErr[ing.Namespace] == ""
		if err := r.annotate(ctx, ing, want); err != nil {
			return reconcile.Result{}, fmt.Errorf("wire ingress %s: %w", k, err)
		}
	}

	if err := r.report(ctx, policies.Items, byKey, wire, traefikCRDs, middlewareErr, pods.Items, r.injectingSince(ctx)); err != nil {
		return reconcile.Result{}, err
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

// programmed computes a policy's Programmed condition.
func programmed(p *wafv1alpha1.WAFPolicy, byKey map[types.NamespacedName]*networkingv1.Ingress, wire map[types.NamespacedName]target,
	traefikCRDs bool, middlewareErr map[string]string, pods []corev1.Pod, injectingSince time.Time) (metav1.ConditionStatus, string, string) {
	var unsupported, failed []string
	wired := 0
	for _, t := range p.Spec.TargetRefs {
		if t.Kind != "Ingress" {
			unsupported = append(unsupported, fmt.Sprintf("%s %s (only Ingress targets are wired so far)", t.Kind, t.Name))
			continue
		}
		k := types.NamespacedName{Namespace: p.Namespace, Name: t.Name}
		if _, ok := byKey[k]; !ok {
			continue // reported by Accepted
		}
		tg := wire[k]
		switch {
		case tg.controller != integrations.Traefik.Controller:
			c := tg.controller
			if c == "" {
				c = "no known IngressClass"
			}
			unsupported = append(unsupported, fmt.Sprintf("Ingress %s is served by %s, which Inkwall doesn't wire yet", t.Name, c))
		case !traefikCRDs:
			failed = append(failed, "Traefik's Middleware CRD is not installed")
		case middlewareErr[p.Namespace] != "":
			failed = append(failed, middlewareErr[p.Namespace])
		default:
			wired++
		}
	}
	switch {
	case len(failed) > 0:
		return metav1.ConditionFalse, ReasonWiringFailed, strings.Join(slices.Compact(failed), "; ")
	case len(unsupported) > 0:
		return metav1.ConditionFalse, ReasonControllerUnsupported, strings.Join(unsupported, "; ")
	case wired == 0:
		return metav1.ConditionFalse, ReasonNoTargets, "none of the policy's targets exists"
	}

	// The routes go to Traefik's pods, whose sidecar must be there.
	var missed, optedOut, before []string
	running := 0
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		running++
		name := pod.Namespace + "/" + pod.Name
		switch {
		case hasEngine(&pod):
		case injection.OptedOut(&pod):
			optedOut = append(optedOut, name)
		case !injectingSince.IsZero() && pod.CreationTimestamp.After(injectingSince):
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
	return metav1.ConditionTrue, ReasonProgrammed, fmt.Sprintf("%d Ingress(es) wired to the engine in Traefik", wired)
}

func hasEngine(pod *corev1.Pod) bool {
	for _, c := range slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers) {
		if c.Name == injection.ContainerName {
			return true
		}
	}
	return false
}

func (r *Reconciler) report(ctx context.Context, policies []wafv1alpha1.WAFPolicy, byKey map[types.NamespacedName]*networkingv1.Ingress,
	wire map[types.NamespacedName]target, traefikCRDs bool, middlewareErr map[string]string, pods []corev1.Pod, injectingSince time.Time) error {
	for i := range policies {
		p := &policies[i]
		st, reason, msg := programmed(p, byKey, wire, traefikCRDs, middlewareErr, pods, injectingSince)
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
