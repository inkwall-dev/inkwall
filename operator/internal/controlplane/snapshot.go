// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// In Managed mode the leader writes the control plane's policies as CRDs
// (0004 §4.9); the validating webhook lets no one else change them.
//
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies;wafrulesets;clusterwafrulesets,verbs=create;update;delete

// snapshotKinds are the kinds a PolicySnapshot may carry, in the order they
// are written: rule sets before the policies that use them. Deletes go in
// the reverse order.
var snapshotKinds = []string{"ClusterWAFRuleSet", "WAFRuleSet", "WAFPolicy"}

// policyVersionAnnotation, on the identity Secret, is the version of the
// last snapshot applied, for Hello. It belongs to the cluster ID: a cluster
// enrolled as another one starts again from 0.
const policyVersionAnnotation = "waf.inkwall.dev/policy-version"

// strict refuses fields the CRD doesn't know, instead of dropping them: a
// policy from a newer control plane is refused, never applied in part.
const strict = client.FieldValidation("Strict")

// applier applies the snapshots of one primary stream, one at a time.
type applier struct {
	client client.Client
	// reader reads from the API server, not a cache: the dry run and the
	// prune must see what is there now.
	reader    client.Reader
	namespace string
	// applied is the last snapshot version applied.
	applied uint64
	// backoff paces the retries of a write that fails after the dry run
	// passed.
	backoff wait.Backoff
}

// reply is what the applier answers a snapshot with: a PolicyAck or a
// PolicyNack, or err when the snapshot couldn't be fully written: the
// stream then ends, and the control plane sends it again after the
// reconnect, as Hello's policy version is older.
type reply struct {
	msg *controlplanev1.ConnectRequest
	err error
}

// run applies the snapshots from in until ctx ends or a write fails.
func (a *applier) run(ctx context.Context, in <-chan *controlplanev1.PolicySnapshot, out chan<- reply) {
	for {
		select {
		case <-ctx.Done():
			return
		case snap := <-in:
			msg, err := a.apply(ctx, snap)
			if ctx.Err() != nil {
				return
			}
			select {
			case out <- reply{msg, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func nack(version uint64, msg string, objs ...*controlplanev1.ObjectError) *controlplanev1.ConnectRequest {
	return &controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_PolicyNack{PolicyNack: &controlplanev1.PolicyNack{
		Version: version, Error: msg, Objects: objs,
	}}}
}

// apply writes the snapshot, all or nothing: every object passes a
// server-side dry run (the CRD schema and the validating webhook) before
// any is written.
func (a *applier) apply(ctx context.Context, snap *controlplanev1.PolicySnapshot) (*controlplanev1.ConnectRequest, error) {
	v := snap.GetVersion()
	logger := log.FromContext(ctx).WithValues("version", v)
	var cfg wafv1alpha1.InkwallConfig
	if err := a.reader.Get(ctx, types.NamespacedName{Name: "default"}, &cfg); client.IgnoreNotFound(err) != nil {
		return nil, fmt.Errorf("read the InkwallConfig: %w", err)
	}
	if cfg.Spec.Mode != wafv1alpha1.ModeManaged {
		return nack(v, fmt.Sprintf("the cluster is not in Managed mode (its InkwallConfig says %q): nothing was written", cfg.Spec.Mode)), nil
	}
	switch {
	case v == 0:
		return nack(v, "snapshot version 0: versions start at 1"), nil
	case v < a.applied:
		return nack(v, fmt.Sprintf("snapshot %d is older than the applied snapshot %d: nothing was written", v, a.applied)), nil
	}
	objs, errs := decode(snap.GetObjects())
	if len(errs) == 0 {
		var err error
		if errs, err = a.dryRun(ctx, objs); err != nil {
			return nil, fmt.Errorf("checking policy snapshot %d: %w", v, err)
		}
	}
	if len(errs) > 0 {
		logger.Info("policy snapshot refused", "objects", len(errs))
		return nack(v, fmt.Sprintf("%d of %d objects refused: nothing was written", len(errs), len(snap.GetObjects())), errs...), nil
	}
	err := retry.OnError(a.backoff, func(error) bool { return ctx.Err() == nil }, func() error { return a.write(ctx, objs, v) })
	if err != nil {
		return nil, fmt.Errorf("writing policy snapshot %d: %w", v, err)
	}
	a.applied = v
	logger.Info("policy snapshot applied", "objects", len(objs))
	return &controlplanev1.ConnectRequest{Msg: &controlplanev1.ConnectRequest_PolicyAck{PolicyAck: &controlplanev1.PolicyAck{Version: v}}}, nil
}

// decode turns the snapshot's objects into the objects to write, labelled
// as the control plane's, sorted in writing order; or says what is wrong
// with them.
func decode(in []*controlplanev1.Object) ([]*unstructured.Unstructured, []*controlplanev1.ObjectError) {
	var (
		out  []*unstructured.Unstructured
		errs []*controlplanev1.ObjectError
		seen = map[string]bool{}
	)
	for _, o := range in {
		refuse := func(format string, args ...any) {
			errs = append(errs, &controlplanev1.ObjectError{Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName(), Error: fmt.Sprintf(format, args...)})
		}
		kind, ns, name := o.GetKind(), o.GetNamespace(), o.GetName()
		var spec map[string]any
		switch {
		case o.GetApiVersion() != wafv1alpha1.GroupVersion.String():
			refuse("apiVersion %q: want %s", o.GetApiVersion(), wafv1alpha1.GroupVersion)
		case !slices.Contains(snapshotKinds, kind):
			refuse("kind %q: a snapshot carries only %s", kind, strings.Join(snapshotKinds, ", "))
		case name == "":
			refuse("no name")
		case kind == "ClusterWAFRuleSet" && ns != "":
			refuse("a ClusterWAFRuleSet has no namespace")
		case kind != "ClusterWAFRuleSet" && ns == "":
			refuse("no namespace")
		case seen[objectKey(kind, ns, name)]:
			refuse("twice in the snapshot")
		case utiljson.Unmarshal(o.GetSpec(), &spec) != nil || spec == nil:
			refuse("spec: not a JSON object")
		case kind != "WAFPolicy" && hasConfigMapRef(spec):
			refuse("spec.source.configMapRef: the control plane can't create the ConfigMap; carry the rules inline (seclang or builtin)")
		default:
			seen[objectKey(kind, ns, name)] = true
			labels := maps.Clone(o.GetLabels())
			if labels == nil {
				labels = map[string]string{}
			}
			labels[wafv1alpha1.SourceLabel] = wafv1alpha1.SourceSaaS
			u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
			u.SetGroupVersionKind(wafv1alpha1.GroupVersion.WithKind(kind))
			u.SetNamespace(ns)
			u.SetName(name)
			u.SetLabels(labels)
			out = append(out, u)
		}
	}
	slices.SortStableFunc(out, func(a, b *unstructured.Unstructured) int {
		return slices.Index(snapshotKinds, a.GetKind()) - slices.Index(snapshotKinds, b.GetKind())
	})
	return out, errs
}

func hasConfigMapRef(spec map[string]any) bool {
	src, _ := spec["source"].(map[string]any)
	return src["configMapRef"] != nil
}

func objectKey(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

func describe(o *unstructured.Unstructured) string {
	if o.GetNamespace() == "" {
		return o.GetKind() + " " + o.GetName()
	}
	return o.GetKind() + " " + o.GetNamespace() + "/" + o.GetName()
}

// dryRun checks every write and delete the snapshot needs, changing
// nothing, and returns the objects refused. Any other error (the API
// server or the webhook unreachable, say) says nothing about the snapshot:
// it is returned, and the snapshot comes again after the reconnect.
func (a *applier) dryRun(ctx context.Context, objs []*unstructured.Unstructured) ([]*controlplanev1.ObjectError, error) {
	var errs []*controlplanev1.ObjectError
	refused := func(o *unstructured.Unstructured, prefix string, err error) error {
		if !isRefusal(err) {
			return fmt.Errorf("%s: %w", describe(o), err)
		}
		errs = append(errs, &controlplanev1.ObjectError{Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName(), Error: prefix + err.Error()})
		return nil
	}
	for _, o := range objs {
		if err := a.put(ctx, o, true); err != nil {
			if err := refused(o, "", err); err != nil {
				return nil, err
			}
		}
	}
	stale, err := a.stale(ctx, objs)
	if err != nil {
		return nil, err
	}
	for _, o := range stale {
		if err := a.client.Delete(ctx, o, client.DryRunAll); client.IgnoreNotFound(err) != nil {
			if err := refused(o, "delete: ", err); err != nil {
				return nil, err
			}
		}
	}
	return errs, nil
}

// isRefusal tells an object the API server refuses (the schema, strict
// field validation, the webhook, a missing namespace, someone else's
// object) from a failure to ask.
func isRefusal(err error) bool {
	return errors.Is(err, errNotOurs) || apierrors.IsInvalid(err) || apierrors.IsBadRequest(err) ||
		apierrors.IsForbidden(err) || apierrors.IsNotFound(err) || apierrors.IsAlreadyExists(err)
}

// errNotOurs refuses to take over an object someone else wrote.
var errNotOurs = fmt.Errorf("exists without the %s=%s label: it isn't the control plane's; delete or rename it first",
	wafv1alpha1.SourceLabel, wafv1alpha1.SourceSaaS)

// put creates or replaces the object's labels and spec, keeping the rest
// of an existing object (annotations, finalizers). An object the control
// plane didn't write is never taken over.
func (a *applier) put(ctx context.Context, want *unstructured.Unstructured, dryRun bool) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur := &unstructured.Unstructured{}
		cur.SetGroupVersionKind(want.GroupVersionKind())
		err := a.reader.Get(ctx, client.ObjectKeyFromObject(want), cur)
		switch {
		case apierrors.IsNotFound(err):
			opts := []client.CreateOption{strict}
			if dryRun {
				opts = append(opts, client.DryRunAll)
			}
			return a.client.Create(ctx, want.DeepCopy(), opts...)
		case err != nil:
			return err
		case cur.GetLabels()[wafv1alpha1.SourceLabel] != wafv1alpha1.SourceSaaS:
			return errNotOurs
		}
		cur.SetLabels(want.GetLabels())
		cur.Object["spec"] = want.Object["spec"]
		opts := []client.UpdateOption{strict}
		if dryRun {
			opts = append(opts, client.DryRunAll)
		}
		return a.client.Update(ctx, cur, opts...)
	})
}

// stale lists the control plane's objects that objs no longer has,
// policies first.
func (a *applier) stale(ctx context.Context, objs []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	keep := map[string]bool{}
	for _, o := range objs {
		keep[objectKey(o.GetKind(), o.GetNamespace(), o.GetName())] = true
	}
	var out []*unstructured.Unstructured
	for _, kind := range slices.Backward(snapshotKinds) {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(wafv1alpha1.GroupVersion.WithKind(kind + "List"))
		if err := a.reader.List(ctx, list, client.MatchingLabels{wafv1alpha1.SourceLabel: wafv1alpha1.SourceSaaS}); err != nil {
			return nil, fmt.Errorf("%s: %w", kind, err)
		}
		for i := range list.Items {
			o := &list.Items[i]
			o.SetGroupVersionKind(wafv1alpha1.GroupVersion.WithKind(kind))
			if !keep[objectKey(kind, o.GetNamespace(), o.GetName())] {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// write writes every object, deletes the control plane's objects the
// snapshot no longer has, and records the version. It is idempotent, so a
// failure is retried from the start.
func (a *applier) write(ctx context.Context, objs []*unstructured.Unstructured, version uint64) error {
	for _, o := range objs {
		if err := a.put(ctx, o, false); err != nil {
			return fmt.Errorf("%s: %w", describe(o), err)
		}
	}
	stale, err := a.stale(ctx, objs)
	if err != nil {
		return err
	}
	for _, o := range stale {
		// Only the object listed: never one created since under its name.
		uid := o.GetUID()
		if err := a.client.Delete(ctx, o, client.Preconditions{UID: &uid}); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete %s: %w", describe(o), err)
		}
	}
	return storePolicyVersion(ctx, a.client, a.namespace, version)
}

// storePolicyVersion records the last snapshot applied on the identity
// Secret.
func storePolicyVersion(ctx context.Context, c client.Client, namespace string, version uint64) error {
	s := &corev1.Secret{}
	s.Namespace, s.Name = namespace, IdentitySecret
	patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, policyVersionAnnotation, strconv.FormatUint(version, 10))
	if err := c.Patch(ctx, s, client.RawPatch(types.MergePatchType, []byte(patch))); err != nil {
		return fmt.Errorf("record the policy version: %w", err)
	}
	return nil
}

// defaultApplyBackoff retries a failed write for about 15 s before the
// stream is dropped.
var defaultApplyBackoff = wait.Backoff{Duration: 500 * time.Millisecond, Factor: 2, Jitter: 0.1, Steps: 5}
