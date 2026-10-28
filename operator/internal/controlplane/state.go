// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	controlplanev1 "github.com/inkwall-dev/inkwall/api/controlplane/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
	"github.com/inkwall-dev/inkwall/operator/internal/bundle"
	"github.com/inkwall-dev/inkwall/operator/internal/distribution"
	"github.com/inkwall-dev/inkwall/operator/internal/injection"
)

// The leader reports every Inkwall object to the control plane (and
// writes only the control plane's own, in Managed mode: snapshot.go).
//
// +kubebuilder:rbac:groups=waf.inkwall.dev,resources=wafpolicies;wafrulesets;clusterwafrulesets;inkwallconfigs,verbs=get;list;watch

// clusterState is a full snapshot of the cluster (0004 §4.9): every
// Inkwall object with its conditions, the proxies, the engines and the
// bundle being served.
func (c *Connector) clusterState(ctx context.Context) (*controlplanev1.ClusterState, error) {
	st := &controlplanev1.ClusterState{Time: timestamppb.Now()}
	var err error
	if st.Objects, err = c.objects(ctx); err != nil {
		return nil, err
	}
	if st.Integrations, err = c.integrations(ctx); err != nil {
		return nil, err
	}
	engines, err := distribution.ReadEngines(ctx, c.APIReader, c.Namespace, c.EngineStale, time.Now())
	if err != nil {
		return nil, fmt.Errorf("engines: %w", err)
	}
	for _, e := range engines {
		st.Engines = append(st.Engines, &controlplanev1.Engine{
			EngineId: e.ID, PodNamespace: e.PodNamespace, PodName: e.PodName, NodeName: e.NodeName,
			EngineVersion: e.EngineVersion, AppliedBundleVersion: e.Applied, RejectedBundleVersion: e.Rejected,
			RejectError: e.RejectError, ConnectedAt: timestamppb.New(e.ConnectedAt),
		})
	}
	if st.BundleVersion, st.BundleContentHash, err = c.bundle(ctx); err != nil {
		return nil, err
	}
	if size := proto.Size(st); size > maxMessage {
		return nil, fmt.Errorf("the cluster state is %d bytes, over the contract's %d", size, maxMessage)
	}
	return st, nil
}

// objects lists the Inkwall objects, sorted, so equal clusters give equal
// snapshots.
func (c *Connector) objects(ctx context.Context) ([]*controlplanev1.Object, error) {
	var out []*controlplanev1.Object
	add := func(kind string, o metav1.Object, spec any, conds []metav1.Condition) error {
		obj, err := object(kind, o, spec, conds)
		if err != nil {
			return err
		}
		out = append(out, obj)
		return nil
	}
	var policies wafv1alpha1.WAFPolicyList
	if err := c.Client.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("WAFPolicies: %w", err)
	}
	for i := range policies.Items {
		p := &policies.Items[i]
		if err := add("WAFPolicy", p, p.Spec, p.Status.Conditions); err != nil {
			return nil, err
		}
	}
	var ruleSets wafv1alpha1.WAFRuleSetList
	if err := c.Client.List(ctx, &ruleSets); err != nil {
		return nil, fmt.Errorf("WAFRuleSets: %w", err)
	}
	for i := range ruleSets.Items {
		r := &ruleSets.Items[i]
		if err := add("WAFRuleSet", r, r.Spec, r.Status.Conditions); err != nil {
			return nil, err
		}
	}
	var clusterRuleSets wafv1alpha1.ClusterWAFRuleSetList
	if err := c.Client.List(ctx, &clusterRuleSets); err != nil {
		return nil, fmt.Errorf("ClusterWAFRuleSets: %w", err)
	}
	for i := range clusterRuleSets.Items {
		r := &clusterRuleSets.Items[i]
		if err := add("ClusterWAFRuleSet", r, r.Spec, r.Status.Conditions); err != nil {
			return nil, err
		}
	}
	var configs wafv1alpha1.InkwallConfigList
	if err := c.Client.List(ctx, &configs); err != nil {
		return nil, fmt.Errorf("InkwallConfigs: %w", err)
	}
	for i := range configs.Items {
		cfg := &configs.Items[i]
		if err := add("InkwallConfig", cfg, cfg.Spec, cfg.Status.Conditions); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b *controlplanev1.Object) int {
		return cmp.Or(cmp.Compare(a.GetKind(), b.GetKind()), cmp.Compare(a.GetNamespace(), b.GetNamespace()), cmp.Compare(a.GetName(), b.GetName()))
	})
	return out, nil
}

func object(kind string, o metav1.Object, spec any, conds []metav1.Condition) (*controlplanev1.Object, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", kind, o.GetName(), err)
	}
	obj := &controlplanev1.Object{
		ApiVersion: wafv1alpha1.GroupVersion.String(), Kind: kind,
		Namespace: o.GetNamespace(), Name: o.GetName(), Generation: o.GetGeneration(),
		Labels: o.GetLabels(), Spec: raw,
	}
	for _, cd := range conds {
		obj.Conditions = append(obj.Conditions, &controlplanev1.Condition{
			Type: cd.Type, Status: string(cd.Status), Reason: cd.Reason, Message: cd.Message,
			ObservedGeneration: cd.ObservedGeneration, LastTransitionTime: timestamppb.New(cd.LastTransitionTime.Time),
		})
	}
	return obj, nil
}

// integrations counts the proxy pods running, and those with the engine.
func (c *Connector) integrations(ctx context.Context) ([]*controlplanev1.Integration, error) {
	sel := c.ProxyPods
	if sel == nil {
		sel = labels.SelectorFromSet(integrations.Traefik.PodSelector)
	}
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods, client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, fmt.Errorf("proxy pods: %w", err)
	}
	in := &controlplanev1.Integration{Name: integrations.Traefik.Name, Controller: integrations.Traefik.Controller}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		in.Pods++
		if injection.HasEngine(p) {
			in.PodsWithEngine++
		}
	}
	return []*controlplanev1.Integration{in}, nil
}

// bundle reads the version and content hash of the bundle being served
// (none before the first).
func (c *Connector) bundle(ctx context.Context) (uint64, []byte, error) {
	var s corev1.Secret
	err := c.Client.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: bundle.BundleSecret}, &s)
	if apierrors.IsNotFound(err) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, fmt.Errorf("bundle Secret: %w", err)
	}
	signed, err := bundle.Decode(s.Data[bundle.BundleKey])
	if err != nil {
		return 0, nil, fmt.Errorf("bundle Secret: %w", err)
	}
	var b bundlev1.Bundle
	if err := proto.Unmarshal(signed.GetBundle(), &b); err != nil {
		return 0, nil, fmt.Errorf("bundle Secret: %w", err)
	}
	return b.GetVersion(), b.GetContentHash(), nil
}

// stateSender sends the ClusterState when it changes, and in full every
// resend, even unchanged, so a control plane that lost it recovers.
type stateSender struct {
	resend time.Duration
	last   [sha256.Size]byte
	sentAt time.Time
}

// changed reports whether st should be sent: forced, different from the
// last one sent, or due for its periodic resend.
func (s *stateSender) changed(st *controlplanev1.ClusterState, force bool) (bool, [sha256.Size]byte) {
	// The time differs in every snapshot: compare without it.
	t := st.GetTime()
	st.Time = nil
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(st)
	st.Time = t
	sum := sha256.Sum256(raw)
	return force || sum != s.last || time.Since(s.sentAt) >= s.resend, sum
}
