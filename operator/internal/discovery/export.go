// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/enginereport"
)

// Reasons of the InkwallConfig's EventsExported condition (design 0010
// §8). When several apply, the first of ExportConfigInvalid,
// ExportAddressRefused, ExportFailing and ExportDropping wins.
const (
	ReasonExporting            = "Exporting"
	ReasonExportFailing        = "ExportFailing"
	ReasonExportConfigInvalid  = "ExportConfigInvalid"
	ReasonExportDropping       = "ExportDropping"
	ReasonExportAddressRefused = "ExportAddressRefused"
)

// exportFieldManager owns the EventsExported condition alone: it is
// applied server-side, so the discovery's and the control plane
// connector's conditions are never overwritten.
const exportFieldManager = "inkwall-export-status"

// exportResync is how often the leader folds the replicas' reports while
// the InkwallConfig has sinks.
const exportResync = 10 * time.Second

// maxConditionMessage keeps the message readable.
const maxConditionMessage = 1024

// The replicas' sink states, by precedence, and the reason each gives.
var exportPrecedence = []struct{ state, reason string }{
	{enginereport.SinkConfigInvalid, ReasonExportConfigInvalid},
	{enginereport.SinkAddressRefused, ReasonExportAddressRefused},
	{enginereport.SinkFailing, ReasonExportFailing},
	{enginereport.SinkDropping, ReasonExportDropping},
}

// ExportCondition folds the replicas' reports of the configured sinks
// into the EventsExported condition; nil with no sinks, or before any
// replica reports one.
func ExportCondition(sinks []string, reports []enginereport.ReplicaSinks, generation int64) *metav1.Condition {
	if len(sinks) == 0 {
		return nil
	}
	configured := map[string]bool{}
	for _, s := range sinks {
		configured[s] = true
	}
	byState := map[string][]string{}
	var plaintext []string
	reported := 0
	for _, r := range reports {
		for _, s := range r.Sinks {
			if !configured[s.Name] {
				// Removed, and the replica hasn't caught up.
				continue
			}
			reported++
			if s.Plaintext && !slices.Contains(plaintext, s.Name) {
				plaintext = append(plaintext, s.Name)
			}
			if s.State == enginereport.SinkExporting || s.State == "" {
				continue
			}
			what := fmt.Sprintf("sink %s on %s", s.Name, r.Replica)
			if s.Message != "" {
				what += ": " + s.Message
			}
			byState[s.State] = append(byState[s.State], what)
		}
	}
	if reported == 0 {
		return nil
	}
	c := &metav1.Condition{Type: wafv1alpha1.ConditionEventsExported, ObservedGeneration: generation}
	var parts []string
	for _, p := range exportPrecedence {
		if list := byState[p.state]; len(list) > 0 {
			slices.Sort(list)
			if c.Reason == "" {
				c.Status, c.Reason = metav1.ConditionFalse, p.reason
			}
			parts = append(parts, p.reason+": "+strings.Join(list, "; "))
		}
	}
	if c.Reason == "" {
		c.Status, c.Reason = metav1.ConditionTrue, ReasonExporting
		parts = append(parts, fmt.Sprintf("every sink exports (%d)", len(sinks)))
	}
	if len(plaintext) > 0 {
		slices.Sort(plaintext)
		parts = append(parts, "plaintext (insecure: true): "+strings.Join(plaintext, ", "))
	}
	c.Message = strings.Join(parts, ". ")
	if len(c.Message) > maxConditionMessage {
		c.Message = c.Message[:maxConditionMessage-3] + "..."
	}
	return c
}

// applyExportCondition sets the InkwallConfig's EventsExported condition,
// or removes it (nil), with a server-side apply of that condition alone.
func applyExportCondition(ctx context.Context, c client.Client, cfg *wafv1alpha1.InkwallConfig, cond *metav1.Condition) error {
	prev := meta.FindStatusCondition(cfg.Status.Conditions, wafv1alpha1.ConditionEventsExported)
	if cond == nil && prev == nil {
		return nil
	}
	conds := []any{}
	if cond != nil {
		if prev != nil && prev.Status == cond.Status && prev.Reason == cond.Reason && prev.Message == cond.Message && prev.ObservedGeneration == cond.ObservedGeneration {
			return nil
		}
		cond.LastTransitionTime = metav1.Now()
		if prev != nil && prev.Status == cond.Status {
			cond.LastTransitionTime = prev.LastTransitionTime
		}
		conds = append(conds, map[string]any{
			"type": cond.Type, "status": string(cond.Status), "reason": cond.Reason, "message": cond.Message,
			"observedGeneration": cond.ObservedGeneration, "lastTransitionTime": cond.LastTransitionTime.UTC().Format(time.RFC3339),
		})
	}
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(wafv1alpha1.GroupVersion.String())
	u.SetKind("InkwallConfig")
	u.SetName(cfg.Name)
	if err := unstructured.SetNestedSlice(u.Object, conds, "status", "conditions"); err != nil {
		return err
	}
	return c.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner(exportFieldManager), client.ForceOwnership)
}
