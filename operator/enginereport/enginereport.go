// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package enginereport reads the engines the operator's replicas report in
// their inkwall-engines-<pod> ConfigMaps (0004 §4.8): which engines are
// connected, the bundle each runs and the one it rejected. The leader
// reads them for the policies' status; inkwallctl status reads them too.
package enginereport

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Labels and keys of the replicas' report ConfigMaps.
const (
	// Label marks a report ConfigMap.
	Label = "waf.inkwall.dev/engines"
	// EnginesKey holds the engines, a JSON array of Engine.
	EnginesKey = "engines.json"
	// UpdatedAtKey is when the replica last wrote it (RFC 3339): a report
	// not refreshed for long is from a replica that is gone.
	UpdatedAtKey = "updatedAt"
	// LeftOutKey counts the engines left out of a full report.
	LeftOutKey = "leftOut"
	// NamePrefix and the replica's pod name name a report.
	NamePrefix = "inkwall-engines-"
)

// Engine is one connected engine, as a replica reports it.
type Engine struct {
	// ID is the engine's own, from its Hello.
	ID string `json:"id"`
	// ServiceAccount authenticated the stream, as "namespace/name".
	ServiceAccount string `json:"serviceAccount"`
	// Pod and node: from the token when it is bound to a pod, otherwise as
	// the engine reported them.
	PodNamespace  string `json:"podNamespace,omitempty"`
	PodName       string `json:"podName,omitempty"`
	NodeName      string `json:"nodeName,omitempty"`
	EngineVersion string `json:"engineVersion,omitempty"`
	// Applied is the newest bundle version the engine runs.
	Applied uint64 `json:"applied"`
	// Rejected is the newest version the engine refused, and why.
	Rejected    uint64 `json:"rejected,omitempty"`
	RejectError string `json:"rejectError,omitempty"`
	// TrustedKeys are the IDs of the bundle signing keys the engine
	// accepts; empty from an engine older than key rotation.
	TrustedKeys []string `json:"trustedKeys,omitempty"`
	// Replica is the operator replica the engine is connected to.
	Replica     string    `json:"replica"`
	ConnectedAt time.Time `json:"connectedAt"`
}

// Read merges the replicas' reports in namespace, skipping those not
// refreshed within stale (their replica is gone). An engine listed twice,
// while it moves between replicas, counts once, with its newest
// connection. They are sorted by ID. leftOut counts the engines left out
// of full reports: while it isn't 0, the list is incomplete.
func Read(ctx context.Context, c client.Reader, namespace string, stale time.Duration, now time.Time) (engines []Engine, leftOut int, err error) {
	var list corev1.ConfigMapList
	if err := c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{Label: "true"}); err != nil {
		return nil, 0, err
	}
	byID := map[string]Engine{}
	for _, cm := range list.Items {
		updated, err := time.Parse(time.RFC3339Nano, cm.Data[UpdatedAtKey])
		if err != nil || now.Sub(updated) > stale {
			continue
		}
		var listed []Engine
		if err := json.Unmarshal([]byte(cm.Data[EnginesKey]), &listed); err != nil {
			continue
		}
		// Missing from an older replica's report: 0.
		n, _ := strconv.Atoi(cm.Data[LeftOutKey])
		leftOut += max(n, 0)
		for _, e := range listed {
			if old, ok := byID[e.ID]; !ok || e.ConnectedAt.After(old.ConnectedAt) {
				byID[e.ID] = e
			}
		}
	}
	engines = make([]Engine, 0, len(byID))
	for _, e := range byID {
		engines = append(engines, e)
	}
	slices.SortFunc(engines, func(a, b Engine) int { return strings.Compare(a.ID, b.ID) })
	return engines, leftOut, nil
}
