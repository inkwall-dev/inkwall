// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package enginereport

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ExportKey holds the replica's export sinks, a JSON array of Sink
// (design 0010 §8).
const ExportKey = "export.json"

// The state classes of a sink, as a replica reports them.
const (
	SinkExporting      = "Exporting"
	SinkFailing        = "Failing"
	SinkConfigInvalid  = "ConfigInvalid"
	SinkDropping       = "Dropping"
	SinkAddressRefused = "AddressRefused"
)

// Sink is an export sink's state on one replica.
type Sink struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
	// Pending counts the events the sink hasn't had accepted, as of the
	// report.
	Pending   uint64 `json:"pending"`
	Plaintext bool   `json:"plaintext,omitempty"`
}

// ReplicaSinks are one replica's sinks.
type ReplicaSinks struct {
	Replica string
	Sinks   []Sink
}

// ReadExport reads the replicas' sinks from their reports in namespace,
// skipping those not refreshed within stale; sorted by replica. Every
// fresh report is listed, a replica that reports no sinks with none.
func ReadExport(ctx context.Context, c client.Reader, namespace string, stale time.Duration, now time.Time) ([]ReplicaSinks, error) {
	var list corev1.ConfigMapList
	if err := c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabels{Label: "true"}); err != nil {
		return nil, err
	}
	var out []ReplicaSinks
	for _, cm := range list.Items {
		updated, err := time.Parse(time.RFC3339Nano, cm.Data[UpdatedAtKey])
		if err != nil || now.Sub(updated) > stale {
			continue
		}
		// A live replica that reports no sinks (still starting, or older
		// than export) is listed too: its sinks are missing.
		var sinks []Sink
		if raw, ok := cm.Data[ExportKey]; ok {
			if err := json.Unmarshal([]byte(raw), &sinks); err != nil {
				sinks = nil
			}
		}
		out = append(out, ReplicaSinks{Replica: strings.TrimPrefix(cm.Name, NamePrefix), Sinks: sinks})
	}
	slices.SortFunc(out, func(a, b ReplicaSinks) int { return strings.Compare(a.Replica, b.Replica) })
	return out, nil
}
