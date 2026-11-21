// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8seventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/webhook"
)

// auditLog holds the operator's audit log lines (Options.AuditLog).
var auditLog = &syncBuffer{}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// records are the audit log's lines about the object namespace/name.
func (b *syncBuffer) records(t *testing.T, kind, namespace, name string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(b.buf.String(), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit log line %q: %v", line, err)
		}
		if m["msg"] == webhook.AuditMessage && m["kind"] == kind && m["namespace"] == namespace && m["name"] == name {
			out = append(out, m)
		}
	}
	return out
}

// testAuditLog checks the audit log as deployed (#726): a change made
// through the API server is logged, with its user and what changed, and
// recorded as an Event on the object; a dry run and a change of labels
// only are not.
func testAuditLog(ctx context.Context, t *testing.T, c client.Client) {
	cfg, err := env.User("alice", "system:masters")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := client.New(cfg, client.Options{Scheme: c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	p := &wafv1alpha1.WAFPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "audited"},
		Spec: wafv1alpha1.WAFPolicySpec{
			TargetRefs: []wafv1alpha1.TargetRef{{Kind: "Ingress", Name: "audited"}},
			Mode:       wafv1alpha1.PolicyDetect,
		},
	}
	if err := alice.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	// A dry run is never recorded, nor a change of labels only.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dry := p.DeepCopy()
		if err := alice.Get(ctx, client.ObjectKeyFromObject(dry), dry); err != nil {
			return err
		}
		dry.Spec.Mode = wafv1alpha1.PolicyBlock
		return alice.Update(ctx, dry, client.DryRunAll)
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	update(ctx, t, alice, p, func(p *wafv1alpha1.WAFPolicy) { p.Labels = map[string]string{"team": "shop"} })
	update(ctx, t, alice, p, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
	if err := alice.Delete(ctx, p); err != nil {
		t.Fatal(err)
	}

	var got []map[string]any
	eventually(t, "the audit log's create, update and delete", func() string {
		got = auditLog.records(t, "WAFPolicy", "default", "audited")
		var ops []string
		for _, r := range got {
			if r["user"] == "alice" {
				ops = append(ops, fmt.Sprint(r["operation"]))
			}
		}
		if strings.Join(ops, ",") != "create,update,delete" {
			return fmt.Sprintf("alice's operations %q, want create, update, delete; the lines: %v", ops, got)
		}
		return ""
	})
	var aliceUpdate map[string]any
	for _, r := range got {
		if r["user"] == "alice" && r["operation"] == "update" {
			aliceUpdate = r
		}
	}
	changes, _ := json.Marshal(aliceUpdate["changes"])
	if want := `[{"new":"Block","old":"Detect","path":"spec.mode"}]`; string(changes) != want {
		t.Errorf("update's changes %s, want %s", changes, want)
	}
	if aliceUpdate["generation"] != float64(2) || aliceUpdate["uid"] == "" || aliceUpdate["operator"] != false {
		t.Errorf("update's record: %v", aliceUpdate)
	}
	groups, _ := json.Marshal(aliceUpdate["groups"])
	if !strings.Contains(string(groups), "system:masters") {
		t.Errorf("update's groups %s", groups)
	}

	eventually(t, "the Events on the policy", func() string {
		var list k8seventsv1.EventList
		if err := c.List(ctx, &list, client.InNamespace("default")); err != nil {
			return err.Error()
		}
		want := map[string]string{
			// spec.timeout is the CRD's default.
			"Created": "Created by alice: spec.mode, spec.targetRefs, spec.timeout",
			"Changed": "Changed by alice: spec.mode",
			"Deleted": "Deleted by alice",
		}
		var seen []string
		for _, e := range list.Items {
			if e.Regarding.Kind != "WAFPolicy" || e.Regarding.Name != "audited" {
				continue
			}
			seen = append(seen, e.Reason+": "+e.Note)
			if note, ok := want[e.Reason]; ok && e.Note == note && e.Type == corev1.EventTypeNormal {
				delete(want, e.Reason)
			}
		}
		if len(want) > 0 {
			return fmt.Sprintf("missing %v; seen %q", want, seen)
		}
		return ""
	})
}
