// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8seventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

// errors are the audit log's ERROR lines (Events not recorded).
func (b *syncBuffer) errors() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, line := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(line, `"level":"ERROR"`) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// records are the audit log's lines about the object of uid: a run of
// the test again in the process (go test -count) makes another object of
// the same name.
func (b *syncBuffer) records(t *testing.T, uid types.UID) []map[string]any {
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
		if m["msg"] == webhook.AuditMessage && m["uid"] == string(uid) {
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
	cfg, err = env.User("bob", "system:masters")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := client.New(cfg, client.Options{Scheme: c.Scheme()})
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
	// A dry run is never recorded, nor a change of labels only. The dry run
	// changes a field no other change does: its record would be a change
	// of its own, not one the check below takes for a retry.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dry := p.DeepCopy()
		if err := alice.Get(ctx, client.ObjectKeyFromObject(dry), dry); err != nil {
			return err
		}
		dry.Spec.Timeout = &metav1.Duration{Duration: time.Second}
		return alice.Update(ctx, dry, client.DryRunAll)
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	update(ctx, t, alice, p, func(p *wafv1alpha1.WAFPolicy) { p.Labels = map[string]string{"team": "shop"} })
	update(ctx, t, alice, p, func(p *wafv1alpha1.WAFPolicy) { p.Spec.Mode = wafv1alpha1.PolicyBlock })
	// Bob's change right after alice's is an Event of its own, with his
	// name: an event recorder would count it in alice's (the review of
	// #793).
	update(ctx, t, bob, p, func(p *wafv1alpha1.WAFPolicy) { p.Spec.FailureMode = wafv1alpha1.FailOpen })
	if err := alice.Delete(ctx, p); err != nil {
		t.Fatal(err)
	}

	// The changes, as their Events note them. An update the API server
	// admits and then refuses as a conflict is recorded although it wasn't
	// saved: it checks the request's resourceVersion against its watch
	// cache, which may lag behind the operator's status writes, and finds
	// the conflict only when it writes. The update helper then tries again,
	// which is recorded too, with the same generation: at most one of them
	// was saved (docs/audit-log.md). The checks allow that, and only that.
	want := []string{
		// spec.timeout is the CRD's default.
		"Created by alice: spec.mode, spec.targetRefs, spec.timeout",
		"Changed by alice: spec.mode",
		"Changed by bob: spec.failureMode",
		"Deleted by alice",
	}
	var records map[string][]map[string]any
	eventually(t, "the audit log's records", func() string {
		records = map[string][]map[string]any{}
		for _, r := range auditLog.records(t, p.UID) {
			records[auditNote(r)] = append(records[auditNote(r)], r)
		}
		for _, note := range want {
			if len(records[note]) == 0 {
				return fmt.Sprintf("no record of %q; the records: %q", note, slices.Collect(maps.Keys(records)))
			}
		}
		if len(records) != len(want) {
			return fmt.Sprintf("records %q, want %q", slices.Collect(maps.Keys(records)), want)
		}
		for note, rs := range records {
			for _, r := range rs[1:] {
				if r["operation"] != "update" || r["generation"] != rs[0]["generation"] {
					return fmt.Sprintf("%q recorded %d times, not as the tries of one update: %v", note, len(rs), rs)
				}
			}
		}
		return ""
	})
	aliceUpdate := records["Changed by alice: spec.mode"][0]
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

	// One Event per record: never merged into another's series, never
	// one more.
	reasons := map[string]string{"create": "Created", "update": "Changed", "delete": "Deleted"}
	eventually(t, "the Events on the policy", func() string {
		var list k8seventsv1.EventList
		if err := c.List(ctx, &list, client.InNamespace("default")); err != nil {
			return err.Error()
		}
		events := map[string]int{}
		for _, e := range list.Items {
			if e.Regarding.UID != p.UID || e.Action == "StatusChanged" {
				continue
			}
			if e.Type != corev1.EventTypeNormal || e.Series != nil || e.DeprecatedCount > 1 {
				return fmt.Sprintf("Event %s: type %s, series %v, count %d", e.Name, e.Type, e.Series, e.DeprecatedCount)
			}
			events[e.Reason+": "+e.Note]++
		}
		wantEvents := map[string]int{}
		for note, rs := range records {
			wantEvents[reasons[fmt.Sprint(rs[0]["operation"])]+": "+note] = len(rs)
		}
		if !maps.Equal(events, wantEvents) {
			return fmt.Sprintf("Events %v, want %v (one per record); the audit logger's errors: %s", events, wantEvents, auditLog.errors())
		}
		return ""
	})
}

// auditNote is the note of the Event for the audit record r (none of the
// test's changes has more paths than an Event names).
func auditNote(r map[string]any) string {
	op := fmt.Sprint(r["operation"])
	note := map[string]string{"create": "Created", "update": "Changed", "delete": "Deleted"}[op] + " by " + fmt.Sprint(r["user"])
	if op == "delete" {
		return note
	}
	var paths []string
	changes, _ := r["changes"].([]any)
	for _, c := range changes {
		if c, ok := c.(map[string]any); ok {
			paths = append(paths, fmt.Sprint(c["path"]))
		}
	}
	return note + ": " + strings.Join(paths, ", ")
}
