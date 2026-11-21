// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/proto"

	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
)

func fuzzSeeds(f *testing.F) {
	for _, ev := range []*eventsv1.SecurityEvent{fullEvent(), oldEvent(), rateLimited(), {}} {
		raw, err := proto.Marshal(ev)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, "shop/web")
	}
	f.Add([]byte{}, "")
}

// Any event (from fuzzed protobuf) encodes to valid JSON, one line in
// Lines (no raw newline from any field), and decodes back to its fields.
func FuzzEncodeJSON(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte, policy string) {
		var ev eventsv1.SecurityEvent
		if proto.Unmarshal(raw, &ev) != nil {
			return
		}
		it := item{ev: &ev, observed: time.Unix(1_800_000_000, 0)}
		if ev.GetPolicy() == policy {
			it.policy = policy
		}
		line := encode(formatJSONLines, &view{clusterID: "uid", clusterName: "c"}, []item{it}).body
		if bytes.Count(line, []byte("\n")) != 1 || line[len(line)-1] != '\n' {
			t.Fatalf("not one line: %q", line)
		}
		var got struct {
			EventID string `json:"event_id"`
			Engine  struct {
				ID, Namespace, Pod string
			} `json:"engine"`
			Policy struct {
				Namespace, Name string
			} `json:"policy"`
			RateLimit string `json:"rate_limit"`
			Status    int32  `json:"status"`
			Matches   []struct {
				RuleID   int32  `json:"rule_id"`
				Variable string `json:"variable"`
				Snippet  string `json:"snippet"`
			} `json:"matches"`
			Request struct {
				ID        string `json:"id"`
				Method    string `json:"method"`
				Host      string `json:"host"`
				Path      string `json:"path"`
				ClientIP  string `json:"client_ip"`
				UserAgent string `json:"user_agent"`
			} `json:"request"`
		}
		if err := json.Unmarshal(line, &got); err != nil {
			t.Fatalf("not JSON: %v: %s", err, line)
		}
		arr := encode(formatJSONArray, &view{}, []item{it, it}).body
		if !json.Valid(arr) {
			t.Fatalf("array not JSON: %s", arr)
		}
		ns, name := splitPolicy(it.policy)
		r := got.Request
		if got.EventID != ev.GetEventId() || got.Engine.ID != ev.GetEngineId() || got.Engine.Namespace != ev.GetPodNamespace() ||
			got.Engine.Pod != ev.GetPodName() || got.Policy.Namespace != ns || got.Policy.Name != name || got.Status != ev.GetStatus() ||
			got.RateLimit != ev.GetRateLimit() || r.ID != ev.GetRequestId() || r.Method != ev.GetMethod() || r.Host != ev.GetHost() ||
			r.Path != ev.GetPath() || r.ClientIP != ev.GetClientIp() || r.UserAgent != ev.GetUserAgent() || len(got.Matches) != len(ev.GetMatches()) {
			t.Fatalf("decoded %+v from %s, want the fields of %v", got, line, &ev)
		}
		for i, m := range ev.GetMatches() {
			if g := got.Matches[i]; g.RuleID != m.GetRuleId() || g.Variable != m.GetVariable() || g.Snippet != m.GetSnippet() {
				t.Fatalf("match %d = %+v, want %v", i, g, m)
			}
		}
	})
}

// Any event encodes, marshals and unmarshals to the same attributes.
func FuzzEncodeOTLP(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte, policy string) {
		var ev eventsv1.SecurityEvent
		if proto.Unmarshal(raw, &ev) != nil {
			return
		}
		it := item{ev: &ev, observed: time.Unix(1_800_000_000, 0)}
		if ev.GetPolicy() == policy {
			it.policy = policy
		}
		p := encode(formatOTLPHTTP, &view{clusterID: "uid"}, []item{it})
		var back collogspb.ExportLogsServiceRequest
		if err := proto.Unmarshal(p.body, &back); err != nil {
			t.Fatalf("doesn't unmarshal: %v", err)
		}
		if !proto.Equal(&back, p.otlp) {
			t.Fatalf("round trip differs:\n%v\n%v", &back, p.otlp)
		}
		if n := len(back.GetResourceLogs()[0].GetScopeLogs()[0].GetLogRecords()); n != 1 {
			t.Fatalf("%d records", n)
		}
		if p.size > len(p.body) && len(p.body) > 0 {
			t.Fatalf("size %d over the body's %d", p.size, len(p.body))
		}
	})
}
