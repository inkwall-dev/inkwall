// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/pkg/events"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

var testView = newView("6f1c0d2e-uid", "prod-eu-1", nil)

func TestJSONGolden(t *testing.T) {
	evs := items(fullEvent(), oldEvent(), rateLimited(), llmChecked())
	for _, f := range []struct {
		name string
		f    format
	}{{"events.ndjson", formatJSONLines}, {"events-array.json", formatJSONArray}} {
		p := encode(f.f, &testView, evs)
		if !json.Valid(p.body) && f.f == formatJSONArray {
			t.Errorf("%s: not JSON: %s", f.name, p.body)
		}
		golden(t, f.name, p.body)
	}
	// Each line of Lines is one event, whatever its fields hold.
	lines := bytes.Split(bytes.TrimSuffix(encode(formatJSONLines, &testView, evs).body, []byte("\n")), []byte("\n"))
	if len(lines) != 4 {
		t.Fatalf("%d lines for 4 events", len(lines))
	}
	for _, l := range lines {
		if !json.Valid(l) {
			t.Errorf("not JSON: %s", l)
		}
	}
}

// otlpView is a request as plain values, for a stable golden file.
func otlpView(req *collogspb.ExportLogsServiceRequest) any {
	var out []any
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, r := range sl.GetLogRecords() {
				out = append(out, map[string]any{
					"resource":                attrMap(rl.GetResource().GetAttributes()),
					"scope":                   sl.GetScope().GetName() + "/" + sl.GetScope().GetVersion(),
					"time_unix_nano":          r.GetTimeUnixNano(),
					"observed_time_unix_nano": r.GetObservedTimeUnixNano(),
					"severity":                r.GetSeverityNumber().String() + " " + r.GetSeverityText(),
					"event_name":              r.GetEventName(),
					"body":                    r.GetBody().GetStringValue(),
					"attributes":              attrMap(r.GetAttributes()),
				})
			}
		}
	}
	return out
}

func attrMap(kvs []*commonpb.KeyValue) map[string]any {
	m := map[string]any{}
	for _, kv := range kvs {
		m[kv.GetKey()] = anyValue(kv.GetValue())
	}
	return m
}

func anyValue(v *commonpb.AnyValue) any {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return fmt.Sprintf("int %d", x.IntValue)
	case *commonpb.AnyValue_DoubleValue:
		return fmt.Sprintf("double %g", x.DoubleValue)
	case *commonpb.AnyValue_KvlistValue:
		return attrMap(x.KvlistValue.GetValues())
	case *commonpb.AnyValue_ArrayValue:
		var out []any
		for _, e := range x.ArrayValue.GetValues() {
			out = append(out, anyValue(e))
		}
		return out
	}
	return fmt.Sprintf("%T", v.GetValue())
}

func TestOTLPGolden(t *testing.T) {
	p := encode(formatOTLPGRPC, &testView, items(fullEvent(), oldEvent(), rateLimited(), llmChecked()))
	// Grouped per engine pod: traefik-7d9c (with the third event, whose
	// pod the stream didn't name, apart), traefik-old.
	if n := len(p.otlp.GetResourceLogs()); n != 3 {
		t.Errorf("%d resources, want one per pod: 3", n)
	}
	raw, err := json.MarshalIndent(otlpView(p.otlp), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "events-otlp.json", append(raw, '\n'))
}

// jsonFields lists the paths of every field of a JSON event.
func jsonFields(prefix string, v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			jsonFields(prefix+k+".", e, out)
		}
	case []any:
		for _, e := range x {
			jsonFields(prefix+"[].", e, out)
		}
	default:
		out[strings.TrimSuffix(prefix, ".")] = true
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// The v1 field list, JSON and OTLP: a rename fails here rather than in a
// user's saved searches (design 0010 §5.3).
func TestFieldListGolden(t *testing.T) {
	all := items(fullEvent(), rateLimited(), llmChecked())
	fields := map[string]bool{}
	for _, it := range all {
		var v any
		if err := json.Unmarshal(appendJSON(nil, it, &testView), &v); err != nil {
			t.Fatal(err)
		}
		jsonFields("", v, fields)
	}
	golden(t, "fields-json.txt", []byte(strings.Join(sortedKeys(fields), "\n")+"\n"))

	attrs := map[string]bool{}
	p := encode(formatOTLPGRPC, &testView, all)
	for _, rl := range p.otlp.GetResourceLogs() {
		for _, kv := range rl.GetResource().GetAttributes() {
			attrs["resource "+kv.GetKey()] = true
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, r := range sl.GetLogRecords() {
				for _, kv := range r.GetAttributes() {
					attrs["record "+kv.GetKey()] = true
					if kv.GetKey() == "inkwall.matches" {
						for _, m := range kv.GetValue().GetArrayValue().GetValues() {
							for _, e := range m.GetKvlistValue().GetValues() {
								attrs["match "+e.GetKey()] = true
							}
						}
					}
				}
			}
		}
	}
	golden(t, "fields-otlp.txt", []byte(strings.Join(sortedKeys(attrs), "\n")+"\n"))
}

// The presence rules of design 0010 §5.
func TestPresence(t *testing.T) {
	var old map[string]any
	if err := json.Unmarshal(appendJSON(nil, items(oldEvent())[0], &view{clusterID: "uid"}), &old); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"phase", "protocol", "latency_seconds", "rule_id", "anomaly_score", "matches", "rate_limit", "sampled_count"} {
		if _, ok := old[absent]; ok {
			t.Errorf("%s written for an event without it", absent)
		}
	}
	if old["time"] != old["observed_time"] {
		t.Errorf("time %v, want observed_time %v for an event without one", old["time"], old["observed_time"])
	}
	if c := old["cluster"].(map[string]any); c["id"] != "uid" || c["name"] != nil {
		t.Errorf("cluster = %v", c)
	}
	// Always written, even when zero.
	if old["status"] != float64(0) || old["action"] != "log" || old["reason"] != "rule" || old["event_id"] == nil {
		t.Errorf("event = %v", old)
	}
	if p := old["policy"].(map[string]any); p["bundle_version"] != float64(7) || p["name"] != nil || p["namespace"] != nil {
		t.Errorf("policy = %v, want only the bundle version", p)
	}
	// A policy the bundle doesn't have counts as none.
	var rl map[string]any
	if err := json.Unmarshal(appendJSON(nil, items(rateLimited())[0], &testView), &rl); err != nil {
		t.Fatal(err)
	}
	if p := rl["policy"].(map[string]any); p["name"] != nil {
		t.Errorf("policy = %v for a policy not in the bundle", p)
	}
	if rl["latency_seconds"] != float64(0) {
		t.Errorf("latency_seconds = %v, want 0 for a zero latency that is set", rl["latency_seconds"])
	}
	if e := rl["engine"].(map[string]any); e["namespace"] != nil || e["pod"] != nil || e["id"] != "01JDENGINE" {
		t.Errorf("engine = %v", e)
	}
}

func TestOmit(t *testing.T) {
	v := newView("uid", "", []wafv1alpha1.ExportOmit{wafv1alpha1.OmitSnippets, wafv1alpha1.OmitClientIP, wafv1alpha1.OmitUserAgent, wafv1alpha1.OmitRequestID})
	it := items(fullEvent())[0]
	j := string(appendJSON(nil, it, &v))
	for _, gone := range []string{"203.0.113.7", "curl/8.10.1", "a1b2c3", "1' OR", "snippet", "client_ip", "user_agent", `"id":"a1b2c3"`} {
		if strings.Contains(j, gone) {
			t.Errorf("JSON carries %q with it omitted: %s", gone, j)
		}
	}
	if !strings.Contains(j, `"variable":"ARGS:id"`) {
		t.Errorf("JSON lost the match's variable: %s", j)
	}
	rec := logRecord(it, &v)
	for _, kv := range rec.GetAttributes() {
		switch kv.GetKey() {
		case "client.address", "user_agent.original", "inkwall.request.id":
			t.Errorf("OTLP carries %s with it omitted", kv.GetKey())
		case "inkwall.matches":
			for _, m := range kv.GetValue().GetArrayValue().GetValues() {
				for _, e := range m.GetKvlistValue().GetValues() {
					if e.GetKey() == "snippet" {
						t.Error("OTLP carries a snippet with Snippets omitted")
					}
				}
			}
		}
	}
}

// The names are the engine's own (pkg/pipeline): an exported reason reads
// as the engine's log does.
func TestNamesMatchTheEngine(t *testing.T) {
	for r := pipeline.Reason(0); r < 64; r++ {
		api := events.Reason(r)
		if api == enginev1.Reason_REASON_UNSPECIFIED {
			continue
		}
		if got, want := reasonName(api), r.String(); got != want {
			t.Errorf("reason %v: %q, the engine logs %q", api, got, want)
		}
	}
	for _, a := range []pipeline.Action{pipeline.ActionAllow, pipeline.ActionDeny, pipeline.ActionLog} {
		if got := actionName(events.Action(a)); got != a.String() {
			t.Errorf("action %v: %q, the engine logs %q", a, got, a.String())
		}
	}
	// Every value the API has, named.
	for v := range enginev1.Reason_name {
		if r := enginev1.Reason(v); r != enginev1.Reason_REASON_UNSPECIFIED && reasonName(r) == "unknown" {
			t.Errorf("reason %v has no name", r)
		}
	}
	for v := range eventsv1.Phase_name {
		if p := eventsv1.Phase(v); p != eventsv1.Phase_PHASE_UNSPECIFIED && slices.Contains([]string{"", "unknown"}, phaseName(p)) {
			t.Errorf("phase %v has no name", p)
		}
	}
	for v := range eventsv1.Protocol_name {
		if p := eventsv1.Protocol(v); p != eventsv1.Protocol_PROTOCOL_UNSPECIFIED && slices.Contains([]string{"", "unknown"}, protocolName(p)) {
			t.Errorf("protocol %v has no name", p)
		}
	}
}

func TestBody(t *testing.T) {
	if got := body(items(fullEvent())[0]); got != "deny 403 rule 949110 GET shop.example.com/search" {
		t.Errorf("body = %q", got)
	}
}
