// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"strconv"
	"strings"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
)

// OTLP (design 0010 §5.2): one LogRecord per event, grouped in a
// ResourceLogs per engine pod, with the semantic conventions where one
// exists and the rest under inkwall., flat.
const (
	otlpScope     = "inkwall.dev/events"
	otlpEventName = "inkwall.security_event"
	otlpService   = "inkwall-engine"
)

func str(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}}
}

func num(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}}
}

// logRecord is the event's LogRecord.
func logRecord(it item, v *view) *logspb.LogRecord {
	ev := it.ev
	attrs := make([]*commonpb.KeyValue, 0, 20)
	add := func(k, s string) {
		if s != "" {
			attrs = append(attrs, str(k, s))
		}
	}
	add("http.request.method", ev.GetMethod())
	add("server.address", ev.GetHost())
	add("url.path", ev.GetPath())
	if !v.omitClientIP {
		add("client.address", ev.GetClientIp())
		// The client's country, left out with its address.
		add("client.geo.country.iso_code", ev.GetCountry())
	}
	if !v.omitUserAgent {
		add("user_agent.original", ev.GetUserAgent())
	}
	attrs = append(attrs, num("http.response.status_code", int64(ev.GetStatus())), str("inkwall.event_id", ev.GetEventId()))
	add("inkwall.engine.id", ev.GetEngineId())
	if it.policy != "" {
		ns, name := splitPolicy(it.policy)
		add("inkwall.policy.namespace", ns)
		add("inkwall.policy.name", name)
	}
	attrs = append(attrs,
		num("inkwall.policy.bundle_version", int64(min(ev.GetBundleVersion(), 1<<63-1))), // #nosec G115 -- capped
		str("inkwall.action", actionName(ev.GetAction())), str("inkwall.reason", reasonName(ev.GetReason())))
	if r := ev.GetInterruptingRuleId(); r != 0 {
		attrs = append(attrs, num("inkwall.rule_id", int64(r)))
	}
	if s := ev.GetAnomalyScore(); s != 0 {
		attrs = append(attrs, num("inkwall.anomaly_score", int64(s)))
	}
	if ms := ev.GetMatches(); len(ms) > 0 {
		vals := make([]*commonpb.AnyValue, len(ms))
		for i, m := range ms {
			kv := []*commonpb.KeyValue{num("rule_id", int64(m.GetRuleId()))}
			if s := m.GetVariable(); s != "" {
				kv = append(kv, str("variable", s))
			}
			if s := m.GetSnippet(); s != "" && !v.omitSnippets {
				kv = append(kv, str("snippet", s))
			}
			vals[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: kv}}}
		}
		attrs = append(attrs, &commonpb.KeyValue{Key: "inkwall.matches", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: vals}}}})
	}
	if !v.omitRequestID {
		add("inkwall.request.id", ev.GetRequestId())
	}
	add("inkwall.phase", phaseName(ev.GetPhase()))
	add("inkwall.protocol", protocolName(ev.GetProtocol()))
	add("inkwall.rate_limit", ev.GetRateLimit())
	if n := ev.GetSampledCount(); n > 1 {
		attrs = append(attrs, num("inkwall.sampled_count", int64(n)))
	}
	if l := ev.GetLlm(); l != nil {
		add("inkwall.llm.check", l.GetCheck())
		add("inkwall.llm.format", l.GetFormat())
		add("inkwall.llm.model", l.GetModel())
		add("inkwall.llm.role", l.GetRole())
		attrs = append(attrs, num("inkwall.llm.message_index", int64(l.GetMessageIndex())), num("inkwall.llm.offset", l.GetOffset()))
		if t := l.GetEstimatedTokens(); t > 0 {
			attrs = append(attrs, num("inkwall.llm.estimated_tokens", t))
		}
	}
	if l := ev.GetLatency(); l != nil {
		attrs = append(attrs, &commonpb.KeyValue{Key: "inkwall.latency_seconds", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: l.AsDuration().Seconds()}}})
	}
	sev, sevText := logspb.SeverityNumber_SEVERITY_NUMBER_INFO, "INFO"
	if ev.GetAction() == enginev1.Action_ACTION_DENY {
		sev, sevText = logspb.SeverityNumber_SEVERITY_NUMBER_WARN, "WARN"
	}
	return &logspb.LogRecord{
		TimeUnixNano:         unixNano(it.eventTime().UnixNano()),
		ObservedTimeUnixNano: unixNano(it.observed.UnixNano()),
		SeverityNumber:       sev,
		SeverityText:         sevText,
		EventName:            otlpEventName,
		Body:                 &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: body(it)}},
		Attributes:           attrs,
	}
}

func unixNano(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// body is a short summary: deny 403 rule 949110 GET shop.example.com/search.
func body(it item) string {
	ev := it.ev
	var b strings.Builder
	b.WriteString(actionName(ev.GetAction()))
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(int(ev.GetStatus())))
	b.WriteByte(' ')
	b.WriteString(reasonName(ev.GetReason()))
	if r := ev.GetInterruptingRuleId(); r != 0 {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(int(r)))
	}
	if m := ev.GetMethod(); m != "" {
		b.WriteByte(' ')
		b.WriteString(m)
	}
	if h, p := ev.GetHost(), ev.GetPath(); h != "" || p != "" {
		b.WriteByte(' ')
		b.WriteString(h)
		b.WriteString(p)
	}
	return b.String()
}

// resourceKey groups events by engine pod.
type resourceKey struct{ namespace, pod string }

func resource(k resourceKey, v *view) *resourcepb.Resource {
	attrs := []*commonpb.KeyValue{str("service.name", otlpService)}
	if v.clusterID != "" {
		attrs = append(attrs, str("k8s.cluster.uid", v.clusterID))
	}
	if v.clusterName != "" {
		attrs = append(attrs, str("k8s.cluster.name", v.clusterName))
	}
	if k.namespace != "" {
		attrs = append(attrs, str("k8s.namespace.name", k.namespace))
	}
	if k.pod != "" {
		attrs = append(attrs, str("k8s.pod.name", k.pod))
	}
	return &resourcepb.Resource{Attributes: attrs}
}

// otlpEncoder builds one ExportLogsServiceRequest, measuring it as it
// grows, so a request closes before it would pass the size limit.
type otlpEncoder struct {
	v      *view
	limit  int
	groups map[resourceKey]*logspb.ScopeLogs
	req    *collogspb.ExportLogsServiceRequest
	size   int
	n      int
}

func newOTLPEncoder(v *view, limit int) *otlpEncoder {
	return &otlpEncoder{v: v, limit: limit, groups: map[resourceKey]*logspb.ScopeLogs{}, req: &collogspb.ExportLogsServiceRequest{}}
}

// nesting bounds what a record adds to its enclosing messages' length
// prefixes: a varint grows by at most 5 bytes for each of ResourceLogs and
// ScopeLogs, and the record's own tag and length are counted exactly.
const nesting = 2 * 5

// add appends an event, unless the request has one already and would pass
// the limit with it.
func (e *otlpEncoder) add(it item) bool {
	rec := logRecord(it, e.v)
	key := resourceKey{it.ev.GetPodNamespace(), it.ev.GetPodName()}
	grow := protowire.SizeTag(1) + protowire.SizeBytes(proto.Size(rec)) + nesting
	sl, ok := e.groups[key]
	var rl *logspb.ResourceLogs
	if !ok {
		sl = &logspb.ScopeLogs{Scope: &commonpb.InstrumentationScope{Name: otlpScope, Version: SchemaVersion}}
		rl = &logspb.ResourceLogs{Resource: resource(key, e.v), ScopeLogs: []*logspb.ScopeLogs{sl}}
		grow += protowire.SizeTag(1) + protowire.SizeBytes(proto.Size(rl)) + nesting
	}
	if e.n > 0 && e.size+grow > e.limit {
		return false
	}
	if !ok {
		e.groups[key] = sl
		e.req.ResourceLogs = append(e.req.ResourceLogs, rl)
	}
	sl.LogRecords = append(sl.LogRecords, rec)
	e.size += grow
	e.n++
	return true
}
