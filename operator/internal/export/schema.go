// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// The exported event (design 0010 §5): the SecurityEvent, with what the
// operator adds (the cluster, the time it received the event). Field names
// are stable within a schema version; the golden tests pin them.
const (
	// SchemaVersion is the schema's version: the scope version in OTLP.
	SchemaVersion = "1"
	// SchemaName is the "schema" of every JSON event.
	SchemaName = "inkwall.dev/security-event/v" + SchemaVersion
)

// item is one event the sender took from the buffer.
type item struct {
	ev *eventsv1.SecurityEvent
	// observed is when the replica received it.
	observed time.Time
	// policy is the event's policy when the bundle the replica serves has
	// it, "" otherwise (an engine can't name another team's policy).
	policy string
}

// view is what a sink's encoder adds and leaves out.
type view struct {
	clusterID, clusterName string
	omitSnippets           bool
	omitClientIP           bool
	omitUserAgent          bool
	omitRequestID          bool
}

func newView(clusterID, clusterName string, omit []wafv1alpha1.ExportOmit) view {
	v := view{clusterID: clusterID, clusterName: clusterName}
	for _, o := range omit {
		switch o {
		case wafv1alpha1.OmitSnippets:
			v.omitSnippets = true
		case wafv1alpha1.OmitClientIP:
			v.omitClientIP = true
		case wafv1alpha1.OmitUserAgent:
			v.omitUserAgent = true
		case wafv1alpha1.OmitRequestID:
			v.omitRequestID = true
		}
	}
	return v
}

// eventTime is the event's time, or the replica's when it has none.
func (it item) eventTime() time.Time {
	if t := it.ev.GetTime(); t != nil {
		return t.AsTime()
	}
	return it.observed
}

// splitPolicy splits "namespace/name".
func splitPolicy(p string) (ns, name string) {
	ns, name, ok := strings.Cut(p, "/")
	if !ok {
		return "", p
	}
	return ns, name
}

// The names the engine logs (pkg/pipeline/verdict.go), lower-case.
func actionName(a enginev1.Action) string {
	switch a {
	case enginev1.Action_ACTION_ALLOW:
		return "allow"
	case enginev1.Action_ACTION_DENY:
		return "deny"
	case enginev1.Action_ACTION_LOG:
		return "log"
	}
	return "unknown"
}

var reasonNames = map[enginev1.Reason]string{
	enginev1.Reason_REASON_NONE:            "none",
	enginev1.Reason_REASON_RULE:            "rule",
	enginev1.Reason_REASON_TIMEOUT:         "timeout",
	enginev1.Reason_REASON_ERROR:           "error",
	enginev1.Reason_REASON_CANCELED:        "canceled",
	enginev1.Reason_REASON_OVERLOAD:        "overload",
	enginev1.Reason_REASON_OVERSIZE:        "oversize",
	enginev1.Reason_REASON_SKIPPED:         "skipped",
	enginev1.Reason_REASON_NO_POLICY:       "no-policy",
	enginev1.Reason_REASON_SUSPENDED:       "suspended",
	enginev1.Reason_REASON_WEBSOCKET:       "websocket",
	enginev1.Reason_REASON_IP_DENY:         "ip-deny",
	enginev1.Reason_REASON_IP_ALLOW:        "ip-allow",
	enginev1.Reason_REASON_GRPC:            "grpc",
	enginev1.Reason_REASON_RATE_LIMIT:      "rate-limit",
	enginev1.Reason_REASON_GEO_DENY:        "geo-deny",
	enginev1.Reason_REASON_GEO_UNAVAILABLE: "geo-unavailable",
	enginev1.Reason_REASON_LLM:             "llm",
}

func reasonName(r enginev1.Reason) string {
	if n, ok := reasonNames[r]; ok {
		return n
	}
	return "unknown"
}

// phaseName is "" for PHASE_UNSPECIFIED (engines before 0.4.0).
func phaseName(p eventsv1.Phase) string {
	switch p {
	case eventsv1.Phase_PHASE_UNSPECIFIED:
		return ""
	case eventsv1.Phase_PHASE_REQUEST:
		return "request"
	case eventsv1.Phase_PHASE_RESPONSE:
		return "response"
	case eventsv1.Phase_PHASE_WEBSOCKET_MESSAGE:
		return "websocket-message"
	}
	return "unknown"
}

// protocolName is "" for PROTOCOL_UNSPECIFIED (engines before 0.5.0).
func protocolName(p eventsv1.Protocol) string {
	switch p {
	case eventsv1.Protocol_PROTOCOL_UNSPECIFIED:
		return ""
	case eventsv1.Protocol_PROTOCOL_HTTP:
		return "http"
	case eventsv1.Protocol_PROTOCOL_GRPC:
		return "grpc"
	case eventsv1.Protocol_PROTOCOL_WEBSOCKET:
		return "websocket"
	}
	return "unknown"
}

// jsonTime is RFC 3339 in UTC with microseconds.
const jsonTime = "2006-01-02T15:04:05.000000Z07:00"

// appendJSON appends the event, one line of JSON with no newline, in the
// schema of design 0010 §5.1. Every string goes through appendString, so a
// newline in a path or user agent can't start a fake event.
func appendJSON(b []byte, it item, v *view) []byte {
	ev := it.ev
	b = append(b, `{"schema":"`+SchemaName+`","event_id":`...)
	b = appendString(b, ev.GetEventId())
	b = append(b, `,"time":"`...)
	b = it.eventTime().UTC().AppendFormat(b, jsonTime)
	b = append(b, `","observed_time":"`...)
	b = it.observed.UTC().AppendFormat(b, jsonTime)
	b = append(b, `","cluster":{"id":`...)
	b = appendString(b, v.clusterID)
	if v.clusterName != "" {
		b = append(b, `,"name":`...)
		b = appendString(b, v.clusterName)
	}
	b = append(b, '}')
	b = appendObject(b, "engine", []field{
		{"id", ev.GetEngineId()}, {"namespace", ev.GetPodNamespace()}, {"pod", ev.GetPodName()},
	})
	b = append(b, `,"policy":{`...)
	if it.policy != "" {
		ns, name := splitPolicy(it.policy)
		b = append(b, `"namespace":`...)
		b = appendString(b, ns)
		b = append(b, `,"name":`...)
		b = appendString(b, name)
		b = append(b, ',')
	}
	b = append(b, `"bundle_version":`...)
	b = strconv.AppendUint(b, ev.GetBundleVersion(), 10)
	b = append(b, `},"action":"`...)
	b = append(b, actionName(ev.GetAction())...)
	b = append(b, `","reason":"`...)
	b = append(b, reasonName(ev.GetReason())...)
	b = append(b, `","status":`...)
	b = strconv.AppendInt(b, int64(ev.GetStatus()), 10)
	if r := ev.GetInterruptingRuleId(); r != 0 {
		b = append(b, `,"rule_id":`...)
		b = strconv.AppendInt(b, int64(r), 10)
	}
	if s := ev.GetAnomalyScore(); s != 0 {
		b = append(b, `,"anomaly_score":`...)
		b = strconv.AppendInt(b, int64(s), 10)
	}
	if ms := ev.GetMatches(); len(ms) > 0 {
		b = append(b, `,"matches":[`...)
		for i, m := range ms {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, `{"rule_id":`...)
			b = strconv.AppendInt(b, int64(m.GetRuleId()), 10)
			if s := m.GetVariable(); s != "" {
				b = append(b, `,"variable":`...)
				b = appendString(b, s)
			}
			if s := m.GetSnippet(); s != "" && !v.omitSnippets {
				b = append(b, `,"snippet":`...)
				b = appendString(b, s)
			}
			b = append(b, '}')
		}
		b = append(b, ']')
	}
	if p := phaseName(ev.GetPhase()); p != "" {
		b = append(b, `,"phase":"`...)
		b = append(b, p...)
		b = append(b, '"')
	}
	if p := protocolName(ev.GetProtocol()); p != "" {
		b = append(b, `,"protocol":"`...)
		b = append(b, p...)
		b = append(b, '"')
	}
	if r := ev.GetRateLimit(); r != "" {
		b = append(b, `,"rate_limit":`...)
		b = appendString(b, r)
	}
	if n := ev.GetSampledCount(); n > 1 {
		b = append(b, `,"sampled_count":`...)
		b = strconv.AppendUint(b, uint64(n), 10)
	}
	if l := ev.GetLlm(); l != nil {
		// The check and where it failed: an event has no prompt text.
		b = append(b, `,"llm":{"check":`...)
		b = appendString(b, l.GetCheck())
		b = append(b, `,"format":`...)
		b = appendString(b, l.GetFormat())
		if m := l.GetModel(); m != "" {
			b = append(b, `,"model":`...)
			b = appendString(b, m)
		}
		if r := l.GetRole(); r != "" {
			b = append(b, `,"role":`...)
			b = appendString(b, r)
		}
		b = append(b, `,"message_index":`...)
		b = strconv.AppendInt(b, int64(l.GetMessageIndex()), 10)
		b = append(b, `,"offset":`...)
		b = strconv.AppendInt(b, l.GetOffset(), 10)
		if t := l.GetEstimatedTokens(); t > 0 {
			b = append(b, `,"estimated_tokens":`...)
			b = strconv.AppendInt(b, t, 10)
		}
		b = append(b, '}')
	}
	b = appendObject(b, "request", []field{
		{"id", v.keep(!v.omitRequestID, ev.GetRequestId())},
		{"method", ev.GetMethod()},
		{"host", ev.GetHost()},
		{"path", ev.GetPath()},
		{"client_ip", v.keep(!v.omitClientIP, ev.GetClientIp())},
		// The client's country (geo blocking): personal data about the
		// client, left out with its address.
		{"country", v.keep(!v.omitClientIP, ev.GetCountry())},
		{"user_agent", v.keep(!v.omitUserAgent, ev.GetUserAgent())},
	})
	if l := ev.GetLatency(); l != nil {
		b = append(b, `,"latency_seconds":`...)
		b = strconv.AppendFloat(b, l.AsDuration().Seconds(), 'f', -1, 64)
	}
	return append(b, '}')
}

func (*view) keep(ok bool, s string) string {
	if !ok {
		return ""
	}
	return s
}

type field struct{ name, value string }

// appendObject appends ,"name":{...} with the fields that aren't empty, or
// nothing when all are.
func appendObject(b []byte, name string, fields []field) []byte {
	first := true
	for _, f := range fields {
		if f.value == "" {
			continue
		}
		if first {
			b = append(b, `,"`...)
			b = append(b, name...)
			b = append(b, `":{`...)
			first = false
		} else {
			b = append(b, ',')
		}
		b = append(b, '"')
		b = append(b, f.name...)
		b = append(b, `":`...)
		b = appendString(b, f.value)
	}
	if !first {
		b = append(b, '}')
	}
	return b
}

const hexDigits = "0123456789abcdef"

// appendString appends s as a JSON string. Control characters, quotes and
// backslashes are escaped, and so are <, >, & and U+2028/U+2029, so the
// text stays inert in HTML and JavaScript; invalid UTF-8 becomes U+FFFD.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i += size
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}
