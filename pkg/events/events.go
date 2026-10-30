// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package events turns the engine's security events into SecurityEvents
// (0002 §5.4) and holds them, bounded, until the agent sends them to the
// operator. Redaction happens here, before anything leaves the engine
// (0002 §8.3): no bodies, no query strings, no snippets from credentials,
// and every field the client controls truncated to its limit.
package events

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	enginev1 "github.com/inkwall-dev/inkwall/api/engine/v1"
	eventsv1 "github.com/inkwall-dev/inkwall/api/events/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
)

// Field limits of the contract, in bytes.
const (
	maxHost      = 255
	maxPath      = 1024
	maxUserAgent = 256
	maxRequestID = 128
	maxVariable  = 128
	maxSnippet   = 64
	maxPolicy    = 253 + 1 + 253
	// maxMatches bounds an event's size: CRS rarely matches more rules.
	maxMatches = 32
)

// Redacted are the headers whose values never leave the engine, not even as
// a snippet (0002 §8.3).
var Redacted = []string{"Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization"}

// Source is the engine and pod the events come from.
type Source struct {
	EngineID     string
	PodNamespace string
	PodName      string
	// BundleVersion returns the bundle being enforced (nil: 0).
	BundleVersion func() uint64
}

// New builds the event for a request and its verdict. path is the request's
// path without the query string, as the adapter logs it.
func New(src Source, req *request.Request, path string, v pipeline.Verdict, now time.Time) *eventsv1.SecurityEvent {
	ev := &eventsv1.SecurityEvent{
		EventId:            NewID(now),
		Time:               timestamppb.New(now),
		EngineId:           src.EngineID,
		PodNamespace:       src.PodNamespace,
		PodName:            src.PodName,
		Policy:             truncate(v.Policy, maxPolicy),
		Action:             Action(v.Action),
		Reason:             Reason(v.Reason),
		InterruptingRuleId: int32(v.InterruptingRuleID), // #nosec G115 -- rule IDs fit
		AnomalyScore:       int32(v.AnomalyScore),       // #nosec G115 -- scores are small
		Method:             truncate(req.Method, 16),
		Host:               truncate(req.Host, maxHost),
		Path:               truncate(stripQuery(path), maxPath),
		UserAgent:          truncate(req.Headers.Get("User-Agent"), maxUserAgent),
		RequestId:          truncate(req.ID, maxRequestID),
		Latency:            durationpb.New(v.Duration),
	}
	if src.BundleVersion != nil {
		ev.BundleVersion = src.BundleVersion()
	}
	if req.ClientIP.IsValid() {
		ev.ClientIp = req.ClientIP.String()
	}
	if v.Action == pipeline.ActionDeny {
		ev.Status = int32(v.Status) // #nosec G115 -- an HTTP status
	}
	for _, m := range v.Matches[:min(len(v.Matches), maxMatches)] {
		ev.Matches = append(ev.Matches, &eventsv1.Match{
			RuleId:   int32(m.RuleID), // #nosec G115 -- rule IDs fit
			Variable: truncate(m.Variable, maxVariable),
			Snippet:  snippet(m.Variable, m.Value),
		})
	}
	return ev
}

// snippet is at most maxSnippet bytes of a matched value, none for a
// redacted header or a cookie.
func snippet(variable, value string) string {
	name, key, _ := strings.Cut(variable, ":")
	switch strings.ToUpper(name) {
	case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "RESPONSE_COOKIES":
		return ""
	case "REQUEST_HEADERS", "RESPONSE_HEADERS":
		for _, h := range Redacted {
			if strings.EqualFold(key, h) {
				return ""
			}
		}
	}
	return truncate(value, maxSnippet)
}

func stripQuery(path string) string {
	path, _, _ = strings.Cut(path, "?")
	return path
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence,
// and replaces invalid UTF-8 (protobuf strings must be valid).
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// crockford is the ULID alphabet.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a ULID for now: sortable by time, unique by its 80 random
// bits.
func NewID(now time.Time) string {
	var b [16]byte
	ms := uint64(now.UnixMilli())                      // #nosec G115 -- after 1970
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32)) // #nosec G115 -- 48-bit milliseconds: the high 16 bits
	binary.BigEndian.PutUint32(b[2:6], uint32(ms))     // #nosec G115 -- the low 32 bits
	_, _ = rand.Read(b[6:])
	// 128 bits as 26 base-32 characters, the first holding 3 bits.
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

// Action is a verdict's action in the API's terms.
func Action(a pipeline.Action) enginev1.Action {
	switch a {
	case pipeline.ActionAllow:
		return enginev1.Action_ACTION_ALLOW
	case pipeline.ActionDeny:
		return enginev1.Action_ACTION_DENY
	case pipeline.ActionLog:
		return enginev1.Action_ACTION_LOG
	default:
		return enginev1.Action_ACTION_UNSPECIFIED
	}
}

// Reason is a verdict's reason in the API's terms.
func Reason(r pipeline.Reason) enginev1.Reason {
	switch r {
	case pipeline.ReasonNone:
		return enginev1.Reason_REASON_NONE
	case pipeline.ReasonRule:
		return enginev1.Reason_REASON_RULE
	case pipeline.ReasonTimeout:
		return enginev1.Reason_REASON_TIMEOUT
	case pipeline.ReasonError:
		return enginev1.Reason_REASON_ERROR
	case pipeline.ReasonCanceled:
		return enginev1.Reason_REASON_CANCELED
	case pipeline.ReasonOverload:
		return enginev1.Reason_REASON_OVERLOAD
	case pipeline.ReasonOversize:
		return enginev1.Reason_REASON_OVERSIZE
	case pipeline.ReasonSkipped:
		return enginev1.Reason_REASON_SKIPPED
	case pipeline.ReasonNoPolicy:
		return enginev1.Reason_REASON_NO_POLICY
	case pipeline.ReasonSuspended:
		return enginev1.Reason_REASON_SUSPENDED
	default:
		return enginev1.Reason_REASON_UNSPECIFIED
	}
}
