// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"time"

	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// Action is what the proxy should do with the request.
type Action uint8

const (
	// ActionAllow forwards the request.
	ActionAllow Action = iota
	// ActionDeny rejects the request with Verdict.Status.
	ActionDeny
	// ActionLog forwards the request but records that it would have been
	// blocked (detect mode).
	ActionLog
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionLog:
		return "log"
	default:
		return "unknown"
	}
}

// Reason explains a verdict.
type Reason uint8

const (
	// ReasonNone means no rule interrupted the request.
	ReasonNone Reason = iota
	// ReasonRule means a rule interrupted the request.
	ReasonRule
	// ReasonTimeout means inspection exceeded the deadline.
	ReasonTimeout
	// ReasonError means the evaluator failed.
	ReasonError
	// ReasonCanceled means the caller canceled the request.
	ReasonCanceled
	// ReasonOverload means all evaluation slots were busy, so the request
	// was not inspected.
	ReasonOverload
	// ReasonOversize means the body was longer than the inspection limit
	// and the policy rejects oversized bodies.
	ReasonOversize
	// ReasonSkipped means the route is configured to skip inspection.
	ReasonSkipped
	// ReasonNoPolicy means no policy covers the request's route, so it was
	// not inspected.
	ReasonNoPolicy
	// ReasonSuspended means inspection is suspended (the emergency switch).
	ReasonSuspended
	// ReasonWebSocket means a WebSocket handshake didn't meet the policy's
	// WebSocket rules: an origin not allowed, a required header missing.
	ReasonWebSocket
	// ReasonIPDeny means the client IP is in the policy's deny list.
	ReasonIPDeny
	// ReasonIPAllow means the client IP is in the policy's allow list, so
	// the request was not inspected.
	ReasonIPAllow
	// ReasonGRPC means a gRPC call on a policy that refuses gRPC
	// (DenyGRPC).
	ReasonGRPC
	// ReasonRateLimit means the client was over one of the policy's rate
	// limits (Verdict.RateLimit).
	ReasonRateLimit
	// ReasonGeoDeny means the client's country is denied by the policy's
	// geo blocking (Verdict.Country).
	ReasonGeoDeny
	// ReasonGeoUnavailable means the bundle names a country table the
	// engine doesn't hold, and the policy fails closed.
	ReasonGeoUnavailable
)

func (r Reason) String() string {
	switch r {
	case ReasonNone:
		return "none"
	case ReasonRule:
		return "rule"
	case ReasonTimeout:
		return "timeout"
	case ReasonError:
		return "error"
	case ReasonCanceled:
		return "canceled"
	case ReasonOverload:
		return "overload"
	case ReasonOversize:
		return "oversize"
	case ReasonSkipped:
		return "skipped"
	case ReasonNoPolicy:
		return "no-policy"
	case ReasonSuspended:
		return "suspended"
	case ReasonWebSocket:
		return "websocket"
	case ReasonIPDeny:
		return "ip-deny"
	case ReasonIPAllow:
		return "ip-allow"
	case ReasonGRPC:
		return "grpc"
	case ReasonRateLimit:
		return "rate-limit"
	case ReasonGeoDeny:
		return "geo-deny"
	case ReasonGeoUnavailable:
		return "geo-unavailable"
	default:
		return "unknown"
	}
}

// Verdict is the pipeline's decision for one request.
type Verdict struct {
	Action Action
	// Status is the HTTP status to return when Action is ActionDeny.
	Status int
	Reason Reason
	// InterruptingRuleID is the rule that interrupted the request, if any.
	InterruptingRuleID int
	// RuleIDs lists every rule that matched, including score-only matches.
	RuleIDs []int
	// Matches says where they matched (unredacted), and AnomalyScore is the
	// CRS inbound anomaly score.
	Matches      []rules.Match
	AnomalyScore int
	// Duration is the time spent inspecting.
	Duration time.Duration
	// Policy is the policy that decided, in bundle mode ("namespace/name").
	Policy string
	// DenyResponse is that policy's denial body (spec.denyResponse, or the
	// bundle's default), which adapters answer a deny with; nil: their
	// own.
	DenyResponse *DenyResponse
	// RateLimit is, with ReasonRateLimit, the limit the client was over,
	// and RetryAfter how long until a request would be within it (whole
	// seconds; the answer's Retry-After).
	RateLimit  string
	RetryAfter time.Duration
	// SampledEvent is, with ReasonRateLimit, ReasonGeoDeny or
	// ReasonGeoUnavailable, whether the verdict becomes a security event:
	// limited requests are sampled per client and capped (pkg/ratelimit),
	// geo's per (policy, country), so a flood can't push other events out.
	// SampledCount is the requests the event stands for, this one included.
	SampledEvent bool
	SampledCount uint32
	// GeoMatch is set when the policy's geo blocking denied the request or
	// would have (in Detect, also when a rule's reason won), and Country
	// is the client's country as the metrics label it: the code, or
	// "unknown".
	GeoMatch bool
	Country  string
	// Response reports a verdict on the upstream's response, not on the
	// request: a deny replaces the response, and AnomalyScore is the CRS
	// outbound score.
	Response bool
	// WebSocketMessage reports a verdict on a message a client sent on a
	// WebSocket, not on a request.
	WebSocketMessage bool
	// StreamEvent, with Response, is the index (from 1) of the event or
	// message of a streamed response the verdict is about; without
	// Response, of the message of a gRPC call's request stream (#315). 0
	// for a whole request or response.
	StreamEvent int
}

// Stricter reports whether verdict a is stricter than b: deny over log
// over allow.
func Stricter(a, b Verdict) bool {
	rank := func(a Action) int {
		switch a {
		case ActionDeny:
			return 2
		case ActionLog:
			return 1
		}
		return 0
	}
	return rank(a.Action) > rank(b.Action)
}
