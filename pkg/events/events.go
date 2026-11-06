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
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
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

// sensitiveParts are what an argument or header name that looks like a
// credential contains, once lower-cased and without "-", "_" and ".":
// a password, a secret, a token, an API or private key, authentication, a
// session, a JWT, a bearer token or a payment card (0002 §8.3). Plain
// substring search keeps the check linear and cheap on long names.
var sensitiveParts = []string{
	"pass", "pwd", "secret", "token", "apikey", "auth", "session", "sessid", "jwt", "bearer",
	"credential", "privatekey", "card", "ccnum", "cvv", "cvc",
}

// Sensitive reports whether a name looks like a credential's, so that its
// value never leaves the engine, not even as a snippet: it contains one of
// sensitiveParts, or "ssn" between non-letters, without regard to case. It
// errs on the side of redacting ("author" is sensitive).
func Sensitive(name string) bool {
	lower := strings.Map(foldASCII, name)
	for i := 0; ; {
		j := strings.Index(lower[i:], "ssn")
		if j < 0 {
			break
		}
		j += i
		if (j == 0 || !isLetter(lower[j-1])) && (j+3 == len(lower) || !isLetter(lower[j+3])) {
			return true
		}
		i = j + 1
	}
	compact := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' {
			return -1
		}
		return r
	}, lower)
	for _, p := range sensitiveParts {
		if strings.Contains(compact, p) {
			return true
		}
	}
	return false
}

// foldASCII lower-cases r, and maps a rune that folds to an ASCII letter
// (the Kelvin sign, the long s) to that letter.
func foldASCII(r rune) rune {
	if r < utf8.RuneSelf {
		return unicode.ToLower(r)
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < utf8.RuneSelf {
			return unicode.ToLower(f)
		}
	}
	return unicode.ToLower(r)
}

func isLetter(b byte) bool { return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' }

// Redaction is what a match leaves no snippet for, on top of the fixed
// redaction: InkwallConfig.spec.events.redact, from the bundle. A nil
// Redaction adds nothing.
type Redaction struct {
	headers    []string // lower case
	arguments  []string // lower case
	noSnippets bool
}

// NewRedaction returns the redaction a bundle's events config asks for
// (nil: none beyond the fixed one).
func NewRedaction(cfg *bundlev1.EventsConfig) *Redaction {
	if cfg == nil {
		return nil
	}
	r := &Redaction{noSnippets: cfg.GetNoSnippets()}
	for _, h := range cfg.GetRedactHeaders() {
		if h != "" {
			r.headers = append(r.headers, strings.ToLower(h))
		}
	}
	for _, a := range cfg.GetRedactArguments() {
		if a != "" {
			r.arguments = append(r.arguments, strings.ToLower(a))
		}
	}
	return r
}

// header reports whether the configuration redacts header name.
func (r *Redaction) header(name string) bool {
	if r == nil {
		return false
	}
	for _, h := range r.headers {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// argument reports whether the configuration redacts the arguments named
// in s (an argument's name, or a raw query string or body).
func (r *Redaction) argument(s string) bool {
	if r == nil || len(r.arguments) == 0 {
		return false
	}
	s = strings.ToLower(s)
	for _, a := range r.arguments {
		if strings.Contains(s, a) {
			return true
		}
	}
	return false
}

// Source is the engine and pod the events come from.
type Source struct {
	EngineID     string
	PodNamespace string
	PodName      string
	// BundleVersion returns the bundle being enforced (nil: 0).
	BundleVersion func() uint64
	// Redaction returns the bundle's redaction (nil, or nil returned: the
	// fixed one only).
	Redaction func() *Redaction
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
		Phase:              eventsv1.Phase_PHASE_REQUEST,
	}
	ev.Protocol = protocol(req)
	switch {
	case v.WebSocketMessage:
		ev.Phase, ev.Protocol = eventsv1.Phase_PHASE_WEBSOCKET_MESSAGE, eventsv1.Protocol_PROTOCOL_WEBSOCKET
	case v.Response:
		ev.Phase = eventsv1.Phase_PHASE_RESPONSE
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
	var redact *Redaction
	if src.Redaction != nil {
		redact = src.Redaction()
	}
	for _, m := range v.Matches[:min(len(v.Matches), maxMatches)] {
		ev.Matches = append(ev.Matches, &eventsv1.Match{
			RuleId:   int32(m.RuleID), // #nosec G115 -- rule IDs fit
			Variable: truncate(m.Variable, maxVariable),
			Snippet:  snippet(redact, m.Variable, m.Value),
		})
	}
	return ev
}

// snippet is at most maxSnippet bytes of a matched value: none for a
// cookie, a response body, a credential header, an argument or header whose
// name looks sensitive, a raw query string or body that names one, or
// anything r redacts.
func snippet(r *Redaction, variable, value string) string {
	if r != nil && r.noSnippets {
		return ""
	}
	name, key, _ := strings.Cut(variable, ":")
	switch strings.ToUpper(name) {
	case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "RESPONSE_COOKIES":
		return ""
	case "RESPONSE_BODY":
		// What a data leakage rule matched there is the leaked data.
		return ""
	case "REQUEST_HEADERS", "RESPONSE_HEADERS":
		for _, h := range Redacted {
			if strings.EqualFold(key, h) {
				return ""
			}
		}
		if Sensitive(key) || r.header(key) {
			return ""
		}
	case "ARGS", "ARGS_GET", "ARGS_POST", "FILES", "MULTIPART_PART_HEADERS":
		if Sensitive(key) || r.argument(key) {
			return ""
		}
	case "QUERY_STRING", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_LINE", "REQUEST_BODY", "FULL_REQUEST":
		// The whole query string or body: its argument names are in the
		// value. A value in the snippet comes after its name, so the
		// snippet holds the whole name of any value it shows: checking it
		// is enough, and bounded.
		if snip := truncate(value, maxSnippet); Sensitive(snip) || r.argument(snip) {
			return ""
		}
	}
	return truncate(value, maxSnippet)
}

// protocol is what req speaks: a WebSocket handshake asks to upgrade to
// one, a gRPC call has a gRPC media type.
func protocol(req *request.Request) eventsv1.Protocol {
	for _, u := range req.Headers.Values("Upgrade") {
		for t := range strings.SplitSeq(u, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "websocket") {
				return eventsv1.Protocol_PROTOCOL_WEBSOCKET
			}
		}
	}
	mediaType, _, _ := strings.Cut(req.Headers.Get("Content-Type"), ";")
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(mediaType)), "application/grpc") {
		return eventsv1.Protocol_PROTOCOL_GRPC
	}
	return eventsv1.Protocol_PROTOCOL_HTTP
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
	case pipeline.ReasonWebSocket:
		return enginev1.Reason_REASON_WEBSOCKET
	default:
		return enginev1.Reason_REASON_UNSPECIFIED
	}
}
