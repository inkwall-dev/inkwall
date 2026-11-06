// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/pipeline"
	"github.com/inkwall-dev/inkwall/pkg/request"
	"github.com/inkwall-dev/inkwall/pkg/rules"
)

// FuzzNew checks the redaction of client-controlled fields: whatever the
// request, every string of the event is valid UTF-8 (or it couldn't be sent)
// and within its limit, a cut-down prefix of what the client sent, the path
// carries no query string, and credentials, sensitive arguments and what
// events.redact names leave no snippet (none at all with snippets: false).
func FuzzNew(f *testing.F) {
	f.Fuzz(func(t *testing.T, method, host, path, userAgent, id, policy, variable, value string, matches int,
		redactHeader, redactArgument string, noSnippets bool) {
		req := &request.Request{
			ID: id, Method: method, Host: host, ClientIP: netip.MustParseAddr("203.0.113.7"),
			Headers: http.Header{"User-Agent": {userAgent}},
		}
		v := pipeline.Verdict{Action: pipeline.ActionDeny, Status: 403, Reason: pipeline.ReasonRule, Policy: policy}
		for i := range min(max(matches, 0), 2*maxMatches) {
			v.Matches = append(v.Matches, rules.Match{RuleID: i, Variable: variable, Value: value})
		}
		cfg := &bundlev1.EventsConfig{NoSnippets: noSnippets}
		if redactHeader != "" {
			cfg.RedactHeaders = []string{redactHeader}
		}
		if redactArgument != "" {
			cfg.RedactArguments = []string{redactArgument}
		}
		redaction := NewRedaction(cfg)
		ev := New(Source{EngineID: "e-1", Redaction: func() *Redaction { return redaction }}, req, path, v, time.Unix(0, 0))

		for _, c := range []struct {
			name, got, in string
			max           int
		}{
			{"method", ev.GetMethod(), method, 16},
			{"host", ev.GetHost(), host, maxHost},
			{"path", ev.GetPath(), path, maxPath},
			{"user agent", ev.GetUserAgent(), userAgent, maxUserAgent},
			{"request ID", ev.GetRequestId(), id, maxRequestID},
			{"policy", ev.GetPolicy(), policy, maxPolicy},
		} {
			checkField(t, c.name, c.got, c.in, c.max)
		}
		if strings.Contains(ev.GetPath(), "?") {
			t.Errorf("path %q carries a query string", ev.GetPath())
		}
		if n := len(ev.GetMatches()); n > maxMatches {
			t.Errorf("%d matches, at most %d", n, maxMatches)
		}
		for _, m := range ev.GetMatches() {
			checkField(t, "variable", m.GetVariable(), variable, maxVariable)
			if noSnippets || redacted(variable, value, redactHeader, redactArgument) {
				if m.GetSnippet() != "" {
					t.Errorf("%q: snippet %q, want none", variable, m.GetSnippet())
				}
			} else {
				checkField(t, "snippet", m.GetSnippet(), value, maxSnippet)
			}
		}
		if _, err := proto.Marshal(ev); err != nil {
			t.Errorf("event doesn't marshal: %v", err)
		}
	})
}

// checkField checks that got is valid UTF-8, at most limit bytes, and a
// prefix of in (with invalid UTF-8 replaced).
func checkField(t *testing.T, name, got, in string, limit int) {
	t.Helper()
	if !utf8.ValidString(got) {
		t.Errorf("%s %q: invalid UTF-8", name, got)
	}
	if len(got) > limit {
		t.Errorf("%s: %d bytes, at most %d", name, len(got), limit)
	}
	if name == "path" {
		in, _, _ = strings.Cut(in, "?")
	}
	if !strings.HasPrefix(strings.ToValidUTF8(in, "�"), got) {
		t.Errorf("%s %q is not a prefix of %q", name, got, in)
	}
}

// redacted reports whether a match on variable must leave no snippet: a
// cookie, a credential header, a header or argument whose name looks
// sensitive or is configured, or a raw query string or body naming one.
func redacted(variable, value, header, argument string) bool {
	name, key, _ := strings.Cut(variable, ":")
	configured := func(s string) bool {
		return argument != "" && strings.Contains(strings.ToLower(s), strings.ToLower(argument))
	}
	switch strings.ToUpper(name) {
	case "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES", "RESPONSE_COOKIES", "RESPONSE_BODY":
		return true
	case "REQUEST_HEADERS", "RESPONSE_HEADERS":
		for _, h := range []string{"authorization", "cookie", "set-cookie", "proxy-authorization", header} {
			if h != "" && strings.EqualFold(key, h) {
				return true
			}
		}
		return sensitiveName.MatchString(key)
	case "ARGS", "ARGS_GET", "ARGS_POST", "FILES", "MULTIPART_PART_HEADERS":
		return sensitiveName.MatchString(key) || configured(key)
	case "QUERY_STRING", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_LINE", "REQUEST_BODY", "FULL_REQUEST":
		// What the snippet would show.
		snip := truncate(value, maxSnippet)
		return sensitiveName.MatchString(snip) || configured(snip)
	}
	return false
}

// sensitiveName is what Sensitive must catch at least: the documented
// names (0002 §8.3), as a regular expression independent of its code.
var sensitiveName = regexp.MustCompile(`(?i)pass|pwd|secret|token|api[-_.]?key|auth|session|sess_?id|jwt|bearer|credential|private[-_.]?key|card|ccnum|cvv|cvc|(^|[^a-z])ssn($|[^a-z])`)
