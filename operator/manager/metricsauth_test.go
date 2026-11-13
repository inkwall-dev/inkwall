// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// fakeAuthn authenticates the token "reader" and "other"; "error" is
// rejected with an error (as the TokenReview authenticator rejects a
// malformed or expired token), anything else without one.
type fakeAuthn struct{}

func (fakeAuthn) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	switch tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok {
	case "reader", "other", "authz-error":
		return &authenticator.Response{User: &user.DefaultInfo{Name: tok}}, true, nil
	case "error":
		return nil, false, errors.New("token has expired")
	default:
		return nil, false, nil
	}
}

// fakeAuthz allows "reader" to get /metrics, fails for "authz-error".
type fakeAuthz struct{}

func (fakeAuthz) Authorize(_ context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	switch a.GetUser().GetName() {
	case "authz-error":
		return authorizer.DecisionNoOpinion, "", errors.New("SubjectAccessReview failed")
	case "reader":
		if a.GetVerb() == "get" && a.GetPath() == "/metrics" {
			return authorizer.DecisionAllow, "", nil
		}
	}
	return authorizer.DecisionDeny, "no role", nil
}

func TestMetricsAuthFilter(t *testing.T) {
	now := time.Unix(1000, 0)
	var errs, infos []string
	log := logr.New(&recordingSink{
		onInfo:  func(_ int, msg string, _ []any) { infos = append(infos, msg) },
		onError: func(err error, msg string, _ []any) { errs = append(errs, msg+": "+err.Error()) },
	})
	f := newMetricsAuthFilter(fakeAuthn{}, fakeAuthz{}, func() time.Time { return now })
	h, err := f(log, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("metrics")) }))
	if err != nil {
		t.Fatal(err)
	}
	scrape := func(token string) int {
		r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for token, want := range map[string]int{
		"reader":      http.StatusOK,
		"":            http.StatusUnauthorized,
		"unknown":     http.StatusUnauthorized,
		"error":       http.StatusUnauthorized,
		"other":       http.StatusForbidden,
		"authz-error": http.StatusInternalServerError,
	} {
		if got := scrape(token); got != want {
			t.Errorf("token %q: %d, want %d", token, got, want)
		}
	}

	// Refused requests, many of them: never an error log, and at most one
	// line per interval, which counts them.
	errs, infos = nil, nil
	for range 1000 {
		scrape("error")
		scrape("other")
	}
	if len(errs) != 0 {
		t.Errorf("refusals logged as errors: %q", errs)
	}
	if len(infos) > 1 {
		t.Errorf("1000 refusals in one interval logged %d lines, want at most 1: %q", len(infos), infos)
	}
	before := len(infos)
	now = now.Add(refusalLogInterval)
	scrape("error")
	if len(infos) != before+1 || len(errs) != 0 {
		t.Fatalf("after the interval: %d info lines %q, errors %q; want one more", len(infos), infos, errs)
	}
	// A failed SubjectAccessReview is the server's failure, not the
	// client's: an error.
	scrape("authz-error")
	if len(errs) != 1 {
		t.Errorf("a failed SubjectAccessReview: errors %q, want one", errs)
	}
}

// recordingSink is a logr.LogSink that records Info (at any verbosity) and
// Error calls.
type recordingSink struct {
	onInfo  func(level int, msg string, kv []any)
	onError func(err error, msg string, kv []any)
}

func (s *recordingSink) Init(logr.RuntimeInfo) {}
func (s *recordingSink) Enabled(int) bool      { return true }
func (s *recordingSink) Info(level int, msg string, kv ...any) {
	s.onInfo(level, msg, kv)
}
func (s *recordingSink) Error(err error, msg string, kv ...any) { s.onError(err, msg, kv) }
func (s *recordingSink) WithValues(...any) logr.LogSink         { return s }
func (s *recordingSink) WithName(string) logr.LogSink           { return s }
