// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// refusalLogInterval is the least time between two log lines about
// refused scrapes.
const refusalLogInterval = time.Minute

// metricsAuthFilter is the secure metrics' authentication and
// authorization: controller-runtime's filters.WithAuthenticationAndAuthorization,
// with the same TokenReview and SubjectAccessReview and the same caches,
// except for how it refuses (#562). That one answers 500, and logs an
// error, for a token the TokenReview rejects with a reason (malformed,
// expired, from another cluster): any client that reaches the port could
// have the operator log an error per request. Here such a token is 401,
// as the API server itself answers it, and refusals (401 and 403) are
// logged at info level, at most one line a minute, with their count and
// the last reason. A failed SubjectAccessReview stays 500, logged as an
// error: no client can cause it.
func metricsAuthFilter(config *rest.Config, httpClient *http.Client) (metricsserver.Filter, error) {
	authnClient, err := authenticationv1.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, err
	}
	authzClient, err := authorizationv1.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, err
	}
	// The API server's own retry backoff for its authentication and
	// authorization webhooks, as controller-runtime's filter uses.
	backoff := func() *wait.Backoff {
		return &wait.Backoff{Duration: 500 * time.Millisecond, Factor: 1.5, Jitter: 0.2, Steps: 5}
	}
	authn, _, err := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:                &apiserver.AnonymousAuthConfig{Enabled: false},
		CacheTTL:                 time.Minute,
		TokenAccessReviewClient:  authnClient,
		TokenAccessReviewTimeout: 10 * time.Second,
		WebhookRetryBackoff:      backoff(),
	}.New()
	if err != nil {
		return nil, fmt.Errorf("the metrics authenticator: %w", err)
	}
	authz, err := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: authzClient,
		AllowCacheTTL:             5 * time.Minute,
		DenyCacheTTL:              30 * time.Second,
		WebhookRetryBackoff:       backoff(),
	}.New()
	if err != nil {
		return nil, fmt.Errorf("the metrics authorizer: %w", err)
	}
	return newMetricsAuthFilter(authn, authz, time.Now), nil
}

// newMetricsAuthFilter is the filter with its authenticator, authorizer and
// clock.
func newMetricsAuthFilter(authn authenticator.Request, authz authorizer.UnconditionalAuthorizer, now func() time.Time) metricsserver.Filter {
	return func(log logr.Logger, handler http.Handler) (http.Handler, error) {
		refusals := &refusalLog{log: log, now: now}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, ok, err := authn.AuthenticateRequest(r)
			if err != nil || !ok {
				reason := "no valid bearer token"
				if err != nil {
					reason = err.Error()
				}
				refusals.add(http.StatusUnauthorized, reason)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			attrs := authorizer.AttributesRecord{User: res.User, Verb: strings.ToLower(r.Method), Path: r.URL.Path}
			decision, reason, err := authz.Authorize(r.Context(), attrs)
			if err != nil {
				log.Error(err, "Authorization of a metrics scrape failed", "user", res.User.GetName())
				http.Error(w, "Authorization failed", http.StatusInternalServerError)
				return
			}
			if decision != authorizer.DecisionAllow {
				refusals.add(http.StatusForbidden, fmt.Sprintf("%s may not %s %s: %s", res.User.GetName(), attrs.Verb, attrs.Path, reason))
				http.Error(w, fmt.Sprintf("Forbidden: %s may not %s %s", res.User.GetName(), attrs.Verb, attrs.Path), http.StatusForbidden)
				return
			}
			handler.ServeHTTP(w, r)
		}), nil
	}
}

// refusalLog counts the refused scrapes and logs them at most once per
// refusalLogInterval: the first refusal at once, the ones after it in the
// next line.
type refusalLog struct {
	log logr.Logger
	now func() time.Time

	mu           sync.Mutex
	next         time.Time
	unauthorized int
	forbidden    int
	last         string
}

func (l *refusalLog) add(status int, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if status == http.StatusUnauthorized {
		l.unauthorized++
	} else {
		l.forbidden++
	}
	l.last = reason
	now := l.now()
	if now.Before(l.next) {
		return
	}
	l.log.Info("Refused metrics scrapes (logged at most once a minute)", "unauthorized", l.unauthorized,
		"forbidden", l.forbidden, "last", l.last)
	l.unauthorized, l.forbidden = 0, 0
	l.next = now.Add(refusalLogInterval)
}
