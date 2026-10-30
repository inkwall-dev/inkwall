// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package distribution

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/bundle"
)

// Engines authenticate with a projected ServiceAccount token for this
// audience, and must be allowed to read the bundle Secret: the same
// permission they need to start from it when the operator is down.
//
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// Audience is the token audience engines request.
const Audience = "inkwall-operator"

// Errors of Authenticate.
var (
	ErrUnauthenticated = errors.New("not authenticated")
	ErrForbidden       = errors.New("not allowed to read the bundle")
)

// Identity is an authenticated engine.
type Identity struct {
	// ServiceAccount as "namespace/name".
	ServiceAccount string
	// The pod the token is bound to, if it is.
	PodNamespace string
	PodName      string
}

// Authenticator checks an engine's bearer token.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (Identity, error)
}

// KubeAuthenticator checks tokens with TokenReview, and authorizes them with
// a SubjectAccessReview for reading the bundle Secret.
type KubeAuthenticator struct {
	Client client.Client
	// Namespace is the operator's, where the bundle Secret is.
	Namespace string
	// TTL caches a successful check, so reconnecting engines don't each
	// cost two API calls. Revoking access takes effect after at most TTL.
	TTL time.Duration
	Now func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]cached
}

type cached struct {
	id      Identity
	expires time.Time
}

// Authenticate implements Authenticator.
func (a *KubeAuthenticator) Authenticate(ctx context.Context, token string) (Identity, error) {
	if token == "" {
		return Identity{}, fmt.Errorf("%w: no bearer token", ErrUnauthenticated)
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	key := sha256.Sum256([]byte(token))
	a.mu.Lock()
	if c, ok := a.cache[key]; ok && now().Before(c.expires) {
		a.mu.Unlock()
		return c.id, nil
	}
	a.mu.Unlock()

	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{Audience}}}
	if err := a.Client.Create(ctx, tr); err != nil {
		return Identity{}, fmt.Errorf("token review: %w", err)
	}
	st := tr.Status
	if !st.Authenticated || !slices.Contains(st.Audiences, Audience) {
		return Identity{}, fmt.Errorf("%w: %s", ErrUnauthenticated, st.Error)
	}
	ns, name, ok := strings.Cut(strings.TrimPrefix(st.User.Username, "system:serviceaccount:"), ":")
	if !ok || !strings.HasPrefix(st.User.Username, "system:serviceaccount:") {
		return Identity{}, fmt.Errorf("%w: %s is not a ServiceAccount", ErrUnauthenticated, st.User.Username)
	}
	id := Identity{ServiceAccount: ns + "/" + name}
	if pods := st.User.Extra["authentication.kubernetes.io/pod-name"]; len(pods) == 1 {
		id.PodNamespace, id.PodName = ns, pods[0]
	}

	extra := map[string]authzv1.ExtraValue{}
	for k, v := range st.User.Extra {
		extra[k] = authzv1.ExtraValue(v)
	}
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User:   st.User.Username,
		Groups: st.User.Groups,
		UID:    st.User.UID,
		Extra:  extra,
		ResourceAttributes: &authzv1.ResourceAttributes{
			Namespace: a.Namespace,
			Verb:      "get",
			Resource:  "secrets",
			Name:      bundle.BundleSecret,
		},
	}}
	if err := a.Client.Create(ctx, sar); err != nil {
		return Identity{}, fmt.Errorf("access review: %w", err)
	}
	if !sar.Status.Allowed {
		return Identity{}, fmt.Errorf("%w: ServiceAccount %s can't get Secret %s/%s", ErrForbidden, id.ServiceAccount, a.Namespace, bundle.BundleSecret)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil {
		a.cache = map[[sha256.Size]byte]cached{}
	}
	// Drop expired entries, so rotated tokens don't pile up.
	for k, c := range a.cache {
		if !now().Before(c.expires) {
			delete(a.cache, k)
		}
	}
	a.cache[key] = cached{id: id, expires: now().Add(a.TTL)}
	return id, nil
}
