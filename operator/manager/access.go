// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/inkwall-dev/inkwall/operator/internal/access"
)

// accessClient checks permissions, one review each: not rate limited, so
// the checks don't hold up the operator's other requests.
func accessClient(cfg *rest.Config, s *runtime.Scheme) (client.Client, error) {
	cfg = rest.CopyConfig(cfg)
	cfg.QPS = -1
	return client.New(cfg, client.Options{Scheme: s})
}

// readAccess finds the integrations the operator may not wire (their
// ClusterRole isn't granted), by name and why, before the manager exists:
// they are disabled, so the cache never waits on objects the operator may
// not read.
func readAccess(c client.Client) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	denied, err := access.Denied(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("check the integrations' permissions: %w", err)
	}
	for name, why := range denied {
		log.Log.Info(why, "integration", name)
	}
	return denied, nil
}

// accessWatch stops the operator once an integration's permissions change:
// granted to a disabled one, so it restarts with the integration enabled
// (they may be granted later, or a moment after it started); or revoked
// from an enabled one, so it restarts with the integration disabled instead
// of failing to watch and write its proxy's objects. Every replica runs
// it, and waits a random while first, so they don't all restart at once;
// it checks again after the wait, so a binding replaced meanwhile (a Helm
// upgrade) doesn't restart it.
type accessWatch struct {
	client client.Client
	denied map[string]string
	// maxDelay bounds the random wait before the restart; 0:
	// DefaultSelectorRestartMaxDelay.
	maxDelay time.Duration
}

// accessCheckInterval is a variable for the tests.
var accessCheckInterval = time.Minute

// errAccessChanged ends the manager; the container restarts.
var errAccessChanged = errors.New("an integration's permissions changed: restarting to enable or disable it")

func (w *accessWatch) Start(ctx context.Context) error {
	roles, err := access.Roles()
	if err != nil {
		return err
	}
	tick := time.NewTicker(accessCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		name, change := w.changed(ctx, roles)
		if name == "" {
			continue
		}
		delay := rand.N(cmp.Or(w.maxDelay, DefaultSelectorRestartMaxDelay)) // #nosec G404 -- spreading restarts, not security
		log.FromContext(ctx).Info("integration "+change+"; restarting", "integration", name, "in", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		if again, _ := w.changed(ctx, roles); again == "" {
			log.FromContext(ctx).Info("integration's permissions changed back; not restarting", "integration", name)
			continue
		}
		return errAccessChanged
	}
}

// changed returns an integration whose permissions no longer match how it
// runs, and "granted" or "revoked"; "" if none (or it can't tell).
func (w *accessWatch) changed(ctx context.Context, roles map[string][]rbacv1.PolicyRule) (name, change string) {
	for _, name := range slices.Sorted(maps.Keys(roles)) {
		missing, err := access.Missing(ctx, w.client, roles[name])
		if err != nil {
			continue
		}
		switch disabled := w.denied[name] != ""; {
		case disabled && len(missing) == 0:
			return name, "granted"
		case !disabled && len(missing) > 0:
			return name, "revoked (" + strings.Join(missing, ", ") + ")"
		}
	}
	return "", ""
}

func (*accessWatch) NeedLeaderElection() bool { return false }
