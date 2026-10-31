// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/inkwall-dev/inkwall/operator/internal/access"
)

// readAccess finds the integrations the operator may not wire (their
// ClusterRole isn't granted), by name and why, before the manager exists:
// they are disabled, so the cache never waits on objects the operator may
// not read.
func readAccess(cfg *rest.Config, s *runtime.Scheme) (map[string]string, error) {
	// One review per permission: not rate limited, as they are done once.
	cfg = rest.CopyConfig(cfg)
	cfg.QPS = -1
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		return nil, err
	}
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

// accessWatch stops the operator once it is granted a disabled
// integration's permissions, so it restarts with the integration enabled:
// they may be granted later, or a moment after it started. Every replica
// runs it, and waits a random while first, so they don't all restart at
// once.
type accessWatch struct {
	client client.Client
	denied map[string]string
	// maxDelay bounds the random wait before the restart; 0:
	// DefaultSelectorRestartMaxDelay.
	maxDelay time.Duration
}

// accessCheckInterval is a variable for the tests.
var accessCheckInterval = time.Minute

// errAccessGranted ends the manager; the container restarts.
var errAccessGranted = errors.New("granted a disabled integration's permissions: restarting to enable it")

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
		for name := range w.denied {
			missing, err := access.Missing(ctx, w.client, roles[name])
			if err != nil || len(missing) > 0 {
				continue
			}
			delay := rand.N(cmp.Or(w.maxDelay, DefaultSelectorRestartMaxDelay)) // #nosec G404 -- spreading restarts, not security
			log.FromContext(ctx).Info("integration granted; restarting", "integration", name, "in", delay)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
			return errAccessGranted
		}
	}
}

func (*accessWatch) NeedLeaderElection() bool { return false }
