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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
	"github.com/inkwall-dev/inkwall/operator/integrations"
)

// readSelectors reads the proxy pods' selectors from the InkwallConfig,
// before the manager (and its cache) exists. No InkwallConfig, or no CRD
// yet: the defaults. An invalid selector (an unknown operator: the CRD
// can't check it within its cost budget) is logged and the defaults are
// used: refusing to start would leave the
// webhooks, which may fail closed, unanswered.
func readSelectors(cfg *rest.Config, s *runtime.Scheme) (*integrations.Selectors, error) {
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ic wafv1alpha1.InkwallConfig
	switch err := c.Get(ctx, types.NamespacedName{Name: "default"}, &ic); {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return integrations.Defaults(), nil
	case err != nil:
		return nil, fmt.Errorf("read the InkwallConfig for the integrations' selectors: %w", err)
	}
	sel, ignored, err := integrations.FromConfig(ic.Spec.Integrations)
	if err != nil {
		log.Log.Error(err, "InkwallConfig integration selectors not applied; using the defaults")
		return integrations.Defaults(), nil
	}
	if len(ignored) > 0 {
		log.Log.Info("InkwallConfig integrations not supported yet, ignored", "controllers", ignored)
	}
	return sel, nil
}

// selectorWatch stops the operator when the InkwallConfig selects other
// proxy pods than it started with, so it restarts with them: its cache of
// proxy pods is built from them. Every replica runs it; the replicas wait
// a random while first, so they don't all restart at once.
type selectorWatch struct {
	client  client.Reader
	current *integrations.Selectors
	// maxDelay bounds the random wait before the restart; 0:
	// DefaultSelectorRestartMaxDelay.
	maxDelay time.Duration
}

// DefaultSelectorRestartMaxDelay bounds the random wait of each replica
// before it restarts with changed integration selectors.
const DefaultSelectorRestartMaxDelay = 30 * time.Second

// selectorCheckInterval is a variable for the tests.
var selectorCheckInterval = 10 * time.Second

// errSelectorsChanged ends the manager; the container restarts.
var errSelectorsChanged = errors.New("the InkwallConfig's integration selectors changed: restarting to apply them")

func (w *selectorWatch) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("integrations")
	logger.Info("proxy pods selected", "selectors", w.current.String())
	tick := time.NewTicker(selectorCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		next, ok := w.read(ctx)
		if !ok || next.Equal(w.current) {
			continue
		}
		delay := rand.N(cmp.Or(w.maxDelay, DefaultSelectorRestartMaxDelay)) // #nosec G404 -- spreading restarts, not security
		logger.Info("integration selectors changed; restarting", "from", w.current.String(), "to", next.String(), "in", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		return errSelectorsChanged
	}
}

func (*selectorWatch) NeedLeaderElection() bool { return false }

// read returns the selectors the InkwallConfig asks for; false if it can't
// tell (an invalid selector is kept out by validation, and logged).
func (w *selectorWatch) read(ctx context.Context) (*integrations.Selectors, bool) {
	var ic wafv1alpha1.InkwallConfig
	err := w.client.Get(ctx, types.NamespacedName{Name: "default"}, &ic)
	if apierrors.IsNotFound(err) {
		return integrations.Defaults(), true
	}
	if err != nil {
		return nil, false
	}
	sel, _, err := integrations.FromConfig(ic.Spec.Integrations)
	if err != nil {
		log.FromContext(ctx).Error(err, "InkwallConfig integration selectors not applied")
		return nil, false
	}
	return sel, true
}
