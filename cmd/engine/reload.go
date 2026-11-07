// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inkwall-dev/inkwall/pkg/rules"
	"github.com/inkwall-dev/inkwall/pkg/rules/coraza"
	"github.com/inkwall-dev/inkwall/pkg/telemetry"
)

// rulesReloader recompiles standalone mode's rule files (--rules,
// --rules-before-crs) and swaps them in without a restart (#359): on SIGHUP,
// and with --watch-rules when their content changes (a mounted ConfigMap
// swaps a symlink). The new rules compile off the request path; requests
// in flight finish on the old ones. On an error the old rules stay.
type rulesReloader struct {
	cfg     engineConfig
	swap    *rules.Swap
	logger  *slog.Logger
	metrics *telemetry.Metrics

	mu  sync.Mutex
	sum [sha256.Size]byte // of the rules in force, or of the last bad ones
	// reloads counts the reloads tried, for tests.
	reloads atomic.Int64
}

// ruleFiles reads the rule files, and the hash of their content.
func ruleFiles(cfg engineConfig) (after, before string, sum [sha256.Size]byte, err error) {
	if after, err = readOptional(cfg.rulesFile); err != nil {
		return "", "", sum, fmt.Errorf("read --rules: %w", err)
	}
	if before, err = readOptional(cfg.rulesBeforeCRS); err != nil {
		return "", "", sum, fmt.Errorf("read --rules-before-crs: %w", err)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%d\n%s", len(before), before, len(after), after)
	h.Sum(sum[:0])
	return after, before, sum, nil
}

// compileRules compiles the flags' policy with the rule files' content.
func compileRules(cfg engineConfig, after, before string) (*coraza.Evaluator, error) {
	return coraza.New(coraza.Config{
		ParanoiaLevel:           cfg.paranoiaLevel,
		InboundAnomalyThreshold: cfg.threshold,
		MaxArgs:                 cfg.maxArgs,
		BodyLimit:               int(cfg.maxBodyBytes),
		ResponseBodyLimit:       int(cfg.responses.MaxBytes),
		DisabledRuleGroups:      cfg.ruleGroupsOff,
		DirectivesBeforeCRS:     before,
		Directives:              after,
	})
}

// reload reads, compiles and swaps the rules in, logging and counting the
// result (inkwall_rules_reloads_total).
func (r *rulesReloader) reload(why string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloads.Add(1)
	after, before, sum, err := ruleFiles(r.cfg)
	if err == nil {
		r.sum = sum
		var e *coraza.Evaluator
		if e, err = compileRules(r.cfg, after, before); err == nil {
			r.swap.Store(e)
		}
	}
	if err != nil {
		r.metrics.RulesReloaded("error")
		r.logger.Error("rules not reloaded: the old rules stay in force", slog.String("trigger", why), slog.Any("error", err))
		return err
	}
	r.metrics.RulesReloaded("ok")
	r.logger.Info("rules reloaded", slog.String("trigger", why), slog.String("sha256", hex.EncodeToString(sum[:])))
	return nil
}

// changed reports whether the files' content differs from the last
// reload's (or start's). A file that can't be read is not a change: the
// next one that can is.
func (r *rulesReloader) changed() bool {
	_, _, sum, err := ruleFiles(r.cfg)
	r.mu.Lock()
	defer r.mu.Unlock()
	return err == nil && sum != r.sum
}

// run reloads on each signal from hup and, with watch positive, when the
// files change, checked every watch, until ctx ends.
func (r *rulesReloader) run(ctx context.Context, hup <-chan os.Signal, watch time.Duration) {
	var tick <-chan time.Time
	if watch > 0 {
		t := time.NewTicker(watch)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			_ = r.reload("SIGHUP")
		case <-tick:
			if r.changed() {
				_ = r.reload("file change")
			}
		}
	}
}
