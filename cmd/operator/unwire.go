// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/inkwall-dev/inkwall/operator/manager"
)

// unwire is the chart's pre-delete hook (helm uninstall): manager.Unwire.
func unwire(args []string, stderr io.Writer, logger *slog.Logger) int {
	fs := flag.NewFlagSet("inkwall-operator unwire", flag.ContinueOnError)
	fs.SetOutput(stderr)
	namespace := fs.String("namespace", os.Getenv("POD_NAMESPACE"), "the operator's namespace (default: $POD_NAMESPACE)")
	deployment := fs.String("deployment", "inkwall-operator", "the operator's Deployment, scaled to 0 first")
	timeout := fs.Duration("timeout", 2*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *namespace == "" {
		fmt.Fprintln(stderr, "--namespace is required")
		return 2
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		logger.Error("no Kubernetes API configuration", slog.Any("error", err))
		return 1
	}
	scheme, err := manager.NewScheme()
	if err != nil {
		logger.Error("scheme", slog.Any("error", err))
		return 1
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		logger.Error("client", slog.Any("error", err))
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := manager.Unwire(ctx, c, *namespace, *deployment, logger); err != nil {
		logger.Error("unwire failed; rerun the uninstall, or `helm uninstall --no-hooks` to skip it", slog.Any("error", err))
		return 1
	}
	return 0
}
