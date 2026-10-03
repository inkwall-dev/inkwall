// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"

	"github.com/inkwall-dev/inkwall/pkg/pipeline"
)

func TestParseProxyFlags(t *testing.T) {
	cfg, err := parseProxyFlags([]string{
		"--upstream", "http://app:8080", "--mode", "block", "--failure-mode", "closed",
		"--trusted-proxies", "10.0.0.0/8,192.0.2.1", "--oversize-body", "deny", "--max-args", "255",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.upstream.Host != "app:8080" || cfg.mode != pipeline.ModeBlock || cfg.failureMode != pipeline.FailClosed {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.oversize != pipeline.OversizeDeny || cfg.maxArgs != 255 {
		t.Fatalf("oversize/max-args not parsed: %+v", cfg)
	}
	if len(cfg.trustedProxies) != 2 {
		t.Fatalf("trusted proxies = %v", cfg.trustedProxies)
	}
}

func TestParseProxyFlagsDefaults(t *testing.T) {
	cfg, err := parseProxyFlags([]string{"--upstream", "http://app"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mode != pipeline.ModeDetect || cfg.failureMode != pipeline.FailOpen {
		t.Fatalf("defaults must be detect and fail-open, got %+v", cfg)
	}
}

func TestParseProxyFlagsErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--upstream", "http://app", "--mode", "enforce"},
		{"--upstream", "http://app", "--failure-mode", "maybe"},
		{"--upstream", "http://app", "--oversize-body", "truncate"},
	} {
		if _, err := parseProxyFlags(args, io.Discard); err == nil {
			t.Errorf("parseProxyFlags(%v) succeeded, want error", args)
		}
	}
}

func TestRunUsage(t *testing.T) {
	if code := run(nil, io.Discard); code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
}
