#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Lists the Go fuzz targets, for the nightly fuzz workflow's matrix: every
# `func FuzzXxx(` in a _test.go file Git tracks, as a JSON array of
# {"package": "./pkg/x", "target": "FuzzXxx", "name": "pkg/x FuzzXxx"},
# sorted. A new target is fuzzed nightly without editing the workflow.
set -euo pipefail

cd "$(dirname "$0")/../.."

git ls-files -- '*_test.go' | xargs grep -H -o '^func Fuzz[A-Za-z0-9_]*(' |
  sed -E 's|^(.*)/[^/]*_test\.go:func (Fuzz[A-Za-z0-9_]*)\($|\1 \2|' | sort -u |
  awk 'BEGIN { printf "[" }
    { printf "%s{\"package\":\"./%s\",\"target\":\"%s\",\"name\":\"%s %s\"}", (NR > 1 ? "," : ""), $1, $2, $1, $2 }
    END { print "]" }'
