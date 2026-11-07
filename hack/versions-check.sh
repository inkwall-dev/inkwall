#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Fails if a version of hack/versions.env is pinned anywhere else in the
# scripts, the Makefile or the workflows (#393): they read it from there.
set -euo pipefail

cd "$(dirname "$0")/.."

files=$(git ls-files '*.sh' Makefile '.github/workflows/*.yaml' | grep -v '^hack/versions-check\.sh$')
bad=0
while IFS='=' read -r key value; do
  [[ $key =~ ^[A-Z_]+$ && -n $value ]] || continue
  # shellcheck disable=SC2086 # one path per word
  # runs-on can't read a file: make workflow-check holds it to CI_RUNNER.
  if hits=$(grep -nwF -- "$value" $files | grep -v 'runs-on: '); then
    echo "$hits" | sed "s/\$/  <- $key, from hack\/versions.env/"
    bad=1
  fi
done < <(grep -E '^[A-Z_]+=' hack/versions.env)
if ((bad)); then
  echo "versions-check: read these from hack/versions.env instead" >&2
  exit 1
fi
