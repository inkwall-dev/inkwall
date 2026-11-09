#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Fails if a version of hack/versions.env is pinned anywhere else in the
# scripts, the Makefile or the workflows (#393): they read it from there.
# Also fails if a workflow reads one as env.KEY, which is always empty (#542).
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
  # A workflow reads them from the file (a versions step's outputs), never
  # as env.KEY: no workflow's env sets them, so that is always empty (#542).
  # shellcheck disable=SC2086 # one path per word
  if hits=$(grep -nE -- "env\.$key([^A-Za-z0-9_]|\$)" $files); then
    while IFS= read -r hit; do
      echo "$hit  <- env.$key is empty: use the versions step's outputs"
    done <<<"$hits"
    bad=1
  fi
done < <(grep -E '^[A-Z_]+=' hack/versions.env)
if ((bad)); then
  echo "versions-check: read these from hack/versions.env instead" >&2
  exit 1
fi
