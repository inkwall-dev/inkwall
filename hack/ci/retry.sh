#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# retry.sh ATTEMPTS COMMAND...: runs COMMAND until it succeeds, at most
# ATTEMPTS times, waiting 15 s, 30 s, 60 s... in between (RETRY_DELAY sets
# the first wait, in seconds). The release
# signs through Sigstore (the workflow's OIDC token, Fulcio, Rekor), whose
# transient errors would otherwise leave a published artifact unsigned
# (#586). Signing again is safe: a signature is added, never replaced.
set -uo pipefail

if (($# < 2)); then
  echo "usage: retry.sh ATTEMPTS COMMAND..." >&2
  exit 2
fi
attempts=$1
shift
delay=${RETRY_DELAY:-15}
for ((i = 1; ; i++)); do
  "$@" && exit 0
  rc=$?
  if ((i >= attempts)); then
    echo "::error::$1 failed $attempts times (last exit status $rc)"
    exit "$rc"
  fi
  echo "::warning::$1 failed (exit status $rc), attempt $i of $attempts; again in ${delay}s"
  sleep "$delay"
  delay=$((delay * 2))
done
