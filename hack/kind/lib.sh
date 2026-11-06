# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Shared helpers of the kind scripts (#391), sourced after `cd` to the
# repository root:
#
#   EVENTUALLY_TRIES=360 # optional: tries of eventually, 0.5 s apart
#   . hack/kind/lib.sh
#
# A check that fails is counted in failures, and the test goes on; the
# script reports and exits with failures at its end. A command that fails
# outside a check (set -e) prints its file, line and command before the
# script exits, so a job never ends with a bare "exit 1".

failures=${failures:-0}
ok() { printf 'ok    %s\n' "$1"; }
fail() {
  printf 'FAIL  %s\n' "$1"
  failures=$((failures + 1))
}
# check DESCRIPTION COMMAND...: one try.
check() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}
# eventually DESCRIPTION COMMAND...: retries EVENTUALLY_TRIES times (120 by
# default: 60 s), half a second apart.
eventually() {
  local what=$1
  shift
  for _ in $(seq "${EVENTUALLY_TRIES:-120}"); do
    if "$@" >/dev/null 2>&1; then
      ok "$what"
      return 0
    fi
    sleep 0.5
  done
  fail "$what"
}

# The failing command where set -e stops the script, with its file and line,
# in functions too (errtrace). Commands in checks and conditions, and those
# followed by || true, don't trigger it.
set -E
trap 'echo "error: ${BASH_SOURCE[0]}:${LINENO}: \"${BASH_COMMAND}\" exited $?" >&2' ERR
