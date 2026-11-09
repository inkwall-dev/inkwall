#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Reports a scheduled workflow's result as an issue, so a red nightly run
# doesn't go unnoticed:
#
#   hack/ci/report-scheduled.sh WORKFLOW RESULT RUN_URL [DETAIL]
#
# RESULT failure opens one issue per workflow (pinned, labeled
# ci-scheduled-failure), or comments on the open one; RESULT success closes
# it. Other results (cancelled, skipped) change nothing. DETAIL is added as
# is: keep it to what may be public (the fuzz workflow names its failing
# targets, never their inputs or output). Needs gh, with GH_TOKEN allowed to
# write issues and GH_REPO set (or run in the repository).
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 WORKFLOW RESULT RUN_URL [DETAIL]" >&2
  exit 2
fi
workflow=$1 result=$2 run=$3 detail=${4:-}
label=ci-scheduled-failure
title="Scheduled workflow failing: $workflow"

# The open issue for this workflow, by its exact title.
open=$(gh issue list --label "$label" --state open --limit 100 --json number,title \
  --jq ".[] | select(.title == \"$title\") | .number" | head -1)

case $result in
failure)
  body="The scheduled run failed: $run"
  [[ -n $detail ]] && body+=$'\n\n'"$detail"
  if [[ -n $open ]]; then
    gh issue comment "$open" --body "$body"
    echo "commented on #$open"
  else
    gh label create "$label" --color B60205 --description "A scheduled CI workflow is failing" --force >/dev/null
    url=$(gh issue create --title "$title" --label "$label" \
      --body "$body"$'\n\n'"This issue is opened and closed by the workflow itself (hack/ci/report-scheduled.sh): it is closed when a scheduled run passes again.")
    # Pinning needs more than some tokens allow; the issue stands without it.
    gh issue pin "$url" >/dev/null 2>&1 || true
    echo "opened $url"
  fi
  ;;
success)
  if [[ -n $open ]]; then
    gh issue unpin "$open" >/dev/null 2>&1 || true
    gh issue close "$open" --comment "The scheduled run passes again: $run"
    echo "closed #$open"
  fi
  ;;
*)
  echo "result $result: nothing to report"
  ;;
esac
