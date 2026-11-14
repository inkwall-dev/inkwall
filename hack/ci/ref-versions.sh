#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Prints the versions under test at a commit, as KEY=value lines for a
# workflow's $GITHUB_OUTPUT, read with git from the local repository (the
# commit needn't be checked out):
#
#   hack/ci/ref-versions.sh origin/release-0.4
#
# From 0.5 on, that's the commit's hack/versions.env (#393). A release
# branch from before has none: it pinned the one version the workflows need,
# Helm's, in its CI workflow, and is tested with that (#618). Fails, printing
# nothing, if neither is there.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 COMMIT" >&2
  exit 2
fi
commit=$1
if ! git rev-parse -q --verify "$commit^{commit}" >/dev/null; then
  echo "ref-versions: no such commit: $commit" >&2
  exit 1
fi

if env=$(git show "$commit:hack/versions.env" 2>/dev/null); then
  grep -E '^[A-Z_]+=' <<<"$env"
  exit 0
fi

# The first version: after an azure/setup-helm step.
ci=$(git show "$commit:.github/workflows/ci.yaml" 2>/dev/null) || ci=
helm=$(awk '/uses: azure\/setup-helm@/ { n = 3; next }
  n > 0 && match($0, /version: v[0-9]+\.[0-9]+\.[0-9]+/) { print substr($0, RSTART + 9, RLENGTH - 9); exit }
  { n-- }' <<<"$ci")
if [[ -z $helm ]]; then
  echo "ref-versions: $commit has no hack/versions.env and no Helm version in .github/workflows/ci.yaml" >&2
  exit 1
fi
echo "ref-versions: $commit has no hack/versions.env (before 0.5): Helm $helm, from its CI workflow" >&2
echo "HELM_VERSION=$helm"
