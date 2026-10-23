#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Renders every diagram source in docs/diagrams/src with Archify
# (.claude/skills/archify) and exports the SVGs the docs embed.
#
#   hack/docs/diagrams.sh [name...]     (default: all)
#
# A source is docs/diagrams/src/<name>.<type>.json. `finalize` validates it,
# checks its source citations against the pinned revision in
# meta.repository, and runs the browser gate; any failure stops the script.
# The interactive HTML lands in .archify/<name>/<name>.html.
set -euo pipefail

cd "$(dirname "$0")/../.."
ARCHIFY=.claude/skills/archify/bin/archify.mjs
# The docs build must not depend on, or report to, Archify's update server.
export ARCHIFY_UPDATE_CHECK_DISABLED=1

sources=()
if (($#)); then
  for name in "$@"; do sources+=(docs/diagrams/src/"$name".*.json); done
else
  sources=(docs/diagrams/src/*.json)
fi

html=()
for src in "${sources[@]}"; do
  file=$(basename "$src" .json) # <name>.<type>
  name=${file%.*}
  type=${file##*.}
  out=.archify/$name/$name.html
  # Each finalize owns its browser evidence; start clean so reruns don't
  # trip over the previous run's receipts.
  rm -rf ".archify/$name"
  echo "== $name ($type)"
  node "$ARCHIFY" finalize "$type" "$src" "$out" --repo-root . --quality showcase
  html+=("$out")
done

node hack/docs/export-diagrams.mjs "${html[@]}"
