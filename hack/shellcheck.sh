#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Runs shellcheck, installed or from its image (SHELLCHECK_VERSION in
# hack/versions.env), for make lint-scripts and actionlint (#398).
set -euo pipefail
if command -v shellcheck >/dev/null; then
  exec shellcheck "$@"
fi
version=$(sed -n 's/^SHELLCHECK_VERSION=//p' "$(dirname "$0")/versions.env")
exec docker run --rm -i -v "$PWD:$PWD" -w "$PWD" "koalaman/shellcheck:$version" "$@"
