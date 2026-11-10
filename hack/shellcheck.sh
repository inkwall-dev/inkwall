#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Runs shellcheck SHELLCHECK_VERSION (hack/versions.env), installed or from
# its image, for make lint-scripts and actionlint (#398). An installed one of
# another version isn't used: newer versions add checks, and CI and a laptop
# must check the same things (#572).
set -euo pipefail
version=$(sed -n 's/^SHELLCHECK_VERSION=//p' "$(dirname "$0")/versions.env")
if command -v shellcheck >/dev/null && [[ $(shellcheck --version | sed -n 's/^version: //p') == "${version#v}" ]]; then
  exec shellcheck "$@"
fi
exec docker run --rm -i -v "$PWD:$PWD" -w "$PWD" "koalaman/shellcheck:$version" "$@"
