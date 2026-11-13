#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Keyless signing in the release workflow (#586). cosign signs with the
# job's OIDC token, which GitHub sometimes fails to hand out (v0.5.1: "invalid
# character 'u'", a body that wasn't JSON) after the release was pushed:
#
#   hack/ci/sigstore.sh check         fetches the token for Sigstore, as cosign
#                                     does: run it before publishing anything,
#                                     so a broken token endpoint stops the job
#                                     first
#   hack/ci/sigstore.sh retry CMD...  runs CMD (cosign sign ...) until it
#                                     passes: what is signed is already
#                                     published
#
# Both try SIGSTORE_ATTEMPTS times (5), SIGSTORE_DELAY seconds apart (15).
# The token is never printed. check needs the job's id-token: write
# permission (ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN).
set -euo pipefail

attempts=${SIGSTORE_ATTEMPTS:-5}
delay=${SIGSTORE_DELAY:-15}

retry() {
  local i
  for ((i = 1; ; i++)); do
    if "$@"; then
      return 0
    fi
    if ((i >= attempts)); then
      echo "::error::$1 failed $attempts times" >&2
      return 1
    fi
    echo "::warning::$1 failed (attempt $i of $attempts), retrying in ${delay}s" >&2
    sleep "$delay"
  done
}

token() {
  local body
  # The request token in a header read from stdin, not on the command line.
  if ! body=$(printf 'Authorization: bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" |
    curl -fsS --max-time 30 -H @- "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore"); then
    return 1
  fi
  if ! jq -e '.value | type == "string" and length > 0' <<<"$body" >/dev/null 2>&1; then
    echo "the OIDC token endpoint answered without a token" >&2
    return 1
  fi
}

case ${1:-} in
check)
  if [[ -z ${ACTIONS_ID_TOKEN_REQUEST_URL:-} || -z ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} ]]; then
    echo "::error::no OIDC token to sign with: the job needs the id-token: write permission" >&2
    exit 1
  fi
  retry token
  echo "The job's OIDC token for Sigstore can be fetched."
  ;;
retry)
  shift
  if [[ $# -eq 0 ]]; then
    echo "usage: $0 retry CMD [ARG...]" >&2
    exit 2
  fi
  retry "$@"
  ;;
*)
  echo "usage: $0 check | retry CMD [ARG...]" >&2
  exit 2
  ;;
esac
