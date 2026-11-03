#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# go-build-cache.sh inject|extract DIR: copies the Go build cache of the
# image builds (the Dockerfile's cache mount on /root/.cache/go-build) from
# DIR into Docker's builder, or from the builder into DIR. CI keeps DIR
# across runs (actions/cache), so the images compile only what changed:
# Docker's layer cache can't help there, since COPY . . changes with every
# commit, and a cache mount lives only as long as the builder.
#
# extract keeps only the entries the builds since inject used (#298): Go
# refreshes an entry's mtime when it uses one older than an hour, and inject
# and actions/cache keep mtimes, so an entry not modified for KEEP_MINUTES
# (default 120, longer than an hour plus the builds) wasn't used. Without
# this the cache grows with every go.sum, since each run restores the last
# one (restore-keys), and the copy out gets slower.
set -euo pipefail

cd "$(dirname "$0")/../.."

mode=${1:-}
dir=${2:-}
if [[ -z $dir || ($mode != inject && $mode != extract) ]]; then
  echo "usage: $0 inject|extract DIR" >&2
  exit 2
fi
# The Dockerfile's build image, already pulled for the images.
BASE=$(sed -n 's/^FROM .*\(golang:[^ ]*\) AS build$/\1/p' Dockerfile)
MOUNT=type=cache,target=/root/.cache/go-build

case $mode in
inject)
  mkdir -p "$dir"
  docker build -q -f - "$dir" >/dev/null <<EOF
# syntax=docker/dockerfile:1
FROM $BASE
RUN --mount=$MOUNT --mount=type=bind,target=/in cp -a /in/. /root/.cache/go-build/
EOF
  ;;
extract)
  rm -rf "$dir"
  keep=${KEEP_MINUTES:-120}
  # The date, so the copy isn't taken from the layer cache. Plain progress,
  # so CI's log shows how long each part takes.
  docker build --progress=plain --build-arg "NOW=$(date +%s%N)" --build-arg "KEEP=$keep" \
    --output "type=local,dest=$dir" - <<EOF
# syntax=docker/dockerfile:1
FROM $BASE AS copy
ARG NOW
ARG KEEP
RUN --mount=$MOUNT mkdir /out && cp -a /root/.cache/go-build/. /out/ && \
  du -sh /out && find /out -mindepth 2 -type f -mmin +\$KEEP -delete && du -sh /out
FROM scratch
COPY --from=copy /out /
EOF
  ;;
esac
du -sh "$dir"
