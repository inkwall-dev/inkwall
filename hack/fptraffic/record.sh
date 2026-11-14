#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Records hack/fptraffic/juice-shop.har.gz (make fp-har): starts OWASP Juice
# Shop (JUICE_SHOP_VERSION, hack/versions.env) in Docker on a new
# database, plays its shoppers with hack/fptraffic, and removes the
# container. OUT sets another file. Needs Docker and the network (the
# image).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=hack/versions.env
. hack/versions.env

OUT=${OUT:-hack/fptraffic/juice-shop.har.gz}
name=inkwall-fp-juice-shop-$$
port=$((23000 + RANDOM % 5000))

docker run --rm -d --name "$name" -p "127.0.0.1:$port:3000" "bkimminich/juice-shop:$JUICE_SHOP_VERSION" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 120); do
  if curl -sf -o /dev/null "http://127.0.0.1:$port/rest/admin/application-version"; then
    break
  fi
  sleep 1
done
go run ./hack/fptraffic -target "http://127.0.0.1:$port" -out "$OUT"
