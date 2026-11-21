#!/usr/bin/env bash
# Copyright 2026 The Inkwall Authors
# SPDX-License-Identifier: Apache-2.0

# Records hack/fptraffic/<APP>.har.gz (make fp-har APP=<app>): starts the
# application (its version in hack/versions.env) in Docker on a new
# database, plays its users with hack/fptraffic, and removes the
# containers, network and volumes it made. APP is juice-shop (the
# default), gitea, wordpress or directus; OUT sets another file. Needs
# Docker and the network (the images).
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=hack/versions.env
. hack/versions.env

APP=${APP:-juice-shop}
OUT=${OUT:-hack/fptraffic/$APP.har.gz}
name=inkwall-fp-$APP-$$
port=$((23000 + RANDOM % 5000))

# The containers run with --rm, and anonymous volumes go with them.
trap 'docker rm -f "$name" "$name-db" >/dev/null 2>&1 || true; docker network rm "$name" >/dev/null 2>&1 || true' EXIT
case $APP in
juice-shop)
  docker run --rm -d --name "$name" -p "127.0.0.1:$port:3000" "bkimminich/juice-shop:$JUICE_SHOP_VERSION" >/dev/null
  ready=/rest/admin/application-version
  ;;
gitea)
  # Installed, on SQLite, with sign-up open and no e-mail to confirm.
  docker run --rm -d --name "$name" -p "127.0.0.1:$port:3000" \
    -e GITEA__security__INSTALL_LOCK=true -e GITEA__database__DB_TYPE=sqlite3 \
    -e GITEA__server__ROOT_URL="http://127.0.0.1:$port/" -e GITEA__service__DISABLE_REGISTRATION=false \
    -e GITEA__service__REGISTER_EMAIL_CONFIRM=false "gitea/gitea:$GITEA_VERSION" >/dev/null
  ready=/api/healthz
  ;;
wordpress)
  # MariaDB on a network of its own; hack/fptraffic installs WordPress.
  docker network create "$name" >/dev/null
  docker run --rm -d --name "$name-db" --network "$name" -e MARIADB_DATABASE=wordpress -e MARIADB_USER=wordpress \
    -e MARIADB_PASSWORD=wordpress -e MARIADB_RANDOM_ROOT_PASSWORD=1 "mariadb:$MARIADB_VERSION" >/dev/null
  docker run --rm -d --name "$name" --network "$name" -p "127.0.0.1:$port:80" -e WORDPRESS_DB_HOST="$name-db" \
    -e WORDPRESS_DB_USER=wordpress -e WORDPRESS_DB_PASSWORD=wordpress -e WORDPRESS_DB_NAME=wordpress \
    "wordpress:$WORDPRESS_VERSION" >/dev/null
  ready=/wp-admin/install.php
  ;;
directus)
  # SQLite; the administrator from the environment, as its image makes it.
  docker run --rm -d --name "$name" -p "127.0.0.1:$port:8055" \
    -e KEY=fp-run-key -e SECRET=fp-run-secret-0123456789abcdef0123456789abcdef \
    -e DB_CLIENT=sqlite3 -e DB_FILENAME=/directus/database/data.db \
    -e ADMIN_EMAIL=siobhan.oconnor@example.com -e 'ADMIN_PASSWORD=Gr33n-Fields!2026' \
    -e TELEMETRY=false -e RATE_LIMITER_ENABLED=false -e PUBLIC_URL="http://127.0.0.1:$port" \
    "directus/directus:$DIRECTUS_VERSION" >/dev/null
  ready=/server/ping
  ;;
*)
  echo "record.sh: APP=$APP: want juice-shop, gitea, wordpress or directus" >&2
  exit 2
  ;;
esac
for _ in $(seq 180); do
  if curl -sf -o /dev/null "http://127.0.0.1:$port$ready"; then
    break
  fi
  sleep 1
done
if [[ $APP == wordpress ]]; then
  # Readers comment one after the other from one address: WordPress's
  # flood check (one comment per 15 s per IP) is off, as for a site behind
  # a proxy that sends the readers' own addresses.
  docker exec -u www-data "$name" sh -c 'mkdir -p wp-content/mu-plugins &&
    printf "<?php\nadd_filter(\"comment_flood_filter\", \"__return_false\");\n" >wp-content/mu-plugins/fp-run.php'
fi
go run ./hack/fptraffic -app "$APP" -target "http://127.0.0.1:$port" -out "$OUT"
